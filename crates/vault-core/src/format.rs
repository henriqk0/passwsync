use std::collections::{BTreeMap, HashSet};

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::entry::EntryV1;
use crate::kdf::derive_key;
use crate::{
    DeviceId, Entry, KdfConfig, MasterPassword, StateVector, Timestamp, VaultError, VaultKey,
    VersionVector, WalletId,
};

const MAGIC: &[u8; 4] = b"PWSV";
/// Version written by this build (004, contracts/file-format-v2.md).
pub(crate) const FORMAT_VERSION: u16 = 2;
const FORMAT_V1: u16 = 1;
const KDF_ARGON2ID: u8 = 1;
pub(crate) const HEADER_LEN: usize = 63;
const TAG_LEN: usize = 16;
pub(crate) const MIN_FILE_LEN: usize = HEADER_LEN + TAG_LEN;
pub(crate) const MAX_FILE_LEN: usize = 64 * 1024 * 1024;

/// Plaintext, authenticated file header (see contracts/file-format.md). Version 2 keeps the
/// v1 layout; only the version field differs (no sync metadata in clear, research R2).
pub(crate) struct Header {
    pub version: u16,
    pub kdf: KdfConfig,
    pub salt: [u8; 32],
    pub nonce: [u8; 12],
}

impl Header {
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut bytes = [0u8; HEADER_LEN];
        bytes[0..4].copy_from_slice(MAGIC);
        bytes[4..6].copy_from_slice(&self.version.to_le_bytes());
        bytes[6] = KDF_ARGON2ID;
        bytes[7..11].copy_from_slice(&self.kdf.memory_kib.to_le_bytes());
        bytes[11..15].copy_from_slice(&self.kdf.iterations.to_le_bytes());
        bytes[15..19].copy_from_slice(&self.kdf.parallelism.to_le_bytes());
        bytes[19..51].copy_from_slice(&self.salt);
        bytes[51..63].copy_from_slice(&self.nonce);
        bytes
    }

    /// Checks 1-4 of the parse order; runs before any key derivation.
    pub fn parse(bytes: &[u8]) -> Result<Self, VaultError> {
        if !(MIN_FILE_LEN..=MAX_FILE_LEN).contains(&bytes.len()) || &bytes[0..4] != MAGIC {
            return Err(VaultError::MalformedFile);
        }
        let version = u16::from_le_bytes([bytes[4], bytes[5]]);
        if version != FORMAT_V1 && version != FORMAT_VERSION {
            return Err(VaultError::UnsupportedVersion(version));
        }
        if bytes[6] != KDF_ARGON2ID {
            return Err(VaultError::UnsupportedKdf);
        }
        let kdf = KdfConfig {
            memory_kib: u32_at(bytes, 7),
            iterations: u32_at(bytes, 11),
            parallelism: u32_at(bytes, 15),
        };
        kdf.validate()?;
        Ok(Self {
            version,
            kdf,
            salt: bytes[19..51].try_into().expect("32-byte slice"),
            nonce: bytes[51..63].try_into().expect("12-byte slice"),
        })
    }
}

/// Parses only the header fields needed to budget memory before unlocking: the same parse
/// steps as `unlock` up to KDF parameter validation. Never touches a password, key, or the
/// ciphertext. The values are untrusted until `unlock` authenticates the header as AAD.
pub fn peek_kdf_config(bytes: &[u8]) -> Result<KdfConfig, VaultError> {
    Header::parse(bytes).map(|header| header.kdf)
}

/// The (unauthenticated) format version of wallet bytes, read without any password: 1 or 2.
/// Used only to tell the person that a version 1 wallet is not synced yet.
pub fn peek_format_version(bytes: &[u8]) -> Result<u16, VaultError> {
    Header::parse(bytes).map(|header| header.version)
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("4-byte slice"))
}

/// Encrypted body (v2), borrowed for sealing so entries are not copied.
#[derive(Serialize)]
pub(crate) struct PayloadRef<'a> {
    pub wallet_id: WalletId,
    pub created_at: Timestamp,
    pub state: &'a StateVector,
    pub password_epoch: &'a VersionVector,
    pub entries: &'a [Entry],
}

/// Encrypted body as read back (v1 bodies are converted on read).
pub(crate) struct Payload {
    pub wallet_id: WalletId,
    pub created_at: Timestamp,
    pub state: StateVector,
    pub password_epoch: VersionVector,
    pub entries: Vec<Entry>,
    /// Format version of the file it came from.
    pub format: u16,
}

#[derive(Deserialize)]
struct PayloadV2 {
    wallet_id: WalletId,
    created_at: Timestamp,
    state: StateVector,
    password_epoch: VersionVector,
    entries: Vec<Entry>,
}

#[derive(Deserialize)]
struct PayloadV1 {
    wallet_id: WalletId,
    created_at: Timestamp,
    entries: Vec<EntryV1>,
}

fn unique_ids(entries: &[Entry]) -> bool {
    let mut seen = HashSet::with_capacity(entries.len());
    entries.iter().all(|entry| seen.insert(entry.id()))
}

impl PayloadV2 {
    /// The body is authentic here, so a failure means a bug or a forged-but-valid file; it is
    /// reported with the same generic error. Entry invariants were checked while decoding.
    fn validate(self) -> Result<Payload, VaultError> {
        let within_state = self.entries.iter().all(|entry| {
            entry.versions().iter().all(|version| {
                version
                    .version()
                    .iter()
                    .all(|(device, counter)| self.state.get(device) >= counter)
            })
        });
        if !unique_ids(&self.entries) || !within_state {
            return Err(VaultError::InvalidPasswordOrCorrupted);
        }
        Ok(Payload {
            wallet_id: self.wallet_id,
            created_at: self.created_at,
            state: self.state,
            password_epoch: self.password_epoch,
            entries: self.entries,
            format: FORMAT_VERSION,
        })
    }
}

impl PayloadV1 {
    /// Each entry becomes a single current version; `state[d]` is the exact number of changes
    /// `d` made (the sum of its entry counters, research R3).
    fn convert(self) -> Result<Payload, VaultError> {
        let corrupt = || VaultError::InvalidPasswordOrCorrupted;
        let entries: Vec<Entry> = self.entries.into_iter().map(EntryV1::into_entry).collect();
        let valid = entries.iter().all(|entry| {
            entry
                .fields()
                .is_none_or(|fields| fields.validate().is_ok())
        });
        if !unique_ids(&entries) || !valid {
            return Err(corrupt());
        }
        let mut sums: BTreeMap<DeviceId, u64> = BTreeMap::new();
        for entry in &entries {
            for (device, counter) in entry.version().iter() {
                let slot = sums.entry(device.clone()).or_insert(0);
                *slot = slot.checked_add(counter).ok_or_else(corrupt)?;
            }
        }
        let state = StateVector::from_pairs(sums.into_iter().collect()).map_err(|_| corrupt())?;
        Ok(Payload {
            wallet_id: self.wallet_id,
            created_at: self.created_at,
            state,
            password_epoch: VersionVector::empty(),
            entries,
            format: FORMAT_V1,
        })
    }
}

/// Serializes `payload` and encrypts it under `key` with a fresh random nonce.
pub(crate) fn seal(
    key: &VaultKey,
    kdf: KdfConfig,
    salt: &[u8; 32],
    payload: &PayloadRef<'_>,
) -> Result<Vec<u8>, VaultError> {
    let size =
        postcard::experimental::serialized_size(payload).map_err(|_| VaultError::MalformedFile)?;
    // Refuse here: a larger file would save fine but could never be unlocked again.
    if HEADER_LEN + size + TAG_LEN > MAX_FILE_LEN {
        return Err(VaultError::WalletTooLarge);
    }
    // Zeroizing from the start (so error paths wipe it too) and pre-sized with room for the
    // tag so the plaintext buffer never reallocates.
    let mut plaintext = Zeroizing::new(Vec::with_capacity(size + TAG_LEN));
    plaintext.resize(size, 0);
    postcard::to_slice(payload, &mut plaintext).map_err(|_| VaultError::MalformedFile)?;
    seal_plaintext(key, FORMAT_VERSION, kdf, salt, plaintext)
}

pub(crate) fn seal_plaintext(
    key: &VaultKey,
    version: u16,
    kdf: KdfConfig,
    salt: &[u8; 32],
    buffer: Zeroizing<Vec<u8>>,
) -> Result<Vec<u8>, VaultError> {
    let mut nonce = [0u8; 12];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| VaultError::Rng)?;
    seal_plaintext_with_nonce(key, version, kdf, salt, nonce, buffer)
}

/// As [`seal_plaintext`] with a caller-chosen nonce (008: deterministic fuzz seeds through
/// `testkit` only; production always draws a fresh nonce).
pub(crate) fn seal_plaintext_with_nonce(
    key: &VaultKey,
    version: u16,
    kdf: KdfConfig,
    salt: &[u8; 32],
    nonce: [u8; 12],
    mut buffer: Zeroizing<Vec<u8>>,
) -> Result<Vec<u8>, VaultError> {
    let header = Header {
        version,
        kdf,
        salt: *salt,
        nonce,
    }
    .encode();
    cipher(key)?
        .encrypt_in_place(Nonce::from_slice(&nonce), &header, &mut *buffer)
        .map_err(|_| VaultError::InvalidPasswordOrCorrupted)?;
    let mut file = Vec::with_capacity(HEADER_LEN + buffer.len());
    file.extend_from_slice(&header);
    file.extend_from_slice(&buffer);
    Ok(file)
}

/// Decrypts and decodes `bytes` whose header was already parsed.
pub(crate) fn open_with_key(
    bytes: &[u8],
    header: &Header,
    key: &VaultKey,
) -> Result<Payload, VaultError> {
    let buffer = decrypt(bytes, header, key)?;
    decode_plaintext(header.version, &buffer)
}

/// Authenticates and decrypts the body; the plaintext is wiped on drop.
fn decrypt(
    bytes: &[u8],
    header: &Header,
    key: &VaultKey,
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let mut buffer = Zeroizing::new(bytes[HEADER_LEN..].to_vec());
    cipher(key)?
        .decrypt_in_place(
            Nonce::from_slice(&header.nonce),
            &bytes[..HEADER_LEN],
            &mut *buffer,
        )
        .map_err(|_| VaultError::InvalidPasswordOrCorrupted)?;
    Ok(buffer)
}

/// Decodes an authenticated plaintext of format `version` (008: also reached by the
/// `testkit` fuzz entry, so tests run exactly this production decoder).
pub(crate) fn decode_plaintext(version: u16, plaintext: &[u8]) -> Result<Payload, VaultError> {
    let corrupt = || VaultError::InvalidPasswordOrCorrupted;
    if version == FORMAT_V1 {
        let (payload, rest) =
            postcard::take_from_bytes::<PayloadV1>(plaintext).map_err(|_| corrupt())?;
        if !rest.is_empty() {
            return Err(corrupt());
        }
        return payload.convert();
    }
    let (payload, rest) =
        postcard::take_from_bytes::<PayloadV2>(plaintext).map_err(|_| corrupt())?;
    if !rest.is_empty() {
        return Err(corrupt());
    }
    payload.validate()
}

/// Full unlock: parse the header, derive the key from `password`, decrypt.
pub(crate) fn open(
    bytes: &[u8],
    password: &MasterPassword,
) -> Result<(Header, VaultKey, Payload), VaultError> {
    let header = Header::parse(bytes)?;
    let key = derive_key(password, &header.kdf, &header.salt)?;
    let payload = open_with_key(bytes, &header, &key)?;
    Ok((header, key, payload))
}

fn cipher(key: &VaultKey) -> Result<Aes256Gcm, VaultError> {
    Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|_| VaultError::InvalidPasswordOrCorrupted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DeviceId, Entry, EntryFields, WalletId};

    fn key(byte: u8) -> VaultKey {
        VaultKey::from_bytes([byte; 32])
    }

    fn sample_entries() -> Vec<Entry> {
        let device = DeviceId::new("laptop").unwrap();
        let mut fields = EntryFields::default();
        fields.title = "GitHub".into();
        fields.password = "pw".into();
        vec![Entry::new_live(fields, &device, 10).unwrap()]
    }

    #[test]
    fn header_is_63_bytes_with_documented_offsets() {
        let header = Header {
            version: 1,
            kdf: KdfConfig::DEFAULT,
            salt: [9; 32],
            nonce: [5; 12],
        };
        let bytes = header.encode();
        assert_eq!(bytes.len(), 63);
        assert_eq!(&bytes[0..4], b"PWSV");
        assert_eq!(&bytes[4..6], &1u16.to_le_bytes());
        assert_eq!(bytes[6], 1);
        assert_eq!(&bytes[7..11], &65_536u32.to_le_bytes());
        assert_eq!(&bytes[11..15], &12u32.to_le_bytes());
        assert_eq!(&bytes[15..19], &1u32.to_le_bytes());
        assert_eq!(&bytes[19..51], &[9; 32]);
        assert_eq!(&bytes[51..63], &[5; 12]);
    }

    #[test]
    fn header_parse_round_trips() {
        let header = Header {
            version: 2,
            kdf: KdfConfig::MINIMUM,
            salt: [3; 32],
            nonce: [4; 12],
        };
        let mut file = header.encode().to_vec();
        file.extend_from_slice(&[0; 16]);
        let parsed = Header::parse(&file).unwrap();
        assert_eq!(parsed.kdf, KdfConfig::MINIMUM);
        assert_eq!(parsed.salt, [3; 32]);
        assert_eq!(parsed.nonce, [4; 12]);
    }

    #[test]
    fn seal_then_open_returns_same_payload() {
        let entries = sample_entries();
        let wallet = WalletId::from_bytes([8; 16]);
        let mut state = StateVector::new();
        state.bump(&DeviceId::new("laptop").unwrap()).unwrap();
        let epoch = VersionVector::empty();
        let payload = PayloadRef {
            wallet_id: wallet,
            created_at: 42,
            state: &state,
            password_epoch: &epoch,
            entries: &entries,
        };
        let bytes = seal(&key(1), KdfConfig::MINIMUM, &[7; 32], &payload).unwrap();
        let header = Header::parse(&bytes).unwrap();
        let opened = open_with_key(&bytes, &header, &key(1)).unwrap();
        assert_eq!(opened.wallet_id, wallet);
        assert_eq!(opened.created_at, 42);
        assert_eq!(opened.entries.len(), 1);
        assert_eq!(opened.entries[0].id(), entries[0].id());
        assert_eq!(opened.entries[0].fields(), entries[0].fields());
    }

    #[test]
    fn each_seal_uses_a_fresh_nonce() {
        let entries = sample_entries();
        let (state, epoch) = (StateVector::new(), VersionVector::empty());
        let payload = PayloadRef {
            wallet_id: WalletId::from_bytes([0; 16]),
            created_at: 0,
            state: &state,
            password_epoch: &epoch,
            entries: &entries,
        };
        let a = seal(&key(1), KdfConfig::MINIMUM, &[7; 32], &payload).unwrap();
        let b = seal(&key(1), KdfConfig::MINIMUM, &[7; 32], &payload).unwrap();
        assert_ne!(a[51..63], b[51..63]);
        assert_ne!(a[63..], b[63..]);
    }

    #[test]
    fn wrong_key_is_the_generic_error() {
        let (state, epoch) = (StateVector::new(), VersionVector::empty());
        let payload = PayloadRef {
            wallet_id: WalletId::from_bytes([0; 16]),
            created_at: 0,
            state: &state,
            password_epoch: &epoch,
            entries: &[],
        };
        let bytes = seal(&key(1), KdfConfig::MINIMUM, &[7; 32], &payload).unwrap();
        let header = Header::parse(&bytes).unwrap();
        assert!(matches!(
            open_with_key(&bytes, &header, &key(2)),
            Err(VaultError::InvalidPasswordOrCorrupted)
        ));
    }

    // Authenticated-but-invalid version 1 payloads, crafted by mirroring the wire shape.
    #[derive(serde::Serialize)]
    struct RawPayload {
        wallet_id: [u8; 16],
        created_at: i64,
        entries: Vec<RawEntry>,
    }

    #[derive(serde::Serialize)]
    struct RawEntry {
        id: [u8; 16],
        created_at: i64,
        modified_at: i64,
        last_modified_by: String,
        version: Vec<(String, u64)>,
        state: RawState,
    }

    #[derive(serde::Serialize)]
    enum RawState {
        Live {
            title: String,
            username: String,
            password: String,
            url: String,
            notes: String,
        },
        Deleted {
            deleted_at: i64,
        },
    }

    fn raw_entry(id: u8) -> RawEntry {
        RawEntry {
            id: [id; 16],
            created_at: 1,
            modified_at: 1,
            last_modified_by: "laptop".into(),
            version: vec![("laptop".into(), 1)],
            state: RawState::Live {
                title: "t".into(),
                username: String::new(),
                password: String::new(),
                url: String::new(),
                notes: String::new(),
            },
        }
    }

    fn open_crafted(entries: Vec<RawEntry>, trailing: &[u8]) -> Result<Payload, VaultError> {
        let raw = RawPayload {
            wallet_id: [1; 16],
            created_at: 0,
            entries,
        };
        let mut plaintext = postcard::to_allocvec(&raw).unwrap();
        plaintext.extend_from_slice(trailing);
        let bytes = seal_plaintext(
            &key(1),
            1,
            KdfConfig::MINIMUM,
            &[7; 32],
            Zeroizing::new(plaintext),
        )
        .unwrap();
        let header = Header::parse(&bytes).unwrap();
        open_with_key(&bytes, &header, &key(1))
    }

    fn assert_rejected(result: Result<Payload, VaultError>) {
        assert!(matches!(
            result,
            Err(VaultError::InvalidPasswordOrCorrupted)
        ));
    }

    #[test]
    fn crafted_valid_payload_is_accepted() {
        let payload = open_crafted(vec![raw_entry(1), raw_entry(2)], &[]).unwrap();
        assert_eq!(payload.entries.len(), 2);
    }

    #[test]
    fn duplicate_entry_ids_are_rejected() {
        assert_rejected(open_crafted(vec![raw_entry(1), raw_entry(1)], &[]));
    }

    #[test]
    fn unsorted_or_duplicate_version_keys_are_rejected() {
        let mut unsorted = raw_entry(1);
        unsorted.version = vec![("b".into(), 1), ("a".into(), 1)];
        assert_rejected(open_crafted(vec![unsorted], &[]));
        let mut duplicate = raw_entry(1);
        duplicate.version = vec![("a".into(), 1), ("a".into(), 2)];
        assert_rejected(open_crafted(vec![duplicate], &[]));
    }

    #[test]
    fn zero_version_counter_is_rejected() {
        let mut entry = raw_entry(1);
        entry.version = vec![("a".into(), 0)];
        assert_rejected(open_crafted(vec![entry], &[]));
    }

    #[test]
    fn live_entry_with_empty_title_is_rejected() {
        let mut entry = raw_entry(1);
        entry.state = RawState::Live {
            title: " ".into(),
            username: String::new(),
            password: String::new(),
            url: String::new(),
            notes: String::new(),
        };
        assert_rejected(open_crafted(vec![entry], &[]));
    }

    #[test]
    fn tombstone_entries_are_accepted() {
        let mut entry = raw_entry(1);
        entry.state = RawState::Deleted { deleted_at: 5 };
        assert!(open_crafted(vec![entry], &[]).is_ok());
    }

    #[test]
    fn trailing_bytes_after_the_payload_are_rejected() {
        assert_rejected(open_crafted(vec![raw_entry(1)], &[0]));
    }
}
