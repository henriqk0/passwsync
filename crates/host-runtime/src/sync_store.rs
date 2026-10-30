//! File adapter of the `wallet-sync` [`SyncStore`] port (contracts/host-runtime-sync.md
//! "Files"): `$XDG_DATA_HOME/passwsync/sync/<wallet-id>/{record, pending-<peer>,
//! incoming-<peer>.part}`, directories 0700, files 0600, records written atomically (temp
//! file, fsync, rename, directory fsync). Anything not owner-only, a symlink or unreadable is
//! `Corrupted` and left as it is (never silently replaced, FR-025).

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, BufWriter, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use vault_core::WalletId;
use wallet_sync::ports::{IncomingCopy, PeerId, StoreError, SyncStore};
use wallet_sync::record::{self, MAX_RECORD, SyncRecord};

const RECORD: &str = "record";
const PENDING_PREFIX: &str = "pending-";
const INCOMING_PREFIX: &str = "incoming-";
const PART_SUFFIX: &str = ".part";
/// Buffered writes while receiving (the transfer buffer stays well under 1 MiB, FR-029).
const WRITE_BUFFER: usize = 64 * 1024;

/// A step of the atomic record write where a test can inject a failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteStep {
    TempWrite,
    Fsync,
    Rename,
}

/// Maps an I/O error to the port's coarse classes (ENOSPC is `NoSpace`).
pub fn classify(error: &io::Error) -> StoreError {
    if error.raw_os_error() == Some(28) || error.kind() == io::ErrorKind::StorageFull {
        StoreError::NoSpace
    } else {
        StoreError::Io
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn wallet_from_hex(name: &str) -> Option<WalletId> {
    if name.len() != 32 || !name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (slot, i) in bytes.iter_mut().zip((0..32).step_by(2)) {
        *slot = u8::from_str_radix(&name[i..i + 2], 16).ok()?;
    }
    Some(WalletId::from_bytes(bytes))
}

fn owner_only(metadata: &fs::Metadata) -> bool {
    metadata.uid() == rustix::process::getuid().as_raw() && metadata.mode() & 0o077 == 0
}

fn sync_dir_fsync(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

pub struct FileSyncStore {
    root: PathBuf,
    /// Serializes record read-modify-writes (records are tiny; one lock is enough).
    lock: Mutex<()>,
    fault: Mutex<Option<WriteStep>>,
}

impl FileSyncStore {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            lock: Mutex::new(()),
            fault: Mutex::new(None),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Creates `sync/` (0700) or checks the existing one.
    pub fn prepare(&self) -> Result<(), StoreError> {
        ensure_dir(&self.root)
    }

    /// The next record write fails at `step` (fault injection for crash tests).
    pub fn inject(&self, step: WriteStep) {
        *self.fault.lock().unwrap_or_else(PoisonError::into_inner) = Some(step);
    }

    fn take_fault(&self, step: WriteStep) -> io::Result<()> {
        let mut fault = self.fault.lock().unwrap_or_else(PoisonError::into_inner);
        if *fault == Some(step) {
            *fault = None;
            return Err(io::Error::other("injected fault"));
        }
        Ok(())
    }

    fn guard(&self) -> MutexGuard<'_, ()> {
        self.lock.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn wallet_dir(&self, wallet: &WalletId) -> PathBuf {
        self.root.join(hex(wallet.as_bytes()))
    }

    fn pending_path(&self, wallet: &WalletId, peer: &PeerId) -> PathBuf {
        self.wallet_dir(wallet)
            .join(format!("{PENDING_PREFIX}{}", peer.to_hex()))
    }

    fn read_record(&self, wallet: &WalletId) -> Result<Option<SyncRecord>, StoreError> {
        let dir = self.wallet_dir(wallet);
        match fs::symlink_metadata(&dir) {
            Ok(meta) if meta.is_dir() && owner_only(&meta) => {}
            Ok(_) => return Err(StoreError::Corrupted),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(StoreError::Io),
        }
        let path = dir.join(RECORD);
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(StoreError::Io),
        };
        if !meta.is_file() || !owner_only(&meta) || meta.len() > MAX_RECORD as u64 {
            return Err(StoreError::Corrupted);
        }
        let mut text = String::new();
        File::open(&path)
            .and_then(|f| f.take(MAX_RECORD as u64 + 1).read_to_string(&mut text))
            .map_err(|_| StoreError::Corrupted)?;
        record::decode(&text)
            .map(Some)
            .map_err(|_| StoreError::Corrupted)
    }

    fn write_record(&self, record: &SyncRecord) -> Result<(), StoreError> {
        let dir = self.wallet_dir(&record.wallet_id);
        ensure_dir(&dir)?;
        let path = dir.join(RECORD);
        let temp = dir.join(".record.tmp");
        let _ = fs::remove_file(&temp);
        let text = record::encode(record);
        let result = (|| -> io::Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp)?;
            self.take_fault(WriteStep::TempWrite)?;
            file.write_all(text.as_bytes())?;
            self.take_fault(WriteStep::Fsync)?;
            file.sync_all()?;
            self.take_fault(WriteStep::Rename)?;
            fs::rename(&temp, &path)?;
            sync_dir_fsync(&dir)
        })();
        if let Err(error) = result {
            let _ = fs::remove_file(&temp);
            return Err(classify(&error));
        }
        Ok(())
    }

    /// Start-up (step 5c): deletes every `*.part`, every pending file without a record line,
    /// and every pending line without a file. Corrupted records are left untouched.
    pub fn cleanup(&self) -> Result<(), StoreError> {
        for wallet in self.wallets()? {
            let dir = self.wallet_dir(&wallet);
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            let mut files: Vec<PeerId> = Vec::new();
            for entry in entries.flatten() {
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                if name.starts_with(INCOMING_PREFIX) && name.ends_with(PART_SUFFIX) {
                    let _ = fs::remove_file(entry.path());
                } else if let Some(peer) =
                    name.strip_prefix(PENDING_PREFIX).and_then(PeerId::from_hex)
                {
                    files.push(peer);
                }
            }
            let _guard = self.guard();
            let Ok(Some(mut record)) = self.read_record(&wallet) else {
                continue;
            };
            for peer in &files {
                if !record.pending.contains_key(peer) {
                    let _ = fs::remove_file(self.pending_path(&wallet, peer));
                }
            }
            let before = record.pending.len();
            record.pending.retain(|peer, _| files.contains(peer));
            if record.pending.len() != before {
                self.write_record(&record)?;
            }
        }
        Ok(())
    }

    /// Replaces a record whatever the current file holds (explicit "reset sync state" only).
    pub fn overwrite(&self, record: &SyncRecord) -> Result<(), StoreError> {
        let _guard = self.guard();
        self.write_record(record)
    }

    /// The local wallet name written in a record that no longer parses (for the "record
    /// corrupted" message only).
    pub fn raw_wallet_name(&self, wallet: &WalletId) -> Option<String> {
        let mut text = String::new();
        File::open(self.wallet_dir(wallet).join(RECORD))
            .ok()?
            .take(MAX_RECORD as u64)
            .read_to_string(&mut text)
            .ok()?;
        let hex = text.lines().find_map(|l| l.strip_prefix("wallet_name "))?;
        if hex.len() % 2 != 0 {
            return None;
        }
        let bytes: Option<Vec<u8>> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok())
            .collect();
        String::from_utf8(bytes?).ok()
    }

    /// Size of a stored pending copy (for the UI and bounds).
    pub fn pending_size(&self, wallet: &WalletId, peer: &PeerId) -> Option<u64> {
        fs::symlink_metadata(self.pending_path(wallet, peer))
            .ok()
            .filter(|m| m.is_file())
            .map(|m| m.len())
    }

    /// Deletes every partial copy (shutdown: rounds are aborted).
    pub fn delete_partials(&self) {
        let Ok(wallets) = self.wallets() else {
            return;
        };
        for wallet in wallets {
            self.remove_partial_files(&wallet);
        }
    }

    /// Deletes the partial copies of one wallet (a round was aborted).
    pub fn remove_partial_files(&self, wallet: &WalletId) {
        if let Ok(entries) = fs::read_dir(self.wallet_dir(wallet)) {
            for entry in entries.flatten() {
                if entry
                    .file_name()
                    .to_str()
                    .is_some_and(|n| n.ends_with(PART_SUFFIX))
                {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
    }
}

fn ensure_dir(dir: &Path) -> Result<(), StoreError> {
    match DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {
            if let Some(parent) = dir.parent() {
                let _ = sync_dir_fsync(parent);
            }
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(classify(&e)),
    }
    let meta = fs::symlink_metadata(dir).map_err(|_| StoreError::Io)?;
    if !meta.is_dir() || !owner_only(&meta) {
        return Err(StoreError::Corrupted);
    }
    Ok(())
}

impl SyncStore for FileSyncStore {
    fn wallets(&self) -> Result<Vec<WalletId>, StoreError> {
        let mut out = Vec::new();
        let entries = match fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
            Err(_) => return Err(StoreError::Io),
        };
        for entry in entries.flatten() {
            let is_dir = entry.file_type().is_ok_and(|t| t.is_dir());
            if let Some(wallet) = entry.file_name().to_str().and_then(wallet_from_hex) {
                if is_dir {
                    out.push(wallet);
                }
            }
        }
        out.sort();
        Ok(out)
    }

    fn load(&self, wallet: &WalletId) -> Result<Option<SyncRecord>, StoreError> {
        let _guard = self.guard();
        self.read_record(wallet)
    }

    fn update(
        &self,
        wallet: &WalletId,
        f: &mut dyn FnMut(Option<SyncRecord>) -> Option<SyncRecord>,
    ) -> Result<Option<SyncRecord>, StoreError> {
        let _guard = self.guard();
        let current = self.read_record(wallet)?;
        match f(current.clone()) {
            None => Ok(current),
            Some(next) => {
                if next.wallet_id != *wallet {
                    return Err(StoreError::Io);
                }
                self.write_record(&next)?;
                Ok(Some(next))
            }
        }
    }

    fn begin_incoming(
        &self,
        wallet: &WalletId,
        peer: &PeerId,
    ) -> Result<Box<dyn IncomingCopy>, StoreError> {
        let dir = self.wallet_dir(wallet);
        ensure_dir(&dir)?;
        let part = dir.join(format!("{INCOMING_PREFIX}{}{PART_SUFFIX}", peer.to_hex()));
        let _ = fs::remove_file(&part);
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&part)
            .map_err(|e| classify(&e))?;
        Ok(Box::new(FileIncoming {
            writer: Some(BufWriter::with_capacity(WRITE_BUFFER, file)),
            part,
            pending: self.pending_path(wallet, peer),
            dir,
        }))
    }

    fn read_pending(&self, wallet: &WalletId, peer: &PeerId) -> Result<Vec<u8>, StoreError> {
        let path = self.pending_path(wallet, peer);
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(StoreError::NotFound),
            Err(_) => return Err(StoreError::Io),
        };
        if !meta.is_file()
            || !owner_only(&meta)
            || meta.len() > u64::from(wallet_sync::codec::MAX_COPY)
        {
            return Err(StoreError::Corrupted);
        }
        let mut bytes = Vec::with_capacity(meta.len() as usize);
        File::open(&path)
            .and_then(|f| {
                f.take(u64::from(wallet_sync::codec::MAX_COPY))
                    .read_to_end(&mut bytes)
            })
            .map_err(|e| classify(&e))?;
        Ok(bytes)
    }

    fn delete_pending(&self, wallet: &WalletId, peer: &PeerId) -> Result<(), StoreError> {
        match fs::remove_file(self.pending_path(wallet, peer)) {
            Ok(()) => {
                let _ = sync_dir_fsync(&self.wallet_dir(wallet));
                Ok(())
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(classify(&e)),
        }
    }

    fn pending_peers(&self, wallet: &WalletId) -> Result<Vec<PeerId>, StoreError> {
        let mut out = Vec::new();
        let entries = match fs::read_dir(self.wallet_dir(wallet)) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
            Err(_) => return Err(StoreError::Io),
        };
        for entry in entries.flatten() {
            if let Some(peer) = entry
                .file_name()
                .to_str()
                .and_then(|n| n.strip_prefix(PENDING_PREFIX))
                .and_then(PeerId::from_hex)
            {
                out.push(peer);
            }
        }
        out.sort();
        Ok(out)
    }
}

struct FileIncoming {
    writer: Option<BufWriter<File>>,
    part: PathBuf,
    pending: PathBuf,
    dir: PathBuf,
}

impl IncomingCopy for FileIncoming {
    fn append(&mut self, bytes: &[u8]) -> Result<(), StoreError> {
        let writer = self.writer.as_mut().ok_or(StoreError::Io)?;
        writer.write_all(bytes).map_err(|e| classify(&e))
    }

    fn finish(mut self: Box<Self>) -> Result<(), StoreError> {
        let result = (|| -> io::Result<()> {
            let writer = self
                .writer
                .take()
                .ok_or_else(|| io::Error::other("closed"))?;
            let file = writer.into_inner().map_err(|e| e.into_error())?;
            file.sync_all()?;
            drop(file);
            fs::rename(&self.part, &self.pending)?;
            sync_dir_fsync(&self.dir)
        })();
        if let Err(error) = result {
            let _ = fs::remove_file(&self.part);
            return Err(classify(&error));
        }
        Ok(())
    }

    fn abort(mut self: Box<Self>) {
        self.writer = None;
        let _ = fs::remove_file(&self.part);
    }
}

impl Drop for FileIncoming {
    fn drop(&mut self) {
        // Dropped without `finish`: never leave a partial copy behind.
        if self.writer.take().is_some() {
            let _ = fs::remove_file(&self.part);
        }
    }
}
