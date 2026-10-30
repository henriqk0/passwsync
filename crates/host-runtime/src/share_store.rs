//! File adapter of the `wallet-sync` [`ReceivedStore`] port (005
//! contracts/host-runtime-share.md "Files (added)"): `$XDG_DATA_HOME/passwsync/received/`
//! (0700) holding `<id>.pwsw` (ciphertext exactly as received), `<id>.meta` (text, checksum)
//! and transiently `<id>.part`, all 0600. Write order on receipt: append to `.part` -> fsync ->
//! rename to `.pwsw` -> directory fsync -> atomic meta write. A permissive, foreign-owned or
//! symlinked directory is unusable and never rewritten. No wallet name, wallet id, code or
//! password is ever written.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, BufWriter, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use sha2::{Digest, Sha256};
use wallet_sync::codec::MAX_COPY;
use wallet_sync::ports::{IncomingCopy, PeerId, ReceivedMeta, ReceivedStore, StoreError};

use crate::sync_store::classify;

const META_MAGIC: &str = "passwsync-received-v1";
const MAX_META: u64 = 1024;
/// Buffered writes while receiving (well under the 1 MiB transfer bound).
const WRITE_BUFFER: usize = 64 * 1024;

/// A step of the receive path where a test can inject a failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiveFault {
    Create,
    Append,
    Fsync,
    Rename,
    DirFsync,
    MetaWrite,
}

fn hex(bytes: &[u8]) -> String {
    crate::hex::encode(bytes)
}

fn id_from_hex(text: &str) -> Option<[u8; 16]> {
    if text.len() != 32 || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0u8; 16];
    for (slot, i) in out.iter_mut().zip((0..32).step_by(2)) {
        *slot = u8::from_str_radix(&text[i..i + 2], 16).ok()?;
    }
    Some(out)
}

fn owner_only(metadata: &fs::Metadata) -> bool {
    metadata.uid() == rustix::process::getuid().as_raw() && metadata.mode() & 0o077 == 0
}

fn dir_fsync(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// The meta text of `meta` (contracts/host-runtime-share.md "Meta format").
pub fn encode_meta(meta: &ReceivedMeta) -> String {
    let body = format!(
        "{META_MAGIC}\nsender {}\nreceived {}\nsize {}\n",
        meta.sender.to_hex(),
        meta.received_at,
        meta.size
    );
    let check = hex(&Sha256::digest(body.as_bytes()));
    format!("{body}check {check}\n")
}

/// Parses meta text; `None` when malformed or the checksum fails.
pub fn decode_meta(id: [u8; 16], text: &str) -> Option<ReceivedMeta> {
    let split = text.rfind("check ")?;
    let (body, check_line) = text.split_at(split);
    let check = check_line.strip_prefix("check ")?.strip_suffix('\n')?;
    if check != hex(&Sha256::digest(body.as_bytes())) {
        return None;
    }
    let mut lines = body.lines();
    if lines.next()? != META_MAGIC {
        return None;
    }
    let sender = PeerId::from_hex(lines.next()?.strip_prefix("sender ")?)?;
    let number = |line: Option<&str>, key: &str| -> Option<u64> {
        let digits = line?.strip_prefix(key)?;
        if digits.is_empty() || digits.len() > 20 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        digits.parse().ok()
    };
    let received_at = number(lines.next(), "received ")?;
    let size = number(lines.next(), "size ")?;
    if lines.next().is_some() || !body.ends_with('\n') {
        return None;
    }
    Some(ReceivedMeta {
        id,
        sender,
        received_at,
        size,
    })
}

/// What [`FsReceivedStore::scan`] found in the directory (start-up step 5e classes).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Scan {
    /// Complete, consistent entries.
    pub entries: Vec<ReceivedMeta>,
    /// `*.part` files.
    pub partial: Vec<[u8; 16]>,
    /// `.pwsw` without `.meta`, or `.meta` without `.pwsw`.
    pub orphan: Vec<[u8; 16]>,
    /// Meta unparsable, checksum failure, size mismatch or not a private regular file.
    pub corrupted: Vec<[u8; 16]>,
}

pub struct FsReceivedStore {
    root: PathBuf,
    fault: Arc<Mutex<Option<ReceiveFault>>>,
}

impl FsReceivedStore {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            fault: Arc::new(Mutex::new(None)),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Creates `received/` (0700) if missing, else checks it: a symlink, a non-directory, or
    /// one not owner-only is `Corrupted` (status `received_unusable`) and left as it is.
    pub fn prepare(&self) -> Result<(), StoreError> {
        if let Some(parent) = self.root.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent).map_err(|e| classify(&e))?;
            }
        }
        match DirBuilder::new().mode(0o700).create(&self.root) {
            Ok(()) => {
                if let Some(parent) = self.root.parent() {
                    let _ = dir_fsync(parent);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(classify(&e)),
        }
        self.check_dir()
    }

    fn check_dir(&self) -> Result<(), StoreError> {
        let meta = fs::symlink_metadata(&self.root).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => StoreError::NotFound,
            _ => StoreError::Io,
        })?;
        if !meta.is_dir() || !owner_only(&meta) {
            return Err(StoreError::Corrupted);
        }
        Ok(())
    }

    /// The next receive fails at `step` (fault injection).
    pub fn inject(&self, step: ReceiveFault) {
        *self.fault.lock().unwrap_or_else(PoisonError::into_inner) = Some(step);
    }

    fn path(&self, id: &[u8; 16], ext: &str) -> PathBuf {
        self.root.join(format!("{}.{ext}", hex(id)))
    }

    /// Classifies every file of the directory without changing anything.
    pub fn scan(&self) -> Result<Scan, StoreError> {
        self.check_dir()?;
        let mut scan = Scan::default();
        let mut pwsw: Vec<[u8; 16]> = Vec::new();
        let mut metas: Vec<[u8; 16]> = Vec::new();
        for entry in fs::read_dir(&self.root)
            .map_err(|_| StoreError::Io)?
            .flatten()
        {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some((stem, ext)) = name.split_once('.') else {
                continue;
            };
            let Some(id) = id_from_hex(stem) else {
                continue;
            };
            match ext {
                "part" => scan.partial.push(id),
                "pwsw" => pwsw.push(id),
                "meta" => metas.push(id),
                _ => {}
            }
        }
        for id in &pwsw {
            if !metas.contains(id) {
                scan.orphan.push(*id);
            }
        }
        for id in metas {
            if !pwsw.contains(&id) {
                scan.orphan.push(id);
                continue;
            }
            match self.read_entry_meta(id) {
                Some(meta) => scan.entries.push(meta),
                None => scan.corrupted.push(id),
            }
        }
        scan.entries.sort_by_key(|m| (m.received_at, m.id));
        Ok(scan)
    }

    /// Reads and checks one entry's meta against its ciphertext file.
    fn read_entry_meta(&self, id: [u8; 16]) -> Option<ReceivedMeta> {
        let meta_path = self.path(&id, "meta");
        let fmeta = fs::symlink_metadata(&meta_path).ok()?;
        if !fmeta.is_file() || !owner_only(&fmeta) || fmeta.len() > MAX_META {
            return None;
        }
        let mut text = String::new();
        File::open(&meta_path)
            .ok()?
            .take(MAX_META)
            .read_to_string(&mut text)
            .ok()?;
        let meta = decode_meta(id, &text)?;
        let data = fs::symlink_metadata(self.path(&id, "pwsw")).ok()?;
        if !data.is_file() || !owner_only(&data) || data.len() != meta.size {
            return None;
        }
        if meta.size > u64::from(MAX_COPY) {
            return None;
        }
        Some(meta)
    }

    /// Complete entries and how many unusable ones were skipped.
    pub fn list_report(&self) -> Result<(Vec<ReceivedMeta>, usize), StoreError> {
        let scan = self.scan()?;
        let skipped = scan.orphan.len() + scan.corrupted.len();
        Ok((scan.entries, skipped))
    }

    /// Deletes every file of `id` (`.part`, `.pwsw`, `.meta`), best effort.
    pub fn remove_all(&self, id: [u8; 16]) {
        for ext in ["part", "pwsw", "meta"] {
            let _ = fs::remove_file(self.path(&id, ext));
        }
        let _ = dir_fsync(&self.root);
    }
}

impl ReceivedStore for FsReceivedStore {
    fn list(&self) -> Result<Vec<ReceivedMeta>, StoreError> {
        self.list_report().map(|(entries, _)| entries)
    }

    fn begin(
        &self,
        id: [u8; 16],
        sender: PeerId,
        received_at: u64,
    ) -> Result<Box<dyn IncomingCopy>, StoreError> {
        self.check_dir()?;
        let part = self.path(&id, "part");
        let take = |step| take_fault(&self.fault, step);
        let file = take(ReceiveFault::Create)
            .and_then(|()| {
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&part)
            })
            .map_err(|e| classify(&e))?;
        Ok(Box::new(FsReceiving {
            writer: Some(BufWriter::with_capacity(WRITE_BUFFER, file)),
            written: 0,
            part,
            pwsw: self.path(&id, "pwsw"),
            meta: self.path(&id, "meta"),
            dir: self.root.clone(),
            info: ReceivedMeta {
                id,
                sender,
                received_at,
                size: 0,
            },
            fault: Arc::clone(&self.fault),
        }))
    }

    fn read(&self, id: [u8; 16]) -> Result<Vec<u8>, StoreError> {
        self.check_dir()?;
        let Some(meta) = self.read_entry_meta(id) else {
            return if self.path(&id, "pwsw").exists() || self.path(&id, "meta").exists() {
                Err(StoreError::Corrupted)
            } else {
                Err(StoreError::NotFound)
            };
        };
        let mut bytes = Vec::with_capacity(meta.size as usize);
        File::open(self.path(&id, "pwsw"))
            .and_then(|f| f.take(meta.size).read_to_end(&mut bytes))
            .map_err(|e| classify(&e))?;
        if bytes.len() as u64 != meta.size {
            return Err(StoreError::Corrupted);
        }
        Ok(bytes)
    }

    fn delete(&self, id: [u8; 16]) -> Result<(), StoreError> {
        self.check_dir()?;
        let pwsw = self.path(&id, "pwsw");
        let meta = self.path(&id, "meta");
        if !pwsw.exists() && !meta.exists() {
            return Err(StoreError::NotFound);
        }
        // Meta first: an entry without meta is an orphan and is cleaned at start-up.
        for path in [meta, pwsw] {
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(classify(&e)),
            }
        }
        let _ = dir_fsync(&self.root);
        Ok(())
    }
}

fn take_fault(fault: &Mutex<Option<ReceiveFault>>, step: ReceiveFault) -> io::Result<()> {
    let mut fault = fault.lock().unwrap_or_else(PoisonError::into_inner);
    if *fault == Some(step) {
        *fault = None;
        return Err(io::Error::other("injected fault"));
    }
    Ok(())
}

struct FsReceiving {
    writer: Option<BufWriter<File>>,
    written: u64,
    part: PathBuf,
    pwsw: PathBuf,
    meta: PathBuf,
    dir: PathBuf,
    info: ReceivedMeta,
    fault: Arc<Mutex<Option<ReceiveFault>>>,
}

impl FsReceiving {
    fn discard(&mut self) {
        self.writer = None;
        let _ = fs::remove_file(&self.part);
    }
}

impl IncomingCopy for FsReceiving {
    fn append(&mut self, bytes: &[u8]) -> Result<(), StoreError> {
        let result = take_fault(&self.fault, ReceiveFault::Append).and_then(|()| {
            self.writer
                .as_mut()
                .ok_or_else(|| io::Error::other("closed"))?
                .write_all(bytes)
        });
        match result {
            Ok(()) => {
                self.written += bytes.len() as u64;
                Ok(())
            }
            Err(error) => {
                self.discard();
                Err(classify(&error))
            }
        }
    }

    fn finish(mut self: Box<Self>) -> Result<(), StoreError> {
        let fault = Arc::clone(&self.fault);
        let take = |step| take_fault(&fault, step);
        let mut info = self.info.clone();
        info.size = self.written;
        let writer = self.writer.take();
        let staged = (|| -> io::Result<()> {
            let writer = writer.ok_or_else(|| io::Error::other("closed"))?;
            let file = writer.into_inner().map_err(|e| e.into_error())?;
            take(ReceiveFault::Fsync)?;
            file.sync_all()?;
            drop(file);
            take(ReceiveFault::Rename)?;
            fs::rename(&self.part, &self.pwsw)
        })();
        if let Err(error) = staged {
            let _ = fs::remove_file(&self.part);
            return Err(classify(&error));
        }
        let committed = (|| -> io::Result<()> {
            take(ReceiveFault::DirFsync)?;
            dir_fsync(&self.dir)?;
            take(ReceiveFault::MetaWrite)?;
            crate::files::write_private_atomic(&self.meta, encode_meta(&info).as_bytes())?;
            dir_fsync(&self.dir)
        })();
        if let Err(error) = committed {
            let _ = fs::remove_file(&self.meta);
            let _ = fs::remove_file(&self.pwsw);
            let _ = dir_fsync(&self.dir);
            return Err(classify(&error));
        }
        Ok(())
    }

    fn abort(mut self: Box<Self>) {
        self.discard();
    }
}

impl Drop for FsReceiving {
    fn drop(&mut self) {
        // Dropped without `finish`: never leave a partial file behind.
        if self.writer.is_some() {
            self.discard();
        }
    }
}
