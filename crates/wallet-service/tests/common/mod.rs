#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;

use vault_core::{DeviceId, EntryFields, FixedClock, KdfConfig, MasterPassword, Vault};
use wallet_service::testkit::{FakeElapsedClock, MemoryWalletDirectory};
use wallet_service::{Service, ServiceConfig, WalletName};
use zeroize::Zeroizing;

pub const PASSWORD: &str = "correct horse battery";
pub const AUTO_LOCK: Duration = Duration::from_secs(15 * 60);

pub struct Fx {
    pub service: Service,
    pub dir: MemoryWalletDirectory,
    pub elapsed: Arc<FakeElapsedClock>,
    pub time: Arc<FixedClock>,
}

pub fn fx() -> Fx {
    fx_with_dir(MemoryWalletDirectory::new())
}

pub fn fx_with_dir(dir: MemoryWalletDirectory) -> Fx {
    let elapsed = Arc::new(FakeElapsedClock::new());
    let time = Arc::new(FixedClock::new(1_000));
    let service = Service::new(
        Arc::new(dir.clone()),
        time.clone(),
        elapsed.clone(),
        ServiceConfig {
            device: DeviceId::new("0123456789abcdef0123456789abcdef").unwrap(),
            wallet_kdf: KdfConfig::MINIMUM,
            auto_lock: AUTO_LOCK,
        },
    );
    Fx {
        service,
        dir,
        elapsed,
        time,
    }
}

pub fn pw(text: &str) -> Zeroizing<String> {
    Zeroizing::new(text.to_string())
}

pub fn name(text: &str) -> WalletName {
    WalletName::parse(text).unwrap()
}

pub fn fields(title: &str) -> EntryFields {
    EntryFields {
        title: title.into(),
        username: format!("{title}-user"),
        password: format!("{title}-secret"),
        url: format!("https://{}.example", title.to_lowercase()),
        notes: format!("{title} notes"),
    }
}

pub fn create(fx: &Fx, wallet: &str) -> WalletName {
    fx.service
        .create(wallet, pw(PASSWORD), pw(PASSWORD))
        .unwrap()
}

/// Wallet bytes created elsewhere (e.g. copied in), locked from the service's view.
pub fn foreign_wallet(fx: &Fx, wallet: &str, kdf: KdfConfig, titles: &[&str]) -> WalletName {
    let mut vault = Vault::create(
        MasterPassword::new(PASSWORD.into()),
        kdf,
        DeviceId::new("other-device").unwrap(),
        Box::new(FixedClock::new(5)),
    )
    .unwrap();
    for title in titles {
        vault.add_entry(fields(title)).unwrap();
    }
    let n = name(wallet);
    fx.dir.insert(&n, &vault.seal().unwrap());
    n
}

/// Opens the stored bytes independently of the service.
pub fn reopen(fx: &Fx, wallet: &WalletName) -> Vault {
    Vault::unlock(
        &fx.dir.bytes(wallet).unwrap(),
        MasterPassword::new(PASSWORD.into()),
        DeviceId::new("check").unwrap(),
        Box::new(FixedClock::new(0)),
    )
    .unwrap()
}
