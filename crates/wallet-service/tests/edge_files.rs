mod common;

use common::*;
use vault_core::KdfConfig;
use wallet_service::{ServiceError, UnlockOutcome, WalletStatus};

#[test]
fn damaged_files_are_listed_and_do_not_affect_other_wallets() {
    let fx = fx();
    let good = foreign_wallet(&fx, "Good", KdfConfig::MINIMUM, &["GitHub"]);
    fx.dir.insert(
        &name("Corrupt"),
        b"definitely not a wallet file at all, just some text bytes ...............",
    );
    let truncated = foreign_wallet(&fx, "Truncated", KdfConfig::MINIMUM, &[]);
    let bytes = fx.dir.bytes(&truncated).unwrap();
    // Cut the authentication tag: long enough to parse, too short to authenticate.
    fx.dir.insert(&truncated, &bytes[..bytes.len() - 3]);
    let future = foreign_wallet(&fx, "Future", KdfConfig::MINIMUM, &[]);
    let mut bytes = fx.dir.bytes(&future).unwrap();
    bytes[4] = 3; // 004: version 2 is the current format; 3 is the first unknown one
    fx.dir.insert(&future, &bytes);

    let names: Vec<WalletStatus> = fx.service.list().unwrap();
    let names: Vec<&str> = names.iter().map(|w| w.name.as_str()).collect();
    assert_eq!(names, ["Corrupt", "Future", "Good", "Truncated"]);

    assert_eq!(
        fx.service.unlock(&name("Corrupt"), pw(PASSWORD)),
        Err(ServiceError::MalformedFile)
    );
    assert_eq!(
        fx.service.unlock(&truncated, pw(PASSWORD)),
        Err(ServiceError::InvalidPasswordOrCorrupted)
    );
    assert_eq!(
        fx.service.unlock(&future, pw(PASSWORD)),
        Err(ServiceError::UnsupportedVersion)
    );
    assert_eq!(
        fx.service.unlock(&good, pw(PASSWORD)),
        Ok(UnlockOutcome::Unlocked)
    );
}

#[test]
fn wallet_deleted_while_unlocked_stays_usable_and_the_next_save_rewrites_it() {
    let fx = fx();
    let wallet = create(&fx, "Personal");
    fx.service.add_entry(&wallet, fields("GitHub")).unwrap();
    fx.dir.remove(&wallet);
    assert_eq!(
        fx.service.list().unwrap(),
        vec![WalletStatus {
            name: wallet.clone(),
            unlocked: true
        }]
    );
    fx.service.add_entry(&wallet, fields("GitLab")).unwrap();
    assert_eq!(reopen(&fx, &wallet).list().len(), 2);
}

#[test]
fn wallet_replaced_while_unlocked_is_overwritten_without_merging() {
    let fx = fx();
    let wallet = create(&fx, "Personal");
    fx.service.add_entry(&wallet, fields("Mine")).unwrap();
    // Another program puts a different wallet file under the same name.
    let other = foreign_wallet(&fx, "Scratch", KdfConfig::MINIMUM, &["Theirs"]);
    fx.dir.insert(&wallet, &fx.dir.bytes(&other).unwrap());
    fx.service.add_entry(&wallet, fields("Second")).unwrap();
    let stored = reopen(&fx, &wallet);
    let mut titles: Vec<String> = stored
        .list()
        .iter()
        .map(|e| e.fields().unwrap().title.clone())
        .collect();
    titles.sort();
    assert_eq!(titles, ["Mine", "Second"]);
}
