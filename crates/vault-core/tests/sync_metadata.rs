use std::sync::Arc;

use vault_core::{
    Clock, DeviceId, EntryFields, FixedClock, KdfConfig, MasterPassword, Timestamp, Vault,
    VersionOrdering,
};

const PASSWORD: &str = "correct horse battery";

struct SharedClock(Arc<FixedClock>);

impl Clock for SharedClock {
    fn now(&self) -> Timestamp {
        self.0.now()
    }
}

fn pw() -> MasterPassword {
    MasterPassword::new(PASSWORD.to_string())
}

fn device(name: &str) -> DeviceId {
    DeviceId::new(name).unwrap()
}

fn titled(title: &str) -> EntryFields {
    let mut fields = EntryFields::default();
    fields.title = title.into();
    fields
}

#[test]
fn lifecycle_keeps_identity_and_counts_changes() {
    let time = Arc::new(FixedClock::new(100));
    let mut vault = Vault::create(
        pw(),
        KdfConfig::MINIMUM,
        device("A"),
        Box::new(SharedClock(time.clone())),
    )
    .unwrap();
    let id = vault.add_entry(titled("one")).unwrap();

    time.advance(10);
    vault.update_entry(id, titled("two")).unwrap();
    assert_eq!(vault.get(id).unwrap().modified_at(), 110);
    time.advance(10);
    vault.update_entry(id, titled("three")).unwrap();
    assert_eq!(vault.get(id).unwrap().modified_at(), 120);
    time.advance(10);
    vault.delete_entry(id).unwrap();

    let bytes = vault.seal().unwrap();
    let reopened = Vault::unlock(&bytes, pw(), device("A"), Box::new(FixedClock::new(0))).unwrap();
    let tombstone = reopened.all_records().next().unwrap();
    assert_eq!(tombstone.id(), id);
    assert_eq!(tombstone.version().get(&device("A")), 4);
    assert_eq!(tombstone.version().iter().count(), 1);
    assert_eq!(tombstone.last_modified_by(), &device("A"));
    assert_eq!(tombstone.modified_at(), 130);
    assert_eq!(tombstone.deleted_at(), Some(130));
}

#[test]
fn copies_edited_on_different_devices_are_classified() {
    let mut original = Vault::create(
        pw(),
        KdfConfig::MINIMUM,
        device("A"),
        Box::new(FixedClock::new(1)),
    )
    .unwrap();
    let id = original.add_entry(titled("shared")).unwrap();
    let bytes = original.seal().unwrap();

    let mut on_a = Vault::unlock(&bytes, pw(), device("A"), Box::new(FixedClock::new(2))).unwrap();
    let mut on_b = Vault::unlock(&bytes, pw(), device("B"), Box::new(FixedClock::new(2))).unwrap();
    assert_eq!(on_a.wallet_id(), on_b.wallet_id());
    assert_eq!(on_a.get(id).unwrap().id(), on_b.get(id).unwrap().id());
    assert_eq!(
        on_a.get(id)
            .unwrap()
            .version()
            .compare(on_b.get(id).unwrap().version()),
        VersionOrdering::Equal
    );

    // Only B edits: B is newer, A is older.
    on_b.update_entry(id, titled("edited on B")).unwrap();
    let (a_version, b_version) = (
        on_a.get(id).unwrap().version(),
        on_b.get(id).unwrap().version(),
    );
    assert_eq!(b_version.compare(a_version), VersionOrdering::Newer);
    assert_eq!(a_version.compare(b_version), VersionOrdering::Older);

    // Both edit independently: concurrent.
    on_a.update_entry(id, titled("edited on A")).unwrap();
    let (a_version, b_version) = (
        on_a.get(id).unwrap().version(),
        on_b.get(id).unwrap().version(),
    );
    assert_eq!(a_version.compare(b_version), VersionOrdering::Concurrent);
    assert_eq!(b_version.compare(a_version), VersionOrdering::Concurrent);
}
