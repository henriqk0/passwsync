use vault_core::MemoryStorage;
use vault_core::testkit::storage_contract;

#[test]
fn memory_storage_satisfies_the_contract() {
    storage_contract(MemoryStorage::new);
}
