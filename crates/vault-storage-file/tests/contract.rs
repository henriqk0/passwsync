mod common;

use std::cell::Cell;

use common::TestDir;
use vault_core::testkit::storage_contract;
use vault_storage_file::FileStorage;

#[test]
fn file_storage_satisfies_the_contract() {
    let dir = TestDir::new();
    let count = Cell::new(0);
    storage_contract(|| {
        count.set(count.get() + 1);
        FileStorage::new(dir.path().join(format!("wallet-{}.pwsv", count.get())))
    });
}
