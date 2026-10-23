//! SC-009: the real binary refuses to run when memory cannot be locked.

mod common;

use std::process::Command;

use common::server::Fixture;

#[test]
fn real_binary_under_a_low_memlock_limit_exits_3_without_a_launch_file() {
    let fx = Fixture::new("");
    let output = Command::new("sh")
        .arg("-c")
        .arg("ulimit -l 1024 && exec \"$0\"")
        .arg(env!("CARGO_BIN_EXE_passwsyncd"))
        .env_clear()
        .env("HOME", &fx.home)
        .env("XDG_RUNTIME_DIR", fx.root.path().join("run"))
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(3), "stderr: {stderr}");
    assert!(
        stderr.contains("protection failed: memlock-limit"),
        "stderr: {stderr}"
    );
    assert!(!fx.launch_file.exists());
    assert!(!fx.runtime_dir.exists());
}
