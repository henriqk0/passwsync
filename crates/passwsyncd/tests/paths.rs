mod common;

use std::fs;
use std::path::PathBuf;

use common::{TempDir, mode, set_mode};
use passwsyncd::paths::{Env, Paths, load_or_create_device_id};

fn env(root: &TempDir) -> Env {
    Env {
        home: Some(root.path().join("home")),
        xdg_config_home: None,
        xdg_data_home: None,
        xdg_runtime_dir: Some(root.path().join("run")),
    }
}

#[test]
fn resolves_xdg_defaults_under_home() {
    let root = TempDir::new("paths");
    let paths = Paths::resolve(&env(&root)).unwrap();
    let home = root.path().join("home");
    assert_eq!(paths.config_dir, home.join(".config/passwsync"));
    assert_eq!(paths.config_file, home.join(".config/passwsync/config"));
    assert_eq!(
        paths.device_id_file,
        home.join(".config/passwsync/device-id")
    );
    assert_eq!(
        paths.wallets_dir,
        home.join(".local/share/passwsync/wallets")
    );
    assert_eq!(paths.runtime_dir, root.path().join("run/passwsync"));
    assert_eq!(
        paths.launch_file,
        root.path().join("run/passwsync/launch-url")
    );
    assert_eq!(
        paths.lock_file,
        root.path().join("run/passwsync/instance.lock")
    );
}

#[test]
fn explicit_xdg_variables_win_and_relative_ones_are_ignored() {
    let root = TempDir::new("paths");
    let mut e = env(&root);
    e.xdg_config_home = Some(root.path().join("cfg"));
    e.xdg_data_home = Some(PathBuf::from("relative/data"));
    let paths = Paths::resolve(&e).unwrap();
    assert_eq!(paths.config_dir, root.path().join("cfg/passwsync"));
    assert_eq!(
        paths.wallets_dir,
        root.path().join("home/.local/share/passwsync/wallets")
    );
}

#[test]
fn missing_runtime_dir_is_an_error() {
    let root = TempDir::new("paths");
    let mut e = env(&root);
    e.xdg_runtime_dir = None;
    let message = Paths::resolve(&e).unwrap_err().to_string();
    assert!(message.contains("XDG_RUNTIME_DIR"), "{message}");
}

#[test]
fn prepare_creates_private_directories() {
    let root = TempDir::new("paths");
    fs::create_dir(root.path().join("run")).unwrap();
    let paths = Paths::resolve(&env(&root)).unwrap();
    paths.prepare().unwrap();
    for dir in [&paths.config_dir, &paths.wallets_dir, &paths.runtime_dir] {
        assert!(dir.is_dir(), "{}", dir.display());
        assert_eq!(mode(dir), 0o700, "{}", dir.display());
    }
    paths.prepare().unwrap();
}

#[test]
fn existing_directory_with_group_or_other_bits_is_refused_by_name() {
    let root = TempDir::new("paths");
    fs::create_dir(root.path().join("run")).unwrap();
    let paths = Paths::resolve(&env(&root)).unwrap();
    paths.prepare().unwrap();
    for dir in [&paths.config_dir, &paths.wallets_dir, &paths.runtime_dir] {
        set_mode(dir, 0o750);
        let message = paths.prepare().unwrap_err().to_string();
        assert!(message.contains(&*dir.to_string_lossy()), "{message}");
        set_mode(dir, 0o700);
    }
}

#[test]
fn device_id_is_created_once_and_reused() {
    let root = TempDir::new("paths");
    let path = root.path().join("device-id");
    let first = load_or_create_device_id(&path).unwrap();
    let text = fs::read_to_string(&path).unwrap();
    assert_eq!(text.len(), 33);
    assert!(text.ends_with('\n'));
    assert!(
        text[..32]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    assert_eq!(first.as_str(), &text[..32]);
    assert_eq!(mode(&path), 0o600);
    let second = load_or_create_device_id(&path).unwrap();
    assert_eq!(first, second);
}

#[test]
fn invalid_device_id_file_is_refused_never_replaced() {
    let root = TempDir::new("paths");
    let path = root.path().join("device-id");
    for bad in [
        "",
        "xyz\n",
        "ABCDEFABCDEFABCDEFABCDEFABCDEFAB\n",
        "0123456789abcdef0123456789abcdef",
    ] {
        fs::write(&path, bad).unwrap();
        set_mode(&path, 0o600);
        assert!(load_or_create_device_id(&path).is_err(), "{bad:?}");
        assert_eq!(fs::read_to_string(&path).unwrap(), bad);
    }
}

#[test]
fn device_id_file_with_loose_permissions_is_refused() {
    let root = TempDir::new("paths");
    let path = root.path().join("device-id");
    fs::write(&path, "0123456789abcdef0123456789abcdef\n").unwrap();
    set_mode(&path, 0o644);
    let message = load_or_create_device_id(&path).unwrap_err().to_string();
    assert!(message.contains(&*path.to_string_lossy()), "{message}");
}
