//! In-process service on a temporary XDG tree, driven with raw HTTP over `TcpStream`.

use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use device_link::link::Timing;
use device_link::policy::AddressPolicy;
use device_link_net::interfaces::FakeInterfaces;
use passwsyncd::app::{Deps, Running, start};
use passwsyncd::hardening::FakeHardening;
use passwsyncd::log::Log;
use passwsyncd::net_runtime::NetDeps;
use passwsyncd::paths::Env;
use vault_core::KdfConfig;
use wallet_service::testkit::FakeElapsedClock;

use super::{TempDir, set_mode};

/// A port no other test in this process has been given. Ports come from below the kernel's
/// ephemeral range (32768+), so an outgoing connection of a concurrent test can never take a
/// port between the moment it is handed out and the moment it is bound.
pub fn free_port() -> u16 {
    static NEXT: Mutex<u16> = Mutex::new(0);
    let mut next = NEXT.lock().unwrap();
    if *next == 0 {
        // Spread concurrent test processes over the range.
        *next = 15_000 + (std::process::id() % 1_700) as u16 * 10;
    }
    loop {
        let port = *next;
        *next = if *next >= 32_000 { 15_000 } else { *next + 1 };
        if TcpListener::bind(("127.0.0.1", port)).is_ok()
            && TcpListener::bind(("0.0.0.0", port)).is_ok()
        {
            return port;
        }
    }
}

/// A port free for TCP and UDP alike (peer and discovery sockets).
pub fn free_net_port() -> u16 {
    loop {
        let port = free_port();
        if std::net::UdpSocket::bind(("0.0.0.0", port)).is_ok()
            && TcpListener::bind(("0.0.0.0", port)).is_ok()
        {
            return port;
        }
    }
}

/// Config lines turning networking on with fresh peer and discovery ports.
pub fn net_config() -> String {
    format!(
        "network = on\npeer_port = {}\ndiscovery_port = {}\n",
        free_net_port(),
        free_net_port()
    )
}

/// Short protocol timers so loopback tests finish quickly.
pub fn fast_timing() -> Timing {
    Timing {
        announce: Duration::from_millis(300),
        nearby_expiry: Duration::from_millis(900),
        step_timeout: Duration::from_millis(1500),
        keepalive: Duration::from_millis(600),
        idle_close: Duration::from_millis(1500),
        dial_backoff_min: Duration::from_millis(200),
        dial_backoff_max: Duration::from_millis(800),
        rescan: Duration::from_millis(300),
    }
}

/// 004: short sync timers for loopback tests.
pub fn fast_sync_timing() -> wallet_sync::sched::SyncTiming {
    wallet_sync::sched::SyncTiming {
        quiet: Duration::from_millis(150),
        safety: Duration::from_secs(3600),
        backoff_min: Duration::from_millis(300),
        backoff_max: Duration::from_secs(2),
        round_timeout: Duration::from_secs(3),
    }
}

/// Polls `check` every 20 ms for up to `limit`.
pub fn wait_for(limit: Duration, mut check: impl FnMut() -> bool) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < limit {
        if check() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    check()
}

pub struct Fixture {
    pub root: TempDir,
    pub port: u16,
    pub home: PathBuf,
    pub config_dir: PathBuf,
    pub wallets_dir: PathBuf,
    pub runtime_dir: PathBuf,
    pub launch_file: PathBuf,
}

impl Fixture {
    /// A temporary XDG tree with a config selecting a free port plus `extra_config`.
    pub fn new(extra_config: &str) -> Self {
        let root = TempDir::new("server");
        let home = root.path().join("home");
        let config_dir = home.join(".config/passwsync");
        fs::create_dir_all(&config_dir).unwrap();
        set_mode(&config_dir, 0o700);
        let port = free_port();
        let config = config_dir.join("config");
        fs::write(&config, format!("port = {port}\n{extra_config}")).unwrap();
        set_mode(&config, 0o600);
        let run = root.path().join("run");
        fs::create_dir(&run).unwrap();
        set_mode(&run, 0o700);
        Self {
            wallets_dir: home.join(".local/share/passwsync/wallets"),
            runtime_dir: run.join("passwsync"),
            launch_file: run.join("passwsync/launch-url"),
            port,
            home,
            config_dir,
            root,
        }
    }

    pub fn env(&self) -> Env {
        Env {
            home: Some(self.home.clone()),
            xdg_config_home: None,
            xdg_data_home: None,
            xdg_runtime_dir: Some(self.root.path().join("run")),
        }
    }

    pub fn deps(
        &self,
        hardening: FakeHardening,
    ) -> (Deps, Arc<Mutex<Vec<u8>>>, Arc<FakeElapsedClock>) {
        self.deps_with(hardening, Vec::new())
    }

    /// `announce_ports`: where this instance sends announcements (two instances on one
    /// host listen on different discovery ports).
    pub fn deps_with(
        &self,
        hardening: FakeHardening,
        announce_ports: Vec<u16>,
    ) -> (Deps, Arc<Mutex<Vec<u8>>>, Arc<FakeElapsedClock>) {
        let (log, buffer) = Log::to_buffer();
        let clock = Arc::new(FakeElapsedClock::new());
        let deps = Deps {
            env: self.env(),
            hardening: Box::new(hardening),
            log,
            wallet_kdf: KdfConfig::MINIMUM,
            elapsed: clock.clone(),
            net: NetDeps {
                policy: AddressPolicy::testkit(),
                interfaces: Some(Arc::new(FakeInterfaces::loopback())),
                timing: fast_timing(),
                announce_ports,
                sync: fast_sync_timing(),
            },
        };
        (deps, buffer, clock)
    }
}

pub struct TestServer {
    pub fx: Fixture,
    pub port: u16,
    pub log: Arc<Mutex<Vec<u8>>>,
    pub clock: Arc<FakeElapsedClock>,
    pub running: Option<Running>,
}

impl TestServer {
    pub fn start() -> Self {
        Self::start_with("")
    }

    pub fn start_with(extra_config: &str) -> Self {
        Self::start_in(Fixture::new(extra_config))
    }

    pub fn start_in(fx: Fixture) -> Self {
        Self::start_announcing(fx, Vec::new())
    }

    pub fn start_announcing(fx: Fixture, announce_ports: Vec<u16>) -> Self {
        // A child process spawned by a concurrent test can hold a copy of the previous
        // instance's lock descriptor for a moment between fork and exec; retry briefly.
        let mut attempts = 0;
        let (running, log, clock) = loop {
            let (deps, log, clock) = fx.deps_with(FakeHardening::ok(), announce_ports.clone());
            match start(deps) {
                Ok(running) => break (running, log, clock),
                Err(e) if e.exit_code() == 4 && attempts < 100 => {
                    attempts += 1;
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => panic!("start failed: {e}"),
            }
        };
        Self {
            port: running.addr().port(),
            fx,
            log,
            clock,
            running: Some(running),
        }
    }

    /// The configured peer port (from the config file).
    pub fn peer_port(&self) -> u16 {
        self.config_value("peer_port").unwrap_or(27472)
    }

    pub fn discovery_port(&self) -> u16 {
        self.config_value("discovery_port").unwrap_or(27473)
    }

    fn config_value(&self, key: &str) -> Option<u16> {
        let text = fs::read_to_string(self.fx.config_dir.join("config")).ok()?;
        text.lines()
            .filter_map(|l| l.split_once('='))
            .find(|(k, _)| k.trim() == key)
            .and_then(|(_, v)| v.trim().parse().ok())
    }

    pub fn running(&self) -> &Running {
        self.running.as_ref().unwrap()
    }

    pub fn stop(&mut self) -> i32 {
        self.running.take().map_or(0, Running::stop)
    }

    pub fn log_text(&self) -> String {
        String::from_utf8(self.log.lock().unwrap().clone()).unwrap()
    }

    pub fn host(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    pub fn origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub fn launch_url(&self) -> String {
        fs::read_to_string(&self.fx.launch_file).unwrap()
    }

    pub fn launch_path(&self) -> String {
        let url = self.launch_url();
        let prefix = format!("http://127.0.0.1:{}", self.port);
        url.trim_end().strip_prefix(&prefix).unwrap().to_string()
    }

    pub fn raw(&self, bytes: &[u8]) -> Resp {
        raw(self.port, bytes)
    }

    /// A request with `Host` set correctly plus `headers`; `Content-Length` added for bodies.
    pub fn send(&self, method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Resp {
        let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {}\r\n", self.host());
        for (name, value) in headers {
            req.push_str(&format!("{name}: {value}\r\n"));
        }
        if !body.is_empty() || matches!(method, "POST" | "PUT") {
            req.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        req.push_str("\r\n");
        let mut bytes = req.into_bytes();
        bytes.extend_from_slice(body);
        self.raw(&bytes)
    }

    pub fn get(&self, path: &str) -> Resp {
        self.send("GET", path, &[], b"")
    }

    /// Exchanges the current launch token for a browser session.
    pub fn login(&self) -> Session {
        let resp = self.get(&self.launch_path());
        assert_eq!(resp.status, 303, "launch exchange: {}", resp.text());
        let cookie = resp
            .header("set-cookie")
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .strip_prefix("pws_session=")
            .unwrap()
            .to_string();
        let page = self.send(
            "GET",
            "/",
            &[("Cookie", &format!("pws_session={cookie}"))],
            b"",
        );
        let html = page.text();
        let marker = "<meta name=\"csrf-token\" content=\"";
        let start = html.find(marker).expect("csrf meta") + marker.len();
        let csrf = html[start..start + 64].to_string();
        Session { cookie, csrf }
    }

    /// An API call with session cookie, CSRF header and (for state changes) Origin.
    pub fn api(&self, s: &Session, method: &str, path: &str, body: Option<&str>) -> Resp {
        let cookie = format!("pws_session={}", s.cookie);
        let origin = self.origin();
        let mut headers = vec![
            ("Cookie", cookie.as_str()),
            ("X-CSRF-Token", s.csrf.as_str()),
        ];
        if method != "GET" {
            headers.push(("Origin", origin.as_str()));
        }
        if body.is_some() {
            headers.push(("Content-Type", "application/json"));
        }
        self.send(method, path, &headers, body.unwrap_or("").as_bytes())
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop();
    }
}

#[derive(Clone, Debug)]
pub struct Session {
    pub cookie: String,
    pub csrf: String,
}

#[derive(Debug)]
pub struct Resp {
    /// 0 when the server closed the connection without answering.
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub raw: Vec<u8>,
}

impl Resp {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|e| panic!("not JSON ({e}): {}", self.text()))
    }

    pub fn error_code(&self) -> String {
        self.json()["error"].as_str().unwrap().to_string()
    }
}

pub fn raw(port: u16, bytes: &[u8]) -> Resp {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let _ = stream.write_all(bytes);
    let _ = stream.shutdown(Shutdown::Write);
    let mut out = Vec::new();
    let _ = stream.read_to_end(&mut out);
    parse_response(out)
}

pub fn parse_response(raw: Vec<u8>) -> Resp {
    let Some(split) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Resp {
            status: 0,
            headers: Vec::new(),
            body: Vec::new(),
            raw,
        };
    };
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_string(), v.trim().to_string()))
        .collect();
    Resp {
        status,
        headers,
        body: raw[split + 4..].to_vec(),
        raw,
    }
}
