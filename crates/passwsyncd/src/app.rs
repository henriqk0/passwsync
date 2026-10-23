//! Start-up in the normative order (contracts/host-runtime.md), the running service, and the
//! orderly stop.

use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, PoisonError};

use rustix::fs::{FlockOperation, flock};
use vault_core::{KdfConfig, SystemClock};
use wallet_service::{ElapsedClock, Service, ServiceConfig, Sessions};

use crate::clock::OsElapsedClock;
use crate::config::{self, ConfigError};
use crate::fs_dir::FsWalletDirectory;
use crate::hardening::{self, Hardening, OsHardening};
use crate::http::server::{self, ServerThreads};
use crate::http::{AppState, pages};
use crate::log::{ErrorClass, LockReason, Log, LogEvent, Protection, Rejections};
use crate::paths::{self, Env, PathError, Paths};
use crate::signals::{self, SignalThread};

pub const USAGE: &str = "Usage: passwsyncd [--help | --version]\n\
Runs the local passwsync service on 127.0.0.1 in the foreground until SIGTERM, SIGINT or SIGHUP.\n\
Open the address in $XDG_RUNTIME_DIR/passwsync/launch-url to use it.\n";

/// What the service needs from the outside world; production values come from
/// [`Deps::production`].
pub struct Deps {
    pub env: Env,
    pub hardening: Box<dyn Hardening>,
    pub log: Log,
    /// KDF cost for wallets created by this service.
    pub wallet_kdf: KdfConfig,
    pub elapsed: Arc<dyn ElapsedClock>,
}

impl Deps {
    pub fn production() -> Self {
        Self {
            env: Env::from_process(),
            hardening: Box::new(OsHardening),
            log: Log::stderr(),
            wallet_kdf: KdfConfig::DEFAULT,
            elapsed: Arc::new(OsElapsedClock),
        }
    }
}

#[derive(Debug)]
pub enum StartError {
    Protection(Protection, ErrorClass),
    Config(ConfigError),
    Path(PathError),
    AlreadyRunning,
    Bind(u16),
    Fatal(&'static str),
}

impl StartError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Fatal(_) => 1,
            Self::Config(_) | Self::Path(_) => 2,
            Self::Protection(..) => 3,
            Self::AlreadyRunning | Self::Bind(_) => 4,
        }
    }
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protection(which, class) => fmt::Display::fmt(
                &LogEvent::ProtectionFailed {
                    which: *which,
                    class: *class,
                },
                f,
            ),
            Self::Config(error) => error.fmt(f),
            Self::Path(error) => error.fmt(f),
            Self::AlreadyRunning => f.write_str("another instance is already running"),
            Self::Bind(port) => write!(f, "cannot listen on 127.0.0.1:{port}"),
            Self::Fatal(what) => write!(f, "fatal: {what}"),
        }
    }
}

impl std::error::Error for StartError {}

impl From<PathError> for StartError {
    fn from(error: PathError) -> Self {
        Self::Path(error)
    }
}

/// Requests an orderly stop; clones share the same flag.
#[derive(Clone, Default)]
pub struct Stopper(Arc<(Mutex<bool>, Condvar)>);

impl Stopper {
    pub fn stop(&self) {
        let (flag, wake) = &*self.0;
        *flag.lock().unwrap_or_else(PoisonError::into_inner) = true;
        wake.notify_all();
    }

    /// Waits up to `timeout`; returns whether a stop was requested.
    pub fn wait_timeout(&self, timeout: std::time::Duration) -> bool {
        let (flag, wake) = &*self.0;
        let stopped = flag.lock().unwrap_or_else(PoisonError::into_inner);
        let (stopped, _) = wake
            .wait_timeout_while(stopped, timeout, |stopped| !*stopped)
            .unwrap_or_else(PoisonError::into_inner);
        *stopped
    }

    fn wait(&self) {
        let (flag, wake) = &*self.0;
        let mut stopped = flag.lock().unwrap_or_else(PoisonError::into_inner);
        while !*stopped {
            stopped = wake.wait(stopped).unwrap_or_else(PoisonError::into_inner);
        }
    }
}

/// A started service. Dropping it without [`Running::stop`] or [`Running::wait`] leaves
/// threads running; tests call `stop`.
pub struct Running {
    addr: SocketAddr,
    state: Arc<AppState>,
    stopper: Stopper,
    server: ServerThreads,
    sweeper: std::thread::JoinHandle<()>,
    signals: Option<SignalThread>,
    _instance_lock: File,
}

impl Running {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn launch_file(&self) -> &Path {
        &self.state.launch_file
    }

    pub fn rejections(&self) -> &Rejections {
        &self.state.rejections
    }

    pub fn stopper(&self) -> Stopper {
        self.stopper.clone()
    }

    /// Blocks until a stop is requested, then stops: no more connections, every wallet
    /// locked, launch file deleted, `stopping` logged. Returns exit code 0.
    pub fn wait(self) -> i32 {
        self.stopper.wait();
        if let Some(signals) = self.signals {
            signals.close();
        }
        self.server.shutdown();
        let _ = self.sweeper.join();
        for wallet in &self.state.service.lock_all() {
            self.state.log.emit(&LogEvent::Locked {
                wallet,
                reason: LockReason::Stop,
            });
        }
        let _ = fs::remove_file(&self.state.launch_file);
        self.state.log.emit(&LogEvent::Stopping);
        0
    }

    pub fn stop(self) -> i32 {
        self.stopper.stop();
        self.wait()
    }
}

/// Starts the service without signal handling (the caller stops it).
pub fn start(deps: Deps) -> Result<Running, StartError> {
    start_with(deps, Stopper::default(), false)
}

fn start_with(deps: Deps, stopper: Stopper, with_signals: bool) -> Result<Running, StartError> {
    let Deps {
        env,
        hardening,
        log,
        wallet_kdf,
        elapsed,
    } = deps;

    // 2. Protections first; nothing else happens if one fails.
    if let Err((which, class)) = hardening::apply(hardening.as_ref()) {
        log.emit(&LogEvent::ProtectionFailed { which, class });
        return Err(StartError::Protection(which, class));
    }
    log.emit(&LogEvent::ProtectionsApplied);

    // 3. Paths, configuration, device identifier.
    let paths = Paths::resolve(&env)?;
    paths.prepare()?;
    let settings = config::load(&paths.config_file).map_err(StartError::Config)?;
    let device = paths::load_or_create_device_id(&paths.device_id_file)?;

    // 4. Single instance.
    let instance_lock = acquire_instance_lock(&paths.lock_file)?;

    // 5. Loopback listener only.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, settings.port))
        .map_err(|_| StartError::Bind(settings.port))?;
    let addr = listener
        .local_addr()
        .map_err(|_| StartError::Fatal("listener address"))?;

    // 6. Signal handling before the launch file exists, so a signal can never leave it behind.
    let signals = if with_signals {
        Some(signals::spawn(stopper.clone()).map_err(|_| StartError::Fatal("signal handlers"))?)
    } else {
        None
    };
    let sessions = Sessions::new().map_err(|_| StartError::Fatal("secure random source"))?;
    pages::write_launch_file(&paths.launch_file, settings.port, sessions.launch_token())
        .map_err(|_| StartError::Path(PathError::new(&paths.launch_file, "cannot be written")))?;
    let service = Arc::new(Service::new(
        Arc::new(FsWalletDirectory::new(paths.wallets_dir.clone())),
        Arc::new(SystemClock),
        Arc::clone(&elapsed),
        ServiceConfig {
            device,
            wallet_kdf,
            auto_lock: settings.auto_lock,
        },
    ));
    let state = Arc::new(AppState {
        port: settings.port,
        settings,
        sessions: Mutex::new(sessions),
        rejections: Arc::new(Rejections::default()),
        log: log.clone(),
        launch_file: paths.launch_file.clone(),
        elapsed,
        service,
    });
    let sweeper = crate::sweeper::spawn(
        Arc::clone(&state.service),
        Arc::clone(&state.rejections),
        state.log.clone(),
        Arc::clone(&state.elapsed),
        stopper.clone(),
    )
    .map_err(|_| {
        let _ = fs::remove_file(&paths.launch_file);
        StartError::Fatal("sweeper thread")
    })?;
    let server = server::spawn(listener, Arc::clone(&state)).map_err(|_| {
        stopper.stop();
        let _ = fs::remove_file(&paths.launch_file);
        StartError::Fatal("worker threads")
    })?;

    // 7. Ready.
    log.emit(&LogEvent::Started { addr });
    log.emit(&LogEvent::LaunchFile {
        path: &paths.launch_file,
    });
    Ok(Running {
        addr,
        state,
        stopper,
        server,
        sweeper,
        signals,
        _instance_lock: instance_lock,
    })
}

fn acquire_instance_lock(path: &PathBuf) -> Result<File, StartError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .map_err(|_| StartError::Path(PathError::new(path, "cannot be opened")))?;
    flock(&file, FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| StartError::AlreadyRunning)?;
    Ok(file)
}

enum Command {
    Run,
    Help,
    Version,
}

fn parse_args(args: &[OsString]) -> Option<Command> {
    match args {
        [] => Some(Command::Run),
        [one] if one == "--help" => Some(Command::Help),
        [one] if one == "--version" => Some(Command::Version),
        _ => None,
    }
}

/// The whole program: arguments, start-up, run until a signal, stop. Returns the exit code.
pub fn run(args: Vec<OsString>, deps: Deps) -> i32 {
    match parse_args(&args) {
        Some(Command::Help) => {
            print!("{USAGE}");
            return 0;
        }
        Some(Command::Version) => {
            println!("passwsyncd {}", env!("CARGO_PKG_VERSION"));
            return 0;
        }
        None => {
            eprint!("{USAGE}");
            return 2;
        }
        Some(Command::Run) => {}
    }
    let log = deps.log.clone();
    match start_with(deps, Stopper::default(), true) {
        Ok(running) => running.wait(),
        Err(error) => {
            if !matches!(error, StartError::Protection(..)) {
                log.fatal(&error);
            }
            error.exit_code()
        }
    }
}
