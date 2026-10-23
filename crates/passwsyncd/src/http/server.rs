//! TCP listener feeding a fixed pool of 4 workers (512 KiB stacks) through a bounded queue.
//! One request per connection; every connection is closed after its response.

use std::io::{self, Read};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, TrySendError, sync_channel};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use super::AppState;
use super::guard::{Admitted, admit};
use super::request::{READ_TIMEOUT, Request, RequestError, read_request};
use super::response::Response;
use super::{api, pages};
use crate::log::Reason;
use crate::peer::peer_uid;

pub const WORKERS: usize = 4;
pub const WORKER_STACK: usize = 512 * 1024;
const QUEUE: usize = 16;
const DRAIN_LIMIT: usize = 64 * 1024;
const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

pub struct ServerThreads {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    accept: JoinHandle<()>,
    workers: Vec<JoinHandle<()>>,
}

pub fn spawn(listener: TcpListener, state: Arc<AppState>) -> io::Result<ServerThreads> {
    let addr = listener.local_addr()?;
    let stop = Arc::new(AtomicBool::new(false));
    let (sender, receiver) = sync_channel::<TcpStream>(QUEUE);
    let receiver = Arc::new(Mutex::new(receiver));
    let mut workers = Vec::with_capacity(WORKERS);
    for index in 0..WORKERS {
        let receiver = Arc::clone(&receiver);
        let state = Arc::clone(&state);
        workers.push(
            thread::Builder::new()
                .name(format!("http-worker-{index}"))
                .stack_size(WORKER_STACK)
                .spawn(move || worker(&receiver, &state))?,
        );
    }
    let accept_stop = Arc::clone(&stop);
    let accept = thread::Builder::new()
        .name("http-accept".into())
        .stack_size(WORKER_STACK)
        .spawn(move || {
            for stream in listener.incoming() {
                if accept_stop.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(stream) = stream else { continue };
                // A full queue drops the connection rather than growing memory.
                if let Err(TrySendError::Disconnected(_)) = sender.try_send(stream) {
                    break;
                }
            }
        })?;
    Ok(ServerThreads {
        addr,
        stop,
        accept,
        workers,
    })
}

impl ServerThreads {
    /// Stops accepting, lets workers finish their current request, and joins all threads.
    pub fn shutdown(self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_secs(1));
        let _ = self.accept.join();
        for worker in self.workers {
            let _ = worker.join();
        }
    }
}

fn worker(receiver: &Mutex<Receiver<TcpStream>>, state: &AppState) {
    loop {
        let next = receiver
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .recv();
        match next {
            Ok(stream) => handle_connection(stream, state),
            Err(_) => return,
        }
    }
}

fn handle_connection(mut stream: TcpStream, state: &AppState) {
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let _ = stream.set_write_timeout(Some(READ_TIMEOUT));
    let (Ok(client), Ok(server)) = (stream.peer_addr(), stream.local_addr()) else {
        return;
    };
    if peer_uid(client, server) != Some(rustix::process::getuid().as_raw()) {
        state.rejections.count(Reason::Peer);
        return;
    }
    let response = match read_request(&mut stream) {
        Ok(request) => respond(state, &request),
        Err(RequestError::HeadTooLarge) => {
            state.rejections.count(Reason::Size);
            Response::headers_too_large()
        }
        Err(RequestError::BodyTooLarge) => {
            state.rejections.count(Reason::Size);
            Response::payload_too_large()
        }
        Err(RequestError::TransferEncoding) => {
            state.rejections.count(Reason::Size);
            Response::bad_request()
        }
        Err(RequestError::BadRequest) => Response::bad_request(),
        Err(RequestError::Timeout) => {
            state.rejections.count(Reason::Size);
            return;
        }
        Err(RequestError::Closed) => return,
    };
    if response.write_to(&mut stream).is_ok() {
        close_gracefully(stream);
    }
}

/// Half-closes, then discards a bounded amount of unread input so the kernel does not reset
/// the connection before the client has read the response.
fn close_gracefully(mut stream: TcpStream) {
    let _ = stream.shutdown(Shutdown::Write);
    let _ = stream.set_read_timeout(Some(DRAIN_TIMEOUT));
    // Unread input may be part of a request body; wipe it.
    let mut sink = zeroize::Zeroizing::new([0u8; 4096]);
    let mut drained = 0;
    while drained < DRAIN_LIMIT {
        match stream.read(sink.as_mut()) {
            Ok(0) | Err(_) => break,
            Ok(n) => drained += n,
        }
    }
}

fn respond(state: &AppState, request: &Request) -> Response {
    let admitted = match admit(state, request) {
        Ok(admitted) => admitted,
        Err(response) => return response,
    };
    // A suspended-and-resumed computer locks everything before anything is served.
    crate::sweeper::lock_if_suspended(&state.service, &state.log);
    match admitted {
        Admitted::Launch { token } => pages::launch(state, token),
        Admitted::Index { session } => pages::index(session),
        Admitted::Static {
            content_type,
            bytes,
        } => Response::fixed(200, content_type, bytes),
        Admitted::Api { session: _, path } => api::handle(state, request, path),
        Admitted::NotFound => Response::not_found(),
    }
}
