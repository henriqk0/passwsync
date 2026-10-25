//! A fake peer on an older (or current) build for negotiation tests: closes on any channel
//! Hello above `max` before any crypto, completes a handshake at `max` or below and keeps the
//! channel open (reading and dropping frames) until `close_now` is set.

use std::net::{SocketAddrV4, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use device_link::channel::ChannelResponder;
use device_link::identity::DeviceKey;
use device_link::name::DeviceName;
use device_link::wire::{HelloKind, HelloVersion, parse_hello_versioned};
use device_link_net::framed::{FrameError, read_frame, write_frame};

/// A device on an older build: closes on any channel Hello above `max`, completes a
/// handshake at `max` or below.
pub struct OldPeer {
    pub key: DeviceKey,
    pub addr: SocketAddrV4,
    /// Hellos by version (index 1..=3).
    pub hellos: Arc<[AtomicUsize; 4]>,
    pub channels: Arc<AtomicUsize>,
    pub close_now: Arc<AtomicBool>,
}

pub fn version_index(version: HelloVersion) -> usize {
    match version {
        HelloVersion::V1 => 1,
        HelloVersion::V2 => 2,
        HelloVersion::V3 => 3,
    }
}

pub fn old_peer(seed: u8, pinned: [u8; 32], max: HelloVersion) -> OldPeer {
    let key = DeviceKey::from_private([seed; 32]);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let hellos: Arc<[AtomicUsize; 4]> = Arc::new(Default::default());
    let channels = Arc::new(AtomicUsize::new(0));
    let close_now = Arc::new(AtomicBool::new(false));
    let (h, c, close) = (
        Arc::clone(&hellos),
        Arc::clone(&channels),
        Arc::clone(&close_now),
    );
    let responder_key = key.duplicate();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            serve_old(&responder_key, stream, pinned, max, &h, &c, &close);
        }
    });
    OldPeer {
        key,
        addr: SocketAddrV4::new([127, 0, 0, 1].into(), port),
        hellos,
        channels,
        close_now,
    }
}

fn serve_old(
    key: &DeviceKey,
    stream: TcpStream,
    pinned: [u8; 32],
    max: HelloVersion,
    hellos: &[AtomicUsize; 4],
    channels: &AtomicUsize,
    close: &AtomicBool,
) {
    let step = Duration::from_secs(2);
    let Ok(hello) = read_frame(&stream, step) else {
        return;
    };
    let Ok((HelloKind::Channel, version)) = parse_hello_versioned(&hello) else {
        return;
    };
    hellos[version_index(version)].fetch_add(1, Ordering::SeqCst);
    if version_index(version) > version_index(max) {
        return; // an older parser rejects the Hello: close before any crypto
    }
    let mut responder = ChannelResponder::new(key, DeviceName::parse("Old").unwrap(), &hello);
    let is_pinned = move |k: &[u8; 32]| *k == pinned;
    for _ in 0..2 {
        let Ok(body) = read_frame(&stream, step) else {
            return;
        };
        let result = responder.on_frame(&body, &is_pinned);
        for frame in responder.outgoing() {
            let _ = write_frame(&stream, &frame);
        }
        if let Ok(Some(_channel)) = result {
            channels.fetch_add(1, Ordering::SeqCst);
            close.store(false, Ordering::SeqCst);
            loop {
                if close.load(Ordering::SeqCst) {
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    return;
                }
                match read_frame(&stream, Duration::from_millis(50)) {
                    Ok(_) | Err(FrameError::Timeout) => {}
                    Err(_) => return,
                }
            }
        }
    }
}
