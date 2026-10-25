//! 005 T085 (FR-025, FR-017): a paired peer flooding share frames (repeated `Redeem`,
//! malformed or oversized messages, endless `ShareData`) is cut off after bounded work, never
//! crashes the service and never starves 004 sync.

mod common;

use std::fs;
use std::net::TcpStream;
use std::time::{Duration, Instant};

use common::server::{Fixture, TestServer, free_net_port, wait_for};
use common::sync::*;
use device_link::channel::{Channel, ChannelDialer};
use device_link::files::{decode_device_key, encode_peers};
use device_link::identity::DeviceKey;
use device_link::name::DeviceName;
use device_link::registry::PeerPin;
use device_link::wire::{HelloVersion, Payload};
use device_link_net::framed::{read_frame, write_frame};
use wallet_sync::share::codec::ShareMsg;

fn rss_kib() -> u64 {
    fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find(|l| l.starts_with("VmRSS:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap()
}

/// Opens a v3 channel to `server` as the pinned device `key`.
fn dial(server: &TestServer, key: &DeviceKey) -> (TcpStream, Channel) {
    let a_key =
        decode_device_key(&fs::read(server.fx.config_dir.join("device-key")).unwrap()).unwrap();
    let stream = TcpStream::connect(("127.0.0.1", server.peer_port())).unwrap();
    let mut dialer = ChannelDialer::start_version(
        key,
        *a_key.public(),
        DeviceName::parse("Flooder").unwrap(),
        HelloVersion::V3,
    )
    .unwrap();
    for _ in 0..2 {
        for frame in dialer.outgoing() {
            write_frame(&stream, &frame).unwrap();
        }
        let body = read_frame(&stream, Duration::from_secs(3)).unwrap();
        if let Some(channel) = dialer.on_frame(&body).unwrap() {
            return (stream, channel);
        }
    }
    panic!("no channel");
}

/// Sends `count` payloads until the server cuts the connection; returns how many went out.
fn flood(
    stream: &TcpStream,
    channel: &mut Channel,
    count: usize,
    make: impl Fn(usize) -> Vec<u8>,
) -> usize {
    for i in 0..count {
        let Ok(frame) = channel.seal_any(&make(i)) else {
            return i;
        };
        if write_frame(stream, &frame).is_err() {
            return i;
        }
    }
    count
}

#[test]
fn share_floods_are_cut_off_and_sync_keeps_working() {
    let flooder = DeviceKey::from_private([88; 32]);
    let (peer, disc) = (free_net_port(), free_net_port());
    let fx = Fixture::new(&config("Laptop", peer, disc));
    let pin = PeerPin {
        public: *flooder.public(),
        name: DeviceName::parse("Flooder").unwrap(),
        paired_at: 1,
        last_seen: None,
        last_addr: None,
    };
    let peers = fx.config_dir.join("peers");
    fs::write(&peers, encode_peers(&[pin])).unwrap();
    common::set_mode(&peers, 0o600);
    let server = TestServer::start_in(fx);
    let s = server.login();
    let before = rss_kib();

    type Maker = Box<dyn Fn(usize) -> Vec<u8>>;
    let floods: [(&str, Maker); 3] = [
        (
            "redeem",
            Box::new(|i| {
                Payload::ShareMsg {
                    body: ShareMsg::Redeem {
                        rid: i as u32,
                        proof: [0; 32],
                    }
                    .encode(),
                }
                .encode()
            }),
        ),
        (
            "malformed",
            Box::new(|_| {
                Payload::ShareMsg {
                    body: vec![0x7f; 900],
                }
                .encode()
            }),
        ),
        (
            "data",
            Box::new(|_| {
                Payload::ShareData {
                    bytes: vec![0x55; 1000],
                }
                .encode()
            }),
        ),
    ];
    for (label, make) in floods {
        let (stream, mut channel) = dial(&server, &flooder);
        let started = Instant::now();
        flood(&stream, &mut channel, 20_000, make);
        // The service closes the channel: reads end quickly.
        let closed = wait_for(Duration::from_secs(5), || {
            matches!(
                read_frame(&stream, Duration::from_millis(50)),
                Err(device_link_net::framed::FrameError::Closed
                    | device_link_net::framed::FrameError::Io)
            )
        });
        assert!(closed, "{label}: channel not closed");
        assert!(started.elapsed() < Duration::from_secs(10), "{label}");
        // The UI stays responsive.
        let t = Instant::now();
        assert_eq!(server.api(&s, "GET", "/api/share", None).status, 200);
        assert!(t.elapsed() < Duration::from_secs(1), "{label}: UI slow");
    }
    let grown = rss_kib().saturating_sub(before);
    assert!(grown < 32 * 1024, "{grown} KiB");
    assert!(
        share_state_of(&server, &s)["notices"]
            .as_array()
            .unwrap()
            .len()
            <= 16
    );

    // 004 sync with a real peer still works on the same service.
    let a = Instance {
        server,
        session: s,
        peer_port: peer,
    };
    let b = instance("Phone");
    pair_via(&a, &b, a.peer_port);
    a.create_wallet("W");
    copy_wallet_file(&a, &b, "W");
    b.unlock("W");
    a.add("W", "After flood", "", "", "", "");
    assert!(wait_for(Duration::from_secs(15), || b.titles("W") == ["After flood"]));
}

fn share_state_of(server: &TestServer, s: &common::server::Session) -> serde_json::Value {
    server.api(s, "GET", "/api/share", None).json()
}
