//! Framed I/O over loopback TCP (contracts/peer-protocol.md "TCP framing").

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use device_link_net::framed::{FrameError, read_frame, write_frame};

fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    (client, server)
}

const SHORT: Duration = Duration::from_millis(300);

#[test]
fn reads_exactly_one_frame_at_a_time() {
    let (mut client, server) = pair();
    client.write_all(b"\x00\x03abc\x00\x02de").unwrap();
    assert_eq!(&*read_frame(&server, SHORT).unwrap(), b"abc");
    assert_eq!(&*read_frame(&server, SHORT).unwrap(), b"de");
}

#[test]
fn write_frame_round_trips_and_refuses_bad_lengths() {
    let (client, server) = pair();
    write_frame(&client, &[5u8; 1024]).unwrap();
    assert_eq!(read_frame(&server, SHORT).unwrap().len(), 1024);
    assert!(write_frame(&client, &[]).is_err());
    assert!(write_frame(&client, &[0u8; 1025]).is_err());
}

#[test]
fn oversized_and_zero_lengths_are_refused_before_reading_the_body() {
    let (mut client, server) = pair();
    client.write_all(b"\x04\x01").unwrap(); // 1025, no body sent
    let start = Instant::now();
    assert_eq!(
        read_frame(&server, SHORT).err(),
        Some(FrameError::Oversized)
    );
    assert!(
        start.elapsed() < SHORT,
        "refused without waiting for a body"
    );
    let (mut client, server) = pair();
    client.write_all(b"\xff\xff").unwrap();
    assert_eq!(
        read_frame(&server, SHORT).err(),
        Some(FrameError::Oversized)
    );
    let (mut client, server) = pair();
    client.write_all(b"\x00\x00").unwrap();
    assert_eq!(
        read_frame(&server, SHORT).err(),
        Some(FrameError::Malformed)
    );
}

#[test]
fn silence_and_partial_frames_time_out() {
    let (_client, server) = pair();
    let start = Instant::now();
    assert_eq!(read_frame(&server, SHORT).err(), Some(FrameError::Timeout));
    assert!(start.elapsed() >= SHORT && start.elapsed() < SHORT * 3);
    // A slow peer dribbling bytes cannot extend the step beyond its deadline.
    let (mut client, server) = pair();
    let writer = thread::spawn(move || {
        let _ = client.write_all(b"\x00\x0a");
        for _ in 0..10 {
            thread::sleep(Duration::from_millis(100));
            if client.write_all(b"x").is_err() {
                break;
            }
        }
        client
    });
    let start = Instant::now();
    assert_eq!(read_frame(&server, SHORT).err(), Some(FrameError::Timeout));
    assert!(
        start.elapsed() < SHORT * 2,
        "deadline is per step, not per byte"
    );
    drop(writer.join());
}

#[test]
fn eof_is_reported() {
    let (client, server) = pair();
    drop(client);
    assert_eq!(read_frame(&server, SHORT).err(), Some(FrameError::Closed));
    let (mut client, server) = pair();
    client.write_all(b"\x00\x05ab").unwrap();
    drop(client);
    assert_eq!(read_frame(&server, SHORT).err(), Some(FrameError::Closed));
}
