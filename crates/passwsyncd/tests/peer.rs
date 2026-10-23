use std::net::{SocketAddr, TcpListener, TcpStream};

use passwsyncd::peer::{find_uid, peer_uid};

const TABLE: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:6B5F 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 11111 1 0000000000000000 100 0 0 10 0
   1: 0100007F:6B5F 0100007F:D431 01 00000000:00000000 00:00000000 00000000  1000        0 22222 1 0000000000000000 20 4 30 10 -1
   2: 0100007F:D431 0100007F:6B5F 01 00000000:00000000 00:00000000 00000000  1001        0 33333 1 0000000000000000 20 4 30 10 -1
   3: 0100007F:D432 0100007F:6B5F 01 00000000:00000000 00:00000000 00000000  1000        0 44444 1 0000000000000000 20 4 30 10 -1
   4: 0A00000A:D433 0100007F:6B5F 01 00000000:00000000 00:00000000 00000000  1000        0 55555 1 0000000000000000 20 4 30 10 -1
";

fn addr(text: &str) -> SocketAddr {
    text.parse().unwrap()
}

#[test]
fn finds_the_uid_of_the_client_socket_not_the_server_side() {
    let server = addr("127.0.0.1:27487");
    assert_eq!(find_uid(TABLE, addr("127.0.0.1:54321"), server), Some(1001));
    assert_eq!(find_uid(TABLE, addr("127.0.0.1:54322"), server), Some(1000));
}

#[test]
fn unknown_sockets_and_non_loopback_peers_are_none() {
    let server = addr("127.0.0.1:27487");
    assert_eq!(find_uid(TABLE, addr("127.0.0.1:1"), server), None);
    assert_eq!(find_uid(TABLE, addr("10.0.0.10:54323"), server), None);
    assert_eq!(find_uid(TABLE, addr("[::1]:54322"), server), None);
    assert_eq!(
        find_uid("garbage\n1: zz", addr("127.0.0.1:54322"), server),
        None
    );
    assert_eq!(find_uid("", addr("127.0.0.1:54322"), server), None);
}

#[test]
fn real_loopback_connection_belongs_to_this_user() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let _client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (accepted, peer) = listener.accept().unwrap();
    let uid = peer_uid(peer, accepted.local_addr().unwrap());
    assert_eq!(uid, Some(rustix::process::getuid().as_raw()));
}
