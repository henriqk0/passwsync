//! Known-answer tests pinning the behaviour of the unaudited `snow` and `spake2` crates
//! (research R16 mitigation). A dependency update that changes any byte fails here.

use device_link::pairing::{
    CHANNEL_PROLOGUE, NOISE_CHANNEL, NOISE_PAIR, PAIR_PROLOGUE, SPAKE_ID_A, SPAKE_ID_B,
};
use device_link::testkit::ScriptedRng;
use sha2::{Digest, Sha256};
use spake2::{Ed25519Group, Identity, Password, Spake2};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn protocol_constants_are_the_contract_values() {
    assert_eq!(SPAKE_ID_A, b"passwsync-pair-initiator-v1");
    assert_eq!(SPAKE_ID_B, b"passwsync-pair-joiner-v1");
    assert_eq!(NOISE_PAIR, "Noise_XXpsk2_25519_ChaChaPoly_BLAKE2s");
    assert_eq!(NOISE_CHANNEL, "Noise_XX_25519_ChaChaPoly_BLAKE2s");
    assert_eq!(PAIR_PROLOGUE, b"passwsync-pair-v1");
    assert_eq!(CHANNEL_PROLOGUE, b"passwsync-channel-v1");
}

const SPAKE_MSG_A: &str = "41a082c53b758cbfb2d0192708be996744622f17da5fd25d2f19b78bbbfdeaf453";
const SPAKE_MSG_B: &str = "42ca0e8eb74e1acfe28d8efbc2214276cb96accdf744639fdc1af4512db02fb51c";
const SPAKE_KEY: &str = "ea83c1847af3af1aa470d507c74c120541291105ceb4b6b93f5f30787a94764a";

#[test]
fn spake2_with_fixed_seeds_reproduces_messages_and_key() {
    let password = Password::new(b"12345678");
    let (id_a, id_b) = (Identity::new(SPAKE_ID_A), Identity::new(SPAKE_ID_B));
    let (a, msg_a) =
        Spake2::<Ed25519Group>::start_a_with_rng(&password, &id_a, &id_b, ScriptedRng::seeded(1));
    let (b, msg_b) =
        Spake2::<Ed25519Group>::start_b_with_rng(&password, &id_a, &id_b, ScriptedRng::seeded(2));
    assert_eq!(msg_a.len(), 33);
    assert_eq!(msg_b.len(), 33);
    let key_a = a.finish(&msg_b).unwrap();
    let key_b = b.finish(&msg_a).unwrap();
    assert_eq!(key_a, key_b);
    assert_eq!(key_a.len(), 32);
    assert_eq!(hex(&msg_a), SPAKE_MSG_A);
    assert_eq!(hex(&msg_b), SPAKE_MSG_B);
    assert_eq!(hex(&key_a), SPAKE_KEY);
}

#[test]
fn spake2_with_a_different_password_gives_different_keys() {
    let (id_a, id_b) = (Identity::new(SPAKE_ID_A), Identity::new(SPAKE_ID_B));
    let (a, msg_a) = Spake2::<Ed25519Group>::start_a_with_rng(
        &Password::new(b"12345678"),
        &id_a,
        &id_b,
        ScriptedRng::seeded(1),
    );
    let (b, msg_b) = Spake2::<Ed25519Group>::start_b_with_rng(
        &Password::new(b"12345679"),
        &id_a,
        &id_b,
        ScriptedRng::seeded(2),
    );
    assert_ne!(a.finish(&msg_b).unwrap(), b.finish(&msg_a).unwrap());
}

const XXPSK2_TRANSCRIPT_SHA256: &str =
    "6b1154207fbcf902ca72e106ce9f7b61bd8be7bd886ad5a4d8419ceeba5022c8";

#[test]
fn noise_xxpsk2_with_fixed_keys_reproduces_the_transcript() {
    let params = NOISE_PAIR.parse().unwrap();
    let psk = [0x42u8; 32];
    let (b_static, b_eph) = ([1u8; 32], [2u8; 32]);
    let (a_static, a_eph) = ([3u8; 32], [4u8; 32]);
    let prologue = b"passwsync-pair-v1fixed";
    let mut joiner = snow::Builder::new(params)
        .local_private_key(&b_static)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&b_eph)
        .psk(2, &psk)
        .unwrap()
        .prologue(prologue)
        .unwrap()
        .build_initiator()
        .unwrap();
    let mut shower = snow::Builder::new(NOISE_PAIR.parse().unwrap())
        .local_private_key(&a_static)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&a_eph)
        .psk(2, &psk)
        .unwrap()
        .prologue(prologue)
        .unwrap()
        .build_responder()
        .unwrap();
    let mut transcript = Vec::new();
    let (mut buf, mut out) = ([0u8; 1024], [0u8; 1024]);
    let n = joiner.write_message(&[], &mut buf).unwrap();
    transcript.extend_from_slice(&buf[..n]);
    shower.read_message(&buf[..n], &mut out).unwrap();
    let n = shower.write_message(&[], &mut buf).unwrap();
    transcript.extend_from_slice(&buf[..n]);
    joiner.read_message(&buf[..n], &mut out).unwrap();
    let n = joiner.write_message(b"\x01\x02Ab", &mut buf).unwrap();
    transcript.extend_from_slice(&buf[..n]);
    let m = shower.read_message(&buf[..n], &mut out).unwrap();
    assert_eq!(&out[..m], b"\x01\x02Ab");
    assert_eq!(joiner.get_handshake_hash(), shower.get_handshake_hash());
    let digest = hex(&Sha256::digest(&transcript));
    assert_eq!(digest, XXPSK2_TRANSCRIPT_SHA256);
}

/// Official cacophony vector for `Noise_XX_25519_ChaChaPoly_BLAKE2s` (snow test vectors).
#[test]
fn noise_xx_matches_the_cacophony_vector() {
    let prologue = unhex("4a6f686e2047616c74");
    let init_static = unhex("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1");
    let init_eph = unhex("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a");
    let resp_static = unhex("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893");
    let resp_eph = unhex("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b");
    let messages = [
        (
            "4c756477696720766f6e204d69736573",
            "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c756477696720766f6e204d69736573",
        ),
        (
            "4d757272617920526f746862617264",
            "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f1448088437c365eb362a1c991b0557fe8a7fb187d99346765d93ec63db6c1b01504ebeec55a2298d2dbff80eff034d20595153f63a196a6cead1e11b2bb13e336fa13616dd3e8b0a070c882ed3f1a78c7c06c93",
        ),
        (
            "462e20412e20486179656b",
            "46c3307de83b014258717d97781c1f50936d8b7d50c0722a1739654d10392d415b670c114f79b9a4f80541570f77ce88802efa4220cff733e7b5668ba38059ec904b4b8eef9448085faf51",
        ),
        (
            "4361726c204d656e676572",
            "d5e83adfaac5dc324a68f1862df54549e56d209fba707205f328b2",
        ),
    ];
    let mut init = snow::Builder::new(NOISE_CHANNEL.parse().unwrap())
        .local_private_key(&init_static)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&init_eph)
        .prologue(&prologue)
        .unwrap()
        .build_initiator()
        .unwrap();
    let mut resp = snow::Builder::new(NOISE_CHANNEL.parse().unwrap())
        .local_private_key(&resp_static)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&resp_eph)
        .prologue(&prologue)
        .unwrap()
        .build_responder()
        .unwrap();
    let (mut buf, mut out) = ([0u8; 1024], [0u8; 1024]);
    for (i, (payload, cipher)) in messages[..3].iter().enumerate() {
        let (writer, reader) = if i % 2 == 0 {
            (&mut init, &mut resp)
        } else {
            (&mut resp, &mut init)
        };
        let n = writer.write_message(&unhex(payload), &mut buf).unwrap();
        assert_eq!(hex(&buf[..n]), *cipher, "message {i}");
        let m = reader.read_message(&buf[..n], &mut out).unwrap();
        assert_eq!(hex(&out[..m]), *payload);
    }
    assert_eq!(
        hex(init.get_handshake_hash()),
        "6c4c56cf71612f72d05ceb96c0155e6f4ea54a26b504c93de632a2db4a49d200"
    );
    let mut init = init.into_transport_mode().unwrap();
    let mut resp = resp.into_transport_mode().unwrap();
    // The 4th message (first transport message) goes responder -> initiator.
    let (payload, cipher) = messages[3];
    let n = resp.write_message(&unhex(payload), &mut buf).unwrap();
    assert_eq!(hex(&buf[..n]), cipher);
    let m = init.read_message(&buf[..n], &mut out).unwrap();
    assert_eq!(hex(&out[..m]), payload);
}
