//! `Transaction::deserialize_with_legacy_asset_lock_framing` reads an asset lock's payload
//! whatever length its prefix announces, and must keep reading asset locks the same way whatever
//! else changes in the crate.
//!
//! Its expected results are therefore fixed bytes, txids and errors, not the output of another
//! decoder of this crate; only anything that is not an asset lock is compared with
//! [`deserialize`], which decodes it. The asset lock is a testnet one Dash Core relayed, split
//! into its parts so that the other vectors can be built from it.

use std::str::FromStr;

use dashcore::blockdata::transaction::special_transaction::TransactionPayload;
use dashcore::blockdata::transaction::special_transaction::asset_lock::AssetLockPayload;
use dashcore::consensus::encode::Error;
use dashcore::consensus::{deserialize, serialize};
use dashcore::{ScriptBuf, Transaction, TxOut, Txid, Witness};
use test_case::test_case;

/// Version 3, type 8 (asset lock).
const HEADER: &str = "03000800";
/// One input.
const INPUTS: &str = "014d6d36c50d484aa79f7db080f971c3f6845407f652c7d5865756017fa06969c1010000006a47304402200136894a2ebb4967cf2766c10e238d69c53c24bf330758e4432eb4753def03de02202a2afb05475a064a419a6cc1c582e3504fcb36c2e22b610b5d320f7656573f7f0121028fdb0a3f730bb20f477536d98ca830efa56412dd05992c801219ba0ff35ad530ffffffff";
const OUTPUTS: &str =
    "028801030000000000026a00288d9500000000001976a9148d40dfe30494080a1c1187c74066956043ff13fb88ac";
const LOCK_TIME: &str = "00000000";
/// The payload length prefix Core wrote: 36 bytes.
const PAYLOAD_LENGTH: &str = "24";
/// 197,000 duffs to a P2PKH script.
const CREDIT_OUTPUT: &str = "88010300000000001976a914aa85a9fb4f84bc63046a574ac4f2ce3361f0db0d88ac";
const TXID: &str = "81a1d138a3af6271d7fc4fef44cfd4d3b68fc8028dc208053bdae59f5dcc5581";

/// The coinbase of mainnet block 0000000000000027facf8fffe7c4f92345edf06ee2615eae06b3e20392e22ddf.
const COINBASE: &str = "03000500010000000000000000000000000000000000000000000000000000000000000000ffffffff330341ac1c0499e175642f706f6f6c696e2e636f6d2f5e9fea0288e95fd8864ea6cbf620d16e0c3c6af5d400f8e2030000000000ffffffff027eef8d08000000001976a9147fca51bce950b0ccf0a4994e3d6266202d27aa1f88ac59724506000000001976a914a8d608a131a5fd9c0ac063b33629da422adab17f88ac0000000046020041ac1c00facd1b5ccda08840168298c576b0c52223deb79340147fb85c71125b8bc9b1a1af27d4c4d5a7bfedec9d3fc55e518e69b6d19cb5e69e5e598390eb8e08d520ad";
/// A testnet provider registration.
const PRO_REG_TX: &str = "0300010001ca9a43051750da7c5f858008f2ff7732d15691e48eb7f845c791e5dca78bab58010000006b483045022100fe8fec0b3880bcac29614348887769b0b589908e3f5ec55a6cf478a6652e736502202f30430806a6690524e4dd599ba498e5ff100dea6a872ebb89c2fd651caa71ed012103d85b25d6886f0b3b8ce1eef63b720b518fad0b8e103eba4e85b6980bfdda2dfdffffffff018e37807e090000001976a9144ee1d4e5d61ac40a13b357ac6e368997079678c888ac00000000fd1201010000000000ca9a43051750da7c5f858008f2ff7732d15691e48eb7f845c791e5dca78bab580000000000000000000000000000ffff010205064e1f3dd03f9ec192b5f275a433bfc90f468ee1a3eb4c157b10706659e25eb362b5d902d809f9160b1688e201ee6e94b40f9b5062d7074683ef05a2d5efb7793c47059c878dfad38a30fafe61575db40f05ab0a08d55119b0aad300001976a9144fbc8fb6e11e253d77e5a9c987418e89cf4a63d288ac3477990b757387cb0406168c2720acf55f83603736a314a37d01b135b873a27b411fb37e49c1ff2b8057713939a5513e6e711a71cff2e517e6224df724ed750aef1b7f9ad9ec612b4a7250232e1e400da718a9501e1d9a5565526e4b1ff68c028763";

const NOT_CONSUMED: &str = "data not consumed entirely when explicitly deserializing";

fn hex_bytes(hex: &str) -> Vec<u8> {
    hex::decode(hex).expect("vector is hex")
}

fn tx_bytes(parts: &[&str]) -> Vec<u8> {
    hex_bytes(&parts.concat())
}

/// An asset lock payload of `version` with Core's one credit output.
fn payload(version: u8) -> String {
    format!("{version:02x}01{CREDIT_OUTPUT}")
}

/// Core's asset lock with its payload length prefix replaced by `prefix`.
fn core_asset_lock(prefix: &str) -> Vec<u8> {
    tx_bytes(&[HEADER, INPUTS, OUTPUTS, LOCK_TIME, prefix, &payload(1)])
}

fn decode(bytes: &[u8]) -> Result<Transaction, Error> {
    Transaction::deserialize_with_legacy_asset_lock_framing(bytes)
}

fn credit_output() -> TxOut {
    TxOut {
        value: 197_000,
        script_pubkey: ScriptBuf::from(hex_bytes(&CREDIT_OUTPUT[18..])),
    }
}

fn txid(hex: &str) -> Txid {
    Txid::from_str(hex).expect("txid is hex")
}

#[track_caller]
fn assert_parse_failed(result: Result<Transaction, Error>, reason: &str) {
    match result {
        Err(Error::ParseFailed(r)) => assert_eq!(r, reason),
        other => panic!("expected ParseFailed({reason:?}), got {other:?}"),
    }
}

#[track_caller]
fn assert_eof(result: Result<Transaction, Error>) {
    match result {
        Err(Error::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof),
        other => panic!("expected an unexpected end of data, got {other:?}"),
    }
}

/// The payload is read whatever length its prefix announces, in any width, to the transaction
/// Core relayed.
#[test_case("24" ; "the payload length")]
#[test_case("00" ; "zero")]
#[test_case("23" ; "one less")]
#[test_case("25" ; "one more")]
#[test_case("fc" ; "the largest one-byte value")]
#[test_case("fd0001" ; "three bytes")]
#[test_case("fe00000100" ; "five bytes")]
#[test_case("ff0000000001000000" ; "nine bytes")]
fn reads_the_payload_whatever_length_its_prefix_announces(prefix: &str) {
    let tx = decode(&core_asset_lock(prefix)).expect("the asset lock decodes");

    assert_eq!(serialize(&tx), core_asset_lock(PAYLOAD_LENGTH));
    assert_eq!(tx.txid(), txid(TXID));
    assert_eq!(
        tx.special_transaction_payload,
        Some(TransactionPayload::AssetLockPayloadType(AssetLockPayload {
            version: 1,
            credit_outputs: vec![credit_output()],
        }))
    );
}

/// Every version from 3 up, read as an `i16`, carries a payload.
#[test_case("0400", "1c3457f219869a9fab9f2579cb2b5ae698ce8798b627659df8faaa5391199828" ; "version 4")]
#[test_case("ff7f", "7c6341227ba377a9efd22ed55eb4042156d14ecd7eb26c0d28f8c8b926882edd" ; "version 0x7fff")]
fn reads_the_payload_from_every_version_from_3(version: &str, expected_txid: &str) {
    let header = [version, &HEADER[4..]].concat();
    let asset_lock = |prefix| tx_bytes(&[&header, INPUTS, OUTPUTS, LOCK_TIME, prefix, &payload(1)]);

    let tx = decode(&asset_lock("00")).expect("the asset lock decodes");

    assert_eq!(serialize(&tx), asset_lock(PAYLOAD_LENGTH));
    assert_eq!(tx.txid(), txid(expected_txid));
}

/// A payload of 253 bytes or more has a 3-byte length prefix. Read after a 1-byte prefix it is
/// the same transaction.
#[test_case("fd1201" ; "the payload length")]
#[test_case("24" ; "one byte")]
#[test_case("00" ; "zero")]
fn reads_a_long_payload_after_a_prefix_of_another_width(prefix: &str) {
    let payload = format!("0108{}", CREDIT_OUTPUT.repeat(8));

    let tx = decode(&tx_bytes(&[HEADER, INPUTS, OUTPUTS, LOCK_TIME, prefix, &payload]))
        .expect("the asset lock decodes");

    assert_eq!(serialize(&tx), tx_bytes(&[HEADER, INPUTS, OUTPUTS, LOCK_TIME, "fd1201", &payload]));
    assert_eq!(tx.txid(), txid("b35b6f5a0a16d1b5f14937de3014813ec0c47f557be2b4be9c496d159f10dcc0"));
}

#[test_case("02" ; "the payload length")]
#[test_case("00" ; "zero")]
fn reads_a_payload_without_credit_outputs(prefix: &str) {
    let tx = decode(&tx_bytes(&[HEADER, INPUTS, OUTPUTS, LOCK_TIME, prefix, "0100"]))
        .expect("the asset lock decodes");

    assert_eq!(serialize(&tx), tx_bytes(&[HEADER, INPUTS, OUTPUTS, LOCK_TIME, "02", "0100"]));
    assert_eq!(tx.txid(), txid("0c94c09ffe2292276caa5c26d1dc938b95c1dbe6cb0e533cde915e3057996333"));
}

/// An asset lock with no inputs before the segwit flag is read in the BIP144 form, as a
/// classic transaction is. Its witnesses are not part of the txid.
#[test_case("24" ; "the payload length")]
#[test_case("00" ; "zero")]
fn reads_the_witness_form(prefix: &str) {
    let witness_form = |prefix| {
        tx_bytes(&[HEADER, "0001", INPUTS, OUTPUTS, "0101aa", LOCK_TIME, prefix, &payload(1)])
    };

    let tx = decode(&witness_form(prefix)).expect("the witness form decodes");

    assert_eq!(tx.txid(), txid(TXID));
    assert_eq!(tx.input[0].witness, Witness::from_slice(&[[0xaa]]));
    assert_eq!(serialize(&tx), witness_form(PAYLOAD_LENGTH));
}

/// The witness form needs a witness on one input, not on every input.
#[test_case("24" ; "the payload length")]
#[test_case("00" ; "zero")]
fn reads_the_witness_form_with_a_witness_on_one_of_two_inputs(prefix: &str) {
    let input = &INPUTS[2..];
    let witness_form = |prefix| {
        tx_bytes(&[
            HEADER,
            "000102",
            input,
            input,
            OUTPUTS,
            "0101aa",
            "00",
            LOCK_TIME,
            prefix,
            &payload(1),
        ])
    };

    let tx = decode(&witness_form(prefix)).expect("the witness form decodes");

    assert_eq!(tx.input.len(), 2);
    assert!(tx.input[1].witness.is_empty());
    assert_eq!(tx.txid(), txid("5b5c481f959cf0ea6e00c9d3a9850494b79945022d46741e54096d4f58a138ae"));
    assert_eq!(serialize(&tx), witness_form(PAYLOAD_LENGTH));
}

#[test_case("24" ; "the payload length")]
#[test_case("fd0001" ; "three bytes")]
fn reads_an_asset_lock_without_inputs(prefix: &str) {
    let without_inputs =
        |prefix| tx_bytes(&[HEADER, "000100", OUTPUTS, LOCK_TIME, prefix, &payload(1)]);

    let tx = decode(&without_inputs(prefix)).expect("an asset lock without inputs decodes");

    assert!(tx.input.is_empty());
    assert_eq!(tx.txid(), txid("325f4b5a15524d45dbdee47a7a69e17c1863682cb25d6ab85bcb71ddd63b0ec7"));
    assert_eq!(serialize(&tx), without_inputs(PAYLOAD_LENGTH));
}

#[test_case("24" ; "the payload length")]
#[test_case("00" ; "zero")]
fn refuses_the_segwit_flag_without_witnesses(prefix: &str) {
    assert_parse_failed(
        decode(&tx_bytes(&[HEADER, "0001", INPUTS, OUTPUTS, "00", LOCK_TIME, prefix, &payload(1)])),
        "witness flag set but no witnesses present",
    );
}

#[test_case(0, "24" ; "flag 0")]
#[test_case(0, "00" ; "flag 0, another prefix")]
#[test_case(2, "24" ; "flag 2")]
fn refuses_a_segwit_flag_other_than_1(flag: u8, prefix: &str) {
    let marker_and_flag = format!("00{flag:02x}");
    let result = decode(&tx_bytes(&[
        HEADER,
        &marker_and_flag,
        INPUTS,
        OUTPUTS,
        LOCK_TIME,
        prefix,
        &payload(1),
    ]));
    assert!(matches!(result, Err(Error::UnsupportedSegwitFlag(f)) if f == flag), "{result:?}");
}

/// Every payload version is read with one layout: a version byte, then the credit outputs, and
/// nothing after them, whether the prefix counts what follows or not. A field that a later
/// payload version appends must not make this accept more.
#[test_case(0 ; "version 0")]
#[test_case(2 ; "version 2")]
#[test_case(3 ; "version 3")]
#[test_case(255 ; "version 255")]
fn reads_every_payload_version_with_one_layout(version: u8) {
    let payload = payload(version);

    let exact = tx_bytes(&[HEADER, INPUTS, OUTPUTS, LOCK_TIME, PAYLOAD_LENGTH, &payload]);
    let tx = decode(&exact).expect("the asset lock decodes");
    assert_eq!(serialize(&tx), exact);
    assert_eq!(
        tx.special_transaction_payload,
        Some(TransactionPayload::AssetLockPayloadType(AssetLockPayload {
            version,
            credit_outputs: vec![credit_output()],
        }))
    );

    for appended in [1, 4, 32] {
        let field = "ab".repeat(appended);
        let counted = format!("{:02x}", 36 + appended);
        for prefix in [PAYLOAD_LENGTH, &counted] {
            assert_parse_failed(
                decode(&tx_bytes(&[HEADER, INPUTS, OUTPUTS, LOCK_TIME, prefix, &payload, &field])),
                NOT_CONSUMED,
            );
        }
    }
}

#[test_case("fd2400" ; "three bytes")]
#[test_case("fe24000000" ; "five bytes")]
#[test_case("ff2400000000000000" ; "nine bytes")]
fn refuses_a_prefix_that_is_not_minimally_encoded(prefix: &str) {
    let result = decode(&core_asset_lock(prefix));
    assert!(matches!(result, Err(Error::NonMinimalVarInt)), "{result:?}");
}

#[test]
fn refuses_a_credit_output_count_that_is_not_minimally_encoded() {
    let payload = format!("01fd0100{CREDIT_OUTPUT}");
    let result = decode(&tx_bytes(&[HEADER, INPUTS, OUTPUTS, LOCK_TIME, PAYLOAD_LENGTH, &payload]));
    assert!(matches!(result, Err(Error::NonMinimalVarInt)), "{result:?}");
}

/// The payload must end the transaction, whether or not the prefix counts the bytes after it.
#[test_case(PAYLOAD_LENGTH ; "not counted")]
#[test_case("25" ; "counted")]
fn refuses_a_byte_after_the_payload(prefix: &str) {
    let mut bytes = core_asset_lock(prefix);
    bytes.push(0);
    assert_parse_failed(decode(&bytes), NOT_CONSUMED);
}

#[test_case(&[] ; "empty")]
#[test_case(&["030008"] ; "three bytes")]
#[test_case(&[HEADER, INPUTS, OUTPUTS, LOCK_TIME] ; "no payload length")]
#[test_case(&[HEADER, INPUTS, OUTPUTS, LOCK_TIME, "fd00"] ; "a truncated payload length")]
#[test_case(&[HEADER, INPUTS, OUTPUTS, LOCK_TIME, PAYLOAD_LENGTH] ; "no payload")]
#[test_case(&[HEADER, INPUTS, OUTPUTS, LOCK_TIME, PAYLOAD_LENGTH, "01"] ; "no credit outputs")]
#[test_case(&[HEADER, INPUTS, OUTPUTS, LOCK_TIME, PAYLOAD_LENGTH, "0101", &CREDIT_OUTPUT[..20]] ; "a truncated credit output")]
fn refuses_truncated_bytes(parts: &[&str]) {
    assert_eof(decode(&tx_bytes(parts)));
}

/// A classic transaction has no payload section, so an asset lock payload after one is bytes
/// the transaction does not read.
#[test]
fn refuses_an_asset_lock_payload_after_a_classic_transaction() {
    assert_parse_failed(
        decode(&tx_bytes(&["03000000", INPUTS, OUTPUTS, LOCK_TIME, PAYLOAD_LENGTH, &payload(1)])),
        NOT_CONSUMED,
    );
}

/// Anything that is not an asset lock is decoded by `deserialize`, whatever it returns. That
/// includes type 8 below version 3, where Core reads no payload.
#[test]
fn decodes_other_transactions_as_deserialize_does() {
    let unknown_type = ["03000d00", INPUTS, OUTPUTS, LOCK_TIME].concat();
    let below_version_3 = |header| tx_bytes(&[header, INPUTS, OUTPUTS, LOCK_TIME]);
    for (case, bytes) in [
        ("a coinbase", hex_bytes(COINBASE)),
        ("a provider registration", hex_bytes(PRO_REG_TX)),
        ("an unknown type", tx_bytes(&[&unknown_type, PAYLOAD_LENGTH, &payload(1)])),
        ("an unknown type, another prefix", tx_bytes(&[&unknown_type, "00", &payload(1)])),
        ("type 8 at version 2", below_version_3("02000800")),
        ("type 8 at version 2, with a payload", core_asset_lock_with_header("02000800")),
        ("type 8 at version 0x8003", below_version_3("03800800")),
        ("type 8 at version 0x8003, with a payload", core_asset_lock_with_header("03800800")),
    ] {
        match (decode(&bytes), deserialize::<Transaction>(&bytes)) {
            (Ok(tx), Ok(expected)) => assert_eq!(tx, expected, "{case}"),
            (Err(e), Err(expected)) => {
                assert_eq!(format!("{e:?}"), format!("{expected:?}"), "{case}")
            }
            (result, expected) => panic!("{case}: {result:?}, but deserialize gives {expected:?}"),
        }
    }
}

fn core_asset_lock_with_header(header: &str) -> Vec<u8> {
    tx_bytes(&[header, INPUTS, OUTPUTS, LOCK_TIME, PAYLOAD_LENGTH, &payload(1)])
}

/// Whatever this decodes, it reads back unchanged from its encoding, and so does `deserialize`
/// at payload version 1, the layout Core gives asset lock payloads.
#[test]
fn what_it_decodes_round_trips_through_its_encoding() {
    let input = &INPUTS[2..];
    let seeds = [
        core_asset_lock(PAYLOAD_LENGTH),
        tx_bytes(&[
            HEADER,
            "0001",
            INPUTS,
            OUTPUTS,
            "0101aa",
            LOCK_TIME,
            PAYLOAD_LENGTH,
            &payload(1),
        ]),
        tx_bytes(&[HEADER, "000100", OUTPUTS, LOCK_TIME, PAYLOAD_LENGTH, &payload(1)]),
        tx_bytes(&[HEADER, "02", input, input, OUTPUTS, LOCK_TIME, PAYLOAD_LENGTH, &payload(1)]),
    ];
    // xorshift64, so every run tries the same mutations.
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let mut next = move |below: usize| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        (state % below as u64) as usize
    };
    let mut decoded_from_other_bytes = 0;
    for _ in 0..50_000 {
        let mut bytes = seeds[next(seeds.len())].clone();
        // Half the time, another one-byte payload length prefix: the payload is the last 36
        // bytes of every seed.
        if next(2) == 0 {
            let prefix_at = bytes.len() - 37;
            bytes[prefix_at] = next(0xfd) as u8;
        }
        for _ in 0..next(3) {
            // The header stays an asset lock's.
            let at = 4 + next(bytes.len() - 3);
            match next(3) {
                0 if at < bytes.len() => bytes[at] = next(256) as u8,
                1 if at < bytes.len() => {
                    bytes.remove(at);
                }
                _ => bytes.insert(at, next(256) as u8),
            }
        }
        let Ok(tx) = decode(&bytes) else {
            continue;
        };
        let encoded = serialize(&tx);
        if encoded != bytes {
            decoded_from_other_bytes += 1;
        }
        assert_eq!(decode(&encoded).ok().as_ref(), Some(&tx), "{bytes:02x?}");
        if let Some(TransactionPayload::AssetLockPayloadType(AssetLockPayload {
            version: 1,
            ..
        })) = tx.special_transaction_payload
        {
            assert_eq!(
                deserialize::<Transaction>(&encoded).ok().as_ref(),
                Some(&tx),
                "{bytes:02x?}"
            );
        }
    }
    assert!(
        decoded_from_other_bytes > 1_000,
        "only {decoded_from_other_bytes} transactions decoded from bytes other than their encoding"
    );
}
