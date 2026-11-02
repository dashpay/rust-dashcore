use dashcore::consensus::encode::VarInt;
use honggfuzz::fuzz;

fn do_test(data: &[u8]) {
    // We already fuzz Transactions in `./deserialize_transaction.rs`.
    let tx_result: Result<dashcore::bip152::PrefilledTransaction, _> =
        dashcore::consensus::encode::deserialize(data);

    match tx_result {
        Err(_) => {}
        Ok(tx) => {
            let ser = dashcore::consensus::encode::serialize(&tx);
            // Core sign-extends a negative version over the type, which re-encodes as `ffff`.
            let mut expected = data.to_vec();
            let version_at = VarInt(tx.idx as u64).len();
            if expected[version_at + 1] & 0x80 != 0 {
                expected[version_at + 2..version_at + 4].copy_from_slice(&[0xff, 0xff]);
            }
            assert_eq!(ser, expected);
        }
    }
}

fn main() {
    loop {
        fuzz!(|data| {
            do_test(data);
        });
    }
}

#[cfg(all(test, fuzzing))]
mod tests {
    fn extend_vec_from_hex(hex: &str, out: &mut Vec<u8>) {
        let mut b = 0;
        for (idx, c) in hex.as_bytes().iter().enumerate() {
            b <<= 4;
            match *c {
                b'A'..=b'F' => b |= c - b'A' + 10,
                b'a'..=b'f' => b |= c - b'a' + 10,
                b'0'..=b'9' => b |= c - b'0',
                _ => panic!("Bad hex"),
            }
            if (idx & 1) == 1 {
                out.push(b);
                b = 0;
            }
        }
    }

    #[test]
    fn duplicate_crash() {
        let mut a = Vec::new();
        extend_vec_from_hex("00000000", &mut a);
        super::do_test(&a);
    }
}
