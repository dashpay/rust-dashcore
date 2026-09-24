//
// This file is a part of rust-dashcore.
// Portions written by Andrew Poelstra <apoelstra@wpsoftware.net> for rust-bitcoin.
// SPDX-License-Identifier: CC0-1.0
// See the accompanying file LICENSE or https://creativecommons.org/publicdomain/zero/1.0
//

//! Dash keys.

pub use dashcore_crypto::key::*;

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::Network::{Mainnet, Testnet};
    use crate::address::Address;
    use crate::crypto::key::{PrivateKey, PublicKey};
    use crate::io;

    #[test]
    fn test_key_derivation() {
        // testnet compressed
        let sk =
            PrivateKey::from_wif("cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy").unwrap();
        assert_eq!(sk.network, Testnet);
        assert!(sk.compressed);
        assert_eq!(&sk.to_wif(), "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy");

        let pk = Address::p2pkh(&sk.public_key(), sk.network);
        assert_eq!(&pk.to_string(), "yWkKX7a2WGr14hRyr4rC6NUC8n5F4dX3zr");

        // test string conversion
        assert_eq!(&sk.to_string(), "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy");
        let sk_str =
            PrivateKey::from_str("cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy").unwrap();
        assert_eq!(&sk.to_wif(), &sk_str.to_wif());

        // mainnet uncompressed
        let sk =
            PrivateKey::from_wif("7sU7MdjMtaLYxC4ec2z1zkhzZVBwRzZUcU6gJRzJ94s6UzAwA8c").unwrap();
        assert_eq!(sk.network, Mainnet);
        assert!(!sk.compressed);
        assert_eq!(&sk.to_wif(), "7sU7MdjMtaLYxC4ec2z1zkhzZVBwRzZUcU6gJRzJ94s6UzAwA8c");

        let mut pk = sk.public_key();
        assert!(!pk.compressed);
        assert_eq!(
            &pk.to_string(),
            "0470bb951360439d31352beb36017357ac9cf442c2ddbd511f3a5e5f394ecc173db7e18f6ad3ef9118d0fd1908f58973d0f51ae5e0e93cec8e7b7bc2b5941f176c"
        );
        assert_eq!(pk, PublicKey::from_str("0470bb951360439d31352beb36017357ac9cf442c2ddbd511f3a5e5f394ecc173db7e18f6ad3ef9118d0fd1908f58973d0f51ae5e0e93cec8e7b7bc2b5941f176c").unwrap());
        let addr = Address::p2pkh(&pk, sk.network);
        assert_eq!(&addr.to_string(), "XsaMtZkvTLdhAeQyyKoSUtRNf8eTrNAk44");
        pk.compressed = true;
        assert_eq!(
            &pk.to_string(),
            "0270bb951360439d31352beb36017357ac9cf442c2ddbd511f3a5e5f394ecc173d"
        );
        assert_eq!(
            pk,
            PublicKey::from_str(
                "0270bb951360439d31352beb36017357ac9cf442c2ddbd511f3a5e5f394ecc173d"
            )
            .unwrap()
        );
    }

    #[test]
    fn test_pubkey_hash() {
        let pk = PublicKey::from_str(
            "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af",
        )
        .unwrap();
        let upk = PublicKey::from_str("042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133").unwrap();
        assert_eq!(pk.pubkey_hash().to_string(), "9511aa27ef39bbfa4e4f3dd15f4d66ea57f475b4");
        assert_eq!(upk.pubkey_hash().to_string(), "ac2e7daf42d2c97418fd9f78af2de552bb9c6a7a");
    }

    #[test]
    fn test_wpubkey_hash() {
        let pk = PublicKey::from_str(
            "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af",
        )
        .unwrap();
        let upk = PublicKey::from_str("042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133").unwrap();
        assert_eq!(
            pk.wpubkey_hash().unwrap().to_string(),
            "9511aa27ef39bbfa4e4f3dd15f4d66ea57f475b4"
        );
        assert_eq!(upk.wpubkey_hash(), None);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_key_serde() {
        use serde_test::{Configure, Token, assert_tokens};

        static KEY_WIF: &str = "cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy";
        static PK_STR: &str = "039b6347398505f5ec93826dc61c19f47c66c0283ee9be980e29ce325a0f4679ef";
        static PK_STR_U: &str = "\
            04\
            9b6347398505f5ec93826dc61c19f47c66c0283ee9be980e29ce325a0f4679ef\
            87288ed73ce47fc4f5c79d19ebfa57da7cff3aff6e819e4ee971d86b5e61875d\
        ";
        #[rustfmt::skip]
        static PK_BYTES: [u8; 33] = [
            0x03,
            0x9b, 0x63, 0x47, 0x39, 0x85, 0x05, 0xf5, 0xec,
            0x93, 0x82, 0x6d, 0xc6, 0x1c, 0x19, 0xf4, 0x7c,
            0x66, 0xc0, 0x28, 0x3e, 0xe9, 0xbe, 0x98, 0x0e,
            0x29, 0xce, 0x32, 0x5a, 0x0f, 0x46, 0x79, 0xef,
        ];
        #[rustfmt::skip]
        static PK_BYTES_U: [u8; 65] = [
            0x04,
            0x9b, 0x63, 0x47, 0x39, 0x85, 0x05, 0xf5, 0xec,
            0x93, 0x82, 0x6d, 0xc6, 0x1c, 0x19, 0xf4, 0x7c,
            0x66, 0xc0, 0x28, 0x3e, 0xe9, 0xbe, 0x98, 0x0e,
            0x29, 0xce, 0x32, 0x5a, 0x0f, 0x46, 0x79, 0xef,
            0x87, 0x28, 0x8e, 0xd7, 0x3c, 0xe4, 0x7f, 0xc4,
            0xf5, 0xc7, 0x9d, 0x19, 0xeb, 0xfa, 0x57, 0xda,
            0x7c, 0xff, 0x3a, 0xff, 0x6e, 0x81, 0x9e, 0x4e,
            0xe9, 0x71, 0xd8, 0x6b, 0x5e, 0x61, 0x87, 0x5d,
        ];

        let sk = PrivateKey::from_str(KEY_WIF).unwrap();
        let pk = PublicKey::from_private_key(&sk);
        let pk_u = PublicKey {
            inner: pk.inner,
            compressed: false,
        };

        assert_tokens(&sk, &[Token::BorrowedStr(KEY_WIF)]);
        assert_tokens(&pk.compact(), &[Token::BorrowedBytes(&PK_BYTES[..])]);
        assert_tokens(&pk.readable(), &[Token::BorrowedStr(PK_STR)]);
        assert_tokens(&pk_u.compact(), &[Token::BorrowedBytes(&PK_BYTES_U[..])]);
        assert_tokens(&pk_u.readable(), &[Token::BorrowedStr(PK_STR_U)]);
    }

    fn random_key(mut seed: u8) -> PublicKey {
        loop {
            let mut data = [0; 65];
            for byte in &mut data[..] {
                *byte = seed;
                // totally a rng
                seed = seed.wrapping_mul(41).wrapping_add(43);
            }
            if data[0] % 2 == 0 {
                data[0] = 4;
                if let Ok(key) = PublicKey::from_slice(&data[..]) {
                    return key;
                }
            } else {
                data[0] = 2 + (data[0] >> 7);
                if let Ok(key) = PublicKey::from_slice(&data[..33]) {
                    return key;
                }
            }
        }
    }

    #[test]
    fn pubkey_read_write() {
        const N_KEYS: usize = 20;
        let keys: Vec<_> = (0..N_KEYS).map(|i| random_key(i as u8)).collect();

        let mut v = vec![];
        for k in &keys {
            k.write_into(&mut v).expect("writing into vec");
        }

        let mut dec_keys = vec![];
        let mut cursor = io::Cursor::new(&v);
        for _ in 0..N_KEYS {
            dec_keys.push(PublicKey::read_from(&mut cursor).expect("reading from vec"));
        }

        assert_eq!(keys, dec_keys);

        // sanity checks
        assert!(PublicKey::read_from(&mut cursor).is_err());
        assert!(PublicKey::read_from(io::Cursor::new(&[])).is_err());
        assert!(PublicKey::read_from(io::Cursor::new(&[0; 33][..])).is_err());
        assert!(PublicKey::read_from(io::Cursor::new(&[2; 32][..])).is_err());
        assert!(PublicKey::read_from(io::Cursor::new(&[0; 65][..])).is_err());
        assert!(PublicKey::read_from(io::Cursor::new(&[4; 64][..])).is_err());
    }

    #[test]
    #[cfg(feature = "rand-std")]
    fn public_key_constructors() {
        use secp256k1::rand;

        let kp = Keypair::new(&mut rand::rng());

        let _ = PublicKey::new(kp);
        let _ = PublicKey::new_uncompressed(kp);
    }

    #[test]
    fn public_key_from_str_wrong_length() {
        // Sanity checks, we accept string length 130 digits.
        let s = "042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133";
        assert_eq!(s.len(), 130);
        assert!(PublicKey::from_str(s).is_ok());
        // And 66 digits.
        let s = "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af";
        assert_eq!(s.len(), 66);
        assert!(PublicKey::from_str(s).is_ok());

        let s = "aoeusthb";
        assert_eq!(s.len(), 8);
        let res = PublicKey::from_str(s);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), Error::InvalidHexLength(8));
    }
}
