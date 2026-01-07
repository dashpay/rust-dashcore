use dash_network::Network;
use hashes::{Hash, sha256};

use crate::{
    Address, PrivateKey, PublicKey,
    address::{NetworkChecked, NetworkUnchecked},
};

impl crate::Address {
    pub fn dummy_for_testnet() -> Address<NetworkChecked> {
        "yP8A3cbdxRtLRduy5mXDsBnJtMzHWs6ZXr"
            .parse::<Address<NetworkUnchecked>>()
            .expect("valid address")
            .assume_checked()
    }

    const TEST_PUBKEY_BYTES: [u8; 33] = [
        0x02, 0x50, 0x86, 0x3a, 0xd6, 0x4a, 0x87, 0xae, 0x8a, 0x2f, 0xe8, 0x3c, 0x1a, 0xf1, 0xa8,
        0x40, 0x3c, 0xb5, 0x3f, 0x53, 0xe4, 0x86, 0xd8, 0x51, 0x1d, 0xad, 0x8a, 0x04, 0x88, 0x7e,
        0x5b, 0x23, 0x52,
    ];

    pub fn test_address() -> Address {
        Address::p2pkh(&PublicKey::from_slice(&Self::TEST_PUBKEY_BYTES).unwrap(), Network::Testnet)
    }

    pub fn dummy(network: Network, id: usize) -> Address {
        let mut data = "dash-spv-test-seed".as_bytes().to_vec();
        data.extend_from_slice(&id.to_le_bytes());

        let secret_bytes = sha256::Hash::hash(&data).to_byte_array();
        let secret_key = secp256k1::SecretKey::from_byte_array(&secret_bytes)
            .expect(&format!("Dummy address generation failed for id {id}"));

        let private_key = PrivateKey::new(secret_key, network);
        let public_key = PublicKey::from_private_key(&secp256k1::Secp256k1::new(), &private_key);

        // Create P2PKH address from PublicKey
        Address::p2pkh(&public_key, network)
    }
}
