use dash_network::Network;
use hashes::{Hash, sha256};

use crate::{Address, PrivateKey, PublicKey};

impl crate::Address {
    pub fn dummy(network: Network, id: usize) -> Address {
        let mut data = "dash-spv-test-seed".as_bytes().to_vec();
        data.extend_from_slice(&id.to_le_bytes());

        let secret_bytes = sha256::Hash::hash(&data).to_byte_array();
        let secret_key = secp256k1::SecretKey::from_byte_array(&secret_bytes)
            .unwrap_or_else(|e| panic!("Dummy address generation failed for id {id}: {e}"));

        let private_key = PrivateKey::new(secret_key, network);
        let public_key = PublicKey::from_private_key(&secp256k1::Secp256k1::new(), &private_key);

        // Create P2PKH address from PublicKey
        Address::p2pkh(&public_key, network)
    }
}
