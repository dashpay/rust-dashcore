// Rust Dash Library
// Written for Dash in 2022 by
//     The Dash Core Developers
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Dash Provider Update Service Special Transaction.
//!
//! The provider update service special transaction is used to update the operator controlled
//! options for a masternode.
//!
//! It is defined in DIP3 [dip-0003](https://github.com/dashpay/dips/blob/master/dip-0003.md) as follows:
//!
//! To service update a masternode, the masternode operator must submit another special
//! transaction (DIP2) to the network. This special transaction is called a Provider Update
//! Service Transaction and is abbreviated as ProUpServTx. It can only be done by the operator.
//!
//! An operator can update the IP address and port fields of a masternode entry. If a non-zero
//! operatorReward was set in the initial ProRegTx, the operator may also set the
//! scriptOperatorPayout field in the ProUpServTx. If scriptOperatorPayout is not set and
//! operatorReward is non-zero, the owner gets the full masternode reward.
//!
//! A ProUpServTx is only valid for masternodes in the registered masternodes subset. When
//! processed, it updates the metadata of the masternode entry and revives the masternode if it was
//! previously marked as PoSe-banned.
//!
//! The special transaction type used for ProUpServTx Transactions is 2.

#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};
use hashes::Hash;

use crate::blockdata::transaction::special_transaction::SpecialTransactionBasePayloadEncodable;
use crate::blockdata::transaction::special_transaction::provider_registration::ProviderMasternodeType;
use crate::bls_sig_utils::BLSSignature;
use crate::consensus::{Decodable, Encodable, encode};
use crate::hash_types::{InputsHash, SpecialTransactionPayloadHash, Txid};
use crate::{ScriptBuf, VarInt, io};

/// ProTx version constants
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ProTxVersion {
    LegacyBLS = 1,
    BasicBLS = 2,
}

/// A Provider Update Service Payload used in a Provider Update Service Special Transaction.
/// This is used to update the operational aspects a Masternode on the network.
/// It must be signed by the operator's key that was set either at registration or by the last
/// registrar update of the masternode.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ProviderUpdateServicePayload {
    pub version: u16,
    pub mn_type: Option<u16>, // Only present for BasicBLS version (2)
    pub pro_tx_hash: Txid,
    pub ip_address: u128,
    pub port: u16,
    pub script_payout: ScriptBuf,
    pub inputs_hash: InputsHash,
    // Platform fields (only for BasicBLS version and Evo masternode type)
    pub platform_node_id: Option<[u8; 20]>,
    pub platform_p2p_port: Option<u16>,
    pub platform_http_port: Option<u16>,
    pub payload_sig: BLSSignature,
}

impl ProviderUpdateServicePayload {
    /// The size of the payload in bytes.
    pub fn size(&self) -> usize {
        let mut size = 2 + 32 + 16 + 2 + 32 + 96; // 180
        size += VarInt(self.script_payout.len() as u64).len() + self.script_payout.len();
        size
    }
}

impl SpecialTransactionBasePayloadEncodable for ProviderUpdateServicePayload {
    fn base_payload_data_encode<S: io::Write>(&self, mut s: S) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.version.consensus_encode(&mut s)?;
        len += self.pro_tx_hash.consensus_encode(&mut s)?;
        len += self.ip_address.consensus_encode(&mut s)?;
        len += u16::swap_bytes(self.port).consensus_encode(&mut s)?;
        len += self.script_payout.consensus_encode(&mut s)?;
        len += self.inputs_hash.consensus_encode(&mut s)?;
        Ok(len)
    }

    fn base_payload_hash(&self) -> SpecialTransactionPayloadHash {
        let mut engine = SpecialTransactionPayloadHash::engine();
        self.base_payload_data_encode(&mut engine).expect("engines don't error");
        SpecialTransactionPayloadHash::from_engine(engine)
    }
}

impl Encodable for ProviderUpdateServicePayload {
    fn consensus_encode<W: io::Write + ?Sized>(&self, mut w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.base_payload_data_encode(&mut w)?;
        len += self.payload_sig.consensus_encode(&mut w)?;
        Ok(len)
    }
}

impl Decodable for ProviderUpdateServicePayload {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let version = u16::consensus_decode(r)?;

        // Version validation like C++ SERIALIZE_METHODS
        if version == 0 || version > ProTxVersion::BasicBLS as u16 {
            return Err(encode::Error::ParseFailed("unsupported ProUpServTx version"));
        }

        // Read nType for BasicBLS version
        let mn_type = if version == ProTxVersion::BasicBLS as u16 {
            Some(u16::consensus_decode(r)?)
        } else {
            None
        };

        // Read core fields
        let pro_tx_hash = Txid::consensus_decode(r)?;
        let ip_address = u128::consensus_decode(r)?;
        let port = u16::swap_bytes(u16::consensus_decode(r)?);
        let script_payout = ScriptBuf::consensus_decode(r)?;
        let inputs_hash = InputsHash::consensus_decode(r)?;

        // Read Evo platform fields if needed
        let (platform_node_id, platform_p2p_port, platform_http_port) = if version
            == ProTxVersion::BasicBLS as u16
            && mn_type == Some(ProviderMasternodeType::HighPerformance as u16)
        {
            let node_id = {
                let mut buf = [0u8; 20];
                r.read_exact(&mut buf)?;
                buf
            };
            let p2p_port = u16::consensus_decode(r)?;
            let http_port = u16::consensus_decode(r)?;
            (Some(node_id), Some(p2p_port), Some(http_port))
        } else {
            (None, None, None)
        };

        // Read BLS signature (assuming not SER_GETHASH context)
        let payload_sig = BLSSignature::consensus_decode(r)?;

        Ok(ProviderUpdateServicePayload {
            version,
            mn_type,
            pro_tx_hash,
            ip_address,
            port,
            script_payout,
            inputs_hash,
            platform_node_id,
            platform_p2p_port,
            platform_http_port,
            payload_sig,
        })
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;
    use std::net::Ipv4Addr;

    use hashes::Hash;

    use crate::blockdata::transaction::special_transaction::SpecialTransactionBasePayloadEncodable;
    use crate::blockdata::transaction::special_transaction::TransactionPayload::ProviderUpdateServicePayloadType;
    use crate::blockdata::transaction::special_transaction::provider_update_service::ProviderUpdateServicePayload;
    use crate::bls_sig_utils::BLSSignature;
    use crate::consensus::{Decodable, Encodable, deserialize};
    use crate::hash_types::InputsHash;
    use crate::internal_macros::hex;
    use crate::{Network, ScriptBuf, Transaction, Txid};

    #[test]
    fn test_provider_update_service_transaction() {
        // This is a test for testnet
        let _network = Network::Testnet;

        let expected_transaction_bytes = hex!(
            "03000200018f3fe6683e36326669b6e34876fb2a2264e8327e822f6fec304b66f47d61b3e1010000006b48304502210082af6727408f0f2ec16c7da1c42ccf0a026abea6a3a422776272b03c8f4e262a022033b406e556f6de980b2d728e6812b3ae18ee1c863ae573ece1cbdf777ca3e56101210351036c1192eaf763cd8345b44137482ad24b12003f23e9022ce46752edf47e6effffffff0180220e43000000001976a914123cbc06289e768ca7d743c8174b1e6eeb610f1488ac00000000b501003a72099db84b1c1158568eec863bea1b64f90eccee3304209cebe1df5e7539fd00000000000000000000ffff342440944e1f00e6725f799ea20480f06fb105ebe27e7c4845ab84155e4c2adf2d6e5b73a998b1174f9621bbeda5009c5a6487bdf75edcf602b67fe0da15c275cc91777cb25f5fd4bb94e84fd42cb2bb547c83792e57c80d196acd47020e4054895a0640b7861b3729c41dd681d4996090d5750f65c4b649a5cd5b2bdf55c880459821e53d91c9"
        );

        let expected_transaction: Transaction =
            deserialize(expected_transaction_bytes.as_slice()).expect("expected a transaction");

        let expected_provider_update_service_payload = expected_transaction
            .special_transaction_payload
            .clone()
            .unwrap()
            .to_update_service_payload()
            .expect("expected to get a provider registration payload");

        let tx_id =
            Txid::from_str("fa2f2eba320c56fb0efebe2ace3333024104d8d0a30753da36db4bf97c119be7")
                .expect("expected to decode tx id");

        let provider_update_service_payload_version = 1;
        assert_eq!(
            expected_provider_update_service_payload.version,
            provider_update_service_payload_version
        );
        let pro_tx_hash =
            Txid::from_str("fd39755edfe1eb9c200433eecc0ef9641bea3b86ec8e5658111c4bb89d09723a")
                .expect("expected to decode tx id");
        assert_eq!(expected_provider_update_service_payload.pro_tx_hash, pro_tx_hash);

        let address = Ipv4Addr::from_str("52.36.64.148").expect("expected an ipv4 address");
        let [a, b, c, d] = address.octets();
        let ipv6_bytes: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, a, b, c, d];
        assert_eq!(expected_provider_update_service_payload.ip_address.to_le_bytes(), ipv6_bytes);

        let port = 19999;
        assert_eq!(expected_provider_update_service_payload.port, port);

        let inputs_hash_hex = "b198a9735b6e2ddf2a4c5e1584ab45487c7ee2eb05b16ff08004a29e795f72e6";
        assert_eq!(
            expected_provider_update_service_payload.inputs_hash.to_hex().as_str(),
            inputs_hash_hex,
            "inputs hash calculation has issues"
        );

        assert_eq!(
            expected_provider_update_service_payload.base_payload_hash().to_hex().as_str(),
            "9784b3663039784858420677b00f0b3f34af8ff1f1788adfd0e681d345b776ba",
            "Payload hash calculation has issues"
        );

        // We should verify the script payouts match
        let script_payout = ScriptBuf::new();
        assert_eq!(expected_provider_update_service_payload.script_payout, script_payout);

        assert_eq!(expected_transaction.txid(), tx_id);

        //todo: once we have a BLS signatures library in rust we should implement signing
        let payload_sig = expected_transaction
            .special_transaction_payload
            .clone()
            .unwrap()
            .to_update_service_payload()
            .unwrap()
            .payload_sig;

        let transaction = Transaction {
            version: 3,
            lock_time: 0,
            input: expected_transaction.input.clone(), // todo:implement this
            output: expected_transaction.output.clone(), // todo:implement this
            special_transaction_payload: Some(ProviderUpdateServicePayloadType(
                ProviderUpdateServicePayload {
                    version: provider_update_service_payload_version,
                    mn_type: None, // LegacyBLS version
                    pro_tx_hash,
                    ip_address: u128::from_le_bytes(ipv6_bytes),
                    port,
                    script_payout,
                    inputs_hash: InputsHash::from_str(inputs_hash_hex).unwrap(),
                    platform_node_id: None,
                    platform_p2p_port: None,
                    platform_http_port: None,
                    payload_sig,
                },
            )),
        };

        assert_eq!(transaction.hash_inputs().to_hex(), inputs_hash_hex);

        assert_eq!(transaction, expected_transaction);

        assert_eq!(transaction.txid(), tx_id);
    }

    #[test]
    fn size() {
        let want = 191;
        let payload = ProviderUpdateServicePayload {
            version: 0,
            mn_type: None,
            pro_tx_hash: Txid::all_zeros(),
            ip_address: 0,
            port: 0,
            script_payout: ScriptBuf::from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0]),
            inputs_hash: InputsHash::all_zeros(),
            platform_node_id: None,
            platform_p2p_port: None,
            platform_http_port: None,
            payload_sig: BLSSignature::from([0; 96]),
        };
        let actual = payload.consensus_encode(&mut Vec::new()).unwrap();
        assert_eq!(payload.size(), want);
        assert_eq!(actual, want);
    }

    #[test]
    fn test_protx_update_v2_block_parsing() {
        use crate::blockdata::block::Block;
        use crate::blockdata::transaction::special_transaction::TransactionType;
        use crate::consensus::deserialize;
        use std::fs;
        use std::path::Path;

        // Load block data containing ProTx Update Service v2 transactions (BasicBLS version)
        let block_data_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("dash/contrib/protx_update_v2_block.data");

        println!("🔍 Testing ProTx Update Service v2 (BasicBLS) block parsing");

        let block_hex_string = match fs::read_to_string(&block_data_path) {
            Ok(content) => content.trim().to_string(),
            Err(_e) => {
                println!("⚠️  Skipping test - protx_update_v2_block.data not found");
                return; // Skip test if file not found
            }
        };

        // Decode hex to bytes
        let block_bytes = match hex::decode(&block_hex_string) {
            Ok(bytes) => bytes,
            Err(e) => {
                panic!("❌ Failed to decode hex: {}", e);
            }
        };

        // Try to compute block hash from header first
        let expected_block_hash = if block_bytes.len() >= 80 {
            match crate::blockdata::block::Header::consensus_decode(&mut std::io::Cursor::new(
                &block_bytes[0..80],
            )) {
                Ok(header) => {
                    let hash = header.block_hash();
                    println!("🔗 Block hash: {}", hash);
                    Some(hash)
                }
                Err(e) => {
                    panic!("❌ Failed to decode block header: {}", e);
                }
            }
        } else {
            panic!("❌ Block data too short");
        };

        // Now try to deserialize the full block - this should succeed with our ProTx fix
        match deserialize::<Block>(&block_bytes) {
            Ok(block) => {
                let actual_hash = block.block_hash();
                println!("✅ Successfully deserialized block with ProTx transactions!");
                println!("  Block hash: {}", actual_hash);
                println!("  Transaction count: {}", block.txdata.len());

                // Verify block hash matches
                if let Some(expected_hash) = expected_block_hash {
                    assert_eq!(expected_hash, actual_hash, "Block hash mismatch");
                }

                // Analyze transactions for ProUpServTx (Type 2) transactions
                let mut found_protx = false;
                for (i, tx) in block.txdata.iter().enumerate() {
                    let tx_type = tx.tx_type();
                    if tx_type == TransactionType::ProviderUpdateService {
                        println!("  🎯 Found ProUpServTx (Type 2) at index {}", i);
                        found_protx = true;

                        // Test that we can parse the payload
                        if let Some(payload) = &tx.special_transaction_payload {
                            match payload.clone().to_update_service_payload() {
                                Ok(protx_payload) => {
                                    println!("    ✅ Successfully parsed ProUpServTx payload:");
                                    println!("       Version: {}", protx_payload.version);
                                    println!("       ProTxHash: {}", protx_payload.pro_tx_hash);
                                    println!("       Port: {}", protx_payload.port);
                                    println!(
                                        "       Script length: {}",
                                        protx_payload.script_payout.len()
                                    );
                                    println!(
                                        "       Has nType: {}",
                                        protx_payload.mn_type.is_some()
                                    );
                                    println!(
                                        "       Has platform fields: {}",
                                        protx_payload.platform_node_id.is_some()
                                    );
                                }
                                Err(e) => {
                                    panic!("❌ Failed to parse ProUpServTx payload: {}", e);
                                }
                            }
                        }
                    }
                }

                if !found_protx {
                    println!("⚠️  No ProUpServTx transactions found in this block");
                }

                println!("🎉 ProTx block parsing test passed!");
            }
            Err(e) => {
                panic!("❌ Block parsing failed even with ProTx fix: {}", e);
            }
        }
    }

    #[test]
    fn test_protx_block_parsing_with_pro_reg_tx() {
        use crate::blockdata::block::Block;
        use crate::blockdata::transaction::special_transaction::TransactionType;
        use crate::consensus::deserialize;
        use std::fs;
        use std::path::Path;

        // Test block with Provider Registration transactions
        let block_data_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("dash/contrib/block_with_pro_reg_tx.data");

        println!("🔍 Testing ProTx block parsing with ProRegTx transactions");

        let block_hex_string = match fs::read_to_string(&block_data_path) {
            Ok(content) => content.trim().to_string(),
            Err(_e) => {
                println!("⚠️  Skipping test - block_with_pro_reg_tx.data not found");
                return; // Skip test if file not found
            }
        };

        let block_bytes = match hex::decode(&block_hex_string) {
            Ok(bytes) => bytes,
            Err(e) => {
                panic!("❌ Failed to decode hex: {}", e);
            }
        };

        let expected_hash = "000000000000002016c49d804e7b5d6ca84663ed032222e9061b2efec302edc3";

        // Verify block hash from header
        if block_bytes.len() >= 80 {
            match crate::blockdata::block::Header::consensus_decode(&mut std::io::Cursor::new(
                &block_bytes[0..80],
            )) {
                Ok(header) => {
                    let hash = header.block_hash();
                    assert_eq!(hash.to_string(), expected_hash, "Wrong block - hash mismatch");
                    println!("🔗 Confirmed correct block hash: {}", expected_hash);
                }
                Err(e) => {
                    panic!("❌ Failed to decode block header: {}", e);
                }
            }
        }

        // Parse the full block
        match deserialize::<Block>(&block_bytes) {
            Ok(block) => {
                println!("✅ Successfully parsed block with ProRegTx transactions!");
                println!("  Transaction count: {}", block.txdata.len());

                // Look for Provider Registration transactions
                let mut found_pro_reg = false;
                for (i, tx) in block.txdata.iter().enumerate() {
                    let tx_type = tx.tx_type();
                    if tx_type == TransactionType::ProviderRegistration {
                        println!("  🎯 Found ProRegTx (Type 1) at index {}", i);
                        found_pro_reg = true;

                        // Test payload parsing
                        if let Some(payload) = &tx.special_transaction_payload {
                            match payload.clone().to_provider_registration_payload() {
                                Ok(pro_reg_payload) => {
                                    println!("    ✅ Successfully parsed ProRegTx payload:");
                                    println!("       Version: {}", pro_reg_payload.version);
                                    println!(
                                        "       Masternode type: {:?}",
                                        pro_reg_payload.masternode_type
                                    );
                                    println!(
                                        "       Service address: {}",
                                        pro_reg_payload.service_address
                                    );
                                    println!(
                                        "       Platform fields: node_id={:?}, p2p_port={:?}, http_port={:?}",
                                        pro_reg_payload.platform_node_id.is_some(),
                                        pro_reg_payload.platform_p2p_port,
                                        pro_reg_payload.platform_http_port
                                    );
                                }
                                Err(e) => {
                                    panic!("❌ Failed to parse ProRegTx payload: {}", e);
                                }
                            }
                        }
                    }
                }

                if !found_pro_reg {
                    println!("⚠️  No ProRegTx transactions found in this block");
                }

                println!("🎉 ProRegTx block parsing test passed!");
            }
            Err(e) => {
                panic!("❌ Block parsing failed: {}", e);
            }
        }
    }
}
