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

//! Dash Provider Registration Special Transaction.
//!
//! The provider registration special transaction is used to register a masternode.
//! It is defined in DIP3 [dip-0003](https://github.com/dashpay/dips/blob/master/dip-0003.md).
//!
//! The ProRegTx contains 2 public key IDs and one BLS public key, which represent 3 different
//! roles in the masternode and define update and voting rights. A "public key ID" refers to the
//! hash160 of an ECDSA public key. The keys are:
//!
//! KeyIdOwner (renamed to owner_key_hash): This is the public key ID of the masternode or
//! collateral owner. It is different than the key used in the collateral output. Only the owner
//! is allowed to issue ProUpRegTx transactions.
//!
//! PubKeyOperator (renamed to operator_public_key): This is the BLS public key of the masternode
//! operator. Only the operator is allowed to issue ProUpServTx transactions. The operator key is
//! also used while operating the masternode to sign masternode related P2P messages, quorum
//! related messages and governance trigger votes. Messages signed with this key are only valid
//! while the masternode is in the valid set.
//!
//! KeyIdVoting (renamed to voting_key_hash): This is the public key ID used for proposal voting.
//! Votes signed with this key are valid while the masternode is in the registered set.

use std::net::SocketAddr;

#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};
use hashes::Hash;
use internals::hex::Case::Lower;

use crate::address::Payload;
use crate::blockdata::transaction::special_transaction::SpecialTransactionBasePayloadEncodable;
use crate::bls_sig_utils::BLSPublicKey;
use crate::consensus::{Decodable, Encodable, encode};
use crate::hash_types::{InputsHash, PubkeyHash, SpecialTransactionPayloadHash};
use crate::prelude::*;
use crate::{Address, Network, OutPoint, ScriptBuf, VarInt, io};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Copy)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ProviderMasternodeType {
    Regular = 0,
    HighPerformance = 1,
}

impl Encodable for ProviderMasternodeType {
    fn consensus_encode<W: io::Write + ?Sized>(&self, mut w: &mut W) -> Result<usize, io::Error> {
        let variant = self;
        let len = (*variant as u16).consensus_encode(&mut w)?;
        Ok(len)
    }
}

impl Decodable for ProviderMasternodeType {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let variant = u16::consensus_decode(r)?;
        match variant {
            0 => Ok(ProviderMasternodeType::Regular),
            1 => Ok(ProviderMasternodeType::HighPerformance),
            received => Err(encode::Error::InvalidEnumValue {
                max: 1,
                received,
                msg: "Invalid MasternodeType variant".to_string(),
            }),
        }
    }
}

/// A Provider Registration Payload used in a Provider Registration Special Transaction.
/// This is used to register a Masternode on the network.
/// The current version is 0.
/// Interesting Fields:
/// *Provider type refers to the type of Masternode. Currently only valid value is 0.
/// *Provider mode refers to the mode of the Masternode. Currently only valid value is 0.
/// *The collateral outpoint links to a transaction with a 1000 Dash unspent (at registration)
/// outpoint.
/// *The operator reward defines the ratio when divided by 10000 of the amount going to the operator.
/// The max value for the operator reward is 10000.
/// *The script payout is the script to which one wants to have the masternode pay out.
/// *The inputs hash is used to guarantee the uniqueness of the payload sig.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ProviderRegistrationPayload {
    pub version: u16,
    pub masternode_type: ProviderMasternodeType,
    pub masternode_mode: u16,
    pub collateral_outpoint: OutPoint,
    pub service_address: SocketAddr,
    pub owner_key_hash: PubkeyHash,
    pub operator_public_key: BLSPublicKey,
    pub voting_key_hash: PubkeyHash,
    pub operator_reward: u16,
    pub script_payout: ScriptBuf,
    pub inputs_hash: InputsHash,
    pub signature: Vec<u8>,
    pub platform_node_id: Option<PubkeyHash>,
    pub platform_p2p_port: Option<u16>,
    pub platform_http_port: Option<u16>,
}

impl ProviderRegistrationPayload {
    /// A convenience method to get the address from payout script
    pub fn payout_address(&self, network: Network) -> Result<Address, encode::Error> {
        match Address::from_script(&self.script_payout, network) {
            Ok(addr) => Ok(addr),
            Err(_) => Err(encode::Error::NonStandardScriptPayout(self.script_payout.clone())),
        }
    }
    /// A convenience method to get the address from the owner key hash
    pub fn owner_address(&self, network: Network) -> Address {
        Address::new(network, Payload::PubkeyHash(self.owner_key_hash))
    }
    /// A convenience method to get the address from the voting key hash
    pub fn voting_address(&self, network: Network) -> Address {
        Address::new(network, Payload::PubkeyHash(self.voting_key_hash))
    }
    /// This is used to prove access to the collateral. The collateral private key signs
    /// a string of formatted values proving access to the 1000 Dash and therefore the ability
    /// to register the masternode.
    pub fn payload_collateral_string(&self, network: Network) -> Result<String, encode::Error> {
        let base_payload_hash = self.base_payload_hash();
        let mut base_payload_hash = *base_payload_hash.as_raw_hash().as_byte_array();
        base_payload_hash.reverse();
        let base_payload_hash =
            SpecialTransactionPayloadHash::from_slice(base_payload_hash.as_slice()).unwrap();
        Ok(format!(
            "{}|{}|{}|{}|{}",
            self.payout_address(network)?,
            self.operator_reward,
            self.owner_address(network),
            self.voting_address(network),
            base_payload_hash.as_byte_array().to_hex_string(Lower)
        ))
    }

    /// The size of the payload in bytes.
    /// version(2) + provider_type(2) + provider_mode(2) + collateral_outpoint(32 + 4) + ip_address(16) +
    /// port(2) + owner_key_hash(20) + operator_public_key(48) + voting_key_hash(20) + operator_reward(2) +
    /// script_payout(VarInt(script_payout_len).len() + script_payout_len) +
    /// inputs_hash(32) +
    /// payload_sig(VarInt(payload_sig_len).len() + payload_sig_len)
    pub fn size(&self) -> usize {
        let mut size = 2 + 2 + 2 + 32 + 4 + 16 + 2 + 20 + 48 + 20 + 2 + 32; // 182 bytes
        let script_payout_len = self.script_payout.0.len();
        let signature_len = self.signature.len();
        size += VarInt(script_payout_len as u64).len() + script_payout_len;
        size += VarInt(signature_len as u64).len() + signature_len;
        size
    }
}

impl SpecialTransactionBasePayloadEncodable for ProviderRegistrationPayload {
    fn base_payload_data_encode<W: io::Write>(&self, mut s: W) -> Result<usize, io::Error> {
        let mut len = 0;

        len += self.version.consensus_encode(&mut s)?;
        len += self.masternode_type.consensus_encode(&mut s)?;
        len += self.masternode_mode.consensus_encode(&mut s)?;
        len += self.collateral_outpoint.consensus_encode(&mut s)?;
        len += self.service_address.consensus_encode(&mut s)?;
        len += self.owner_key_hash.consensus_encode(&mut s)?;
        len += self.operator_public_key.consensus_encode(&mut s)?;
        len += self.voting_key_hash.consensus_encode(&mut s)?;
        len += self.operator_reward.consensus_encode(&mut s)?;
        len += self.script_payout.consensus_encode(&mut s)?;
        len += self.inputs_hash.consensus_encode(&mut s)?;

        if self.version >= 2 && self.masternode_type == ProviderMasternodeType::HighPerformance {
            len += self
                .platform_node_id
                .unwrap_or_else(PubkeyHash::all_zeros)
                .consensus_encode(&mut s)?;
            len += self.platform_p2p_port.unwrap_or_default().consensus_encode(&mut s)?;
            len += self.platform_http_port.unwrap_or_default().consensus_encode(&mut s)?;
        }

        Ok(len)
    }

    fn base_payload_hash(&self) -> SpecialTransactionPayloadHash {
        let mut engine = SpecialTransactionPayloadHash::engine();
        self.base_payload_data_encode(&mut engine).expect("engines don't error");
        SpecialTransactionPayloadHash::from_engine(engine)
    }
}

impl Encodable for ProviderRegistrationPayload {
    fn consensus_encode<W: io::Write + ?Sized>(&self, mut w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.base_payload_data_encode(&mut w)?;
        len += self.signature.consensus_encode(&mut w)?;
        Ok(len)
    }
}

impl Decodable for ProviderRegistrationPayload {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let version = u16::consensus_decode(r)?;
        let provider_type = ProviderMasternodeType::consensus_decode(r)?;
        let provider_mode = u16::consensus_decode(r)?;
        let collateral_outpoint = OutPoint::consensus_decode(r)?;
        let service_address = SocketAddr::consensus_decode(r)?;
        let owner_key_hash = PubkeyHash::consensus_decode(r)?;
        let operator_public_key = BLSPublicKey::consensus_decode(r)?;
        let voting_key_hash = PubkeyHash::consensus_decode(r)?;
        let operator_reward = u16::consensus_decode(r)?;
        let script_payout = ScriptBuf::consensus_decode(r)?;
        let inputs_hash = InputsHash::consensus_decode(r)?;

        let mut platform_node_id = None;
        let mut platform_p2p_port = None;
        let mut platform_http_port = None;

        if version >= 2 && provider_type == ProviderMasternodeType::HighPerformance {
            platform_node_id = Some(PubkeyHash::consensus_decode(r)?);
            platform_p2p_port = Some(u16::consensus_decode(r)?);
            platform_http_port = Some(u16::consensus_decode(r)?);
        }

        let payload_sig = Vec::<u8>::consensus_decode(r)?;

        Ok(ProviderRegistrationPayload {
            version,
            masternode_type: provider_type,
            masternode_mode: provider_mode,
            collateral_outpoint,
            service_address,
            owner_key_hash,
            operator_public_key,
            voting_key_hash,
            operator_reward,
            script_payout,
            inputs_hash,
            signature: payload_sig,
            platform_node_id,
            platform_p2p_port,
            platform_http_port,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    use hashes::Hash;

    use crate::bls_sig_utils::BLSPublicKey;
    use crate::consensus::{Encodable, deserialize};
    use crate::hash_types::InputsHash;
    use crate::hashes::hex::FromHex;
    use crate::internal_macros::hex;
    use crate::transaction::special_transaction::provider_registration::{
        ProviderMasternodeType, ProviderRegistrationPayload,
    };
    use crate::{OutPoint, PubkeyHash, ScriptBuf, Txid};

    use std::net::IpAddr;

    use crate::Network;
    use crate::PrivateKey;
    use crate::Transaction;
    use crate::TxIn;
    use crate::TxOut;
    use crate::sign_message::signed_msg_hash;
    use crate::signer::sign_hash;
    use crate::transaction::TransactionPayload::ProviderRegistrationPayloadType;
    use crate::transaction::special_transaction::SpecialTransactionBasePayloadEncodable;
    use std::str::FromStr;

    #[test]
    fn test_collateral_provider_registration_transaction() {
        // This is a test for testnet
        let network = Network::Testnet;

        let expected_transaction_bytes = hex!(
            "0300010001ca9a43051750da7c5f858008f2ff7732d15691e48eb7f845c791e5dca78bab58010000006b483045022100fe8fec0b3880bcac29614348887769b0b589908e3f5ec55a6cf478a6652e736502202f30430806a6690524e4dd599ba498e5ff100dea6a872ebb89c2fd651caa71ed012103d85b25d6886f0b3b8ce1eef63b720b518fad0b8e103eba4e85b6980bfdda2dfdffffffff018e37807e090000001976a9144ee1d4e5d61ac40a13b357ac6e368997079678c888ac00000000fd1201010000000000ca9a43051750da7c5f858008f2ff7732d15691e48eb7f845c791e5dca78bab580000000000000000000000000000ffff010205064e1f3dd03f9ec192b5f275a433bfc90f468ee1a3eb4c157b10706659e25eb362b5d902d809f9160b1688e201ee6e94b40f9b5062d7074683ef05a2d5efb7793c47059c878dfad38a30fafe61575db40f05ab0a08d55119b0aad300001976a9144fbc8fb6e11e253d77e5a9c987418e89cf4a63d288ac3477990b757387cb0406168c2720acf55f83603736a314a37d01b135b873a27b411fb37e49c1ff2b8057713939a5513e6e711a71cff2e517e6224df724ed750aef1b7f9ad9ec612b4a7250232e1e400da718a9501e1d9a5565526e4b1ff68c028763"
        );

        let expected_transaction: Transaction =
            deserialize(expected_transaction_bytes.as_slice()).expect("expected a transaction");

        let expected_provider_registration_payload = expected_transaction
            .special_transaction_payload
            .clone()
            .unwrap()
            .to_provider_registration_payload()
            .expect("expected to get a provider registration payload");
        //    protx register_prepare
        //    58ab8ba7dce591c745f8b78ee49156d13277fff20880855f7cda501705439aca
        //    0
        //    1.2.5.6:19999
        //    yRxHYGLf9G4UVYdtAoB2iAzR3sxxVaZB6y
        //    97762493aef0bcba1925870abf51dc21f4bc2b8c410c79b7589590e6869a0e04
        //    yfbxyP4ctRJR1rs3A8C3PdXA4Wtcrw7zTi
        //    0
        //    ycBFJGv7V95aSs6XvMewFyp1AMngeRHBwy

        let tx_id =
            Txid::from_hex("e65f550356250100513aa9c260400562ac8ee1b93ae1cc1214cc9f6830227b51")
                .expect("expected to decode tx id");
        let output_address0 = Address::from_str("yTWY6DsS4HBGs2JwDtnvVcpykLkbvtjUte")
            .expect("expected to be able to get output address");
        let collateral_address = Address::from_str("yeNVS6tFeQNXJVkjv6nm6gb7PtTERV5dGh")
            .expect("expected to be able to get collateral address");
        let collateral_private_key =
            PrivateKey::from_wif("cTVm7EkgzNBPcwAKGYHfvyK8cyrRAC8n3SUUw8qjLqCg2rpcczfo")
                .expect("expected valid base 58");
        let collateral_hash =
            Txid::from_hex("58ab8ba7dce591c745f8b78ee49156d13277fff20880855f7cda501705439aca")
                .expect("expected to decode collateral hash");
        let collateral_index = 0;
        let payout_address = Address::from_str("yTb47qEBpNmgXvYYsHEN4nh8yJwa5iC4Cs")
            .expect("expected a valid address");

        let payload_collateral_string = expected_provider_registration_payload
            .payload_collateral_string(network)
            .expect("expected to produce a payload collateral string");
        let message_digest = signed_msg_hash(payload_collateral_string.as_str());

        let provider_registration_payload_version = 1;
        assert_eq!(
            expected_provider_registration_payload.version,
            provider_registration_payload_version
        );
        let provider_type = ProviderMasternodeType::Regular;
        assert_eq!(expected_provider_registration_payload.masternode_type, provider_type);
        let provider_mode = 0;
        assert_eq!(expected_provider_registration_payload.masternode_mode, provider_mode);

        let collateral_outpoint = OutPoint {
            txid: collateral_hash,
            vout: collateral_index,
        };
        assert_eq!(expected_provider_registration_payload.collateral_outpoint, collateral_outpoint);

        let address = Ipv4Addr::from_str("1.2.5.6").expect("expected an ipv4 address");
        let [a, b, c, d] = address.octets();
        let ipv6_bytes: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, a, b, c, d];

        let expected_ip_octets = match expected_provider_registration_payload.service_address.ip() {
            IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
            IpAddr::V6(v6) => v6.octets(),
        };

        assert_eq!(ipv6_bytes, address.to_ipv6_mapped().octets());
        assert_eq!(address.to_ipv6_mapped().octets(), expected_ip_octets);

        let port = 19999;
        assert_eq!(port, expected_provider_registration_payload.service_address.port());

        let owner_key_hash_hex = "3dd03f9ec192b5f275a433bfc90f468ee1a3eb4c";
        assert_eq!(
            owner_key_hash_hex,
            expected_provider_registration_payload.owner_key_hash.to_hex()
        );

        let operator_key_hex = "157b10706659e25eb362b5d902d809f9160b1688e201ee6e94b40f9b5062d7074683ef05a2d5efb7793c47059c878dfa";
        assert_eq!(
            operator_key_hex,
            expected_provider_registration_payload.operator_public_key.to_string()
        );

        let voting_key_hash_hex = "d38a30fafe61575db40f05ab0a08d55119b0aad3";
        assert_eq!(
            voting_key_hash_hex,
            expected_provider_registration_payload.voting_key_hash.to_hex()
        );

        let inputs_hash_hex = "7ba273b835b1017da314a3363760835ff5ac20278c160604cb8773750b997734";
        assert_eq!(
            inputs_hash_hex,
            expected_provider_registration_payload.inputs_hash.to_hex(),
            "inputs hash calculation has issues"
        );

        assert_eq!(
            expected_provider_registration_payload.base_payload_hash().to_hex(),
            "71e973f79003accd202b9a2ab2613ac6ced601b26684e82f561f6684fef2f102",
            "Payload hash calculation has issues"
        );

        assert_eq!(
            "yTb47qEBpNmgXvYYsHEN4nh8yJwa5iC4Cs|0|yRxHYGLf9G4UVYdtAoB2iAzR3sxxVaZB6y|yfbxyP4ctRJR1rs3A8C3PdXA4Wtcrw7zTi|71e973f79003accd202b9a2ab2613ac6ced601b26684e82f561f6684fef2f102",
            payload_collateral_string,
            "provider transaction collateral string doesn't match"
        );

        let operator_reward = 0;

        assert_eq!(operator_reward, expected_provider_registration_payload.operator_reward);

        // We should verify the script payouts match
        let script_payout = payout_address.assume_checked().script_pubkey();
        assert_eq!(script_payout, expected_provider_registration_payload.script_payout);

        let expected_base64_signature = "H7N+ScH/K4BXcTk5pVE+bnEacc/y5RfmIk33JO11Cu8bf5rZ7GErSnJQIy4eQA2nGKlQHh2aVWVSbksf9owCh2M=";
        let signature = sign_hash(
            message_digest.as_byte_array().as_slice(),
            collateral_private_key.to_bytes().as_slice(),
        )
        .expect("expected to sign message digest");
        let base64_signature = base64::encode(signature.as_slice());

        assert_eq!(
            expected_base64_signature, base64_signature,
            "message digest signatures don't match"
        );

        assert_eq!(expected_provider_registration_payload.signature, signature.to_vec());

        assert_eq!(expected_transaction.txid(), tx_id);

        let mut transaction = Transaction {
            version: 3,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: OutPoint::new(collateral_hash, 1),
                script_sig: collateral_address.assume_checked().script_pubkey(),
                sequence: 4294967295,
            }],
            output: vec![TxOut::new_from_address(40777037710, &output_address0.assume_checked())],
            special_transaction_payload: Some(ProviderRegistrationPayloadType(
                ProviderRegistrationPayload {
                    version: provider_registration_payload_version,
                    masternode_type: provider_type,
                    masternode_mode: provider_mode,
                    collateral_outpoint,
                    service_address: SocketAddr::V4(SocketAddrV4::new(address, port)),
                    owner_key_hash: PubkeyHash::from_hex(owner_key_hash_hex).unwrap(),
                    operator_public_key: BLSPublicKey::from_hex(operator_key_hex).unwrap(),
                    voting_key_hash: PubkeyHash::from_hex(voting_key_hash_hex).unwrap(),
                    operator_reward,
                    script_payout,
                    inputs_hash: InputsHash::from_hex(inputs_hash_hex).unwrap(),
                    signature: signature.to_vec(),
                    platform_node_id: None,
                    platform_p2p_port: None,
                    platform_http_port: None,
                },
            )),
        };
        // We are currently not supporting transaction signing
        // So just assume signature is correct
        transaction.input = expected_transaction.input.clone();

        assert_eq!(transaction.hash_inputs().to_hex(), inputs_hash_hex);

        let mut encoded_transaction_bytes = Vec::new();
        let _transaction_size =
            transaction.consensus_encode(&mut encoded_transaction_bytes).unwrap();
        assert_eq!(encoded_transaction_bytes, expected_transaction_bytes);

        assert_eq!(transaction, expected_transaction);

        assert_eq!(transaction.txid(), tx_id);
    }

    //todo finish this somewhat low value test
    #[test]
    #[ignore]
    fn test_no_collateral_provider_registration_transaction() {
        // This is a test for testnet
        let network = Network::Testnet;

        let expected_transaction_bytes = Vec::from_hex("030001000379efbe95cba05893d09f4ec51a71171a3852b54aa958ae35ce43276f5f8f1002000000006a473044022015df39c80ca8595cc197a0be692e9d158dc53bdbc8c6abca0d30c086f338c037022063becdb4f891436de3d2fb21cbf294e9dcb5c1a04bc0ba621867479e46d048cc0121030de5cb8989b6902d98017ab4d42b9244912006b0a1561c1d1ba0e2f3117a39adffffffff79efbe95cba05893d09f4ec51a71171a3852b54aa958ae35ce43276f5f8f1002010000006a47304402205c1bae23b459081b060de14133a20378243bebc05c8e2ed9acdabf6717ae7f9702204027ba0abbcce9ba5b2cb563cbff0190ba8f80e5f8fd6beb07c2c449f194c9be01210270b0f0b71472736a397975a84927314261be815d423006d1bcbc00cd693c3d81ffffffff9d925d6cd8e3a408f472e872d1c2849bc664efda8c7f68f1b3a3efde221bc474010000006a47304402203fa23ec33f91efa026b34e90b15a1fd64ff03242a6a92985b16a25b590e5bae002202d1429374b60b1180cd8b9bd0b432158524f5624d6c5d2d6db8c637c9961a21e0121024c0b09e261253dc40ed572c2d63d0b6cda89154583d75a5ab5a14fba81d70089ffffffff0200e87648170000001976a9143795a62df2eb953c1d08bc996d4089ee5d67e28b88ac438ca95a020000001976a91470ed8f5b5cfd4791c15b9d8a7f829cb6a98da18c88ac00000000d101000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffff010101014e1f3dd03f9ec192b5f275a433bfc90f468ee1a3eb4c157b10706659e25eb362b5d902d809f9160b1688e201ee6e94b40f9b5062d7074683ef05a2d5efb7793c47059c878dfad38a30fafe61575db40f05ab0a08d55119b0aad300001976a9143795a62df2eb953c1d08bc996d4089ee5d67e28b88ac14b33f2231f0df567e0dfb12899c893f5d2d05f6dcc7d9c8c27b68a71191c75400").unwrap();

        let expected_transaction: Transaction =
            deserialize(expected_transaction_bytes.as_slice()).expect("expected a transaction");

        let expected_provider_registration_payload = expected_transaction
            .special_transaction_payload
            .clone()
            .unwrap()
            .to_provider_registration_payload()
            .expect("expected to get a provider registration payload");

        let tx_id =
            Txid::from_hex("717d2d4a7d583da184872f4a07e35d897a1be9dd9875b4c017c81cf772e36694")
                .unwrap();

        let output_address0 = Address::from_str("yTWY6DsS4HBGs2JwDtnvVcpykLkbvtjUte")
            .expect("expected to be able to get output address");
        let collateral_address = Address::from_str("yeNVS6tFeQNXJVkjv6nm6gb7PtTERV5dGh")
            .expect("expected to be able to get collateral address");
        let collateral_private_key =
            PrivateKey::from_wif("cTVm7EkgzNBPcwAKGYHfvyK8cyrRAC8n3SUUw8qjLqCg2rpcczfo")
                .expect("expected valid base 58");
        let collateral_hash =
            Txid::from_hex("58ab8ba7dce591c745f8b78ee49156d13277fff20880855f7cda501705439aca")
                .expect("expected to decode collateral hash");
        let payout_address = Address::from_str("yTb47qEBpNmgXvYYsHEN4nh8yJwa5iC4Cs")
            .expect("expected a valid address");

        let payload_collateral_string = expected_provider_registration_payload
            .payload_collateral_string(network)
            .expect("expected to produce a payload collateral string");

        let provider_registration_payload_version = 1;
        assert_eq!(
            expected_provider_registration_payload.version,
            provider_registration_payload_version
        );
        let provider_type = ProviderMasternodeType::Regular;
        assert_eq!(expected_provider_registration_payload.masternode_type, provider_type);
        let provider_mode = 0;
        assert_eq!(expected_provider_registration_payload.masternode_mode, provider_mode);

        let collateral_outpoint = OutPoint {
            txid: collateral_hash,
            vout: 0,
        };
        assert_eq!(expected_provider_registration_payload.collateral_outpoint, collateral_outpoint);

        let address = Ipv4Addr::from_str("1.1.1.1").expect("expected an ipv4 address");
        let [a, b, c, d] = address.octets();
        let ipv6_bytes: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, a, b, c, d];

        let expected_octets = match expected_provider_registration_payload.service_address.ip() {
            IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
            IpAddr::V6(v6) => v6.octets(),
        };

        assert_eq!(ipv6_bytes, expected_octets);

        let port = 19999;
        assert_eq!(port, expected_provider_registration_payload.service_address.port());

        let service_address = SocketAddr::V4(SocketAddrV4::new(address, port));

        let owner_key_hash_hex = "3dd03f9ec192b5f275a433bfc90f468ee1a3eb4c";
        assert_eq!(
            owner_key_hash_hex,
            expected_provider_registration_payload.owner_key_hash.to_hex()
        );

        let operator_key_hex = "157b10706659e25eb362b5d902d809f9160b1688e201ee6e94b40f9b5062d7074683ef05a2d5efb7793c47059c878dfa";
        assert_eq!(
            operator_key_hex,
            expected_provider_registration_payload.operator_public_key.to_string()
        );

        let voting_key_hash_hex = "d38a30fafe61575db40f05ab0a08d55119b0aad3";
        assert_eq!(
            voting_key_hash_hex,
            expected_provider_registration_payload.voting_key_hash.to_hex()
        );

        let inputs_hash_hex = "7ba273b835b1017da314a3363760835ff5ac20278c160604cb8773750b997734";
        assert_eq!(
            inputs_hash_hex,
            expected_provider_registration_payload.inputs_hash.to_hex(),
            "inputs hash calculation has issues"
        );

        assert_eq!(
            expected_provider_registration_payload.base_payload_hash().to_hex(),
            "71e973f79003accd202b9a2ab2613ac6ced601b26684e82f561f6684fef2f102",
            "Payload hash calculation has issues"
        );

        assert_eq!(
            "yTb47qEBpNmgXvYYsHEN4nh8yJwa5iC4Cs|0|yRxHYGLf9G4UVYdtAoB2iAzR3sxxVaZB6y|yfbxyP4ctRJR1rs3A8C3PdXA4Wtcrw7zTi|71e973f79003accd202b9a2ab2613ac6ced601b26684e82f561f6684fef2f102",
            payload_collateral_string,
            "provider transaction collateral string doesn't match"
        );

        let operator_reward = 0;

        assert_eq!(operator_reward, expected_provider_registration_payload.operator_reward);

        // We should verify the script payouts match
        let script_payout = payout_address.assume_checked().script_pubkey();
        assert_eq!(script_payout, expected_provider_registration_payload.script_payout);

        let expected_base64_signature = "H7N+ScH/K4BXcTk5pVE+bnEacc/y5RfmIk33JO11Cu8bf5rZ7GErSnJQIy4eQA2nGKlQHh2aVWVSbksf9owCh2M=";
        let signature = sign_hash(
            base64::decode(&expected_base64_signature).expect("expected valid base64").as_slice(),
            collateral_private_key.to_bytes().as_slice(),
        )
        .expect("expected to sign message digest");
        let base64_signature = base64::encode(signature.as_slice());

        assert_eq!(
            expected_base64_signature, base64_signature,
            "message digest signatures don't match"
        );

        assert_eq!(expected_provider_registration_payload.signature, signature.to_vec());

        assert_eq!(expected_transaction.txid(), tx_id);

        let mut transaction = Transaction {
            version: 3,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: OutPoint::new(collateral_hash, 1),
                script_sig: collateral_address.assume_checked().script_pubkey(),
                sequence: 4294967295,
            }],
            output: vec![TxOut::new_from_address(40777037710, &output_address0.assume_checked())],
            special_transaction_payload: Some(ProviderRegistrationPayloadType(
                ProviderRegistrationPayload {
                    version: provider_registration_payload_version,
                    masternode_type: provider_type,
                    masternode_mode: provider_mode,
                    collateral_outpoint,
                    service_address,
                    owner_key_hash: PubkeyHash::from_hex(owner_key_hash_hex).unwrap(),
                    operator_public_key: BLSPublicKey::from_hex(operator_key_hex).unwrap(),
                    voting_key_hash: PubkeyHash::from_hex(voting_key_hash_hex).unwrap(),
                    operator_reward,
                    script_payout,
                    inputs_hash: InputsHash::from_hex(inputs_hash_hex).unwrap(),
                    signature: signature.to_vec(),
                    platform_node_id: None,
                    platform_p2p_port: None,
                    platform_http_port: None,
                },
            )),
        };
        // We are currently not supporting transaction signing
        // So just assume signature is correct
        transaction.input = expected_transaction.input.clone();

        assert_eq!(transaction.hash_inputs().to_hex(), inputs_hash_hex);

        let mut vector = Vec::new();
        let _transaction_size = transaction.consensus_encode(&mut vector).unwrap();
        assert_eq!(vector, expected_transaction_bytes);

        assert_eq!(transaction, expected_transaction);

        assert_eq!(transaction.txid(), tx_id);
    }

    #[test]
    fn size() {
        let want = 290;
        let payload = ProviderRegistrationPayload {
            version: 0,
            masternode_type: ProviderMasternodeType::Regular,
            masternode_mode: 0,
            collateral_outpoint: OutPoint {
                txid: Txid::all_zeros(),
                vout: 0,
            },
            service_address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from_bits(0), 0)),
            owner_key_hash: PubkeyHash::all_zeros(),
            operator_public_key: BLSPublicKey::from([0; 48]),
            voting_key_hash: PubkeyHash::all_zeros(),
            operator_reward: 0,
            script_payout: ScriptBuf::from_hex("00000000000000000000").unwrap(), // 10 bytes
            inputs_hash: InputsHash::all_zeros(),
            signature: vec![0; 96],
            platform_node_id: None,
            platform_p2p_port: None,
            platform_http_port: None,
        };
        assert_eq!(payload.size(), want);
        let actual = payload.consensus_encode(&mut Vec::new()).unwrap();
        assert_eq!(actual, want);
    }

    #[test]
    fn test_payload_version_2_encoding_and_decoding() {
        let payload_bytes = hex!(
            "02000100000093e740d1640db90b470eacd00a109fd2545604de231339f59d7d6afe1c6fb74e0100000000000000000000000000ffff52d31528270fb76ced2307e84810443d29baada0b3ece85c94dd9492e693537ddcd32edf56a800899c59e64f3e78156a4901072e5b470a21aa7841ad9abbb00cbc0d2c129e82fb4328fdeee23806c51aefc26fec992c30ead6a6410c1c1b00001976a914c4a7f785e341b694425ea2ddebd8e2249eb5664e88acb66b1aa5263c52fbde60b39f21855a4a0893adaea98f7e8195c2005594a7012a4cd2ca50b36e0a2bb1b6b29da140448b47eeb7a12068bb0141202f9d029a3f810d06e1d0001cbe8228af14af79d24ec28f5a5616a23f8b259e100b8533709c3543b4163251f60283d91670cdde5e975887e6a99ce28a001df528"
        );
        let payload: ProviderRegistrationPayload =
            deserialize(&payload_bytes).expect("deserialize payload");

        let mut serialized_payload_bytes = Vec::new();

        payload.consensus_encode(&mut serialized_payload_bytes).expect("serialize payload");

        assert_eq!(serialized_payload_bytes, payload_bytes);
    }
}
