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
use hex_conservative::Case::Lower;
use internals::{impl_array_newtype, impl_bytes_newtype};

use crate::address::Payload;
use crate::blockdata::transaction::special_transaction::SpecialTransactionBasePayloadEncodable;
use crate::blockdata::transaction::special_transaction::provider_update_service::ProTxVersion;
use crate::bls_sig_utils::BLSPublicKey;
use crate::consensus::{Decodable, Encodable, encode};
use crate::hash_types::{InputsHash, PubkeyHash, SpecialTransactionPayloadHash};
use crate::internal_macros::impl_consensus_encoding;
use crate::platform_node_id::PlatformNodeId;
use crate::prelude::*;
use crate::sml::masternode_list_entry::MasternodeNetInfo;
use crate::sml::masternode_list_entry::net_info::ExtNetInfo;
use crate::{Address, Network, OutPoint, ScriptBuf, VarInt, io};

/// One owner reward payee of a version 3 (extended address) ProTx, as defined by DIP-0026.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MasternodePayoutShare {
    pub script_payout: ScriptBuf,
    /// Share of the owner reward in basis points.
    pub reward: u16,
}

impl_consensus_encoding!(MasternodePayoutShare, script_payout, reward);

impl MasternodePayoutShare {
    /// The size of the payout in bytes.
    pub fn size(&self) -> usize {
        VarInt(self.script_payout.len() as u64).len() + self.script_payout.len() + 2
    }
}

/// Encodes payouts as Core does: a `u8` count followed by the entries.
pub(crate) fn encode_payouts<W: io::Write + ?Sized>(
    payouts: &[MasternodePayoutShare],
    w: &mut W,
) -> Result<usize, io::Error> {
    let count = u8::try_from(payouts.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "more than 255 payouts"))?;
    let mut len = count.consensus_encode(w)?;
    for payout in payouts {
        len += payout.consensus_encode(w)?;
    }
    Ok(len)
}

/// Decodes payouts written by [`encode_payouts`].
pub(crate) fn decode_payouts<R: io::Read + ?Sized>(
    r: &mut R,
) -> Result<Vec<MasternodePayoutShare>, encode::Error> {
    let count = u8::consensus_decode(r)?;
    (0..count).map(|_| MasternodePayoutShare::consensus_decode(r)).collect()
}

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

/// A compact recoverable ECDSA signature of 65 bytes, written without a length prefix.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct CompactSignature([u8; 65]);

impl_array_newtype!(CompactSignature, u8, 65);
impl_bytes_newtype!(CompactSignature, 65);

impl Encodable for CompactSignature {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        w.write_all(&self.0)?;
        Ok(self.0.len())
    }
}

impl Decodable for CompactSignature {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let mut bytes = [0; 65];
        r.read_exact(&mut bytes).map_err(encode::Error::Io)?;
        Ok(CompactSignature(bytes))
    }
}

/// Encodes signatures as Core does: a `u8` count followed by the signatures.
pub(crate) fn encode_compact_signatures<W: io::Write + ?Sized>(
    signatures: &[CompactSignature],
    w: &mut W,
) -> Result<usize, io::Error> {
    let count = u8::try_from(signatures.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "more than 255 signatures"))?;
    let mut len = count.consensus_encode(w)?;
    for signature in signatures {
        len += signature.consensus_encode(w)?;
    }
    Ok(len)
}

/// Decodes signatures written by [`encode_compact_signatures`].
pub(crate) fn decode_compact_signatures<R: io::Read + ?Sized>(
    r: &mut R,
) -> Result<Vec<CompactSignature>, encode::Error> {
    let count = u8::consensus_decode(r)?;
    (0..count).map(|_| CompactSignature::consensus_decode(r)).collect()
}

/// One participant's contribution to the collateral of a shared masternode.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CollateralShare {
    /// Contributed amount in duffs.
    pub amount: i64,
    pub script_refund: ScriptBuf,
    /// Script the share's owner rewards are paid to, `script_refund` when empty.
    pub script_reward: ScriptBuf,
    pub owner_key_hash: PubkeyHash,
}

impl_consensus_encoding!(CollateralShare, amount, script_refund, script_reward, owner_key_hash);

impl CollateralShare {
    /// The size of the share in bytes.
    pub fn size(&self) -> usize {
        8 + VarInt(self.script_refund.len() as u64).len()
            + self.script_refund.len()
            + VarInt(self.script_reward.len() as u64).len()
            + self.script_reward.len()
            + 20
    }
}

/// The collateral sharing terms of a version 3 ProRegTx. `shares` is empty when the collateral
/// has a single owner.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Default)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SharedCollateral {
    pub shares: Vec<CollateralShare>,
    /// One consent signature per share, in share order.
    pub join_sigs: Vec<CompactSignature>,
    pub early_period_blocks: u32,
    /// Penalty in duffs for leaving within `early_period_blocks`.
    pub early_penalty: i64,
}

impl SharedCollateral {
    /// The size of the terms in bytes.
    pub fn size(&self) -> usize {
        1 + self.shares.iter().map(CollateralShare::size).sum::<usize>()
            + 65 * self.join_sigs.len()
            + 4
            + 8
    }
}

// Core writes the share count once, as a `u8`, ahead of the shares and then of their
// signatures.
impl Encodable for SharedCollateral {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let count = u8::try_from(self.shares.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "more than 255 shares"))?;
        if self.join_sigs.len() != self.shares.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "join signature count mismatch",
            ));
        }
        let mut len = count.consensus_encode(w)?;
        for share in &self.shares {
            len += share.consensus_encode(w)?;
        }
        for sig in &self.join_sigs {
            len += sig.consensus_encode(w)?;
        }
        len += self.early_period_blocks.consensus_encode(w)?;
        len += self.early_penalty.consensus_encode(w)?;
        Ok(len)
    }
}

impl Decodable for SharedCollateral {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let count = u8::consensus_decode(r)?;
        let shares =
            (0..count).map(|_| CollateralShare::consensus_decode(r)).collect::<Result<_, _>>()?;
        let join_sigs =
            (0..count).map(|_| CompactSignature::consensus_decode(r)).collect::<Result<_, _>>()?;
        Ok(SharedCollateral {
            shares,
            join_sigs,
            early_period_blocks: u32::consensus_decode(r)?,
            early_penalty: i64::consensus_decode(r)?,
        })
    }
}

/// A Provider Registration Payload used in a Provider Registration Special Transaction.
/// This is used to register a Masternode on the network.
/// Interesting Fields:
/// *Provider type refers to the type of Masternode.
/// *Provider mode refers to the mode of the Masternode. Currently only valid value is 0.
/// *The collateral outpoint links to a transaction with a 1000 Dash unspent (at registration)
/// outpoint.
/// *The operator reward defines the ratio when divided by 10000 of the amount going to the operator.
/// The max value for the operator reward is 10000.
/// *The script payout is the script to which one wants to have the masternode pay out.
/// *The inputs hash is used to guarantee the uniqueness of the payload sig.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct ProviderRegistrationPayload {
    pub version: u16,
    pub masternode_type: ProviderMasternodeType,
    pub masternode_mode: u16,
    pub collateral_outpoint: OutPoint,
    /// The service address: [`MasternodeNetInfo::Legacy`] before version 3,
    /// [`MasternodeNetInfo::Extended`] from version 3.
    pub service_address: MasternodeNetInfo,
    pub owner_key_hash: PubkeyHash,
    pub operator_public_key: BLSPublicKey,
    pub voting_key_hash: PubkeyHash,
    pub operator_reward: u16,
    /// Payout script before version 3, empty from version 3 (see `payouts`).
    pub script_payout: ScriptBuf,
    pub inputs_hash: InputsHash,
    pub signature: Vec<u8>,
    /// Tenderdash/CometBFT node ID of the masternode's Platform node:
    /// `SHA256(ed25519_public_key)` truncated to 20 bytes. Not a `hash160`
    /// public key hash. Only present for high-performance (Evo) masternodes
    /// on payload version 2+.
    pub platform_node_id: Option<PlatformNodeId>,
    /// Only before version 3; from version 3 the platform ports are in `service_address`.
    pub platform_p2p_port: Option<u16>,
    /// Only before version 3; from version 3 the platform ports are in `service_address`.
    pub platform_http_port: Option<u16>,
    /// DIP-0026 payouts, present from version 3 in place of `script_payout`.
    pub payouts: Option<Vec<MasternodePayoutShare>>,
    /// Collateral sharing terms, present from version 3.
    pub shared_collateral: Option<SharedCollateral>,
}

impl ProviderRegistrationPayload {
    /// Latest spec version of the ProRegTx payload.
    pub const CURRENT_VERSION: u16 = 2;

    /// Create a new ProRegTx payload at [`Self::CURRENT_VERSION`].
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        masternode_type: ProviderMasternodeType,
        masternode_mode: u16,
        collateral_outpoint: OutPoint,
        service_address: SocketAddr,
        owner_key_hash: PubkeyHash,
        operator_public_key: BLSPublicKey,
        voting_key_hash: PubkeyHash,
        operator_reward: u16,
        script_payout: ScriptBuf,
        inputs_hash: InputsHash,
        signature: Vec<u8>,
        platform_node_id: Option<PlatformNodeId>,
        platform_p2p_port: Option<u16>,
        platform_http_port: Option<u16>,
    ) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            masternode_type,
            masternode_mode,
            collateral_outpoint,
            service_address: MasternodeNetInfo::Legacy(service_address),
            owner_key_hash,
            operator_public_key,
            voting_key_hash,
            operator_reward,
            script_payout,
            inputs_hash,
            signature,
            platform_node_id,
            platform_p2p_port,
            platform_http_port,
            payouts: None,
            shared_collateral: None,
        }
    }

    fn is_ext_addr(&self) -> bool {
        self.version >= ProTxVersion::ExtAddr as u16
    }

    fn is_evo(&self) -> bool {
        self.version >= ProTxVersion::BasicBLS as u16
            && self.masternode_type == ProviderMasternodeType::HighPerformance
    }

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
    /// to register the masternode. Not supported from version 3, which lists its payouts there.
    pub fn payload_collateral_string(&self, network: Network) -> Result<String, encode::Error> {
        if self.is_ext_addr() {
            return Err(encode::Error::ParseFailed(
                "collateral string of a version 3 ProRegTx is not supported",
            ));
        }
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
    pub fn size(&self) -> usize {
        // version + type + mode + collateral outpoint + owner key hash + operator key +
        // voting key hash + operator reward + inputs hash
        let mut size = 2 + 2 + 2 + 36 + 20 + 48 + 20 + 2 + 32;
        size += match &self.service_address {
            MasternodeNetInfo::Legacy(_) => 16 + 2, // ip + port
            MasternodeNetInfo::Extended(info) => info.size(),
        };
        if self.is_ext_addr() {
            let payouts = self.payouts.as_deref().unwrap_or_default();
            size += 1 + payouts.iter().map(MasternodePayoutShare::size).sum::<usize>();
            size += self.shared_collateral.as_ref().map_or(1 + 4 + 8, SharedCollateral::size);
        } else {
            size += VarInt(self.script_payout.len() as u64).len() + self.script_payout.len();
        }
        if self.is_evo() {
            size += 20; // platform_node_id
            if !self.is_ext_addr() {
                size += 2 + 2; // p2p_port + http_port
            }
        }
        size += VarInt(self.signature.len() as u64).len() + self.signature.len();
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
        len += match (self.is_ext_addr(), &self.service_address) {
            (false, MasternodeNetInfo::Legacy(addr)) => addr.consensus_encode(&mut s)?,
            (true, MasternodeNetInfo::Extended(info)) => info.consensus_encode_ext(&mut s)?,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "service_address does not match the payload version",
                ));
            }
        };
        len += self.owner_key_hash.consensus_encode(&mut s)?;
        len += self.operator_public_key.consensus_encode(&mut s)?;
        len += self.voting_key_hash.consensus_encode(&mut s)?;
        len += self.operator_reward.consensus_encode(&mut s)?;
        if self.is_ext_addr() {
            let (Some(payouts), Some(shared_collateral)) = (&self.payouts, &self.shared_collateral)
            else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "payouts or shared_collateral is not set",
                ));
            };
            len += encode_payouts(payouts, &mut s)?;
            len += shared_collateral.consensus_encode(&mut s)?;
        } else {
            len += self.script_payout.consensus_encode(&mut s)?;
        }
        len += self.inputs_hash.consensus_encode(&mut s)?;

        // Platform fields for Evo masternodes (v2+, ports only before v3)
        if self.is_evo() {
            len += self.platform_node_id.unwrap_or_default().consensus_encode(&mut s)?;
            if !self.is_ext_addr() {
                len += self.platform_p2p_port.unwrap_or_default().consensus_encode(&mut s)?;
                len += self.platform_http_port.unwrap_or_default().consensus_encode(&mut s)?;
            }
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

        // Version validation like C++ SERIALIZE_METHODS
        if version == 0 || version > ProTxVersion::ExtAddr as u16 {
            return Err(encode::Error::ParseFailed("unsupported ProRegTx version"));
        }
        let is_ext_addr = version >= ProTxVersion::ExtAddr as u16;

        let masternode_type = ProviderMasternodeType::consensus_decode(r)?;
        let masternode_mode = u16::consensus_decode(r)?;
        let collateral_outpoint = OutPoint::consensus_decode(r)?;
        let service_address = if is_ext_addr {
            MasternodeNetInfo::Extended(ExtNetInfo::consensus_decode_ext(r)?)
        } else {
            MasternodeNetInfo::Legacy(SocketAddr::consensus_decode(r)?)
        };
        let owner_key_hash = PubkeyHash::consensus_decode(r)?;
        let operator_public_key = BLSPublicKey::consensus_decode(r)?;
        let voting_key_hash = PubkeyHash::consensus_decode(r)?;
        let operator_reward = u16::consensus_decode(r)?;
        let (script_payout, payouts, shared_collateral) = if is_ext_addr {
            let payouts = decode_payouts(r)?;
            (ScriptBuf::new(), Some(payouts), Some(SharedCollateral::consensus_decode(r)?))
        } else {
            (ScriptBuf::consensus_decode(r)?, None, None)
        };
        let inputs_hash = InputsHash::consensus_decode(r)?;

        // Platform fields for Evo masternodes; the ports moved to `service_address` in v3
        let (platform_node_id, platform_p2p_port, platform_http_port) = if version
            >= ProTxVersion::BasicBLS as u16
            && masternode_type == ProviderMasternodeType::HighPerformance
        {
            let node_id = PlatformNodeId::consensus_decode(r)?;
            if is_ext_addr {
                (Some(node_id), None, None)
            } else {
                (Some(node_id), Some(u16::consensus_decode(r)?), Some(u16::consensus_decode(r)?))
            }
        } else {
            (None, None, None)
        };

        let signature = Vec::<u8>::consensus_decode(r)?;

        Ok(ProviderRegistrationPayload {
            version,
            masternode_type,
            masternode_mode,
            collateral_outpoint,
            service_address,
            owner_key_hash,
            operator_public_key,
            voting_key_hash,
            operator_reward,
            script_payout,
            inputs_hash,
            signature,
            platform_node_id,
            platform_p2p_port,
            platform_http_port,
            payouts,
            shared_collateral,
        })
    }
}

// Same layout as the earlier derived impl before version 3. Version 3 stores the extended
// addresses in place of the service address and appends `payouts` and `shared_collateral`, so
// payloads persisted before keep decoding.
#[cfg(feature = "bincode")]
impl bincode::Encode for ProviderRegistrationPayload {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        self.version.encode(encoder)?;
        self.masternode_type.encode(encoder)?;
        self.masternode_mode.encode(encoder)?;
        self.collateral_outpoint.encode(encoder)?;
        match (self.is_ext_addr(), &self.service_address) {
            (false, MasternodeNetInfo::Legacy(addr)) => addr.encode(encoder)?,
            (true, MasternodeNetInfo::Extended(info)) => info.encode(encoder)?,
            _ => {
                return Err(bincode::error::EncodeError::Other(
                    "service_address does not match the payload version",
                ));
            }
        }
        self.owner_key_hash.encode(encoder)?;
        self.operator_public_key.encode(encoder)?;
        self.voting_key_hash.encode(encoder)?;
        self.operator_reward.encode(encoder)?;
        self.script_payout.encode(encoder)?;
        self.inputs_hash.encode(encoder)?;
        self.signature.encode(encoder)?;
        self.platform_node_id.encode(encoder)?;
        self.platform_p2p_port.encode(encoder)?;
        self.platform_http_port.encode(encoder)?;
        if self.is_ext_addr() {
            self.payouts.encode(encoder)?;
            self.shared_collateral.encode(encoder)?;
        }
        Ok(())
    }
}

#[cfg(feature = "bincode")]
impl<C> bincode::Decode<C> for ProviderRegistrationPayload {
    fn decode<D: bincode::de::Decoder<Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let version = u16::decode(decoder)?;
        let is_ext_addr = version >= ProTxVersion::ExtAddr as u16;
        let masternode_type = Decode::decode(decoder)?;
        let masternode_mode = Decode::decode(decoder)?;
        let collateral_outpoint = Decode::decode(decoder)?;
        let service_address = if is_ext_addr {
            MasternodeNetInfo::Extended(Decode::decode(decoder)?)
        } else {
            MasternodeNetInfo::Legacy(Decode::decode(decoder)?)
        };
        let owner_key_hash = Decode::decode(decoder)?;
        let operator_public_key = Decode::decode(decoder)?;
        let voting_key_hash = Decode::decode(decoder)?;
        let operator_reward = Decode::decode(decoder)?;
        let script_payout = Decode::decode(decoder)?;
        let inputs_hash = Decode::decode(decoder)?;
        let signature = Decode::decode(decoder)?;
        let platform_node_id = Decode::decode(decoder)?;
        let platform_p2p_port = Decode::decode(decoder)?;
        let platform_http_port = Decode::decode(decoder)?;
        let (payouts, shared_collateral) = if is_ext_addr {
            (Decode::decode(decoder)?, Decode::decode(decoder)?)
        } else {
            (None, None)
        };
        Ok(ProviderRegistrationPayload {
            version,
            masternode_type,
            masternode_mode,
            collateral_outpoint,
            service_address,
            owner_key_hash,
            operator_public_key,
            voting_key_hash,
            operator_reward,
            script_payout,
            inputs_hash,
            signature,
            platform_node_id,
            platform_p2p_port,
            platform_http_port,
            payouts,
            shared_collateral,
        })
    }
}

#[cfg(feature = "bincode")]
bincode::impl_borrow_decode!(ProviderRegistrationPayload);

// Same shape as the earlier derived impl before version 3. Version 3 writes the extended
// addresses as `net_info` in place of `service_address` and appends `payouts` and
// `shared_collateral`. Payloads persisted through serde before keep decoding.
#[cfg(feature = "serde")]
impl serde::Serialize for ProviderRegistrationPayload {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{Error, SerializeStruct};

        let ext_addr = self.is_ext_addr();
        let len = if ext_addr {
            17
        } else {
            15
        };
        let mut state = serializer.serialize_struct("ProviderRegistrationPayload", len)?;
        state.serialize_field("version", &self.version)?;
        state.serialize_field("masternode_type", &self.masternode_type)?;
        state.serialize_field("masternode_mode", &self.masternode_mode)?;
        state.serialize_field("collateral_outpoint", &self.collateral_outpoint)?;
        match (ext_addr, &self.service_address) {
            (false, MasternodeNetInfo::Legacy(addr)) => {
                state.serialize_field("service_address", addr)?;
            }
            (true, MasternodeNetInfo::Extended(info)) => {
                state.serialize_field("net_info", info)?;
            }
            _ => {
                return Err(S::Error::custom("service_address does not match the payload version"));
            }
        }
        state.serialize_field("owner_key_hash", &self.owner_key_hash)?;
        state.serialize_field("operator_public_key", &self.operator_public_key)?;
        state.serialize_field("voting_key_hash", &self.voting_key_hash)?;
        state.serialize_field("operator_reward", &self.operator_reward)?;
        state.serialize_field("script_payout", &self.script_payout)?;
        state.serialize_field("inputs_hash", &self.inputs_hash)?;
        state.serialize_field("signature", &self.signature)?;
        state.serialize_field("platform_node_id", &self.platform_node_id)?;
        state.serialize_field("platform_p2p_port", &self.platform_p2p_port)?;
        state.serialize_field("platform_http_port", &self.platform_http_port)?;
        if ext_addr {
            state.serialize_field("payouts", &self.payouts)?;
            state.serialize_field("shared_collateral", &self.shared_collateral)?;
        }
        state.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for ProviderRegistrationPayload {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use core::fmt;

        use serde::de::{self, IgnoredAny, MapAccess, SeqAccess, Visitor};

        const FIELDS: &[&str] = &[
            "version",
            "masternode_type",
            "masternode_mode",
            "collateral_outpoint",
            "service_address",
            "owner_key_hash",
            "operator_public_key",
            "voting_key_hash",
            "operator_reward",
            "script_payout",
            "inputs_hash",
            "signature",
            "platform_node_id",
            "platform_p2p_port",
            "platform_http_port",
            "net_info",
            "payouts",
            "shared_collateral",
        ];

        struct PayloadVisitor;

        impl<'de> Visitor<'de> for PayloadVisitor {
            type Value = ProviderRegistrationPayload;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a provider registration payload")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut index = 0;
                macro_rules! next {
                    () => {{
                        let value = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(index, &self))?;
                        #[allow(unused_assignments)]
                        {
                            index += 1;
                        }
                        value
                    }};
                }
                let version: u16 = next!();
                let ext_addr = version >= ProTxVersion::ExtAddr as u16;
                let masternode_type = next!();
                let masternode_mode = next!();
                let collateral_outpoint = next!();
                let service_address = if ext_addr {
                    MasternodeNetInfo::Extended(next!())
                } else {
                    MasternodeNetInfo::Legacy(next!())
                };
                let owner_key_hash = next!();
                let operator_public_key = next!();
                let voting_key_hash = next!();
                let operator_reward = next!();
                let script_payout = next!();
                let inputs_hash = next!();
                let signature = next!();
                let platform_node_id = next!();
                let platform_p2p_port = next!();
                let platform_http_port = next!();
                // Read only from version 3: earlier payloads were written without them.
                let (payouts, shared_collateral) = if ext_addr {
                    (next!(), next!())
                } else {
                    (None, None)
                };
                Ok(ProviderRegistrationPayload {
                    version,
                    masternode_type,
                    masternode_mode,
                    collateral_outpoint,
                    service_address,
                    owner_key_hash,
                    operator_public_key,
                    voting_key_hash,
                    operator_reward,
                    script_payout,
                    inputs_hash,
                    signature,
                    platform_node_id,
                    platform_p2p_port,
                    platform_http_port,
                    payouts,
                    shared_collateral,
                })
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut version = None;
                let mut masternode_type = None;
                let mut masternode_mode = None;
                let mut collateral_outpoint = None;
                let mut service_address: Option<SocketAddr> = None;
                let mut net_info: Option<ExtNetInfo> = None;
                let mut owner_key_hash = None;
                let mut operator_public_key = None;
                let mut voting_key_hash = None;
                let mut operator_reward = None;
                let mut script_payout = None;
                let mut inputs_hash = None;
                let mut signature = None;
                let mut platform_node_id = None;
                let mut platform_p2p_port = None;
                let mut platform_http_port = None;
                let mut payouts = None;
                let mut shared_collateral = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "version" => version = Some(map.next_value()?),
                        "masternode_type" => masternode_type = Some(map.next_value()?),
                        "masternode_mode" => masternode_mode = Some(map.next_value()?),
                        "collateral_outpoint" => collateral_outpoint = Some(map.next_value()?),
                        "service_address" => service_address = Some(map.next_value()?),
                        "net_info" => net_info = Some(map.next_value()?),
                        "owner_key_hash" => owner_key_hash = Some(map.next_value()?),
                        "operator_public_key" => operator_public_key = Some(map.next_value()?),
                        "voting_key_hash" => voting_key_hash = Some(map.next_value()?),
                        "operator_reward" => operator_reward = Some(map.next_value()?),
                        "script_payout" => script_payout = Some(map.next_value()?),
                        "inputs_hash" => inputs_hash = Some(map.next_value()?),
                        "signature" => signature = Some(map.next_value()?),
                        "platform_node_id" => platform_node_id = map.next_value()?,
                        "platform_p2p_port" => platform_p2p_port = map.next_value()?,
                        "platform_http_port" => platform_http_port = map.next_value()?,
                        "payouts" => payouts = map.next_value()?,
                        "shared_collateral" => shared_collateral = map.next_value()?,
                        _ => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                // The version picks the fields, as in `visit_seq`; those of another version are
                // rejected rather than read into a payload that can't be encoded.
                let version: u16 = version.ok_or_else(|| de::Error::missing_field("version"))?;
                let service_address = if version >= ProTxVersion::ExtAddr as u16 {
                    if service_address.is_some() {
                        return Err(de::Error::custom(
                            "service_address only exists before version 3",
                        ));
                    }
                    MasternodeNetInfo::Extended(
                        net_info.ok_or_else(|| de::Error::missing_field("net_info"))?,
                    )
                } else {
                    if net_info.is_some() || payouts.is_some() || shared_collateral.is_some() {
                        return Err(de::Error::custom(
                            "net_info, payouts and shared_collateral only exist from version 3",
                        ));
                    }
                    MasternodeNetInfo::Legacy(
                        service_address
                            .ok_or_else(|| de::Error::missing_field("service_address"))?,
                    )
                };
                Ok(ProviderRegistrationPayload {
                    version,
                    masternode_type: masternode_type
                        .ok_or_else(|| de::Error::missing_field("masternode_type"))?,
                    masternode_mode: masternode_mode
                        .ok_or_else(|| de::Error::missing_field("masternode_mode"))?,
                    collateral_outpoint: collateral_outpoint
                        .ok_or_else(|| de::Error::missing_field("collateral_outpoint"))?,
                    service_address,
                    owner_key_hash: owner_key_hash
                        .ok_or_else(|| de::Error::missing_field("owner_key_hash"))?,
                    operator_public_key: operator_public_key
                        .ok_or_else(|| de::Error::missing_field("operator_public_key"))?,
                    voting_key_hash: voting_key_hash
                        .ok_or_else(|| de::Error::missing_field("voting_key_hash"))?,
                    operator_reward: operator_reward
                        .ok_or_else(|| de::Error::missing_field("operator_reward"))?,
                    script_payout: script_payout
                        .ok_or_else(|| de::Error::missing_field("script_payout"))?,
                    inputs_hash: inputs_hash
                        .ok_or_else(|| de::Error::missing_field("inputs_hash"))?,
                    signature: signature.ok_or_else(|| de::Error::missing_field("signature"))?,
                    platform_node_id,
                    platform_p2p_port,
                    platform_http_port,
                    payouts,
                    shared_collateral,
                })
            }
        }

        deserializer.deserialize_struct("ProviderRegistrationPayload", FIELDS, PayloadVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use hashes::Hash;

    use crate::bls_sig_utils::BLSPublicKey;
    use crate::consensus::{Encodable, deserialize};
    use crate::hash_types::InputsHash;
    use crate::internal_macros::hex;
    use crate::transaction::special_transaction::provider_registration::{
        ProviderMasternodeType, ProviderRegistrationPayload,
    };
    use crate::{OutPoint, PubkeyHash, ScriptBuf, Txid};

    use crate::Network;
    use crate::PrivateKey;
    use crate::Transaction;
    use crate::TxIn;
    use crate::TxOut;
    use crate::Witness;
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

        let expected_ip_octets = match expected_provider_registration_payload
            .service_address
            .primary_service_address()
            .unwrap()
            .ip()
        {
            IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
            IpAddr::V6(v6) => v6.octets(),
        };

        assert_eq!(ipv6_bytes, address.to_ipv6_mapped().octets());
        assert_eq!(address.to_ipv6_mapped().octets(), expected_ip_octets);

        let port = 19999;
        assert_eq!(
            port,
            expected_provider_registration_payload
                .service_address
                .primary_service_address()
                .unwrap()
                .port()
        );

        let owner_key_hash_hex = "3dd03f9ec192b5f275a433bfc90f468ee1a3eb4c";
        assert_eq!(
            owner_key_hash_hex,
            expected_provider_registration_payload.owner_key_hash.to_string()
        );

        let operator_key_hex = "157b10706659e25eb362b5d902d809f9160b1688e201ee6e94b40f9b5062d7074683ef05a2d5efb7793c47059c878dfa";
        assert_eq!(
            operator_key_hex,
            expected_provider_registration_payload.operator_public_key.to_string()
        );

        let voting_key_hash_hex = "d38a30fafe61575db40f05ab0a08d55119b0aad3";
        assert_eq!(
            voting_key_hash_hex,
            expected_provider_registration_payload.voting_key_hash.to_string()
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
        let base64_signature = BASE64.encode(signature.as_slice());

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
                witness: Default::default(),
            }],
            output: vec![TxOut::new_from_address(40777037710, &output_address0.assume_checked())],
            special_transaction_payload: Some(ProviderRegistrationPayloadType(
                ProviderRegistrationPayload {
                    version: provider_registration_payload_version,
                    masternode_type: provider_type,
                    masternode_mode: provider_mode,
                    collateral_outpoint,
                    service_address: MasternodeNetInfo::Legacy(SocketAddr::V4(SocketAddrV4::new(
                        address, port,
                    ))),
                    owner_key_hash: PubkeyHash::from_str(owner_key_hash_hex).unwrap(),
                    operator_public_key: BLSPublicKey::from_hex(operator_key_hex).unwrap(),
                    voting_key_hash: PubkeyHash::from_str(voting_key_hash_hex).unwrap(),
                    operator_reward,
                    script_payout,
                    inputs_hash: InputsHash::from_hex(inputs_hash_hex).unwrap(),
                    signature: signature.to_vec(),
                    platform_node_id: None,
                    platform_p2p_port: None,
                    platform_http_port: None,
                    payouts: None,
                    shared_collateral: None,
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

        let expected_transaction_bytes = hex_conservative::decode_to_vec("030001000379efbe95cba05893d09f4ec51a71171a3852b54aa958ae35ce43276f5f8f1002000000006a473044022015df39c80ca8595cc197a0be692e9d158dc53bdbc8c6abca0d30c086f338c037022063becdb4f891436de3d2fb21cbf294e9dcb5c1a04bc0ba621867479e46d048cc0121030de5cb8989b6902d98017ab4d42b9244912006b0a1561c1d1ba0e2f3117a39adffffffff79efbe95cba05893d09f4ec51a71171a3852b54aa958ae35ce43276f5f8f1002010000006a47304402205c1bae23b459081b060de14133a20378243bebc05c8e2ed9acdabf6717ae7f9702204027ba0abbcce9ba5b2cb563cbff0190ba8f80e5f8fd6beb07c2c449f194c9be01210270b0f0b71472736a397975a84927314261be815d423006d1bcbc00cd693c3d81ffffffff9d925d6cd8e3a408f472e872d1c2849bc664efda8c7f68f1b3a3efde221bc474010000006a47304402203fa23ec33f91efa026b34e90b15a1fd64ff03242a6a92985b16a25b590e5bae002202d1429374b60b1180cd8b9bd0b432158524f5624d6c5d2d6db8c637c9961a21e0121024c0b09e261253dc40ed572c2d63d0b6cda89154583d75a5ab5a14fba81d70089ffffffff0200e87648170000001976a9143795a62df2eb953c1d08bc996d4089ee5d67e28b88ac438ca95a020000001976a91470ed8f5b5cfd4791c15b9d8a7f829cb6a98da18c88ac00000000d101000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffff010101014e1f3dd03f9ec192b5f275a433bfc90f468ee1a3eb4c157b10706659e25eb362b5d902d809f9160b1688e201ee6e94b40f9b5062d7074683ef05a2d5efb7793c47059c878dfad38a30fafe61575db40f05ab0a08d55119b0aad300001976a9143795a62df2eb953c1d08bc996d4089ee5d67e28b88ac14b33f2231f0df567e0dfb12899c893f5d2d05f6dcc7d9c8c27b68a71191c75400").unwrap();

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

        let expected_octets = match expected_provider_registration_payload
            .service_address
            .primary_service_address()
            .unwrap()
            .ip()
        {
            IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
            IpAddr::V6(v6) => v6.octets(),
        };

        assert_eq!(ipv6_bytes, expected_octets);

        let port = 19999;
        assert_eq!(
            port,
            expected_provider_registration_payload
                .service_address
                .primary_service_address()
                .unwrap()
                .port()
        );

        let service_address = SocketAddr::V4(SocketAddrV4::new(address, port));

        let owner_key_hash_hex = "3dd03f9ec192b5f275a433bfc90f468ee1a3eb4c";
        assert_eq!(
            owner_key_hash_hex,
            expected_provider_registration_payload.owner_key_hash.to_string()
        );

        let operator_key_hex = "157b10706659e25eb362b5d902d809f9160b1688e201ee6e94b40f9b5062d7074683ef05a2d5efb7793c47059c878dfa";
        assert_eq!(
            operator_key_hex,
            expected_provider_registration_payload.operator_public_key.to_string()
        );

        let voting_key_hash_hex = "d38a30fafe61575db40f05ab0a08d55119b0aad3";
        assert_eq!(
            voting_key_hash_hex,
            expected_provider_registration_payload.voting_key_hash.to_string()
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
            BASE64.decode(expected_base64_signature).expect("expected valid base64").as_slice(),
            collateral_private_key.to_bytes().as_slice(),
        )
        .expect("expected to sign message digest");
        let base64_signature = BASE64.encode(signature.as_slice());

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
                witness: Witness::new(),
            }],
            output: vec![TxOut::new_from_address(40777037710, &output_address0.assume_checked())],
            special_transaction_payload: Some(ProviderRegistrationPayloadType(
                ProviderRegistrationPayload {
                    version: provider_registration_payload_version,
                    masternode_type: provider_type,
                    masternode_mode: provider_mode,
                    collateral_outpoint,
                    service_address: MasternodeNetInfo::Legacy(service_address),
                    owner_key_hash: PubkeyHash::from_str(owner_key_hash_hex).unwrap(),
                    operator_public_key: BLSPublicKey::from_hex(operator_key_hex).unwrap(),
                    voting_key_hash: PubkeyHash::from_str(voting_key_hash_hex).unwrap(),
                    operator_reward,
                    script_payout,
                    inputs_hash: InputsHash::from_hex(inputs_hash_hex).unwrap(),
                    signature: signature.to_vec(),
                    platform_node_id: None,
                    platform_p2p_port: None,
                    platform_http_port: None,
                    payouts: None,
                    shared_collateral: None,
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
            service_address: MasternodeNetInfo::Legacy(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from_bits(0),
                0,
            ))),
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
            payouts: None,
            shared_collateral: None,
        };
        assert_eq!(payload.size(), want);
        let actual = payload.consensus_encode(&mut Vec::new()).unwrap();
        assert_eq!(actual, want);
    }

    /// A v2 high-performance payload with absent platform fields still
    /// writes the zero-filled node id and ports on the wire.
    #[test]
    fn v2_high_performance_none_platform_fields_encode_zero_filled() {
        let payload = ProviderRegistrationPayload {
            version: 2,
            masternode_type: ProviderMasternodeType::HighPerformance,
            masternode_mode: 0,
            collateral_outpoint: OutPoint {
                txid: Txid::all_zeros(),
                vout: 0,
            },
            service_address: MasternodeNetInfo::Legacy(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from_bits(0),
                0,
            ))),
            owner_key_hash: PubkeyHash::all_zeros(),
            operator_public_key: BLSPublicKey::from([0; 48]),
            voting_key_hash: PubkeyHash::all_zeros(),
            operator_reward: 0,
            script_payout: ScriptBuf::new(),
            inputs_hash: InputsHash::all_zeros(),
            signature: vec![],
            platform_node_id: None,
            platform_p2p_port: None,
            platform_http_port: None,
            payouts: None,
            shared_collateral: None,
        };

        let mut encoded = Vec::new();
        payload.consensus_encode(&mut encoded).unwrap();

        let decoded: ProviderRegistrationPayload =
            deserialize(&encoded).expect("deserialize zero-filled payload");
        assert_eq!(decoded.platform_node_id, Some(crate::PlatformNodeId::from_byte_array([0; 20])));
        assert_eq!(decoded.platform_p2p_port, Some(0));
        assert_eq!(decoded.platform_http_port, Some(0));
    }

    #[test]
    fn test_payload_version_2_encoding_and_decoding() {
        let payload_bytes = hex!(
            "02000100000093e740d1640db90b470eacd00a109fd2545604de231339f59d7d6afe1c6fb74e0100000000000000000000000000ffff52d31528270fb76ced2307e84810443d29baada0b3ece85c94dd9492e693537ddcd32edf56a800899c59e64f3e78156a4901072e5b470a21aa7841ad9abbb00cbc0d2c129e82fb4328fdeee23806c51aefc26fec992c30ead6a6410c1c1b00001976a914c4a7f785e341b694425ea2ddebd8e2249eb5664e88acb66b1aa5263c52fbde60b39f21855a4a0893adaea98f7e8195c2005594a7012a4cd2ca50b36e0a2bb1b6b29da140448b47eeb7a12068bb0141202f9d029a3f810d06e1d0001cbe8228af14af79d24ec28f5a5616a23f8b259e100b8533709c3543b4163251f60283d91670cdde5e975887e6a99ce28a001df528"
        );
        let payload: ProviderRegistrationPayload =
            deserialize(&payload_bytes).expect("deserialize payload");

        assert_eq!(payload.version, 2);
        assert_eq!(payload.masternode_type, ProviderMasternodeType::HighPerformance);
        // The wire carries `4cd2ca50b36e0a2bb1b6b29da140448b47eeb7a1` (Dash
        // Core's internal uint160 blob order); the decoded id is the canonical
        // Tenderdash form, i.e. the byte-reversal.
        assert_eq!(
            payload.platform_node_id,
            Some(
                "a1b7ee478b4440a19db2b6b12b0a6eb350cad24c"
                    .parse()
                    .expect("valid platform node id hex")
            )
        );
        assert_eq!(payload.platform_p2p_port, Some(26656));
        assert_eq!(payload.platform_http_port, Some(443));

        let mut serialized_payload_bytes = Vec::new();

        payload.consensus_encode(&mut serialized_payload_bytes).expect("serialize payload");

        assert_eq!(serialized_payload_bytes, payload_bytes);
    }

    fn ext_net_info() -> ExtNetInfo {
        use crate::sml::masternode_list_entry::net_info::{
            Bip155Network, NetInfoEntry, NetInfoPurpose,
        };
        ExtNetInfo {
            version: 1,
            purposes: vec![(
                NetInfoPurpose::CoreP2P,
                vec![NetInfoEntry::Service {
                    network: Bip155Network::Ipv4,
                    addr: vec![1, 2, 3, 4],
                    port: 9999,
                }],
            )],
        }
    }

    fn share(owner: u8) -> CollateralShare {
        CollateralShare {
            amount: 500 * 100_000_000,
            script_refund: ScriptBuf::from(vec![owner; 25]),
            script_reward: ScriptBuf::new(),
            owner_key_hash: PubkeyHash::from_byte_array([owner; 20]),
        }
    }

    /// A version 2 payload, an Evo one at 52.36.64.148:19999 when `evo`.
    fn v2_payload(evo: bool) -> ProviderRegistrationPayload {
        ProviderRegistrationPayload {
            version: 2,
            masternode_type: if evo {
                ProviderMasternodeType::HighPerformance
            } else {
                ProviderMasternodeType::Regular
            },
            masternode_mode: 0,
            collateral_outpoint: OutPoint::new(Txid::from_byte_array([1; 32]), 1),
            service_address: MasternodeNetInfo::Legacy(SocketAddr::from((
                [52, 36, 64, 148],
                19999,
            ))),
            owner_key_hash: PubkeyHash::from_byte_array([2; 20]),
            operator_public_key: BLSPublicKey::from([3; 48]),
            voting_key_hash: PubkeyHash::from_byte_array([4; 20]),
            operator_reward: 100,
            script_payout: ScriptBuf::from(vec![5; 25]),
            inputs_hash: InputsHash::from_byte_array([6; 32]),
            signature: vec![7; 65],
            platform_node_id: evo.then(|| PlatformNodeId::from_byte_array([8; 20])),
            platform_p2p_port: evo.then_some(26656),
            platform_http_port: evo.then_some(443),
            payouts: None,
            shared_collateral: None,
        }
    }

    /// A version 3 payload with `shares` collateral owners.
    fn v3_payload(evo: bool, shares: u8) -> ProviderRegistrationPayload {
        ProviderRegistrationPayload {
            version: 3,
            service_address: MasternodeNetInfo::Extended(ext_net_info()),
            script_payout: ScriptBuf::new(),
            platform_p2p_port: None,
            platform_http_port: None,
            payouts: Some(vec![MasternodePayoutShare {
                script_payout: ScriptBuf::from(vec![5; 25]),
                reward: 10000,
            }]),
            shared_collateral: Some(SharedCollateral {
                shares: (0..shares).map(share).collect(),
                join_sigs: (0..shares).map(|i| CompactSignature::from([i; 65])).collect(),
                early_period_blocks: 1000,
                early_penalty: 100_000_000,
            }),
            ..v2_payload(evo)
        }
    }

    #[test_case::test_case(v2_payload(false) ; "v2 regular")]
    #[test_case::test_case(v2_payload(true) ; "v2 evo")]
    #[test_case::test_case(v3_payload(false, 0) ; "v3 regular")]
    #[test_case::test_case(v3_payload(false, 2) ; "v3 shared")]
    #[test_case::test_case(v3_payload(true, 2) ; "v3 shared evo")]
    fn round_trips(payload: ProviderRegistrationPayload) {
        let mut encoded = Vec::new();
        payload.consensus_encode(&mut encoded).unwrap();
        assert_eq!(payload.size(), encoded.len());
        let mut reader = &encoded[..];
        assert_eq!(ProviderRegistrationPayload::consensus_decode(&mut reader).unwrap(), payload);
        assert!(reader.is_empty());

        #[cfg(feature = "bincode")]
        {
            let config = bincode::config::standard();
            let bytes = bincode::encode_to_vec(&payload, config).unwrap();
            assert_eq!(
                bincode::decode_from_slice(&bytes, config).unwrap(),
                (payload.clone(), bytes.len())
            );
        }
        #[cfg(all(feature = "serde", feature = "bincode"))]
        {
            let config = bincode::config::standard();
            let bytes = bincode::serde::encode_to_vec(&payload, config).unwrap();
            assert_eq!(
                bincode::serde::decode_from_slice(&bytes, config).unwrap(),
                (payload.clone(), bytes.len())
            );
        }
        #[cfg(feature = "serde")]
        {
            let json = serde_json::to_string(&payload).unwrap();
            assert_eq!(
                serde_json::from_str::<ProviderRegistrationPayload>(&json).unwrap(),
                payload
            );
        }
    }

    #[test]
    fn v3_layout_follows_core() {
        let payload = v3_payload(true, 2);
        let mut encoded = Vec::new();
        payload.consensus_encode(&mut encoded).unwrap();

        // `netInfo` follows version + type + mode + collateral outpoint, in place of ip + port.
        let mut net_info = Vec::new();
        ext_net_info().consensus_encode_ext(&mut net_info).unwrap();
        let mut at = 2 + 2 + 2 + 36;
        assert_eq!(&encoded[at..at + net_info.len()], net_info.as_slice());
        // Then the owner, operator and voting keys and the operator reward, the payouts and
        // the share count.
        at += net_info.len() + 20 + 48 + 20 + 2;
        assert_eq!(encoded[at], 1);
        at += 1 + payload.payouts.as_ref().unwrap()[0].size();
        assert_eq!(encoded[at], 2);
        // The join signatures come after both shares, as bare 65 bytes each.
        at += 1 + share(0).size() + share(1).size();
        assert_eq!(&encoded[at..at + 65], &[0; 65]);
        assert_eq!(&encoded[at + 65..at + 130], &[1; 65]);
        // The Evo node id sits right before the signature, with no platform ports after it.
        assert_eq!(&encoded[encoded.len() - 66 - 20..encoded.len() - 66], &[8; 20]);
    }

    #[test_case::test_case(0 ; "version 0")]
    #[test_case::test_case(4 ; "version 4")]
    fn rejects_unknown_versions(version: u16) {
        let mut encoded = Vec::new();
        v3_payload(false, 0).consensus_encode(&mut encoded).unwrap();
        encoded[..2].copy_from_slice(&version.to_le_bytes());
        assert!(ProviderRegistrationPayload::consensus_decode(&mut &encoded[..]).is_err());
    }

    #[test_case::test_case(ProviderRegistrationPayload { version: 2, ..v3_payload(false, 0) } ; "extended address before v3")]
    #[test_case::test_case(ProviderRegistrationPayload { version: 3, ..v2_payload(false) } ; "legacy address at v3")]
    #[test_case::test_case(ProviderRegistrationPayload { payouts: None, ..v3_payload(false, 0) } ; "v3 without payouts")]
    #[test_case::test_case(ProviderRegistrationPayload { shared_collateral: None, ..v3_payload(false, 0) } ; "v3 without shared collateral")]
    #[test_case::test_case({
        let mut payload = v3_payload(false, 2);
        payload.shared_collateral.as_mut().unwrap().join_sigs.pop();
        payload
    } ; "a join signature missing")]
    fn fails_to_encode(payload: ProviderRegistrationPayload) {
        assert!(payload.consensus_encode(&mut Vec::new()).is_err());
    }

    /// The shape `ProviderRegistrationPayload` had with derived serde and bincode before version 3.
    #[cfg(all(feature = "serde", feature = "bincode"))]
    #[derive(serde::Serialize, bincode::Encode)]
    struct PreV3ProviderRegistrationPayload {
        version: u16,
        masternode_type: ProviderMasternodeType,
        masternode_mode: u16,
        collateral_outpoint: OutPoint,
        service_address: SocketAddr,
        owner_key_hash: PubkeyHash,
        operator_public_key: BLSPublicKey,
        voting_key_hash: PubkeyHash,
        operator_reward: u16,
        script_payout: ScriptBuf,
        inputs_hash: InputsHash,
        signature: Vec<u8>,
        platform_node_id: Option<PlatformNodeId>,
        platform_p2p_port: Option<u16>,
        platform_http_port: Option<u16>,
    }

    #[cfg(all(feature = "serde", feature = "bincode"))]
    #[test_case::test_case(false ; "regular")]
    #[test_case::test_case(true ; "evo")]
    fn keeps_the_pre_v3_formats_before_version_3(evo: bool) {
        let payload = v2_payload(evo);
        let MasternodeNetInfo::Legacy(service_address) = payload.service_address.clone() else {
            unreachable!()
        };
        let old = PreV3ProviderRegistrationPayload {
            version: payload.version,
            masternode_type: payload.masternode_type,
            masternode_mode: payload.masternode_mode,
            collateral_outpoint: payload.collateral_outpoint,
            service_address,
            owner_key_hash: payload.owner_key_hash,
            operator_public_key: payload.operator_public_key,
            voting_key_hash: payload.voting_key_hash,
            operator_reward: payload.operator_reward,
            script_payout: payload.script_payout.clone(),
            inputs_hash: payload.inputs_hash,
            signature: payload.signature.clone(),
            platform_node_id: payload.platform_node_id,
            platform_p2p_port: payload.platform_p2p_port,
            platform_http_port: payload.platform_http_port,
        };
        let config = bincode::config::standard();
        assert_eq!(
            bincode::encode_to_vec(&payload, config).unwrap(),
            bincode::encode_to_vec(&old, config).unwrap()
        );
        assert_eq!(
            bincode::serde::encode_to_vec(&payload, config).unwrap(),
            bincode::serde::encode_to_vec(&old, config).unwrap()
        );
        assert_eq!(serde_json::to_value(&payload).unwrap(), serde_json::to_value(&old).unwrap());
    }

    /// The JSON of a valid payload relabelled with the version of the other layout.
    #[cfg(feature = "serde")]
    #[test_case::test_case(v3_payload(false, 0), 2 ; "v3 fields before version 3")]
    #[test_case::test_case(v2_payload(false), 3 ; "service_address at version 3")]
    fn json_rejects_the_fields_of_another_version(
        payload: ProviderRegistrationPayload,
        version: u16,
    ) {
        let mut json = serde_json::to_value(&payload).unwrap();
        json["version"] = version.into();
        assert!(serde_json::from_value::<ProviderRegistrationPayload>(json).is_err());
    }
}
