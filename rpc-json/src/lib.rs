// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # Rust Client for Dash Core API
//!
//! This is a client library for the Dash Core JSON-RPC API.
//!

#![crate_name = "dashcore_rpc_json"]
#![crate_type = "rlib"]

pub use dashcore;

use bincode::{Decode, Encode};
use serde_repr::*;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use dashcore::address;
use dashcore::address::NetworkUnchecked;
use dashcore::block::Version;
use dashcore::consensus::encode;
use dashcore::hashes::sha256;
use dashcore::{
    Address, Amount, BlockHash, PrivateKey, ProTxHash, PublicKey, QuorumHash, Script, ScriptBuf,
    SignedAmount, Transaction, TxMerkleNode, Txid, bip158,
};
use hex::FromHexError;
use key_wallet::bip32;
use serde::de::Error as SerdeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use serde_json::Value;
use serde_with::{Bytes, DeserializeAs, DisplayFromStr, serde_as};
//TODO(stevenroose) consider using a Time type

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetNetworkInfoResultNetwork {
    pub name: String,
    pub limited: bool,
    pub reachable: bool,
    pub proxy: String,
    pub proxy_randomize_credentials: bool,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetNetworkInfoResultAddress {
    pub address: String,
    pub port: usize,
    pub score: usize,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetNetworkInfoResult {
    pub version: usize,
    #[serde(rename = "buildversion")]
    pub build_version: String,
    pub subversion: String,
    #[serde(rename = "protocolversion")]
    pub protocol_version: usize,
    #[serde(rename = "localservices")]
    pub local_services: String,
    #[serde(rename = "localservicesnames")]
    pub local_services_names: Vec<String>,
    #[serde(rename = "localrelay")]
    pub local_relay: bool,
    #[serde(rename = "timeoffset")]
    pub time_offset: isize,
    #[serde(rename = "networkactive")]
    pub network_active: bool,
    pub connections: usize,
    #[serde(rename = "connections_in")]
    pub inbound_connections: usize,
    #[serde(rename = "connections_out")]
    pub outbound_connections: usize,
    #[serde(rename = "connections_mn")]
    pub mn_connections: usize,
    #[serde(rename = "connections_mn_in")]
    pub inbound_mn_connections: usize,
    #[serde(rename = "connections_mn_out")]
    pub outbound_mn_connections: usize,
    #[serde(rename = "socketevents")]
    pub socket_events: String,
    pub networks: Vec<GetNetworkInfoResultNetwork>,
    #[serde(rename = "relayfee", with = "dashcore::amount::serde::as_btc")]
    pub relay_fee: Amount,
    #[serde(rename = "incrementalfee", with = "dashcore::amount::serde::as_btc")]
    pub incremental_fee: Amount,
    #[serde(rename = "localaddresses")]
    pub local_addresses: Vec<GetNetworkInfoResultAddress>,
    pub warnings: String,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddMultiSigAddressResult {
    pub address: Address<NetworkUnchecked>,
    pub redeem_script: ScriptBuf,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct LoadWalletResult {
    pub name: String,
    pub warning: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum UnloadWalletResult {
    Empty(),
    Warning {
        warning: String,
    },
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct GetWalletInfoResult {
    #[serde(rename = "walletname")]
    pub wallet_name: String,
    #[serde(rename = "walletversion")]
    pub wallet_version: u32,
    #[serde(with = "dashcore::amount::serde::as_btc")]
    pub balance: Amount,
    #[serde(with = "dashcore::amount::serde::as_btc")]
    pub coinjoin_balance: Amount,
    #[serde(with = "dashcore::amount::serde::as_btc")]
    pub unconfirmed_balance: Amount,
    #[serde(with = "dashcore::amount::serde::as_btc")]
    pub immature_balance: Amount,
    #[serde(rename = "txcount")]
    pub tx_count: usize,
    #[serde(rename = "timefirstkey")]
    pub time_first_key: u32,
    #[serde(rename = "keypoololdest")]
    pub keypool_oldest: usize,
    #[serde(rename = "keypoolsize")]
    pub keypool_size: usize,
    #[serde(rename = "keypoolsize_hd_internal")]
    pub keypool_size_hd_internal: Option<usize>,
    pub keys_left: usize,
    pub unlocked_until: Option<u64>,
    #[serde(rename = "paytxfee")]
    pub pay_tx_fee: f32,
    #[serde(default, rename = "hdchainid", deserialize_with = "deserialize_hex_opt")]
    pub hd_chainid: Option<Vec<u8>>,
    #[serde(rename = "hdaccountcount")]
    pub hd_account_count: Option<u32>,
    // disable until to get specification about where these fields should be
    // #[serde(rename = "hdaccountcountindex")]
    // pub hd_account_count_index: Option<u32>,
    // #[serde(rename = "hdexternalkeyindex")]
    // pub hd_external_key_index: Option<u32>,
    // #[serde(rename = "hdinternalkeyindex")]
    // pub hd_internal_key_index: Option<u32>,
    pub scanning: Option<ScanningDetails>,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ScanningDetails {
    Scanning {
        duration: usize,
        progress: f32,
    },
    /// The bool in this field will always be false.
    NotScanning(bool),
}

impl Eq for ScanningDetails {}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct CoinbaseTxDetails {
    pub version: usize,
    pub height: i32,
    #[serde(rename = "merkleRootMNList", with = "hex")]
    merkle_root_mn_list: Vec<u8>,
    #[serde(rename = "merkleRootQuorums", with = "hex")]
    merkle_root_quorums: Vec<u8>,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct GetBestChainLockResult {
    pub blockhash: BlockHash,
    pub height: u32,
    #[serde(with = "hex")]
    pub signature: Vec<u8>,
    pub known_block: bool,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockResult {
    pub hash: BlockHash,
    pub confirmations: i32,
    pub size: usize,
    pub strippedsize: Option<usize>,
    pub height: usize,
    pub version: i32,
    #[serde(default, deserialize_with = "deserialize_hex_opt")]
    pub version_hex: Option<Vec<u8>>,
    pub merkleroot: TxMerkleNode,
    pub tx: Vec<Txid>,
    pub cb_tx: CoinbaseTxDetails,
    pub time: usize,
    pub mediantime: usize,
    pub nonce: u32,
    pub bits: String,
    pub difficulty: f64,
    pub chainwork: Vec<u8>,
    pub n_tx: usize,
    pub previousblockhash: Option<BlockHash>,
    pub nextblockhash: Option<BlockHash>,
    pub chainlock: bool,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBlockHeaderResult {
    pub hash: BlockHash,
    pub confirmations: i32,
    pub height: usize,
    pub version: Version,
    #[serde(default, with = "hex")]
    pub version_hex: Vec<u8>,
    #[serde(rename = "merkleroot")]
    pub merkle_root: TxMerkleNode,
    pub time: usize,
    #[serde(rename = "mediantime")]
    pub median_time: Option<usize>,
    pub nonce: u32,
    pub bits: String,
    pub difficulty: f64,
    #[serde(with = "hex")]
    pub chainwork: Vec<u8>,
    pub n_tx: usize,
    #[serde(rename = "previousblockhash")]
    pub previous_block_hash: Option<BlockHash>,
    #[serde(rename = "nextblockhash")]
    pub next_block_hash: Option<BlockHash>,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct GetBlockStatsResult {
    #[serde(rename = "avgfee", with = "dashcore::amount::serde::as_sat")]
    pub avg_fee: Amount,
    #[serde(rename = "avgfeerate", with = "dashcore::amount::serde::as_sat")]
    pub avg_fee_rate: Amount,
    #[serde(rename = "avgtxsize")]
    pub avg_tx_size: u32,
    #[serde(rename = "blockhash")]
    pub block_hash: BlockHash,
    #[serde(rename = "feerate_percentiles")]
    pub fee_rate_percentiles: FeeRatePercentiles,
    pub height: u32,
    pub ins: usize,
    #[serde(rename = "maxfee", with = "dashcore::amount::serde::as_sat")]
    pub max_fee: Amount,
    #[serde(rename = "maxfeerate", with = "dashcore::amount::serde::as_sat")]
    pub max_fee_rate: Amount,
    #[serde(rename = "maxtxsize")]
    pub max_tx_size: u32,
    #[serde(rename = "medianfee", with = "dashcore::amount::serde::as_sat")]
    pub median_fee: Amount,
    #[serde(rename = "mediantime")]
    pub median_time: u64,
    #[serde(rename = "mediantxsize")]
    pub median_tx_size: u32,
    #[serde(rename = "minfee", with = "dashcore::amount::serde::as_sat")]
    pub min_fee: Amount,
    #[serde(rename = "minfeerate", with = "dashcore::amount::serde::as_sat")]
    pub min_fee_rate: Amount,
    #[serde(rename = "mintxsize")]
    pub min_tx_size: u32,
    pub outs: usize,
    #[serde(with = "dashcore::amount::serde::as_sat")]
    pub subsidy: Amount,
    pub time: u64,
    #[serde(with = "dashcore::amount::serde::as_sat")]
    pub total_out: Amount,
    #[serde(rename = "total_size")]
    pub total_size: usize,
    #[serde(rename = "totalfee", with = "dashcore::amount::serde::as_sat")]
    pub total_fee: Amount,
    pub txs: usize,
    pub utxo_increase: i32,
    pub utxo_size_inc: i32,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct GetBlockStatsResultPartial {
    #[serde(
        default,
        rename = "avgfee",
        with = "dashcore::amount::serde::as_sat::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub avg_fee: Option<Amount>,
    #[serde(
        default,
        rename = "avgfeerate",
        with = "dashcore::amount::serde::as_sat::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub avg_fee_rate: Option<Amount>,
    #[serde(default, rename = "avgtxsize", skip_serializing_if = "Option::is_none")]
    pub avg_tx_size: Option<u32>,
    #[serde(default, rename = "blockhash", skip_serializing_if = "Option::is_none")]
    pub block_hash: Option<BlockHash>,
    #[serde(default, rename = "feerate_percentiles", skip_serializing_if = "Option::is_none")]
    pub fee_rate_percentiles: Option<FeeRatePercentiles>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ins: Option<usize>,
    #[serde(
        default,
        rename = "maxfee",
        with = "dashcore::amount::serde::as_sat::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_fee: Option<Amount>,
    #[serde(
        default,
        rename = "maxfeerate",
        with = "dashcore::amount::serde::as_sat::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_fee_rate: Option<Amount>,
    #[serde(default, rename = "maxtxsize", skip_serializing_if = "Option::is_none")]
    pub max_tx_size: Option<u32>,
    #[serde(
        default,
        rename = "medianfee",
        with = "dashcore::amount::serde::as_sat::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub median_fee: Option<Amount>,
    #[serde(default, rename = "mediantime", skip_serializing_if = "Option::is_none")]
    pub median_time: Option<u64>,
    #[serde(default, rename = "mediantxsize", skip_serializing_if = "Option::is_none")]
    pub median_tx_size: Option<u32>,
    #[serde(
        default,
        rename = "minfee",
        with = "dashcore::amount::serde::as_sat::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub min_fee: Option<Amount>,
    #[serde(
        default,
        rename = "minfeerate",
        with = "dashcore::amount::serde::as_sat::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub min_fee_rate: Option<Amount>,
    #[serde(default, rename = "mintxsize", skip_serializing_if = "Option::is_none")]
    pub min_tx_size: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outs: Option<usize>,
    #[serde(
        default,
        with = "dashcore::amount::serde::as_sat::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub subsidy: Option<Amount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time: Option<u64>,
    #[serde(
        default,
        with = "dashcore::amount::serde::as_sat::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub total_out: Option<Amount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_size: Option<usize>,
    #[serde(
        default,
        rename = "totalfee",
        with = "dashcore::amount::serde::as_sat::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub total_fee: Option<Amount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub txs: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub utxo_increase: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub utxo_size_inc: Option<i32>,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct FeeRatePercentiles {
    #[serde(with = "dashcore::amount::serde::as_sat", rename = "10th_percentile_feerate")]
    pub fr_10th: Amount,
    #[serde(with = "dashcore::amount::serde::as_sat", rename = "25th_percentile_feerate")]
    pub fr_25th: Amount,
    #[serde(with = "dashcore::amount::serde::as_sat", rename = "50th_percentile_feerate")]
    pub fr_50th: Amount,
    #[serde(with = "dashcore::amount::serde::as_sat", rename = "75th_percentile_feerate")]
    pub fr_75th: Amount,
    #[serde(with = "dashcore::amount::serde::as_sat", rename = "90th_percentile_feerate")]
    pub fr_90th: Amount,
}

#[derive(Clone)]
pub enum BlockStatsFields {
    AverageFee,
    AverageFeeRate,
    AverageTxSize,
    BlockHash,
    FeeRatePercentiles,
    Height,
    Ins,
    MaxFee,
    MaxFeeRate,
    MaxTxSize,
    MedianFee,
    MedianTime,
    MedianTxSize,
    MinFee,
    MinFeeRate,
    MinTxSize,
    Outs,
    Subsidy,
    SegWitTotalSize,
    SegWitTotalWeight,
    SegWitTxs,
    Time,
    TotalOut,
    TotalSize,
    TotalWeight,
    TotalFee,
    Txs,
    UtxoIncrease,
    UtxoSizeIncrease,
}

impl BlockStatsFields {
    fn get_rpc_keyword(&self) -> &str {
        match *self {
            BlockStatsFields::AverageFee => "avgfee",
            BlockStatsFields::AverageFeeRate => "avgfeerate",
            BlockStatsFields::AverageTxSize => "avgtxsize",
            BlockStatsFields::BlockHash => "blockhash",
            BlockStatsFields::FeeRatePercentiles => "feerate_percentiles",
            BlockStatsFields::Height => "height",
            BlockStatsFields::Ins => "ins",
            BlockStatsFields::MaxFee => "maxfee",
            BlockStatsFields::MaxFeeRate => "maxfeerate",
            BlockStatsFields::MaxTxSize => "maxtxsize",
            BlockStatsFields::MedianFee => "medianfee",
            BlockStatsFields::MedianTime => "mediantime",
            BlockStatsFields::MedianTxSize => "mediantxsize",
            BlockStatsFields::MinFee => "minfee",
            BlockStatsFields::MinFeeRate => "minfeerate",
            BlockStatsFields::MinTxSize => "minfeerate",
            BlockStatsFields::Outs => "outs",
            BlockStatsFields::Subsidy => "subsidy",
            BlockStatsFields::SegWitTotalSize => "swtotal_size",
            BlockStatsFields::SegWitTotalWeight => "swtotal_weight",
            BlockStatsFields::SegWitTxs => "swtxs",
            BlockStatsFields::Time => "time",
            BlockStatsFields::TotalOut => "total_out",
            BlockStatsFields::TotalSize => "total_size",
            BlockStatsFields::TotalWeight => "total_weight",
            BlockStatsFields::TotalFee => "totalfee",
            BlockStatsFields::Txs => "txs",
            BlockStatsFields::UtxoIncrease => "utxo_increase",
            BlockStatsFields::UtxoSizeIncrease => "utxo_size_inc",
        }
    }
}

impl Display for BlockStatsFields {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.get_rpc_keyword())
    }
}

impl From<BlockStatsFields> for serde_json::Value {
    fn from(bsf: BlockStatsFields) -> Self {
        Self::from(bsf.to_string())
    }
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetMiningInfoResult {
    pub blocks: u32,
    #[serde(rename = "currentblockweight")]
    pub current_block_weight: Option<u64>,
    #[serde(rename = "currentblocktx")]
    pub current_block_tx: Option<usize>,
    pub difficulty: f64,
    #[serde(rename = "networkhashps")]
    pub network_hash_ps: f64,
    #[serde(rename = "pooledtx")]
    pub pooled_tx: usize,
    pub chain: String,
    pub warnings: String,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResultVinScriptSig {
    pub asm: String,
    #[serde(with = "hex")]
    pub hex: Vec<u8>,
}

impl GetRawTransactionResultVinScriptSig {
    pub fn script(&self) -> Result<ScriptBuf, encode::Error> {
        Ok(ScriptBuf::from(self.hex.clone()))
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResultVin {
    pub txid: Option<String>,
    pub vout: Option<u32>,
    pub script_sig: Option<GetRawTransactionResultVinScriptSig>,
    #[serde(default, deserialize_with = "deserialize_hex_opt")]
    pub coinbase: Option<Vec<u8>>,
    #[serde(default, with = "dashcore::amount::serde::as_btc::opt")]
    pub value: Option<Amount>,
    #[serde(default)]
    pub value_sat: Option<u64>,
    pub addresses: Option<Vec<String>>,
    pub sequence: u32,
}

impl GetRawTransactionResultVin {
    /// Whether this input is from a coinbase tx.
    /// The `txid`, `vout` and `script_sig` fields are not provided
    /// for coinbase transactions.
    pub fn is_coinbase(&self) -> bool {
        self.coinbase.is_some()
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResultVoutScriptPubKey {
    pub asm: String,
    #[serde(with = "hex")]
    pub hex: Vec<u8>,
    #[serde(rename = "reqSigs")]
    pub req_sigs: Option<usize>,
    #[serde(rename = "type")]
    pub script_type: Option<ScriptPubkeyType>,
    pub addresses: Option<Vec<Address<NetworkUnchecked>>>,
}

impl GetRawTransactionResultVoutScriptPubKey {
    pub fn script(&self) -> Result<ScriptBuf, encode::Error> {
        Ok(ScriptBuf::from(self.hex.clone()))
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResultVout {
    #[serde(with = "dashcore::amount::serde::as_btc")]
    pub value: Amount,
    #[serde(rename = "valueSat")]
    pub value_sat: u64,
    pub n: u32,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: GetRawTransactionResultVoutScriptPubKey,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRawTransactionResult {
    #[serde(default, rename = "in_active_chain")]
    pub in_active_chain: bool,
    pub txid: Txid,
    pub size: usize,
    pub version: u32,
    #[serde(rename = "type")]
    pub tx_type: u32,
    pub locktime: u32,
    pub vin: Vec<GetRawTransactionResultVin>,
    pub vout: Vec<GetRawTransactionResultVout>,
    pub extra_payload_size: Option<u32>,
    #[serde(default, deserialize_with = "deserialize_hex_opt")]
    pub extra_payload: Option<Vec<u8>>,
    #[serde(with = "hex")]
    pub hex: Vec<u8>,
    pub blockhash: Option<BlockHash>,
    pub height: Option<i32>,
    pub confirmations: Option<u32>,
    pub time: Option<usize>,
    pub blocktime: Option<usize>,
    pub instantlock: bool,
    #[serde(rename = "instantlock_internal")]
    pub instantlock_internal: bool,
    pub chainlock: bool,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetBlockFilterResult {
    pub header: dashcore::FilterHash,
    #[serde(with = "hex")]
    pub filter: Vec<u8>,
}

impl GetBlockFilterResult {
    /// Get the filter.
    /// Note that this copies the underlying filter data. To prevent this,
    /// use [`Self::into_filter`] instead.
    pub fn to_filter(&self) -> bip158::BlockFilter {
        bip158::BlockFilter::new(&self.filter)
    }

    /// Convert the result in the filter type.
    pub fn into_filter(self) -> bip158::BlockFilter {
        bip158::BlockFilter {
            content: self.filter,
        }
    }
}

impl GetRawTransactionResult {
    /// Whether this tx is a coinbase tx.
    pub fn is_coinbase(&self) -> bool {
        self.vin.len() == 1 && self.vin[0].is_coinbase()
    }

    pub fn transaction(&self) -> Result<Transaction, encode::Error> {
        encode::deserialize(&self.hex)
    }
}

/// Enum to represent the BIP125 replaceable status for a transaction.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Bip125Replaceable {
    Yes,
    No,
    Unknown,
}

/// Enum to represent the category of a transaction.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GetTransactionResultDetailCategory {
    Send,
    Receive,
    Generate,
    Immature,
    Orphan,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct GetTransactionResultDetail {
    #[serde(rename = "involvesWatchonly")]
    pub involves_watchonly: Option<bool>,
    pub address: Option<Address<NetworkUnchecked>>,
    pub category: GetTransactionResultDetailCategory,
    #[serde(with = "dashcore::amount::serde::as_btc")]
    pub amount: SignedAmount,
    pub label: Option<String>,
    pub vout: u32,
    #[serde(default, with = "dashcore::amount::serde::as_btc::opt")]
    pub fee: Option<SignedAmount>,
    pub abandoned: Option<bool>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct WalletTxInfo {
    pub confirmations: i32,
    pub blockhash: Option<BlockHash>,
    pub blockindex: Option<usize>,
    pub blocktime: Option<u64>,
    pub blockheight: Option<u32>,
    pub txid: Txid,
    pub time: u64,
    pub timereceived: u64,
    /// Conflicting transaction ids
    #[serde(rename = "walletconflicts")]
    pub wallet_conflicts: Vec<Txid>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct GetTransactionLockedResult {
    pub height: i32,
    pub chainlock: bool,
    pub mempool: bool,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AssetUnlockStatus {
    Chainlocked,
    Mined,
    Mempooled,
    Unknown,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct AssetUnlockStatusResult {
    pub index: u64,
    pub status: AssetUnlockStatus,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct ListTransactionResult {
    #[serde(flatten)]
    pub info: WalletTxInfo,
    #[serde(flatten)]
    pub detail: GetTransactionResultDetail,

    pub trusted: Option<bool>,
    pub comment: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct ListSinceBlockResult {
    pub transactions: Vec<ListTransactionResult>,
    #[serde(default)]
    pub removed: Vec<ListTransactionResult>,
    pub lastblock: BlockHash,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetTxOutResult {
    pub bestblock: BlockHash,
    pub confirmations: u32,
    #[serde(with = "dashcore::amount::serde::as_btc")]
    pub value: Amount,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: GetRawTransactionResultVoutScriptPubKey,
    pub coinbase: bool,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ListUnspentQueryOptions {
    #[serde(
        rename = "minimumAmount",
        with = "dashcore::amount::serde::as_btc::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub minimum_amount: Option<Amount>,
    #[serde(
        rename = "maximumAmount",
        with = "dashcore::amount::serde::as_btc::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub maximum_amount: Option<Amount>,
    #[serde(rename = "maximumCount", skip_serializing_if = "Option::is_none")]
    pub maximum_count: Option<usize>,
    #[serde(
        rename = "minimumSumAmount",
        with = "dashcore::amount::serde::as_btc::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub minimum_sum_amount: Option<Amount>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct ListUnspentResultEntry {
    pub txid: Txid,
    pub vout: u32,
    pub address: Option<Address<NetworkUnchecked>>,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: ScriptBuf,
    #[serde(rename = "redeemScript")]
    pub redeem_script: Option<ScriptBuf>,
    #[serde(with = "dashcore::amount::serde::as_btc")]
    pub amount: Amount,
    pub confirmations: u32,
    pub spendable: bool,
    pub solvable: bool,
    #[serde(rename = "desc")]
    pub descriptor: Option<String>,
    pub reused: Option<bool>,
    pub safe: bool,
    pub coinjoin_rounds: i32,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListReceivedByAddressResult {
    #[serde(default, rename = "involvesWatchonly")]
    pub involved_watch_only: bool,
    pub address: Address<NetworkUnchecked>,
    #[serde(with = "dashcore::amount::serde::as_btc")]
    pub amount: Amount,
    pub confirmations: u32,
    pub label: String,
    pub txids: Vec<Txid>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct SignRawTransactionResult {
    #[serde(with = "hex")]
    pub hex: Vec<u8>,
    pub complete: bool,
}

impl SignRawTransactionResult {
    pub fn transaction(&self) -> Result<Transaction, encode::Error> {
        encode::deserialize(&self.hex)
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct TestMempoolAcceptResult {
    pub txid: Txid,
    pub allowed: bool,
    #[serde(rename = "reject-reason")]
    pub reject_reason: Option<String>,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Bip9SoftforkStatus {
    Defined,
    Started,
    LockedIn,
    Active,
    Failed,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct Bip9SoftforkStatistics {
    pub period: Option<u32>,
    pub threshold: Option<u32>,
    pub elapsed: Option<u32>,
    pub count: Option<u32>,
    pub possible: Option<bool>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct Bip9SoftforkInfo {
    pub status: Bip9SoftforkStatus,
    pub bit: Option<u8>,
    // Can be -1 for 0.18.x inactive ones.
    pub start_time: i64,
    pub timeout: u64,
    pub since: u32,
    pub statistics: Option<Bip9SoftforkStatistics>,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SoftforkType {
    Buried,
    Bip9,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct SoftforkInfo {
    #[serde(rename = "type")]
    pub softfork_type: SoftforkType,
    pub active: bool,
    pub height: Option<u32>,
    pub bip9: Option<Bip9SoftforkInfo>,
}

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ScriptPubkeyType {
    Nonstandard,
    Pubkey,
    PubkeyHash,
    ScriptHash,
    MultiSig,
    NullData,
    Witness_v0_KeyHash,
    Witness_v0_ScriptHash,
    Witness_v1_Taproot,
    Witness_Unknown,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GetAddressInfoResultLabelPurpose {
    Send,
    Receive,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum GetAddressInfoResultLabel {
    Simple(String),
    WithPurpose {
        name: String,
        purpose: GetAddressInfoResultLabelPurpose,
    },
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetAddressInfoResult {
    pub address: Address<NetworkUnchecked>,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: ScriptBuf,
    #[serde(rename = "ismine")]
    pub is_mine: bool,
    #[serde(rename = "iswatchonly")]
    pub is_watchonly: bool,
    pub solvable: bool,
    pub desc: Option<String>,
    #[serde(rename = "isscript")]
    pub is_script: bool,
    #[serde(rename = "ischange")]
    pub is_change: bool,
    pub script: Option<ScriptPubkeyType>,
    /// The redeemscript for the p2sh address.
    #[serde(default, deserialize_with = "deserialize_hex_opt")]
    pub hex: Option<Vec<u8>>,
    pub pubkeys: Option<Vec<PublicKey>>,
    pub pubkey: Option<PublicKey>,
    #[serde(rename = "sigsrequired")]
    pub signatures_required: Option<usize>,
    #[serde(rename = "iscompressed")]
    pub is_compressed: Option<bool>,
    /// Deprecated in v0.20.0. See `labels` field instead.
    #[deprecated(note = "since Core v0.20.0")]
    pub label: Option<String>,
    pub timestamp: Option<u64>,
    #[serde(rename = "hdchainid")]
    pub hd_chain_id: Option<String>,
    #[serde(rename = "hdkeypath")]
    pub hd_key_path: Option<bip32::DerivationPath>,
    #[serde(rename = "hdmasterfingerprint")]
    pub hd_master_fingerprint: Option<String>,
    pub labels: Vec<GetAddressInfoResultLabel>,
}

/// Models the result of "getblockchaininfo"
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GetBlockchainInfoResult {
    /// Current network name as defined in BIP70 (main, test, regtest)
    pub chain: String,
    /// The current number of blocks processed in the server
    pub blocks: u64,
    /// The current number of headers we have validated
    pub headers: u64,
    /// The hash of the currently best block
    #[serde(rename = "bestblockhash")]
    pub best_block_hash: BlockHash,
    /// The current difficulty
    pub difficulty: f64,
    /// Median time for the current best block
    #[serde(rename = "mediantime")]
    pub median_time: u64,
    /// Estimate of verification progress [0..1]
    #[serde(rename = "verificationprogress")]
    pub verification_progress: f64,
    /// Estimate of whether this node is in Initial Block Download mode
    #[serde(rename = "initialblockdownload")]
    pub initial_block_download: bool,
    /// Total amount of work in active chain, in hexadecimal
    #[serde(with = "hex")]
    pub chainwork: Vec<u8>,
    /// The estimated size of the block and undo files on disk
    pub size_on_disk: u64,
    /// If the blocks are subject to pruning
    pub pruned: bool,
    /// Lowest-height complete block stored (only present if pruning is enabled)
    #[serde(rename = "pruneheight")]
    pub prune_height: Option<u64>,
    /// Whether automatic pruning is enabled (only present if pruning is enabled)
    pub automatic_pruning: Option<bool>,
    /// The target size used by pruning (only present if automatic pruning is enabled)
    pub prune_target_size: Option<u64>,
    /// Status of softforks in progress
    pub softforks: HashMap<String, SoftforkInfo>,
    /// Any network and blockchain warnings.
    pub warnings: String,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ImportMultiRequestScriptPubkey<'a> {
    Address(&'a Address),
    Script(&'a Script),
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetMempoolEntryResult {
    /// Virtual transaction size as defined in BIP 141. This is different from actual serialized
    /// size for witness transactions as witness data is discounted.
    #[serde(alias = "vsize")]
    pub size: u64,
    /// Transaction weight as defined in BIP 141. Added in Core v0.19.0.
    pub weight: Option<u64>,
    /// Local time transaction entered pool in seconds since 1 Jan 1970 GMT
    pub time: u64,
    /// Block height when transaction entered pool
    pub height: u64,
    /// Number of in-mempool descendant transactions (including this one)
    #[serde(rename = "descendantcount")]
    pub descendant_count: u64,
    /// Virtual transaction size of in-mempool descendants (including this one)
    #[serde(rename = "descendantsize")]
    pub descendant_size: u64,
    /// Number of in-mempool ancestor transactions (including this one)
    #[serde(rename = "ancestorcount")]
    pub ancestor_count: u64,
    /// Virtual transaction size of in-mempool ancestors (including this one)
    #[serde(rename = "ancestorsize")]
    pub ancestor_size: u64,
    /// Fee information
    pub fees: GetMempoolEntryResultFees,
    /// Unconfirmed transactions used as inputs for this transaction
    pub depends: Vec<Txid>,
    /// Unconfirmed transactions spending outputs from this transaction
    #[serde(rename = "spentby")]
    pub spent_by: Vec<Txid>,
    /// Whether this transaction is currently unbroadcast (initial broadcast not yet acknowledged by any peers)
    /// Added in dashcore Core v0.21
    pub unbroadcast: Option<bool>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetMempoolEntryResultFees {
    /// Transaction fee in BTC
    #[serde(with = "dashcore::amount::serde::as_btc")]
    pub base: Amount,
    /// Transaction fee with fee deltas used for mining priority in BTC
    #[serde(with = "dashcore::amount::serde::as_btc")]
    pub modified: Amount,
    /// Modified fees (see above) of in-mempool ancestors (including this one) in BTC
    #[serde(with = "dashcore::amount::serde::as_btc")]
    pub ancestor: Amount,
    /// Modified fees (see above) of in-mempool descendants (including this one) in BTC
    #[serde(with = "dashcore::amount::serde::as_btc")]
    pub descendant: Amount,
}

impl<'a> serde::Serialize for ImportMultiRequestScriptPubkey<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            ImportMultiRequestScriptPubkey::Address(addr) => {
                #[derive(Serialize)]
                struct Tmp<'a> {
                    pub address: &'a Address,
                }
                serde::Serialize::serialize(
                    &Tmp {
                        address: addr,
                    },
                    serializer,
                )
            }
            ImportMultiRequestScriptPubkey::Script(script) => {
                serializer.serialize_str(&script.to_string())
            }
        }
    }
}

/// A import request for importmulti.
///
/// Note: unlike in dashcored, `timestamp` defaults to 0.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize)]
pub struct ImportMultiRequest<'a> {
    pub timestamp: ImportMultiRescanSince,
    /// If using descriptor, do not also provide address/scriptPubKey, scripts, or pubkeys.
    #[serde(rename = "desc", skip_serializing_if = "Option::is_none")]
    pub descriptor: Option<&'a str>,
    #[serde(rename = "scriptPubKey", skip_serializing_if = "Option::is_none")]
    pub script_pubkey: Option<ImportMultiRequestScriptPubkey<'a>>,
    #[serde(rename = "redeemscript", skip_serializing_if = "Option::is_none")]
    pub redeem_script: Option<&'a Script>,
    #[serde(rename = "witnessscript", skip_serializing_if = "Option::is_none")]
    pub witness_script: Option<&'a Script>,
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    pub pubkeys: &'a [PublicKey],
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    pub keys: &'a [PrivateKey],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub range: Option<(usize, usize)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub internal: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub watchonly: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keypool: Option<bool>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize)]
pub struct ImportMultiOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rescan: Option<bool>,
}

#[derive(Clone, PartialEq, Eq, Copy, Debug)]
pub enum ImportMultiRescanSince {
    Now,
    Timestamp(u64),
}

impl serde::Serialize for ImportMultiRescanSince {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            ImportMultiRescanSince::Now => serializer.serialize_str("now"),
            ImportMultiRescanSince::Timestamp(timestamp) => serializer.serialize_u64(timestamp),
        }
    }
}

impl<'de> serde::Deserialize<'de> for ImportMultiRescanSince {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = ImportMultiRescanSince;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                write!(formatter, "unix timestamp or 'now'")
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(ImportMultiRescanSince::Timestamp(value))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value == "now" {
                    Ok(ImportMultiRescanSince::Now)
                } else {
                    Err(de::Error::custom(format!(
                        "invalid str '{}', expecting 'now' or unix timestamp",
                        value
                    )))
                }
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

impl Default for ImportMultiRescanSince {
    fn default() -> Self {
        ImportMultiRescanSince::Timestamp(0)
    }
}

impl From<u64> for ImportMultiRescanSince {
    fn from(timestamp: u64) -> Self {
        ImportMultiRescanSince::Timestamp(timestamp)
    }
}

impl From<Option<u64>> for ImportMultiRescanSince {
    fn from(timestamp: Option<u64>) -> Self {
        timestamp.map_or(ImportMultiRescanSince::Now, ImportMultiRescanSince::Timestamp)
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct ImportMultiResultError {
    pub code: i64,
    pub message: String,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct ImportMultiResultImport {
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: Option<Vec<u8>>,
    pub address: Option<Address<NetworkUnchecked>>,
    pub timestamp: ImportMultiRescanSince,
    #[serde(rename = "redeemscript")]
    pub redeem_script: Option<String>,
    pub pubkeys: Option<Vec<String>>,
    pub keys: Option<Vec<String>>,
    pub internal: Option<bool>,
    pub watchonly: Option<bool>,
    pub label: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct ImportMultiResult {
    pub success: bool,
    #[serde(default)]
    pub warnings: Vec<String>,
    pub error: Option<ImportMultiResultError>,
}

/// Progress toward rejecting pre-softfork blocks
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct RejectStatus {
    /// `true` if threshold reached
    pub status: bool,
}

/// Models the result of "getpeerinfo"
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GetPeerInfoResult {
    /// Peer index
    pub id: u64,
    /// The IP address and port of the peer
    pub addr: SocketAddr,
    /// Bind address of the connection to the peer
    // TODO: use a type for addrbind
    pub addrbind: String,
    /// Local address as reported by the peer
    // TODO: use a type for addrlocal
    pub addrlocal: Option<String>,
    /// Network (ipv4, ipv6, or onion) the peer connected through
    /// Added in Bitcoin Core v0.21
    pub network: Option<GetPeerInfoResultNetwork>,
    /// The services offered
    // TODO: use a type for services
    pub services: String,
    /// Whether peer has asked us to relay transactions to it
    pub relaytxes: bool,
    /// The time in seconds since epoch (Jan 1 1970 GMT) of the last send
    pub lastsend: u64,
    /// The time in seconds since epoch (Jan 1 1970 GMT) of the last receive
    pub lastrecv: u64,
    /// The time in seconds since epoch (Jan 1 1970 GMT) of the last valid transaction received from this peer
    /// Added in Bitcoin Core v0.21
    pub last_transaction: Option<u64>,
    /// The time in seconds since epoch (Jan 1 1970 GMT) of the last block received from this peer
    /// Added in Bitcoin Core v0.21
    pub last_block: Option<u64>,
    /// The total bytes sent
    pub bytessent: u64,
    /// The total bytes received
    pub bytesrecv: u64,
    /// The connection time in seconds since epoch (Jan 1 1970 GMT)
    pub conntime: u64,
    /// The time offset in seconds
    pub timeoffset: i64,
    /// ping time (if available)
    pub pingtime: Option<f64>,
    /// minimum observed ping time (if any at all)
    pub minping: Option<f64>,
    /// ping wait (if non-zero)
    pub pingwait: Option<f64>,
    /// The peer version, such as 70001
    pub version: u64,
    /// The string version
    pub subver: String,
    /// Inbound (true) or Outbound (false)
    pub inbound: bool,
    /// Whether connection was due to `addnode`/`-connect` or if it was an
    /// automatic/inbound connection
    /// Deprecated in Bitcoin Core v0.21
    pub addnode: Option<bool>,
    /// The starting height (block) of the peer
    pub startingheight: i64,
    /// The ban score
    /// Deprecated in Bitcoin Core v0.21
    pub banscore: Option<i64>,
    /// The last header we have in common with this peer
    pub synced_headers: i64,
    /// The last block we have in common with this peer
    pub synced_blocks: i64,
    /// The heights of blocks we're currently asking from this peer
    pub inflight: Vec<u64>,
    /// Whether the peer is whitelisted
    /// Deprecated in Bitcoin Core v0.21
    pub whitelisted: Option<bool>,
    #[serde(rename = "minfeefilter", default, with = "dashcore::amount::serde::as_btc::opt")]
    pub min_fee_filter: Option<Amount>,
    /// The total bytes sent aggregated by message type
    pub bytessent_per_msg: HashMap<String, u64>,
    /// The total bytes received aggregated by message type
    pub bytesrecv_per_msg: HashMap<String, u64>,
    /// The type of the connection
    /// Added in Bitcoin Core v0.21
    pub connection_type: Option<GetPeerInfoResultConnectionType>,
}

#[derive(Copy, Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum GetPeerInfoResultNetwork {
    Ipv4,
    Ipv6,
    Onion,
    NotPubliclyRoutable,
    I2p,
    Cjdns,
    Internal,
}

#[derive(Copy, Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum GetPeerInfoResultConnectionType {
    OutboundFullRelay,
    BlockRelayOnly,
    Inbound,
    Manual,
    AddrFetch,
    Feeler,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetAddedNodeInfoResult {
    /// The node IP address or name (as provided to addnode)
    #[serde(rename = "addednode")]
    pub added_node: String,
    ///  If connected
    pub connected: bool,
    /// Only when connected = true
    pub addresses: Vec<GetAddedNodeInfoResultAddress>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetAddedNodeInfoResultAddress {
    /// The dashcore server IP and port we're connected to
    pub address: String,
    /// connection, inbound or outbound
    pub connected: GetAddedNodeInfoResultAddressType,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GetAddedNodeInfoResultAddressType {
    Inbound,
    Outbound,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetNodeAddressesResult {
    /// Timestamp in seconds since epoch (Jan 1 1970 GMT) keeping track of when the node was last seen
    pub time: u64,
    /// The services offered
    pub services: usize,
    /// The address of the node
    pub address: String,
    /// The port of the node
    pub port: u16,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct ListBannedResult {
    pub address: String,
    pub banned_until: u64,
    pub ban_created: u64,
}

/// Models the result of "estimatesmartfee"
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EstimateSmartFeeResult {
    /// Estimate fee rate in BTC/kB.
    #[serde(
        default,
        rename = "feerate",
        skip_serializing_if = "Option::is_none",
        with = "dashcore::amount::serde::as_btc::opt"
    )]
    pub fee_rate: Option<Amount>,
    /// Errors encountered during processing.
    pub errors: Option<Vec<String>>,
    /// Block number where estimate was found.
    pub blocks: i64,
}

/// Models the result of "waitfornewblock", and "waitforblock"
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct BlockRef {
    pub hash: BlockHash,
    pub height: u64,
}

/// Models the result of "getdescriptorinfo"
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetDescriptorInfoResult {
    pub descriptor: String,
    pub checksum: String,
    #[serde(rename = "isrange")]
    pub is_range: bool,
    #[serde(rename = "issolvable")]
    pub is_solvable: bool,
    #[serde(rename = "hasprivatekeys")]
    pub has_private_keys: bool,
}

/// Models the request options of "getblocktemplate"
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetBlockTemplateOptions {
    pub mode: GetBlockTemplateModes,
    //// List of client side supported softfork deployment
    pub rules: Vec<GetBlockTemplateRules>,
    /// List of client side supported features
    pub capabilities: Vec<GetBlockTemplateCapabilities>,
}

/// Enum to represent client-side supported features
#[derive(Copy, Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GetBlockTemplateCapabilities {
    // No features supported yet. In the future this could be, for example, Proposal and Longpolling
}

/// Enum to representing specific block rules that the requested template
/// should support.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GetBlockTemplateRules {
    SegWit,
    Signet,
    Csv,
    Taproot,
}

/// Enum to represent client-side supported features.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GetBlockTemplateModes {
    /// Using this mode, the server build a block template and return it as
    /// response to the request. This is the default mode.
    Template,
    // TODO: Support for "proposal" mode is not yet implemented on the client
    // side.
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetBlockTemplateResultPayeeInfo {
    pub payee: String,
    pub script: String,
    pub amount: usize,
}

/// Models the result of "getblocktemplate"
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetBlockTemplateResult {
    /// List of features the Bitcoin Core getblocktemplate implementation supports
    pub capabilities: Vec<GetBlockTemplateResultCapabilities>,
    /// Block header version
    pub version: u32,
    /// Block rules that are to be enforced
    pub rules: Vec<GetBlockTemplateResultRules>,
    /// Set of pending, supported versionbit (BIP 9) softfork deployments
    #[serde(rename = "vbavailable")]
    pub version_bits_available: HashMap<String, u32>,
    /// Bit mask of versionbits the server requires set in submissions
    #[serde(rename = "vbrequired")]
    pub version_bits_required: u32,
    /// The previous block hash the current template is mining on
    #[serde(rename = "previousblockhash")]
    pub previous_block_hash: BlockHash,
    /// List of transactions included in the template block
    pub transactions: Vec<GetBlockTemplateResultTransaction>,
    /// Data that should be included in the coinbase's scriptSig content. Only
    /// the values (hexadecimal byte-for-byte) in this map should be included,
    /// not the keys. This does not include the block height, which is required
    /// to be included in the scriptSig by BIP 0034. It is advisable to encode
    /// values inside "PUSH" opcodes, so as to not inadvertently expend SIGOPs
    /// (which are counted toward limits, despite not being executed).
    #[serde(rename = "coinbaseaux")]
    pub coinbase_aux: HashMap<String, String>,
    /// Total funds available for the coinbase
    #[serde(rename = "coinbasevalue", with = "dashcore::amount::serde::as_sat", default)]
    pub coinbase_value: Amount,
    // TODO figure out what is the data is represented to coinbasetxn
    // pub coinbasetxn:
    /// The number which valid hashes must be less than, in big-endian
    #[serde(with = "hex")]
    pub target: Vec<u8>,
    /// The minimum timestamp appropriate for the next block time. Expressed as
    /// UNIX timestamp.
    #[serde(rename = "mintime")]
    pub min_time: u64,
    /// List of things that may be changed by the client before submitting a
    /// block
    pub mutable: Vec<GetBlockTemplateResultMutations>,
    // TODO figure out what is the data is represented to value
    // pub value:
    /// A range of valid nonces
    #[serde(with = "hex", rename = "noncerange")]
    pub nonce_range: Vec<u8>,
    /// Block sigops limit
    #[serde(rename = "sigoplimit")]
    pub sigop_limit: u32,
    /// Block size limit
    #[serde(rename = "sizelimit")]
    pub size_limit: u32,
    /// The current time as seen by the server (recommended for block time)
    /// Note: this is not necessarily the system clock, and must fall within
    /// the mintime/maxtime rules. Expressed as UNIX timestamp.
    #[serde(rename = "curtime")]
    pub current_time: u64,
    /// The compressed difficulty in hexadecimal
    #[serde(with = "hex")]
    pub bits: Vec<u8>,
    #[serde(with = "hex", rename = "previousbits")]
    pub previous_bits: Vec<u8>,
    /// The height of the block we will be mining: `current height + 1`
    pub height: u64,
    pub masternode: Vec<GetBlockTemplateResultPayeeInfo>,
    pub masternode_payments_started: bool,
    pub masternode_payments_enforced: bool,
    #[serde(rename = "superblock")]
    pub super_block: Vec<GetBlockTemplateResultPayeeInfo>,
    #[serde(rename = "superblocks_started")]
    pub super_blocks_started: bool,
    #[serde(rename = "superblocks_enabled")]
    pub super_blocks_enabled: bool,
    pub coinbase_payload: String,
}

/// Models a single transaction entry in the result of "getblocktemplate"
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetBlockTemplateResultTransaction {
    #[serde(with = "hex")]
    pub data: Vec<u8>,
    pub hash: BlockHash,
    /// Transactions that must be in present in the final block if this one is.
    /// Indexed by a 1-based index in the `GetBlockTemplateResult.transactions`
    /// list
    pub depends: Vec<u32>,
    /// The transaction fee
    #[serde(with = "dashcore::amount::serde::as_sat")]
    pub fee: Amount,
    /// Transaction sigops
    pub sigops: u32,
}

/// Enum to represent Bitcoin Core's supported features for getblocktemplate
#[derive(Copy, Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GetBlockTemplateResultCapabilities {
    Proposal,
}

/// Enum to representing specific block rules that client must support to work
/// with the template returned by Bitcoin Core
#[derive(Copy, Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GetBlockTemplateResultRules {
    /// Indicates that the client must support the CSV rules when using this
    /// template.
    Csv,
    /// Indicates that the client must support the v20 rules when using this
    /// template.
    #[serde(alias = "!signet")]
    V20,
    /// Indicates that the client must support the Regtest rules when using this
    /// template. TestDummy is a test soft-fork only used on the regtest network.
    Testdummy,
}

/// Enum to representing mutable parts of the block template. This does only
/// cover the muations implemented in Bitcoin Core. More mutations are defined
/// in [BIP-23](https://github.com/bitcoin/bips/blob/master/bip-0023.mediawiki#Mutations),
/// but not implemented in the getblocktemplate implementation of Bitcoin Core.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GetBlockTemplateResultMutations {
    /// The client is allowed to modify the time in the header of the block
    Time,
    /// The client is allowed to add transactions to the block
    Transactions,
    /// The client is allowed to use the work with other previous blocks.
    /// This implicitly allows removing transactions that are no longer valid.
    /// It also implies adjusting the "height" as necessary.
    #[serde(rename = "prevblock")]
    PreviousBlock,
}

/// Models the result of "walletcreatefundedpsbt"
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct WalletCreateFundedPsbtResult {
    pub psbt: String,
    #[serde(with = "dashcore::amount::serde::as_btc")]
    pub fee: Amount,
    #[serde(rename = "changepos")]
    pub change_position: i32,
}

/// Models the result of "walletprocesspsbt"
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct WalletProcessPsbtResult {
    pub psbt: String,
    pub complete: bool,
}

/// Models the request for "walletcreatefundedpsbt"
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize, Default)]
pub struct WalletCreateFundedPsbtOptions {
    /// For a transaction with existing inputs, automatically include more if they are not enough (default true).
    /// Added in Bitcoin Core v0.21
    #[serde(skip_serializing_if = "Option::is_none")]
    pub add_inputs: Option<bool>,
    #[serde(rename = "changeAddress", skip_serializing_if = "Option::is_none")]
    pub change_address: Option<Address<NetworkUnchecked>>,
    #[serde(rename = "changePosition", skip_serializing_if = "Option::is_none")]
    pub change_position: Option<u16>,
    #[serde(rename = "includeWatching", skip_serializing_if = "Option::is_none")]
    pub include_watching: Option<bool>,
    #[serde(rename = "lockUnspents", skip_serializing_if = "Option::is_none")]
    pub lock_unspent: Option<bool>,
    #[serde(
        rename = "feeRate",
        skip_serializing_if = "Option::is_none",
        with = "dashcore::amount::serde::as_btc::opt"
    )]
    pub fee_rate: Option<Amount>,
    #[serde(rename = "subtractFeeFromOutputs", skip_serializing_if = "Vec::is_empty")]
    pub subtract_fee_from_outputs: Vec<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conf_target: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimate_mode: Option<EstimateMode>,
}

/// Models the result of "finalizepsbt"
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct FinalizePsbtResult {
    pub psbt: String,
    pub hex: Option<String>,
    pub complete: bool,
}

/// Models the result of "getchaintips"
pub type GetChainTipsResult = Vec<GetChainTipsResultTip>;

/// Models a single chain tip for the result of "getchaintips"
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetChainTipsResultTip {
    /// Block height of the chain tip
    pub height: u64,
    /// Header hash of the chain tip
    pub hash: BlockHash,
    /// Length of the branch (number of blocks since the last common block)
    #[serde(rename = "branchlen")]
    pub branch_length: usize,
    /// Status of the tip as seen by Bitcoin Core
    pub status: GetChainTipsResultStatus,
}

#[derive(Copy, Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum GetChainTipsResultStatus {
    /// The branch contains at least one invalid block
    Invalid,
    /// Not all blocks for this branch are available, but the headers are valid
    #[serde(rename = "headers-only")]
    HeadersOnly,
    /// All blocks are available for this branch, but they were never fully validated
    #[serde(rename = "valid-headers")]
    ValidHeaders,
    /// This branch is not part of the active chain, but is fully validated
    #[serde(rename = "valid-fork")]
    ValidFork,
    /// This is the tip of the active main chain, which is certainly valid
    Active,
}

// Custom types for input arguments.

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[serde(rename_all = "UPPERCASE")]
pub enum EstimateMode {
    Unset,
    Economical,
    Conservative,
}

/// A wrapper around dashcore::EcdsaSighashType that will be serialized
/// according to what the RPC expects.
pub struct SigHashType(dashcore::EcdsaSighashType);

impl From<dashcore::EcdsaSighashType> for SigHashType {
    fn from(sht: dashcore::EcdsaSighashType) -> SigHashType {
        SigHashType(sht)
    }
}

impl serde::Serialize for SigHashType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(match self.0 {
            dashcore::EcdsaSighashType::All => "ALL",
            dashcore::EcdsaSighashType::None => "NONE",
            dashcore::EcdsaSighashType::Single => "SINGLE",
            dashcore::EcdsaSighashType::AllPlusAnyoneCanPay => "ALL|ANYONECANPAY",
            dashcore::EcdsaSighashType::NonePlusAnyoneCanPay => "NONE|ANYONECANPAY",
            dashcore::EcdsaSighashType::SinglePlusAnyoneCanPay => "SINGLE|ANYONECANPAY",
        })
    }
}

// Used for createrawtransaction argument.
#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CreateRawTransactionInput {
    pub txid: Txid,
    pub vout: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u32>,
}

#[derive(Serialize, Clone, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct FundRawTransactionOptions {
    /// For a transaction with existing inputs, automatically include more if they are not enough (default true).
    /// Added in Bitcoin Core v0.21
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_address: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_position: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_watching: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lock_unspents: Option<bool>,
    #[serde(
        with = "dashcore::amount::serde::as_btc::opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub fee_rate: Option<Amount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subtract_fee_from_outputs: Option<Vec<u32>>,
}

#[derive(Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FundRawTransactionResult {
    #[serde(with = "hex")]
    pub hex: Vec<u8>,
    #[serde(with = "dashcore::amount::serde::as_btc")]
    pub fee: Amount,
    #[serde(rename = "changepos")]
    pub change_position: i32,
}

#[derive(Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct GetBalancesResultEntry {
    #[serde(with = "dashcore::amount::serde::as_btc")]
    pub trusted: Amount,
    #[serde(with = "dashcore::amount::serde::as_btc")]
    pub untrusted_pending: Amount,
    #[serde(with = "dashcore::amount::serde::as_btc")]
    pub immature: Amount,
}

#[derive(Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GetBalancesResult {
    pub mine: GetBalancesResultEntry,
    pub watchonly: Option<GetBalancesResultEntry>,
}

impl FundRawTransactionResult {
    pub fn transaction(&self) -> Result<Transaction, encode::Error> {
        encode::deserialize(&self.hex)
    }
}

// Used for signrawtransaction argument.
#[derive(Serialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SignRawTransactionInput {
    pub txid: Txid,
    pub vout: u32,
    pub script_pub_key: ScriptBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redeem_script: Option<ScriptBuf>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "dashcore::amount::serde::as_btc::opt"
    )]
    pub amount: Option<Amount>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetTxOutSetInfoResult {
    /// The current block height (index)
    pub height: u64,
    /// The hash of the block at the tip of the chain
    #[serde(rename = "bestblock")]
    pub best_block: BlockHash,
    /// The number of transactions with unspent outputs
    pub transactions: u64,
    /// The number of unspent transaction outputs
    #[serde(rename = "txouts")]
    pub tx_outs: u64,
    /// A meaningless metric for UTXO set size
    pub bogosize: u64,
    /// The serialized hash
    pub hash_serialized_2: sha256::Hash,
    /// The estimated size of the chainstate on disk
    pub disk_size: u64,
    /// The total amount
    #[serde(with = "dashcore::amount::serde::as_btc")]
    pub total_amount: Amount,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetNetTotalsResult {
    /// Total bytes received
    #[serde(rename = "totalbytesrecv")]
    pub total_bytes_recv: u64,
    /// Total bytes sent
    #[serde(rename = "totalbytessent")]
    pub total_bytes_sent: u64,
    /// Current UNIX time in milliseconds
    #[serde(rename = "timemillis")]
    pub time_millis: u64,
    /// Upload target statistics
    #[serde(rename = "uploadtarget")]
    pub upload_target: GetNetTotalsResultUploadTarget,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetNetTotalsResultUploadTarget {
    /// Length of the measuring timeframe in seconds
    #[serde(rename = "timeframe")]
    pub time_frame: u64,
    /// Target in bytes
    pub target: u64,
    /// True if target is reached
    pub target_reached: bool,
    /// True if serving historical blocks
    pub serve_historical_blocks: bool,
    /// Bytes left in current time cycle
    pub bytes_left_in_cycle: u64,
    /// Seconds left in current time cycle
    pub time_left_in_cycle: u64,
}

/// Used to represent an address type.
#[derive(Copy, Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum AddressType {
    Legacy,
    P2shSegwit,
    Bech32,
}

/// Used to represent arguments that can either be an address or a public key.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum PubKeyOrAddress<'a> {
    Address(&'a Address),
    PubKey(&'a PublicKey),
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(untagged)]
/// Start a scan of the UTXO set for an [output descriptor](https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md).
pub enum ScanTxOutRequest {
    /// Scan for a single descriptor
    Single(String),
    /// Scan for a descriptor with xpubs
    Extended {
        /// Descriptor
        desc: String,
        /// Range of the xpub derivations to scan
        range: (u64, u64),
    },
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct ScanTxOutResult {
    pub success: Option<bool>,
    #[serde(rename = "txouts")]
    pub tx_outs: Option<u64>,
    pub height: Option<u64>,
    #[serde(rename = "bestblock")]
    pub best_block_hash: Option<BlockHash>,
    pub unspents: Vec<Utxo>,
    #[serde(with = "dashcore::amount::serde::as_btc")]
    pub total_amount: Amount,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Utxo {
    pub txid: Txid,
    pub vout: u32,
    pub script_pub_key: ScriptBuf,
    #[serde(rename = "desc")]
    pub descriptor: String,
    #[serde(with = "dashcore::amount::serde::as_btc")]
    pub amount: Amount,
    pub height: u64,
}

impl<'a> serde::Serialize for PubKeyOrAddress<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            PubKeyOrAddress::Address(a) => Serialize::serialize(a, serializer),
            PubKeyOrAddress::PubKey(k) => Serialize::serialize(k, serializer),
        }
    }
}

// --------------------------- Masternode -------------------------------

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ProTxListType {
    Registered,
    Valid,
    Wallet,
}

impl Serialize for ProTxListType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            ProTxListType::Registered => serializer.serialize_str("registered"),
            ProTxListType::Valid => serializer.serialize_str("valid"),
            ProTxListType::Wallet => serializer.serialize_str("wallet"),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetMasternodeCountResult {
    pub total: u32,
    pub enabled: u32,
}

#[serde_as]
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct Masternode {
    #[serde(rename = "proTxHash")]
    pub pro_tx_hash: ProTxHash,
    #[serde_as(serialize_as = "DisplayFromStr", deserialize_as = "ServiceOrUnspecified")]
    pub address: SocketAddr,
    #[serde_as(as = "Bytes")]
    pub payee: Vec<u8>,
    pub status: String,
    #[serde(rename = "type")]
    pub node_type: String,
    #[serde(rename = "platformNodeID")]
    pub platform_node_id: Option<String>,
    #[serde(default, rename = "platformP2PPort", deserialize_with = "deserialize_u32_opt")]
    pub platform_p2p_port: Option<u32>,
    #[serde(default, rename = "platformHTTPPort", deserialize_with = "deserialize_u32_opt")]
    pub platform_http_port: Option<u32>,
    #[serde(rename = "pospenaltyscore")]
    pub pos_penalty_score: u32,
    #[serde(rename = "consecutivePayments")]
    pub consecutive_payments: u32,
    #[serde(rename = "lastpaidtime")]
    pub last_paid_time: u32,
    #[serde(rename = "lastpaidblock")]
    pub last_paid_block: u32,
    #[serde_as(as = "Bytes")]
    #[serde(rename = "owneraddress")]
    pub owner_address: Vec<u8>,
    #[serde_as(as = "Bytes")]
    #[serde(rename = "votingaddress")]
    pub voting_address: Vec<u8>,
    #[serde_as(as = "Bytes")]
    #[serde(rename = "collateraladdress")]
    pub collateral_address: Vec<u8>,
    #[serde_as(as = "Bytes")]
    #[serde(rename = "pubkeyoperator")]
    pub pubkey_operator: Vec<u8>,
}

// TODO: clean up the new structure + test deserialization

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize, Encode, Decode)]
pub enum MasternodeType {
    Regular,
    Evo,
}

#[serde_as]
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MasternodeListItem {
    #[serde(rename = "type")]
    pub node_type: MasternodeType,
    pub pro_tx_hash: ProTxHash,
    pub collateral_hash: Txid,
    pub collateral_index: u32,
    /// `None` when Core prints no `collateralAddress`: the collateral output has no address (a
    /// shared masternode's), or Core cannot look the collateral transaction up (no `-txindex`).
    #[serde(default, deserialize_with = "deserialize_address_optional")]
    pub collateral_address: Option<[u8; 20]>,
    pub operator_reward: f32,
    pub state: DMNState,
}

pub struct RemovedMasternodeItem {
    pub protx_hash: ProTxHash,
}

pub struct UpdatedMasternodeItem {
    pub protx_hash: ProTxHash,
    pub state_diff: DMNStateDiff,
}

pub struct MasternodeListDiffWithMasternodes {
    pub base_height: u32,
    pub block_height: u32,
    pub added_mns: Vec<MasternodeListItem>,
    pub removed_mns: Vec<RemovedMasternodeItem>,
    pub updated_mns: Vec<UpdatedMasternodeItem>,
}

#[serde_as]
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct Payee {
    #[serde_as(as = "Bytes")]
    pub address: Vec<u8>,
    pub script: ScriptBuf,
    pub amount: u64,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct MasternodePayment {
    #[serde(rename = "proTxHash")]
    pub pro_tx_hash: ProTxHash,
    pub amount: u64,
    pub payees: Vec<Payee>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct GetMasternodePaymentsResult {
    pub height: u64,
    #[serde(rename = "blockhash")]
    pub block_hash: BlockHash,
    pub amount: u64,
    pub masternodes: Vec<MasternodePayment>,
}

/// Nested `addresses` object on Core 23+ masternode entries.
///
/// Each purpose maps to an array of `"host:port"` strings. Dash Core 23 moved the
/// platform ports here, away from the deprecated top-level `platformP2PPort`/
/// `platformHTTPPort` keys. Unknown purposes are ignored.
#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize)]
pub struct MasternodeAddresses {
    #[serde(default)]
    pub core_p2p: Vec<String>,
    #[serde(default)]
    pub platform_p2p: Vec<String>,
    #[serde(default)]
    pub platform_https: Vec<String>,
}

/// Host of a platform entry in a diff whose port changed alone. Core's diff does not carry the
/// masternode's address then, so it prints this in place of the primary core P2P host.
const PLACEHOLDER_PLATFORM_HOST: &str = "255.255.255.255";

impl MasternodeAddresses {
    /// First valid `(host, port)` from a `"host:port"` array, if any.
    ///
    /// "Valid" means parseable and with a non-zero in-range port; zero ports are
    /// skipped because Dash Core uses `0` as a "not set" sentinel.
    fn first_valid_host_port(addrs: &[String]) -> Option<(String, u32)> {
        addrs.iter().filter_map(|a| parse_host_port(a)).find(|(_, p)| *p != 0)
    }

    /// A masternode's addresses after a diff's `addresses`, as Core prints the resulting full
    /// state. `current` is `None` when the state predates nested addresses, so its core address
    /// is unknown.
    ///
    /// Core's diff prints `addresses` per changed purpose, not as a whole. A changed core
    /// address (`core_address_changed`: the diff prints `service`) prints the whole new
    /// `core_p2p`; an extended-address masternode's diff then prints every purpose, while a
    /// legacy Evo's leaves out a platform entry whose port did not change, and Core renders it
    /// on the new primary address. A legacy Evo's platform port changing alone prints the
    /// entry with [`PLACEHOLDER_PLATFORM_HOST`] for the primary host; with the primary host
    /// unknown the entry is dropped, leaving the flat port the diff also prints. Without a core
    /// address Core prints no platform entries.
    fn merged_with_diff(current: Option<Self>, diff: Self, core_address_changed: bool) -> Self {
        let core_address_changed = core_address_changed || !diff.core_p2p.is_empty();
        let current_known = current.is_some();
        let current = current.unwrap_or_default();
        let core_p2p = if core_address_changed {
            diff.core_p2p
        } else {
            current.core_p2p
        };
        if core_p2p.is_empty() && (core_address_changed || current_known) {
            return Self::default();
        }
        let primary_host =
            core_p2p.first().and_then(|entry| parse_host_port(entry)).map(|(h, _)| h);
        let on_primary_host = |entry: &String| {
            let (_, port) = parse_host_port(entry)?;
            Some(format!("{}:{port}", primary_host.as_ref()?))
        };
        let platform = |diff_entries: Vec<String>, entries: Vec<String>| -> Vec<String> {
            if !diff_entries.is_empty() {
                // The diff's entries replace the purpose's, the placeholder host resolved.
                diff_entries
                    .into_iter()
                    .filter_map(|entry| match parse_host_port(&entry) {
                        Some((host, _)) if host == PLACEHOLDER_PLATFORM_HOST => {
                            on_primary_host(&entry)
                        }
                        _ => Some(entry),
                    })
                    .collect()
            } else if core_address_changed {
                // A legacy Evo's platform entries follow its primary address.
                entries
                    .iter()
                    .map(|entry| on_primary_host(entry).unwrap_or_else(|| entry.clone()))
                    .collect()
            } else {
                entries
            }
        };
        Self {
            platform_p2p: platform(diff.platform_p2p, current.platform_p2p),
            platform_https: platform(diff.platform_https, current.platform_https),
            core_p2p,
        }
    }
}

/// Splits a `"host:port"` string into `(host, port)` with a non-fabricated host.
///
/// Supports IPv4 (`1.2.3.4:9999`) and bracketed IPv6 (`[2001:db8::1]:9999`). The
/// final `:port` segment is parsed through [`u16`] then widened to `u32`, rejecting
/// values outside the TCP/UDP port range (e.g. `"host:70000"`). Unbracketed
/// multi-colon hosts (bare IPv6) are rejected rather than silently mangled. An empty
/// host (e.g. `":36656"`) is also rejected. Returns `None` when no colon is present,
/// the host is empty or ambiguous, or the suffix is not a valid `u16`.
fn parse_host_port(addr: &str) -> Option<(String, u32)> {
    let (host, port) = addr.rsplit_once(':')?;
    if host.is_empty() {
        return None;
    }
    if host.contains(':') && !(host.starts_with('[') && host.ends_with(']')) {
        return None;
    }
    let port = port.parse::<u16>().ok()?;
    Some((host.to_string(), u32::from(port)))
}

/// One entry of a masternode's owner payout list.
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct DMNPayout {
    /// Hash of the payout address: the key hash of a P2PKH script or the script hash of a P2SH
    /// script. Only [`script`](Self::script) tells the two apart.
    #[serde(deserialize_with = "deserialize_address")]
    pub address: [u8; 20],
    /// The payout script, P2PKH or P2SH.
    pub script: ScriptBuf,
    /// Share of the owner reward in basis points; the entries of a list sum to 10000.
    pub reward: u16,
}

#[serde_as]
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DMNState {
    /// Primary core P2P address. `[::]:0` when the masternode has no address or its primary
    /// address has no IP form (Tor, I2P); the nested [`addresses`](Self::addresses) keep those.
    #[serde_as(serialize_as = "DisplayFromStr", deserialize_as = "ServiceOrUnspecified")]
    pub service: SocketAddr,
    pub registered_height: u32,
    #[serde(default, rename = "PoSeRevivedHeight", deserialize_with = "deserialize_u32_opt")]
    pub pose_revived_height: Option<u32>,
    #[serde(default, rename = "PoSeBanHeight", deserialize_with = "deserialize_u32_opt")]
    pub pose_ban_height: Option<u32>,
    pub revocation_reason: u32,
    /// `None` for a shared masternode, whose owners are its share holders.
    #[serde(default, deserialize_with = "deserialize_address_optional")]
    pub owner_address: Option<[u8; 20]>,
    #[serde(deserialize_with = "deserialize_address")]
    pub voting_address: [u8; 20],
    /// Single owner payout address. Core prints at most one of `payoutAddress` and `payouts`,
    /// and neither for a shared masternode; [`apply_diff`](Self::apply_diff) keeps at most one
    /// of `payout_address` and [`payouts`](Self::payouts) set.
    #[serde(default, deserialize_with = "deserialize_address_optional")]
    pub payout_address: Option<[u8; 20]>,
    /// Owner payout list, which replaces [`payout_address`](Self::payout_address) from the
    /// extended-address ProTx version on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payouts: Option<Vec<DMNPayout>>,
    #[serde(with = "hex")]
    pub pub_key_operator: Vec<u8>,
    #[serde(default, deserialize_with = "deserialize_address_optional")]
    pub operator_payout_address: Option<[u8; 20]>,
    #[serde(
        default,
        deserialize_with = "deserialize_hex_to_address_optional",
        rename = "platformNodeID"
    )]
    pub platform_node_id: Option<[u8; 20]>,
    /// `None` when absent or negative: Core prints `-1` for an Evo with no addresses.
    #[deprecated(note = "Core 23+ nested addresses.platform_p2p should be used instead")]
    #[serde(default, rename = "platformP2PPort", deserialize_with = "deserialize_u32_opt")]
    pub legacy_platform_p2p_port: Option<u32>,
    /// `None` when absent or negative: Core prints `-1` for an Evo with no addresses.
    #[deprecated(note = "Core 23+ nested addresses.platform_https should be used instead")]
    #[serde(default, rename = "platformHTTPPort", deserialize_with = "deserialize_u32_opt")]
    pub legacy_platform_http_port: Option<u32>,
    /// Nested addresses; `None` when the source predates them (Core before 23, or a state
    /// rebuilt from stored ports). [`apply_diff`](Self::apply_diff) merges a diff's per-purpose
    /// `addresses` into them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addresses: Option<MasternodeAddresses>,
}

impl DMNState {
    /// Resolved platform P2P `(host, port)`.
    ///
    /// Prefers the first Core 23+ nested `addresses.platform_p2p` entry with a non-zero port,
    /// returning its host and port verbatim. Otherwise falls back to the deprecated top-level
    /// `platformP2PPort` as-is, zero included, paired with the node IP from
    /// [`service`](Self::service) (bracketed when IPv6) because Dash deploys platform services
    /// on the masternode's core IP. The fallback also covers nested addresses without a platform entry, which is
    /// how Core prints a legacy Evo without an address (`addresses: {}` beside its flat ports).
    /// Returns `None` when neither source has a port.
    #[allow(deprecated)]
    pub fn platform_p2p_address(&self) -> Option<(String, u32)> {
        self.addresses
            .as_ref()
            .and_then(|a| MasternodeAddresses::first_valid_host_port(&a.platform_p2p))
            .or_else(|| self.legacy_platform_address(self.legacy_platform_p2p_port))
    }

    /// Resolved platform HTTPS `(host, port)`.
    ///
    /// Resolved like [`platform_p2p_address`](Self::platform_p2p_address), from
    /// `addresses.platform_https` and the deprecated top-level `platformHTTPPort`.
    #[allow(deprecated)]
    pub fn platform_http_address(&self) -> Option<(String, u32)> {
        self.addresses
            .as_ref()
            .and_then(|a| MasternodeAddresses::first_valid_host_port(&a.platform_https))
            .or_else(|| self.legacy_platform_address(self.legacy_platform_http_port))
    }

    /// Pairs a legacy platform port with the node IP, dropping absent and out-of-`u16`-range
    /// ports so the result honors the TCP/UDP port range. An IPv6 node IP is bracketed, as
    /// nested entries print it, so either source joins with its port into a socket address.
    fn legacy_platform_address(&self, port: Option<u32>) -> Option<(String, u32)> {
        port.and_then(|p| u16::try_from(p).ok()).map(|p| {
            let host = match self.service.ip() {
                IpAddr::V4(ip) => ip.to_string(),
                IpAddr::V6(ip) => format!("[{ip}]"),
            };
            (host, u32::from(p))
        })
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
#[serde(try_from = "DMNStateDiffIntermediate")]
pub struct DMNStateDiff {
    pub service: Option<SocketAddr>,
    pub registered_height: Option<u32>,
    pub last_paid_height: Option<u32>,
    pub consecutive_payments: Option<i32>,
    pub pose_penalty: Option<u32>,
    pub pose_revived_height: Option<u32>,
    pub pose_ban_height: Option<Option<u32>>,
    pub revocation_reason: Option<u32>,
    pub owner_address: Option<[u8; 20]>,
    pub voting_address: Option<[u8; 20]>,
    /// Setting it clears [`DMNState::payouts`] on [`DMNState::apply_diff`].
    pub payout_address: Option<[u8; 20]>,
    /// Setting it clears [`DMNState::payout_address`] on [`DMNState::apply_diff`].
    pub payouts: Option<Vec<DMNPayout>>,
    pub pub_key_operator: Option<Vec<u8>>,
    pub operator_payout_address: Option<Option<[u8; 20]>>,
    pub platform_node_id: Option<[u8; 20]>,
    #[deprecated(note = "Core 23+ nested addresses.platform_p2p should be used instead")]
    pub legacy_platform_p2p_port: Option<u32>,
    #[deprecated(note = "Core 23+ nested addresses.platform_https should be used instead")]
    pub legacy_platform_http_port: Option<u32>,
    /// Three-state nested addresses: `None` = unchanged, `Some(None)` = cleared,
    /// `Some(Some(_))` = set. Mirrors [`pose_ban_height`](Self::pose_ban_height).
    pub addresses: Option<Option<MasternodeAddresses>>,
}

impl TryFrom<DMNStateDiffIntermediate> for DMNStateDiff {
    type Error = encode::Error;

    #[allow(deprecated)]
    fn try_from(value: DMNStateDiffIntermediate) -> Result<Self, Self::Error> {
        let DMNStateDiffIntermediate {
            service,
            registered_height,
            last_paid_height,
            consecutive_payments,
            pose_penalty,
            pose_revived_height,
            pose_ban_height,
            revocation_reason,
            owner_address,
            voting_address,
            platform_node_id,
            legacy_platform_p2p_port,
            legacy_platform_http_port,
            payout_address,
            payouts,
            pub_key_operator,
            addresses,
        } = value;

        let owner_address = owner_address
            .map(|address| {
                let address = Address::from_str(address.as_str())?;
                address.payload_to_vec().try_into().map_err(|_| encode::Error::InvalidVectorSize {
                    expected: 20,
                    actual: address.payload_to_vec().len(),
                })
            })
            .transpose()?;
        let voting_address = voting_address
            .map(|address| {
                let address = Address::from_str(address.as_str())?;
                address.payload_to_vec().try_into().map_err(|_| encode::Error::InvalidVectorSize {
                    expected: 20,
                    actual: address.payload_to_vec().len(),
                })
            })
            .transpose()?;
        let payout_address = payout_address
            .map(|address| {
                let address = match Address::from_str(address.as_str()) {
                    Ok(address) => address,
                    Err(e) => return Err(e.into()),
                };
                address.payload_to_vec().try_into().map_err(|_| encode::Error::InvalidVectorSize {
                    expected: 20,
                    actual: address.payload_to_vec().len(),
                })
            })
            .transpose()?;
        let operator_payout_address = None;

        let platform_node_id = platform_node_id
            .map(|address| {
                let address = hex::decode(address)
                    .map_err(|_| encode::Error::ParseFailed("invalid hex in platform node id"))?;
                let len = address.len();
                address.try_into().map_err(|_| encode::Error::InvalidVectorSize {
                    expected: 20,
                    actual: len,
                })
            })
            .transpose()?;

        Ok(DMNStateDiff {
            service,
            registered_height,
            last_paid_height,
            consecutive_payments,
            pose_penalty,
            pose_revived_height,
            pose_ban_height,
            revocation_reason,
            owner_address,
            voting_address,
            payout_address,
            payouts,
            pub_key_operator,
            operator_payout_address,
            platform_node_id,
            #[allow(deprecated)]
            legacy_platform_p2p_port,
            #[allow(deprecated)]
            legacy_platform_http_port,
            addresses,
        })
    }
}

impl DMNStateDiff {
    /// Resolved platform P2P `(host, port)` carried by this diff, if any.
    ///
    /// Returns the host and port from the Core 23+ nested `addresses.platform_p2p`
    /// entry. The legacy top-level `platformP2PPort` is not resolved here: a diff
    /// carries no node IP to pair it with, so a host would have to be fabricated.
    /// Read the legacy port via [`legacy_platform_p2p_port`](Self::legacy_platform_p2p_port).
    /// A legacy Evo's port-only diff prints the host as `255.255.255.255`, standing for the
    /// masternode's primary address; [`DMNState::apply_diff`] resolves it.
    pub fn platform_p2p_address(&self) -> Option<(String, u32)> {
        self.addresses
            .as_ref()
            .and_then(|a| a.as_ref())
            .and_then(|a| MasternodeAddresses::first_valid_host_port(&a.platform_p2p))
    }

    /// Resolved platform HTTPS `(host, port)` carried by this diff, if any.
    ///
    /// Returns the host and port from the Core 23+ nested `addresses.platform_https`
    /// entry. The legacy top-level `platformHTTPPort` is not resolved here: a diff
    /// carries no node IP to pair it with, so a host would have to be fabricated.
    /// Read the legacy port via [`legacy_platform_http_port`](Self::legacy_platform_http_port).
    /// A legacy Evo's port-only diff prints the host as `255.255.255.255`, standing for the
    /// masternode's primary address; [`DMNState::apply_diff`] resolves it.
    pub fn platform_http_address(&self) -> Option<(String, u32)> {
        self.addresses
            .as_ref()
            .and_then(|a| a.as_ref())
            .and_then(|a| MasternodeAddresses::first_valid_host_port(&a.platform_https))
    }
}

impl DMNState {
    pub fn compare_to_older_dmn_state(&self, older: &DMNState) -> Option<DMNStateDiff> {
        older.compare_to_newer_dmn_state(self)
    }
    /// The diff that [`apply_diff`](Self::apply_diff) turns `self` into `newer` with, or `None`
    /// when they match.
    ///
    /// A field that goes from `Some` to `None` with nothing replacing it (the legacy platform
    /// ports, `owner_address`, `platform_node_id`, or both payout fields at once) cannot be
    /// expressed: the diff leaves it out and applying it keeps the old value. Core makes none of
    /// those transitions except on revoking an extended-address Evo, whose printed ports turn
    /// to `-1`, and Core's own diff does not print that change either.
    pub fn compare_to_newer_dmn_state(&self, newer: &DMNState) -> Option<DMNStateDiff> {
        let mut has_diff = false;
        let diff = DMNStateDiff {
            service: if self.service != newer.service {
                has_diff = true;
                Some(newer.service)
            } else {
                None
            },
            registered_height: if self.registered_height != newer.registered_height {
                has_diff = true;
                Some(newer.registered_height)
            } else {
                None
            },
            last_paid_height: None,     //todo?
            consecutive_payments: None, //todo?
            pose_penalty: None,         //todo?
            pose_revived_height: if self.pose_revived_height != newer.pose_revived_height {
                has_diff = true;
                newer.pose_revived_height
            } else {
                None
            },
            pose_ban_height: if self.pose_ban_height != newer.pose_ban_height {
                has_diff = true;
                Some(newer.pose_ban_height)
            } else {
                None
            },
            revocation_reason: if self.revocation_reason != newer.revocation_reason {
                has_diff = true;
                Some(newer.revocation_reason)
            } else {
                None
            },
            owner_address: if self.owner_address != newer.owner_address {
                has_diff = true;
                newer.owner_address
            } else {
                None
            },
            voting_address: if self.voting_address != newer.voting_address {
                has_diff = true;
                Some(newer.voting_address)
            } else {
                None
            },
            payout_address: if self.payout_address != newer.payout_address {
                has_diff = true;
                newer.payout_address
            } else {
                None
            },
            payouts: if self.payouts != newer.payouts {
                has_diff = true;
                newer.payouts.clone()
            } else {
                None
            },
            pub_key_operator: if self.pub_key_operator != newer.pub_key_operator {
                has_diff = true;
                Some(newer.pub_key_operator.clone())
            } else {
                None
            },
            operator_payout_address: if self.operator_payout_address
                != newer.operator_payout_address
            {
                has_diff = true;
                Some(newer.operator_payout_address)
            } else {
                None
            },
            platform_node_id: if self.platform_node_id != newer.platform_node_id {
                has_diff = true;
                newer.platform_node_id
            } else {
                None
            },
            #[allow(deprecated)]
            legacy_platform_p2p_port: if self.legacy_platform_p2p_port
                != newer.legacy_platform_p2p_port
            {
                has_diff = true;
                newer.legacy_platform_p2p_port
            } else {
                None
            },
            #[allow(deprecated)]
            legacy_platform_http_port: if self.legacy_platform_http_port
                != newer.legacy_platform_http_port
            {
                has_diff = true;
                newer.legacy_platform_http_port
            } else {
                None
            },
            addresses: if self.addresses != newer.addresses {
                has_diff = true;
                Some(newer.addresses.clone())
            } else {
                None
            },
        };
        if has_diff {
            Some(diff)
        } else {
            None
        }
    }

    /// Applies a diff as Core prints it.
    ///
    /// Core's diff prints `addresses` per changed purpose rather than as a whole, so they are
    /// merged per purpose: a changed core address moves a legacy Evo's platform entries onto
    /// it, and the `255.255.255.255` host of a legacy Evo's port-only change stands for the
    /// primary core address. For a legacy Evo the resolved platform addresses are then the
    /// same however the changes are batched into diffs. A diff that prints `service` but no
    /// `addresses` empties the addresses (a revocation or an operator change). The flat
    /// platform ports keep what the diff prints, so after an extended-address Evo's revocation
    /// they keep their last value, while Core's full state prints `-1`; which value that is
    /// can depend on how Core batched the changes before the revocation, because the diff
    /// doesn't say whether the Evo was extended-address when it was reset.
    pub fn apply_diff(&mut self, diff: DMNStateDiff) {
        let DMNStateDiff {
            service,
            pose_revived_height,
            pose_ban_height,
            revocation_reason,
            owner_address,
            voting_address,
            payout_address,
            payouts,
            pub_key_operator,
            operator_payout_address,
            platform_node_id,
            #[allow(deprecated)]
            legacy_platform_p2p_port,
            #[allow(deprecated)]
            legacy_platform_http_port,
            addresses,
            ..
        } = diff;
        self.pose_revived_height = pose_revived_height;
        if let Some(pose_ban_height) = pose_ban_height {
            self.pose_ban_height = pose_ban_height;
        }
        if let Some(pub_key_operator) = pub_key_operator {
            self.pub_key_operator = pub_key_operator;
        }
        if let Some(service) = service {
            self.service = service
        }
        if let Some(revocation_reason) = revocation_reason {
            self.revocation_reason = revocation_reason;
        }
        if let Some(owner_address) = owner_address {
            self.owner_address = Some(owner_address);
        }

        if let Some(voting_address) = voting_address {
            self.voting_address = voting_address;
        }
        // A payout address and a payout list are alternatives: setting one clears the other.
        if let Some(payout_address) = payout_address {
            self.payout_address = Some(payout_address);
            self.payouts = None;
        }
        if let Some(payouts) = payouts {
            self.payouts = Some(payouts);
            self.payout_address = None;
        }
        if let Some(operator_payout_address) = operator_payout_address {
            self.operator_payout_address = operator_payout_address;
        }
        if let Some(platform_node_id) = platform_node_id {
            self.platform_node_id = Some(platform_node_id);
        }

        #[allow(deprecated)]
        if let Some(legacy_platform_p2p_port) = legacy_platform_p2p_port {
            self.legacy_platform_p2p_port = Some(legacy_platform_p2p_port);
        }

        #[allow(deprecated)]
        if let Some(legacy_platform_http_port) = legacy_platform_http_port {
            self.legacy_platform_http_port = Some(legacy_platform_http_port);
        }

        match addresses {
            Some(Some(addresses)) => {
                self.addresses = Some(MasternodeAddresses::merged_with_diff(
                    self.addresses.take(),
                    addresses,
                    service.is_some(),
                ));
            }
            Some(None) => self.addresses = None,
            // Core prints `service` but no `addresses` when a masternode's addresses were
            // emptied (a revocation or an operator change). The flat platform ports stay as the
            // diff left them: a legacy Evo keeps printing them after a revocation.
            None if service.is_some() && self.addresses.is_some() => {
                self.addresses = Some(MasternodeAddresses::default());
            }
            None => {}
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub enum MasternodeState {
    MasternodeWaitingForProtx,
    MasternodePoseBanned,
    MasternodeRemoved,
    MasternodeOperatorKeyChanged,
    MasternodeProtxIpChanged,
    MasternodeReady,
    MasternodeError,
    Unknown,
    Nonrecognised,
}

#[serde_as]
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct MasternodeStatus {
    #[serde(default, deserialize_with = "deserialize_outpoint")]
    pub outpoint: dashcore::OutPoint,
    #[serde_as(serialize_as = "DisplayFromStr", deserialize_as = "ServiceOrUnspecified")]
    pub service: SocketAddr,
    #[serde(rename = "proTxHash")]
    pub pro_tx_hash: ProTxHash,
    #[serde(rename = "type")]
    pub node_type: String,
    #[serde(rename = "collateralHash", with = "hex")]
    pub collateral_hash: Vec<u8>,
    #[serde(rename = "collateralIndex")]
    pub collateral_index: u32,
    #[serde(rename = "dmnState")]
    pub dmn_state: DMNState,
    #[serde(deserialize_with = "deserialize_mn_state")]
    pub state: MasternodeState,
    pub status: String,
}

/// Masternode sync status response for `mnsync_status` method
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct MnSyncStatus {
    #[serde(rename = "AssetID")]
    pub asset_id: u16,

    #[serde(rename = "AssetName")]
    #[serde(deserialize_with = "deserialize_mn_sync_asset_name")]
    pub asset_name: MnSyncAssetName,

    #[serde(rename = "AssetStartTime")]
    pub asset_start_time: u32,

    #[serde(rename = "Attempt")]
    pub attempt: u16,

    #[serde(rename = "IsBlockchainSynced")]
    pub is_blockchain_synced: bool,

    #[serde(rename = "IsSynced")]
    pub is_synced: bool,
}

/// Masternode Sync Assets
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, Serialize, Deserialize)]
#[repr(u16)]
pub enum MnSyncAssetName {
    Initial = 0,
    Blockchain = 1,
    Governance = 2,
    Finished = 999,
}

/// deserialize_mn_state deserializes a masternode state
fn deserialize_mn_sync_asset_name<'de, D>(deserializer: D) -> Result<MnSyncAssetName, D::Error>
where
    D: Deserializer<'de>,
{
    let str_sequence = String::deserialize(deserializer)?;

    Ok(match str_sequence.as_str() {
        "MASTERNODE_SYNC_INITIAL" => MnSyncAssetName::Initial,
        "MASTERNODE_SYNC_BLOCKCHAIN" => MnSyncAssetName::Blockchain,
        "MASTERNODE_SYNC_GOVERNANCE" => MnSyncAssetName::Governance,
        "MASTERNODE_SYNC_FINISHED" => MnSyncAssetName::Finished,
        _ => {
            return Err(de::Error::custom(format!(
                "unknown masternode sync asset name: {}",
                str_sequence
            )));
        }
    })
}

// --------------------------- BLS -------------------------------

#[serde_as]
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct BLS {
    #[serde_as(as = "Bytes")]
    pub secret: Vec<u8>,
    #[serde_as(as = "Bytes")]
    pub public: Vec<u8>,
}

// --------------------------- Quorum -------------------------------

#[derive(
    Clone, Copy, PartialEq, Eq, Debug, Serialize_repr, Hash, Encode, Decode, Ord, PartialOrd,
)]
#[repr(u8)]
pub enum QuorumType {
    Llmq50_60 = 1,
    Llmq400_60 = 2,
    Llmq400_85 = 3,
    Llmq100_67 = 4,
    Llmq60_75 = 5,
    Llmq25_67 = 6,
    LlmqTest = 100,
    LlmqDevnet = 101,
    LlmqTestV17 = 102,
    LlmqTestDip0024 = 103,
    LlmqTestInstantsend = 104,
    LlmqDevnetDip0024 = 105,
    LlmqTestPlatform = 106,
    LlmqDevnetPlatform = 107,
    LlmqSingleNode = 111,
    UNKNOWN = 0,
}

impl From<u32> for QuorumType {
    fn from(value: u32) -> Self {
        match value {
            1 => QuorumType::Llmq50_60,
            2 => QuorumType::Llmq400_60,
            3 => QuorumType::Llmq400_85,
            4 => QuorumType::Llmq100_67,
            5 => QuorumType::Llmq60_75,
            6 => QuorumType::Llmq25_67,
            100 => QuorumType::LlmqTest,
            101 => QuorumType::LlmqDevnet,
            102 => QuorumType::LlmqTestV17,
            103 => QuorumType::LlmqTestDip0024,
            104 => QuorumType::LlmqTestInstantsend,
            105 => QuorumType::LlmqDevnetDip0024,
            106 => QuorumType::LlmqTestPlatform,
            107 => QuorumType::LlmqDevnetPlatform,
            111 => QuorumType::LlmqSingleNode,
            _ => QuorumType::UNKNOWN,
        }
    }
}

impl Display for QuorumType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let value = match self {
            QuorumType::Llmq50_60 => "llmq_50_60",
            QuorumType::Llmq60_75 => "llmq_60_75",
            QuorumType::Llmq400_60 => "llmq_400_60",
            QuorumType::Llmq400_85 => "llmq_400_85",
            QuorumType::Llmq100_67 => "llmq_100_67",
            QuorumType::Llmq25_67 => "llmq_25_67",
            QuorumType::LlmqTest => "llmq_test",
            QuorumType::LlmqTestInstantsend => "llmq_test_instantsend",
            QuorumType::LlmqTestV17 => "llmq_test_v17",
            QuorumType::LlmqTestDip0024 => "llmq_test_dip0024",
            QuorumType::LlmqDevnet => "llmq_devnet",
            QuorumType::LlmqDevnetDip0024 => "llmq_devnet_dip0024",
            QuorumType::UNKNOWN => "unknown",
            QuorumType::LlmqTestPlatform => "llmq_test_platform",
            QuorumType::LlmqDevnetPlatform => "llmq_devnet_platform",
            QuorumType::LlmqSingleNode => "llmq_1_100",
        };
        write!(f, "{}", value)
    }
}

impl From<&str> for QuorumType {
    fn from(value: &str) -> Self {
        match value {
            "llmq_50_60" => QuorumType::Llmq50_60,
            "llmq_60_75" => QuorumType::Llmq60_75,
            "llmq_400_60" => QuorumType::Llmq400_60,
            "llmq_400_85" => QuorumType::Llmq400_85,
            "llmq_100_67" => QuorumType::Llmq100_67,
            "llmq_25_67" => QuorumType::Llmq25_67,
            "llmq_test" => QuorumType::LlmqTest,
            "llmq_test_instantsend" => QuorumType::LlmqTestInstantsend,
            "llmq_test_v17" => QuorumType::LlmqTestV17,
            "llmq_test_dip0024" => QuorumType::LlmqTestDip0024,
            "llmq_devnet" => QuorumType::LlmqDevnet,
            "llmq_devnet_dip0024" => QuorumType::LlmqDevnetDip0024,
            "llmq_test_platform" => QuorumType::LlmqTestPlatform,
            "llmq_devnet_platform" => QuorumType::LlmqDevnetPlatform,
            "llmq_1_100" => QuorumType::LlmqSingleNode,
            _ => QuorumType::UNKNOWN,
        }
    }
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize, Encode, Decode)]
#[serde(rename_all = "camelCase")]
pub struct ExtendedQuorumDetails {
    pub creation_height: u32,
    pub quorum_index: Option<u32>,
    #[bincode(with_serde)]
    pub mined_block_hash: BlockHash,
    pub num_valid_members: u32,
    #[serde(deserialize_with = "deserialize_f32")]
    pub health_ratio: f32,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct QuorumListResult<T> {
    #[serde(flatten)]
    pub quorums_by_type: HashMap<QuorumType, T>,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
#[serde(from = "ExtendedQuorumListResultIntermediate")]
pub struct ExtendedQuorumListResult {
    #[serde(flatten)]
    pub quorums_by_type: HashMap<QuorumType, HashMap<QuorumHash, ExtendedQuorumDetails>>,
}

impl From<ExtendedQuorumListResultIntermediate> for ExtendedQuorumListResult {
    fn from(value: ExtendedQuorumListResultIntermediate) -> Self {
        ExtendedQuorumListResult {
            quorums_by_type: value
                .quorums_by_type
                .into_iter()
                .map(|(quorum_type, vec)| {
                    (
                        quorum_type,
                        vec.into_iter()
                            .flatten()
                            .collect::<HashMap<QuorumHash, ExtendedQuorumDetails>>(),
                    )
                })
                .collect(),
        }
    }
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct ExtendedQuorumListResultIntermediate {
    #[serde(flatten)]
    pub quorums_by_type: HashMap<QuorumType, Vec<HashMap<QuorumHash, ExtendedQuorumDetails>>>,
}

impl<'de> Deserialize<'de> for QuorumType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(QuorumType::from(s.as_str()))
    }
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct QuorumListResultInternal<T> {
    pub llmq_50_60: Option<Vec<T>>,
    pub llmq_400_60: Option<Vec<T>>,
    pub llmq_400_85: Option<Vec<T>>,
    pub llmq_100_67: Option<Vec<T>>,
    pub llmq_60_75: Option<Vec<T>>,
    pub llmq_25_67: Option<Vec<T>>,
    // for devnets only
    pub llmq_devnet: Option<Vec<T>>,
    pub llmq_devnet_platform: Option<Vec<T>>,
    // for devnets only. rotated version (v2) for devnets
    pub llmq_devnet_dip0024: Option<Vec<T>>,
    // for testing only
    pub llmq_test: Option<Vec<T>>,
    pub llmq_test_instantsend: Option<Vec<T>>,
    pub llmq_test_v17: Option<Vec<T>>,
    pub llmq_test_dip0024: Option<Vec<T>>,
    pub llmq_test_platform: Option<Vec<T>>,
}

#[serde_as]
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumMember {
    pub pro_tx_hash: ProTxHash,
    #[serde(with = "hex")]
    pub pub_key_operator: Vec<u8>,
    pub valid: bool,
    #[serde(default, deserialize_with = "deserialize_hex_opt")]
    pub pub_key_share: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumInfoResult {
    pub height: u32,
    #[serde(rename = "type", deserialize_with = "deserialize_quorum_type")]
    pub quorum_type: QuorumType,
    pub quorum_hash: QuorumHash,
    pub quorum_index: u32,
    #[serde(with = "hex")]
    pub mined_block: Vec<u8>,
    pub members: Vec<QuorumMember>,
    #[serde(with = "hex")]
    pub quorum_public_key: Vec<u8>,
    #[serde(default, deserialize_with = "deserialize_hex_opt")]
    pub secret_key_share: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumSessionStatusMember {
    pub member_index: u32,
    #[serde(rename = "proTxHash")]
    pub pro_tx_hash: ProTxHash,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum MemberDetail {
    Level0(i32),
    Level1(Vec<i32>),
    Level2(Vec<QuorumSessionStatusMember>),
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumSessionStatus {
    #[serde(deserialize_with = "deserialize_quorum_type")]
    pub llmq_type: QuorumType,
    pub quorum_hash: QuorumHash,
    pub quorum_height: u32,
    pub phase: u8,
    pub sent_contributions: bool,
    pub sent_complaint: bool,
    pub sent_justification: bool,
    pub sent_premature_commitment: bool,
    pub aborted: bool,
    pub bad_members: MemberDetail,
    pub we_complain: MemberDetail,
    pub received_contributions: MemberDetail,
    pub received_complaints: MemberDetail,
    pub received_justifications: MemberDetail,
    pub received_premature_commitments: MemberDetail,
    pub all_members: Option<Vec<QuorumHash>>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumSession {
    #[serde(deserialize_with = "deserialize_quorum_type")]
    pub llmq_type: QuorumType,
    pub quorum_index: u32,
    pub status: QuorumSessionStatus,
}

#[serde_as]
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumConnectionInfo {
    #[serde(rename = "proTxHash")]
    pub pro_tx_hash: ProTxHash,
    pub connected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<SocketAddr>,
    pub outbound: bool,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumConnection {
    #[serde(deserialize_with = "deserialize_quorum_type")]
    pub llmq_type: QuorumType,
    pub quorum_index: u32,
    pub p_quorum_base_block_index: Option<u32>,
    pub quorum_hash: Option<QuorumHash>,
    pub pindex_tip: Option<u32>,
    pub quorum_connections: Option<Vec<QuorumConnectionInfo>>,
}

#[serde_as]
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumMinableCommitments {
    pub version: u8,
    #[serde(deserialize_with = "deserialize_quorum_type")]
    pub llmq_type: QuorumType,
    pub quorum_hash: QuorumHash,
    pub quorum_index: u32,
    pub signers_count: u32,
    #[serde_as(as = "Bytes")]
    pub signers: Vec<u8>,
    pub valid_members_count: u32,
    #[serde_as(as = "Bytes")]
    pub valid_members: Vec<u8>,
    #[serde_as(as = "Bytes")]
    pub quorum_public_key: Vec<u8>,
    #[serde_as(as = "Bytes")]
    pub quorum_vvec_hash: Vec<u8>,
    #[serde_as(as = "Bytes")]
    pub quorum_sig: Vec<u8>,
    #[serde_as(as = "Bytes")]
    pub members_sig: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumItemDeleted {
    #[serde(deserialize_with = "deserialize_quorum_type")]
    pub llmq_type: QuorumType,
    pub quorum_hash: QuorumHash,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumDKGStatus {
    pub time: u64,
    pub time_str: String,
    pub session: Vec<QuorumSession>,
    pub quorum_connections: Vec<QuorumConnection>,
    pub minable_commitments: Vec<QuorumMinableCommitments>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumSignature {
    #[serde(deserialize_with = "deserialize_quorum_type")]
    pub llmq_type: QuorumType,
    pub quorum_hash: QuorumHash,
    pub quorum_member: Option<u8>,
    #[serde(with = "hex")]
    pub id: Vec<u8>,
    #[serde(with = "hex")]
    pub msg_hash: Vec<u8>,
    #[serde(with = "hex")]
    pub sign_hash: Vec<u8>,
    #[serde(with = "hex")]
    pub signature: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum QuorumSignResult {
    QuorumSignStatus(bool),
    QuorumSignSignatureShare(QuorumSignature),
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumMemberOf {
    pub height: u32,
    #[serde(rename = "type", deserialize_with = "deserialize_quorum_type")]
    pub quorum_type: QuorumType,
    pub quorum_hash: QuorumHash,
    #[serde(with = "hex")]
    pub mined_block: Vec<u8>,
    #[serde(with = "hex")]
    pub quorum_public_key: Vec<u8>,
    pub is_valid_member: bool,
    pub member_index: u32,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct QuorumMemberOfResult(pub Vec<QuorumMemberOf>);

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumSnapshot {
    pub active_quorum_members: Vec<bool>,
    pub mn_skip_list_mode: u8,
    pub mn_skip_list: Vec<u8>,
}

#[serde_as]
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumMasternodeListItem {
    #[serde(with = "hex")]
    pub pro_reg_tx_hash: Vec<u8>,
    #[serde(with = "hex")]
    pub confirmed_hash: Vec<u8>,
    #[serde_as(serialize_as = "DisplayFromStr", deserialize_as = "ServiceOrUnspecified")]
    pub service: SocketAddr,
    #[serde(with = "hex")]
    pub pub_key_operator: Vec<u8>,
    #[serde_as(as = "Bytes")]
    pub voting_address: Vec<u8>,
    pub is_valid: bool,
}

#[serde_as]
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MasternodeDiff {
    pub base_block_hash: BlockHash,
    pub block_hash: BlockHash,
    #[serde_as(as = "Bytes")]
    pub cb_tx_merkle_tree: Vec<u8>,
    #[serde_as(as = "Bytes")]
    pub cb_tx: Vec<u8>,
    #[serde(rename = "deletedMNs")]
    pub deleted_mns: Vec<QuorumMasternodeListItem>,
    pub mn_list: Vec<QuorumMasternodeListItem>,
    pub deleted_quorums: Vec<QuorumItemDeleted>,
    pub new_quorums: Vec<QuorumMinableCommitments>,
    #[serde(rename = "merkleRootMNList", with = "hex")]
    pub merkle_root_mn_list: Vec<u8>,
    #[serde(rename = "merkleRootQuorums", with = "hex")]
    pub merkle_root_quorums: Vec<u8>,
}

#[serde_as]
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DMNStateDiffIntermediate {
    #[serde(default)]
    #[serde_as(deserialize_as = "Option<ServiceOrUnspecified>")]
    pub service: Option<SocketAddr>,
    #[serde(default)]
    pub registered_height: Option<u32>,
    #[serde(default)]
    pub last_paid_height: Option<u32>,
    #[serde(default)]
    pub consecutive_payments: Option<i32>,
    #[serde(rename = "PoSePenalty")]
    pub pose_penalty: Option<u32>,
    #[serde(default, rename = "PoSeRevivedHeight", deserialize_with = "deserialize_u32_opt")]
    pub pose_revived_height: Option<u32>,
    // there are 3 possible states
    // =-1: Some(None)
    // >=0: Some(Some(u32))
    // missing field: None
    #[serde(default, rename = "PoSeBanHeight", deserialize_with = "deserialize_u32_2opt")]
    pub pose_ban_height: Option<Option<u32>>,
    #[serde(default)]
    pub revocation_reason: Option<u32>,
    #[serde(default)]
    pub owner_address: Option<String>,
    #[serde(default)]
    pub voting_address: Option<String>,
    #[serde(default, rename = "platformNodeID")]
    pub platform_node_id: Option<String>,
    #[deprecated(note = "Core 23+ nested addresses.platform_p2p should be used instead")]
    #[serde(default, rename = "platformP2PPort", deserialize_with = "deserialize_u32_opt")]
    pub legacy_platform_p2p_port: Option<u32>,
    #[deprecated(note = "Core 23+ nested addresses.platform_https should be used instead")]
    #[serde(default, rename = "platformHTTPPort", deserialize_with = "deserialize_u32_opt")]
    pub legacy_platform_http_port: Option<u32>,
    #[serde(default)]
    pub payout_address: Option<String>,
    #[serde(default)]
    pub payouts: Option<Vec<DMNPayout>>,
    #[serde(default, deserialize_with = "deserialize_hex_opt")]
    pub pub_key_operator: Option<Vec<u8>>,
    // Three-state: missing field = None, `null` = Some(None), object = Some(Some(_)).
    #[serde(default, deserialize_with = "deserialize_addresses_2opt")]
    pub addresses: Option<Option<MasternodeAddresses>>,
}

#[derive(Clone, PartialEq, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(from = "MasternodeListDiffIntermediate")]
pub struct MasternodeListDiff {
    pub base_height: u32,
    pub block_height: u32,
    #[serde(rename = "addedMNs")]
    pub added_mns: Vec<MasternodeListItem>,
    #[serde(rename = "removedMNs")]
    pub removed_mns: Vec<ProTxHash>,
    #[serde(rename = "updatedMNs")]
    pub updated_mns: Vec<(ProTxHash, DMNStateDiff)>,
}

#[derive(Clone, PartialEq, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MasternodeListDiffIntermediate {
    base_height: u32,
    block_height: u32,
    #[serde(rename = "addedMNs")]
    added_mns: Vec<MasternodeListItem>,
    #[serde(rename = "removedMNs")]
    removed_mns: Vec<ProTxHash>,
    #[serde(rename = "updatedMNs")]
    updated_mns: Vec<HashMap<ProTxHash, DMNStateDiff>>,
}

impl From<MasternodeListDiffIntermediate> for MasternodeListDiff {
    fn from(value: MasternodeListDiffIntermediate) -> Self {
        let MasternodeListDiffIntermediate {
            base_height,
            block_height,
            added_mns,
            removed_mns,
            updated_mns,
        } = value;

        MasternodeListDiff {
            base_height,
            block_height,
            added_mns,
            removed_mns,
            updated_mns: updated_mns.into_iter().flatten().collect(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumRotationInfo {
    pub extra_share: bool,
    pub quorum_snapshot_at_h_minus_c: QuorumSnapshot,
    pub quorum_snapshot_at_h_minus_2c: QuorumSnapshot,
    pub quorum_snapshot_at_h_minus_3c: QuorumSnapshot,
    pub mn_list_diff_tip: MasternodeDiff,
    pub mn_list_diff_h: MasternodeDiff,
    pub mn_list_diff_at_h_minus_c: MasternodeDiff,
    pub mn_list_diff_at_h_minus_2c: MasternodeDiff,
    pub mn_list_diff_at_h_minus_3c: MasternodeDiff,
    pub block_hash_list: Vec<BlockHash>,
    pub quorum_snapshot_list: Vec<QuorumSnapshot>,
    pub mn_list_diff_list: Vec<MasternodeDiff>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SelectQuorumResult {
    pub quorum_hash: QuorumHash,
    pub recovery_members: Vec<QuorumHash>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum IntegerOrString<'a> {
    Integer(u32),
    String(&'a str),
}

// --------------------------- ProTx -------------------------------

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Wallet {
    pub has_owner_key: bool,
    pub has_operator_key: bool,
    pub has_voting_key: bool,
    pub owns_collateral: bool,
    pub owns_payee_script: bool,
    pub owns_operator_reward_script: bool,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MetaInfo {
    #[serde(rename = "lastDSQ")]
    pub last_dsq: u32,
    pub mixing_tx_count: u32,
    pub last_outbound_attempt: i32,
    pub last_outbound_attempt_elapsed: i32,
    pub last_outbound_success: i32,
    pub last_outbound_success_elapsed: i32,
}

#[serde_as]
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProTxInfo {
    #[serde(rename = "type")]
    pub mn_type: Option<String>,
    #[serde(rename = "proTxHash")]
    pub pro_tx_hash: ProTxHash,
    #[serde(with = "hex")]
    pub collateral_hash: Vec<u8>,
    pub collateral_index: u32,
    /// `None` when Core prints no `collateralAddress`: the collateral output has no address (a
    /// shared masternode's), or Core cannot look the collateral transaction up (no `-txindex`).
    #[serde(default, deserialize_with = "deserialize_address_optional")]
    pub collateral_address: Option<[u8; 20]>,
    pub operator_reward: u32,
    pub state: DMNState,
    pub confirmations: u32,
    #[serde(default)]
    pub wallet: Option<Wallet>,
    pub meta_info: MetaInfo,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ProTxList {
    Hex(Vec<ProTxHash>),
    Info(Vec<ProTxInfo>),
}

#[serde_as]
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProTxRegPrepare {
    pub tx: ProTxHash,
    #[serde_as(as = "Bytes")]
    pub collateral_address: Vec<u8>,
    #[serde_as(as = "Bytes")]
    pub sign_message: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ProTxRevokeReason {
    NotSpecified = 0,
    TerminationOfService = 1,
    CompromisedKeys = 2,
    ChangeOfKeys = 3,
    NotRecognised = 4,
}

// Custom deserializer functions.

#[derive(Debug)]
pub struct HexError(FromHexError);

impl Display for HexError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "Failed to deserialize hex string: {}", self.0)
    }
}

impl Error for HexError {}

impl From<FromHexError> for HexError {
    fn from(err: FromHexError) -> HexError {
        HexError(err)
    }
}

fn deserialize_hex_opt<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    match String::deserialize(deserializer) {
        Ok(s) => match hex::decode(s) {
            Ok(v) => Ok(Some(v)),
            Err(err) => Err(D::Error::custom(HexError::from(err))),
        },
        Err(e) => Err(e),
    }
}

fn deserialize_hex_to_address_optional<'de, D>(
    deserializer: D,
) -> Result<Option<[u8; 20]>, D::Error>
where
    D: Deserializer<'de>,
{
    match String::deserialize(deserializer) {
        Ok(s) => match hex::decode(s) {
            Ok(v) => match v.clone().try_into() {
                Ok(array) => Ok(Some(array)),
                Err(_) => Err(D::Error::custom(ArrayConversionError(v))),
            },
            Err(err) => Err(D::Error::custom(HexError::from(err))),
        },
        Err(e) => Err(e),
    }
}

#[derive(Debug)]
pub struct CustomAddressError(address::Error);

impl Display for CustomAddressError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "Failed to deserialize address: {}", self.0)
    }
}

impl Error for CustomAddressError {}

impl From<address::Error> for CustomAddressError {
    fn from(err: address::Error) -> CustomAddressError {
        CustomAddressError(err)
    }
}

#[derive(Debug)]
pub struct ArrayConversionError(Vec<u8>);

impl Display for ArrayConversionError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "Failed to convert Vec<u8> to [u8; 20]: {:?}", self.0)
    }
}

impl Error for ArrayConversionError {}

fn deserialize_address<'de, D>(deserializer: D) -> Result<[u8; 20], D::Error>
where
    D: Deserializer<'de>,
{
    match String::deserialize(deserializer) {
        Ok(s) => match Address::from_str(s.as_str()) {
            Ok(address) => {
                let v: Vec<u8> = address.payload_to_vec();
                match v.clone().try_into() {
                    Ok(array) => Ok(array),
                    Err(_) => Err(D::Error::custom(ArrayConversionError(v))),
                }
            }
            Err(err) => Err(D::Error::custom(CustomAddressError::from(err))),
        },
        Err(e) => Err(e),
    }
}

fn deserialize_address_optional<'de, D>(deserializer: D) -> Result<Option<[u8; 20]>, D::Error>
where
    D: Deserializer<'de>,
{
    match Option::<String>::deserialize(deserializer) {
        Ok(Some(s)) => match Address::from_str(s.as_str()) {
            Ok(address) => {
                let v: Vec<u8> = address.payload_to_vec();
                match v.clone().try_into() {
                    Ok(array) => Ok(Some(array)),
                    Err(_) => Err(D::Error::custom(ArrayConversionError(v))),
                }
            }
            Err(err) => Err(D::Error::custom(CustomAddressError::from(err))),
        },
        Ok(None) => Ok(None),
        Err(e) => Err(e),
    }
}

/// deserialize_outpoint deserializes a hex-encoded outpoint
fn deserialize_outpoint<'de, D>(deserializer: D) -> Result<dashcore::OutPoint, D::Error>
where
    D: Deserializer<'de>,
{
    let str_sequence = String::deserialize(deserializer)?;
    let str_array: Vec<String> = str_sequence.split('-').map(|item| item.to_owned()).collect();

    let txid: Txid = Txid::from_hex(&str_array[0]).unwrap();
    let vout: u32 = str_array[1].parse().unwrap();

    let outpoint = dashcore::OutPoint {
        txid,
        vout,
    };
    Ok(outpoint)
}

/// deserialize_mn_state deserializes a masternode state
fn deserialize_mn_state<'de, D>(deserializer: D) -> Result<MasternodeState, D::Error>
where
    D: Deserializer<'de>,
{
    let str_sequence = String::deserialize(deserializer)?;

    Ok(match str_sequence.as_str() {
        "WAITING_FOR_PROTX" => MasternodeState::MasternodeWaitingForProtx,
        "POSE_BANNED" => MasternodeState::MasternodePoseBanned,
        "REMOVED" => MasternodeState::MasternodeRemoved,
        "OPERATOR_KEY_CHANGED" => MasternodeState::MasternodeOperatorKeyChanged,
        "PROTX_IP_CHANGED" => MasternodeState::MasternodeProtxIpChanged,
        "READY" => MasternodeState::MasternodeReady,
        "ERROR" => MasternodeState::MasternodeError,
        "UNKNOWN" => MasternodeState::Unknown,
        _ => MasternodeState::Nonrecognised,
    })
}

/// deserialize_quorum_type deserializes a quorum type
fn deserialize_quorum_type<'de, D>(deserializer: D) -> Result<QuorumType, D::Error>
where
    D: Deserializer<'de>,
{
    match IntegerOrString::deserialize(deserializer)? {
        IntegerOrString::String(s) => {
            let qt: QuorumType = s.into();
            Ok(qt)
        }
        IntegerOrString::Integer(n) => {
            let qt: QuorumType = n.into();
            Ok(qt)
        }
    }
}

fn deserialize_f32<'de, D>(deserializer: D) -> Result<f32, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(match Value::deserialize(deserializer)? {
        Value::String(s) => s.parse().map_err(de::Error::custom)?,
        Value::Number(num) => num.as_f64().ok_or(de::Error::custom("Invalid number"))? as f32,
        _ => return Err(de::Error::custom("wrong type")),
    })
}

/// Reads an optional `u32` that Core prints as `-1` (or any negative value) when not set.
/// `null` also reads as `None`; a value above `u32::MAX` is an error.
fn deserialize_u32_opt<'de, D>(deserializer: D) -> Result<Option<u32>, D::Error>
where
    D: Deserializer<'de>,
{
    match Option::<i64>::deserialize(deserializer)? {
        Some(val) if val >= 0 => u32::try_from(val)
            .map(Some)
            .map_err(|_| D::Error::invalid_value(de::Unexpected::Signed(val), &"a u32")),
        _ => Ok(None),
    }
}

fn deserialize_u32_2opt<'de, D>(deserializer: D) -> Result<Option<Option<u32>>, D::Error>
where
    D: Deserializer<'de>,
{
    let val = i64::deserialize(deserializer)?;
    if val < 0 {
        return Ok(Some(None));
    }
    Ok(Some(Some(val as u32)))
}

/// Deserializes the present-but-clearable nested `addresses` object.
///
/// Paired with `#[serde(default)]`, the field absence yields `None` (unchanged),
/// a JSON `null` yields `Some(None)` (cleared), and an object yields
/// `Some(Some(_))` (set) — the canonical serde double-`Option` pattern.
fn deserialize_addresses_2opt<'de, D>(
    deserializer: D,
) -> Result<Option<Option<MasternodeAddresses>>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Some(Option::<MasternodeAddresses>::deserialize(deserializer)?))
}

/// The `service` Dash Core prints for a masternode without an address.
const UNSPECIFIED_SERVICE: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);

/// Reads a masternode `service`, the primary core P2P address as `"ip:port"`.
///
/// The primary address may be a Tor (`.onion`) or I2P (`.i2p`) address, which has no
/// [`SocketAddr`] form. It reads as `[::]:0`, the value Core prints for a masternode without an
/// address, so that one such entry does not fail a whole masternode list; where the type models
/// the nested `addresses` object, the entry stays readable there. Any other value that is not
/// an `ip:port` is an error.
struct ServiceOrUnspecified;

impl<'de> DeserializeAs<'de, SocketAddr> for ServiceOrUnspecified {
    fn deserialize_as<D>(deserializer: D) -> Result<SocketAddr, D::Error>
    where
        D: Deserializer<'de>,
    {
        let service = String::deserialize(deserializer)?;
        match service.parse() {
            Ok(service) => Ok(service),
            Err(_) if is_privacy_network_service(&service) => Ok(UNSPECIFIED_SERVICE),
            Err(err) => Err(D::Error::custom(format_args!("invalid service {service:?}: {err}"))),
        }
    }
}

/// Whether `service` is a Tor or I2P `host:port` as Core prints it.
fn is_privacy_network_service(service: &str) -> bool {
    service.rsplit_once(':').is_some_and(|(host, port)| {
        (host.ends_with(".onion") || host.ends_with(".i2p")) && port.parse::<u16>().is_ok()
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::SocketAddr;

    use dashcore::hashes::Hash;
    use dashcore::{PubkeyHash, ScriptBuf, ScriptHash};
    use serde::{Deserialize, Serialize};
    use serde_json::json;

    use crate::{
        DMNPayout, DMNState, DMNStateDiff, ExtendedQuorumListResult, Masternode,
        MasternodeAddresses, MasternodeListDiff, MasternodeStatus, MnSyncStatus, ProTxInfo,
        QuorumMasternodeListItem, QuorumType, deserialize_u32_opt, parse_host_port,
    };

    #[test]
    fn test_deserialize_u32_opt() {
        #[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
        struct Test {
            #[serde(deserialize_with = "deserialize_u32_opt")]
            pub field: Option<u32>,
        }

        let json = r#"{"field": 1}"#;
        let result: Test = serde_json::from_str(json).unwrap();
        assert_eq!(result.field, Some(1));
        let json = r#"{"field": -1}"#;
        let result: Test = serde_json::from_str(json).unwrap();
        assert_eq!(result.field, None);
    }

    #[test]
    fn deserialize_quorum_listextended() {
        let json_list = r#"{
              "llmq_50_60": [
                {
                  "000000da4509523408c751905d4e48df335e3ee565b4d2288800c7e51d592e2f": {
                    "creationHeight": 871992,
                    "minedBlockHash": "000000cd7f101437069956c0ca9f4180b41f0506827a828d57e85b35f215487e",
                    "numValidMembers": 50,
                    "healthRatio": "1.00"
                  }
                }
              ]
            }"#;
        let result: ExtendedQuorumListResult =
            serde_json::from_str(json_list).expect("expected to deserialize json");
        let first_type = result.quorums_by_type.get(&QuorumType::Llmq50_60).unwrap();
        let first_quorum = first_type.iter().next().unwrap();

        assert_eq!(
            first_quorum.0.to_byte_array(),
            [
                47, 46, 89, 29, 229, 199, 0, 136, 40, 210, 180, 101, 229, 62, 94, 51, 223, 72, 78,
                93, 144, 81, 199, 8, 52, 82, 9, 69, 218, 0, 0, 0,
            ]
        );

        assert_eq!(
            first_quorum.1.mined_block_hash.to_byte_array(),
            [
                126, 72, 21, 242, 53, 91, 232, 87, 141, 130, 122, 130, 6, 5, 31, 180, 128, 65, 159,
                202, 192, 86, 153, 6, 55, 20, 16, 127, 205, 0, 0, 0,
            ]
        );

        assert_eq!(
            "000000da4509523408c751905d4e48df335e3ee565b4d2288800c7e51d592e2f",
            first_quorum.0.to_string()
        );
        assert_eq!(
            "000000cd7f101437069956c0ca9f4180b41f0506827a828d57e85b35f215487e",
            first_quorum.1.mined_block_hash.to_string()
        );
    }

    #[test]
    fn deserialize_mn_listdiff() {
        let json = r#"{
              "baseHeight": 850000,
              "blockHeight": 867165,
              "addedMNs": [
                 {
                  "type": "Regular",
                  "proTxHash": "c560a9be2be9db79e1aaa16e4dd3cd22bddcb0155f88aba68aa4797d375ef370",
                  "collateralHash": "ff6226e6c97bfcf40b6d04e12e3f75678024988823bfba28cde2a9ac11b1a765",
                  "collateralIndex": 1,
                  "collateralAddress": "yNqYnF9sHURjwRmhZMLFGQ3WjC5DZNJMUi",
                  "operatorReward": 0,
                  "state": {
                    "service": "194.135.88.228:6667",
                    "registeredHeight": 850310,
                    "lastPaidHeight": 0,
                    "consecutivePayments": 0,
                    "PoSePenalty": 0,
                    "PoSeRevivedHeight": -1,
                    "PoSeBanHeight": -1,
                    "revocationReason": 0,
                    "ownerAddress": "yPBWCdMRY5PsS3hJzs7csbdWQVRR85yxUz",
                    "votingAddress": "ySM11LUD65Bi4p1gm68XLkdWc65TBKRzvQ",
                    "payoutAddress": "yX4Ve7Q8Y4jscV4LZJD8HVCHKyePzR3MhA",
                    "pubKeyOperator": "8ed3f0c208efbcfc815cbfb94490dc68cf2e29d44dd9f8a91e20e06057aa110d7062c8ab7ccc85a9ff0c88760157f563"
                  }
                },
                {
                  "type": "Evo",
                  "proTxHash": "c560a9be2be9db79e1aaa16e4dd3cd22bddcb0155f88aba68aa4797d375ef370",
                  "collateralHash": "ff6226e6c97bfcf40b6d04e12e3f75678024988823bfba28cde2a9ac11b1a765",
                  "collateralIndex": 1,
                  "collateralAddress": "yNqYnF9sHURjwRmhZMLFGQ3WjC5DZNJMUi",
                  "operatorReward": 0,
                  "state": {
                    "service": "194.135.88.227:6666",
                    "registeredHeight": 850319,
                    "lastPaidHeight": 0,
                    "consecutivePayments": 0,
                    "PoSePenalty": 525,
                    "PoSeRevivedHeight": 861579,
                    "PoSeBanHeight": 861611,
                    "revocationReason": 0,
                    "ownerAddress": "yPBWCdMRY5PsS3hJzs7csbdWQVRR85yxUz",
                    "votingAddress": "ySM11LUD65Bi4p1gm68XLkdWc65TBKRzvQ",
                    "platformNodeID": "f2dbd9b0a1f541a7c44d34a58674d0262f5feca5",
                    "platformP2PPort": 22821,
                    "platformHTTPPort": 22822,
                    "payoutAddress": "yX4Ve7Q8Y4jscV4LZJD8HVCHKyePzR3MhA",
                    "pubKeyOperator": "8ed3f0c208efbcfc815cbfb94490dc68cf2e29d44dd9f8a91e20e06057aa110d7062c8ab7ccc85a9ff0c88760157f563"
                  }
                },
                {
                  "type": "Evo",
                  "proTxHash": "9a8cfd0e5fa3a7467b81a5a2fa41e40f7981591cfb62d86e35db37962c128bb0",
                  "collateralHash": "35215134107b5e423d327cab12d2b4c60a9b769301096e05a95916676d2f7867",
                  "collateralIndex": 0,
                  "collateralAddress": "yd2PwFoqtEJdnJVSEzBDMxVnFVgEvJyvyY",
                  "operatorReward": 0,
                  "state": {
                    "service": "172.17.0.1:20201",
                    "registeredHeight": 1176,
                    "lastPaidHeight": 1641,
                    "consecutivePayments": 3,
                    "PoSePenalty": 0,
                    "PoSeRevivedHeight": -1,
                    "PoSeBanHeight": -1,
                    "revocationReason": 0,
                    "ownerAddress": "yLtkvxSueGSufQZQq8L9GVHch9QRqJqGkZ",
                    "votingAddress": "yLtkvxSueGSufQZQq8L9GVHch9QRqJqGkZ",
                    "platformNodeID": "9f3ea5525b35daf58dd17e916b8ec03cd0fa2f0c",
                    "platformP2PPort": 46856,
                    "platformHTTPPort": 2643,
                    "payoutAddress": "ybhjexnMcGckdJCyUwFu3F25zPo4mqQg1k",
                    "pubKeyOperator": "a792ce1af5f7bb9281053b3934cb8b08d00d075a56498e1a525388ce467f188e8a80911fd96a20982baa9b9678452534"
                  }
                }
              ],
              "removedMNs": [
                "a370c55db003676e937b1555196f92789506093e7b84eff6197f42617331b4c3",
                "51238bb9e2b68fc822e8eb15d415e97ebc86f769a72c15e0a6e25d9ea8d38475",
                "9bdf384d34d57ce21aab914356f834b6decbde06608dab78cf87188705aab8f2"
              ],
              "updatedMNs": [
                {
                  "3bed128ba5c04b627627cf5d9f1dec0622caef4725d8d9d4c37c65642dce92ff": {
                    "lastPaidHeight": 867103,
                    "PoSePenalty": 0,
                    "PoSeRevivedHeight": 854855,
                    "PoSeBanHeight": -1
                  }
                },
                {
                  "8e7a3cbb99a9ce89685175ce3b3b5efe33498f22ddb539a2c66190390ff9e37e": {
                    "lastPaidHeight": 867104,
                    "PoSeRevivedHeight": 853498
                  }
                }
              ]
            }"#;
        let result: MasternodeListDiff =
            serde_json::from_str(json).expect("expected to deserialize json");
        println!("{:#?}", result);
        assert_eq!(32, result.added_mns[0].pro_tx_hash.as_byte_array().len());

        assert_eq!(
            "8ed3f0c208efbcfc815cbfb94490dc68cf2e29d44dd9f8a91e20e06057aa110d7062c8ab7ccc85a9ff0c88760157f563".to_string(),
            hex::encode(result.added_mns[0].state.pub_key_operator.clone()),
            "invalid pub_key_operator"
        );
    }

    #[test]
    #[allow(deprecated)]
    fn dmn_state_core23_addresses_resolve_platform_ports() {
        // Core 23 entry: legacy platformP2PPort/platformHTTPPort absent, ports live
        // in the nested `addresses` object. Raw fields stay None; accessors resolve.
        let json = r#"{
            "service": "192.0.2.1:9999",
            "registeredHeight": 123456,
            "revocationReason": 0,
            "ownerAddress": "yPBWCdMRY5PsS3hJzs7csbdWQVRR85yxUz",
            "votingAddress": "ySM11LUD65Bi4p1gm68XLkdWc65TBKRzvQ",
            "payoutAddress": "yX4Ve7Q8Y4jscV4LZJD8HVCHKyePzR3MhA",
            "pubKeyOperator": "8ed3f0c208efbcfc815cbfb94490dc68cf2e29d44dd9f8a91e20e06057aa110d7062c8ab7ccc85a9ff0c88760157f563",
            "platformNodeID": "f2dbd9b0a1f541a7c44d34a58674d0262f5feca5",
            "addresses": {
                "core_p2p": ["192.0.2.1:9999"],
                "platform_p2p": ["192.0.2.2:36656"],
                "platform_https": ["192.0.2.2:443"]
            }
        }"#;
        let state: DMNState = serde_json::from_str(json).expect("expected to deserialize json");
        assert_eq!(state.legacy_platform_p2p_port, None, "raw legacy field deserialized as-is");
        assert_eq!(state.legacy_platform_http_port, None, "raw legacy field deserialized as-is");
        assert_eq!(
            state.platform_p2p_address(),
            Some(("192.0.2.2".to_string(), 36656)),
            "p2p resolved from addresses"
        );
        assert_eq!(
            state.platform_http_address(),
            Some(("192.0.2.2".to_string(), 443)),
            "http resolved from addresses"
        );
    }

    #[test]
    #[allow(deprecated)]
    fn dmn_state_diff_core23_addresses_resolve_platform_ports() {
        // updatedMNs entry carrying only the new `addresses` object.
        let json = r#"{
            "addresses": {
                "platform_p2p": ["192.0.2.2:36656"],
                "platform_https": ["192.0.2.2:443"]
            }
        }"#;
        let diff: DMNStateDiff = serde_json::from_str(json).expect("expected to deserialize json");
        assert_eq!(diff.legacy_platform_p2p_port, None, "raw legacy diff field deserialized as-is");
        assert_eq!(
            diff.legacy_platform_http_port, None,
            "raw legacy diff field deserialized as-is"
        );
        assert_eq!(
            diff.platform_p2p_address(),
            Some(("192.0.2.2".to_string(), 36656)),
            "diff p2p resolved from addresses"
        );
        assert_eq!(
            diff.platform_http_address(),
            Some(("192.0.2.2".to_string(), 443)),
            "diff http resolved from addresses"
        );
    }

    #[test]
    fn dmn_state_legacy_platform_ports_resolve_to_node_ip() {
        // Pre-23 entry: legacy top-level keys, no `addresses`. Accessors fall back to
        // the legacy port paired with the node IP from `service`.
        let json = r#"{
            "service": "192.0.2.1:9999",
            "registeredHeight": 123456,
            "revocationReason": 0,
            "ownerAddress": "yPBWCdMRY5PsS3hJzs7csbdWQVRR85yxUz",
            "votingAddress": "ySM11LUD65Bi4p1gm68XLkdWc65TBKRzvQ",
            "payoutAddress": "yX4Ve7Q8Y4jscV4LZJD8HVCHKyePzR3MhA",
            "pubKeyOperator": "8ed3f0c208efbcfc815cbfb94490dc68cf2e29d44dd9f8a91e20e06057aa110d7062c8ab7ccc85a9ff0c88760157f563",
            "platformNodeID": "f2dbd9b0a1f541a7c44d34a58674d0262f5feca5",
            "platformP2PPort": 26656,
            "platformHTTPPort": 443
        }"#;
        let state: DMNState = serde_json::from_str(json).expect("expected to deserialize json");
        assert!(state.addresses.is_none(), "no addresses object present");
        assert_eq!(
            state.platform_p2p_address(),
            Some(("192.0.2.1".to_string(), 26656)),
            "p2p resolved from legacy paired with node IP"
        );
        assert_eq!(
            state.platform_http_address(),
            Some(("192.0.2.1".to_string(), 443)),
            "http resolved from legacy paired with node IP"
        );
    }

    #[test]
    #[allow(deprecated)]
    fn dmn_state_zero_legacy_port_resolves_to_addresses() {
        // Transitional entry: legacy port present but zero -> addresses wins (new-first).
        let json = r#"{
            "service": "192.0.2.1:9999",
            "registeredHeight": 123456,
            "revocationReason": 0,
            "ownerAddress": "yPBWCdMRY5PsS3hJzs7csbdWQVRR85yxUz",
            "votingAddress": "ySM11LUD65Bi4p1gm68XLkdWc65TBKRzvQ",
            "payoutAddress": "yX4Ve7Q8Y4jscV4LZJD8HVCHKyePzR3MhA",
            "pubKeyOperator": "8ed3f0c208efbcfc815cbfb94490dc68cf2e29d44dd9f8a91e20e06057aa110d7062c8ab7ccc85a9ff0c88760157f563",
            "platformNodeID": "f2dbd9b0a1f541a7c44d34a58674d0262f5feca5",
            "platformP2PPort": 0,
            "addresses": {
                "platform_p2p": ["192.0.2.2:36656"]
            }
        }"#;
        let state: DMNState = serde_json::from_str(json).expect("expected to deserialize json");
        assert_eq!(state.legacy_platform_p2p_port, Some(0), "raw legacy zero deserialized as-is");
        assert_eq!(
            state.platform_p2p_address(),
            Some(("192.0.2.2".to_string(), 36656)),
            "zero legacy yields to addresses"
        );
    }

    #[test]
    #[allow(deprecated)]
    fn dmn_state_zero_legacy_port_no_addresses_resolves_as_is() {
        // The legacy fallback returns the flat port as-is, zero included: a consumer that
        // builds members from the flat ports sees this masternode, so the accessor must too.
        let json = r#"{
            "service": "192.0.2.1:9999",
            "registeredHeight": 123456,
            "revocationReason": 0,
            "ownerAddress": "yPBWCdMRY5PsS3hJzs7csbdWQVRR85yxUz",
            "votingAddress": "ySM11LUD65Bi4p1gm68XLkdWc65TBKRzvQ",
            "payoutAddress": "yX4Ve7Q8Y4jscV4LZJD8HVCHKyePzR3MhA",
            "pubKeyOperator": "8ed3f0c208efbcfc815cbfb94490dc68cf2e29d44dd9f8a91e20e06057aa110d7062c8ab7ccc85a9ff0c88760157f563",
            "platformNodeID": "f2dbd9b0a1f541a7c44d34a58674d0262f5feca5",
            "platformP2PPort": 0
        }"#;
        let state: DMNState = serde_json::from_str(json).expect("expected to deserialize json");
        assert_eq!(state.legacy_platform_p2p_port, Some(0), "raw legacy zero deserialized as-is");
        assert_eq!(
            state.platform_p2p_address(),
            Some(("192.0.2.1".to_string(), 0)),
            "zero legacy port with no addresses resolves as-is"
        );
    }

    #[test]
    fn dmn_state_out_of_range_port_rejected() {
        // A port above the u16 range must be rejected rather than truncated/accepted.
        let json = r#"{
            "service": "192.0.2.1:9999",
            "registeredHeight": 123456,
            "revocationReason": 0,
            "ownerAddress": "yPBWCdMRY5PsS3hJzs7csbdWQVRR85yxUz",
            "votingAddress": "ySM11LUD65Bi4p1gm68XLkdWc65TBKRzvQ",
            "payoutAddress": "yX4Ve7Q8Y4jscV4LZJD8HVCHKyePzR3MhA",
            "pubKeyOperator": "8ed3f0c208efbcfc815cbfb94490dc68cf2e29d44dd9f8a91e20e06057aa110d7062c8ab7ccc85a9ff0c88760157f563",
            "platformNodeID": "f2dbd9b0a1f541a7c44d34a58674d0262f5feca5",
            "addresses": {
                "platform_p2p": ["192.0.2.2:70000"]
            }
        }"#;
        let state: DMNState = serde_json::from_str(json).expect("expected to deserialize json");
        assert_eq!(state.platform_p2p_address(), None, "out-of-range port rejected");
    }

    #[test]
    fn dmn_state_legacy_out_of_range_port_rejected() {
        // A legacy port above the u16 range must be rejected, matching the addresses
        // path, so the accessor honors its documented in-range invariant.
        let json = r#"{
            "service": "192.0.2.1:9999",
            "registeredHeight": 123456,
            "revocationReason": 0,
            "ownerAddress": "yPBWCdMRY5PsS3hJzs7csbdWQVRR85yxUz",
            "votingAddress": "ySM11LUD65Bi4p1gm68XLkdWc65TBKRzvQ",
            "payoutAddress": "yX4Ve7Q8Y4jscV4LZJD8HVCHKyePzR3MhA",
            "pubKeyOperator": "8ed3f0c208efbcfc815cbfb94490dc68cf2e29d44dd9f8a91e20e06057aa110d7062c8ab7ccc85a9ff0c88760157f563",
            "platformNodeID": "f2dbd9b0a1f541a7c44d34a58674d0262f5feca5",
            "platformP2PPort": 70000
        }"#;
        let state: DMNState = serde_json::from_str(json).expect("expected to deserialize json");
        assert_eq!(state.platform_p2p_address(), None, "out-of-range legacy port rejected");
    }

    #[test]
    fn dmn_state_no_ports_resolve_to_none() {
        // No addresses and no legacy ports -> accessors return None.
        let json = r#"{
            "service": "192.0.2.1:9999",
            "registeredHeight": 123456,
            "revocationReason": 0,
            "ownerAddress": "yPBWCdMRY5PsS3hJzs7csbdWQVRR85yxUz",
            "votingAddress": "ySM11LUD65Bi4p1gm68XLkdWc65TBKRzvQ",
            "payoutAddress": "yX4Ve7Q8Y4jscV4LZJD8HVCHKyePzR3MhA",
            "pubKeyOperator": "8ed3f0c208efbcfc815cbfb94490dc68cf2e29d44dd9f8a91e20e06057aa110d7062c8ab7ccc85a9ff0c88760157f563",
            "platformNodeID": "f2dbd9b0a1f541a7c44d34a58674d0262f5feca5"
        }"#;
        let state: DMNState = serde_json::from_str(json).expect("expected to deserialize json");
        assert_eq!(state.platform_p2p_address(), None, "no source -> None");
        assert_eq!(state.platform_http_address(), None, "no source -> None");
    }

    fn dmn_state_with_legacy_p2p_zero() -> DMNState {
        let json = r#"{
            "service": "192.0.2.1:9999",
            "registeredHeight": 123456,
            "revocationReason": 0,
            "ownerAddress": "yPBWCdMRY5PsS3hJzs7csbdWQVRR85yxUz",
            "votingAddress": "ySM11LUD65Bi4p1gm68XLkdWc65TBKRzvQ",
            "payoutAddress": "yX4Ve7Q8Y4jscV4LZJD8HVCHKyePzR3MhA",
            "pubKeyOperator": "8ed3f0c208efbcfc815cbfb94490dc68cf2e29d44dd9f8a91e20e06057aa110d7062c8ab7ccc85a9ff0c88760157f563",
            "platformNodeID": "f2dbd9b0a1f541a7c44d34a58674d0262f5feca5",
            "platformP2PPort": 0
        }"#;
        serde_json::from_str(json).expect("expected to deserialize json")
    }

    #[test]
    fn dmn_state_apply_diff_propagates_addresses() {
        // Stored entry has a zero legacy port and no addresses; a diff carrying a
        // nested `addresses` object must make the merged state resolve its entry.
        let mut state = dmn_state_with_legacy_p2p_zero();
        assert_eq!(
            state.platform_p2p_address(),
            Some(("192.0.2.1".to_string(), 0)),
            "only the zero legacy port before the diff"
        );

        let diff = DMNStateDiff {
            service: None,
            registered_height: None,
            last_paid_height: None,
            consecutive_payments: None,
            pose_penalty: None,
            pose_revived_height: None,
            pose_ban_height: None,
            revocation_reason: None,
            owner_address: None,
            voting_address: None,
            payout_address: None,
            payouts: None,
            pub_key_operator: None,
            operator_payout_address: None,
            platform_node_id: None,
            #[allow(deprecated)]
            legacy_platform_p2p_port: None,
            #[allow(deprecated)]
            legacy_platform_http_port: None,
            addresses: Some(Some(MasternodeAddresses {
                core_p2p: vec![],
                platform_p2p: vec!["192.0.2.2:36656".to_string()],
                platform_https: vec![],
            })),
        };

        state.apply_diff(diff);
        assert_eq!(
            state.platform_p2p_address(),
            Some(("192.0.2.2".to_string(), 36656)),
            "diff addresses propagated and resolvable"
        );
    }

    #[test]
    fn dmn_state_diff_clears_addresses() {
        // A Some -> None transition must survive the compare/apply round-trip: the
        // diff carries `Some(None)` and applying it clears the stored addresses.
        let mut newer = dmn_state_with_legacy_p2p_zero();
        newer.addresses = Some(MasternodeAddresses {
            core_p2p: vec![],
            platform_p2p: vec!["192.0.2.2:36656".to_string()],
            platform_https: vec![],
        });
        let older = dmn_state_with_legacy_p2p_zero();

        let diff =
            newer.compare_to_newer_dmn_state(&older).expect("addresses change yields a diff");
        assert_eq!(diff.addresses, Some(None), "clear is encoded as Some(None)");

        let mut applied = newer;
        applied.apply_diff(diff);
        assert!(applied.addresses.is_none(), "Some(None) diff clears stored addresses");
    }

    #[test]
    fn dmn_state_diff_addresses_null_wire_clears() {
        // Wire-level three-state: `null` -> Some(None) (clear), absent -> None
        // (unchanged). Exercises `deserialize_addresses_2opt` through the intermediate.
        let diff: DMNStateDiff =
            serde_json::from_str(r#"{"addresses": null}"#).expect("expected to deserialize json");
        assert_eq!(diff.addresses, Some(None), "null wire -> Some(None) (clear)");

        let diff: DMNStateDiff =
            serde_json::from_str(r#"{}"#).expect("expected to deserialize json");
        assert_eq!(diff.addresses, None, "absent wire -> None (unchanged)");
    }

    #[test]
    fn parse_host_port_ipv6() {
        // Bracketed IPv6 keeps host intact; unbracketed (ambiguous) is rejected.
        assert_eq!(
            parse_host_port("[2001:db8::1]:9999"),
            Some(("[2001:db8::1]".to_string(), 9999)),
            "bracketed IPv6 parses host + port"
        );
        assert_eq!(parse_host_port("2001:db8::1"), None, "unbracketed IPv6 rejected");
        assert_eq!(
            parse_host_port("192.0.2.1:9999"),
            Some(("192.0.2.1".to_string(), 9999)),
            "IPv4 still parses"
        );
        // Empty host must be rejected.
        assert_eq!(parse_host_port(":36656"), None, "empty host rejected");
        assert_eq!(parse_host_port(":443"), None, "empty host rejected");
    }

    // Network fields as Dash Core v24 prints them. `service` is the primary core P2P entry,
    // which may be a Tor or I2P address; an extended-address Evo with no addresses prints
    // `service` as `[::]:0` and both platform ports as `-1` (src/evo/core_write.cpp,
    // `GetPlatformPort`).

    const TOR_SERVICE: &str = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:9999";
    const I2P_SERVICE: &str = "udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna.b32.i2p:0";

    fn unspecified_service() -> SocketAddr {
        "[::]:0".parse().expect("valid socket address")
    }

    /// An Evo state entry with the given network fields and a legacy payout address.
    fn evo_state_json(service: &str, p2p_port: i64, http_port: i64) -> serde_json::Value {
        json!({
            "service": service,
            "registeredHeight": 850319,
            "lastPaidHeight": 0,
            "consecutivePayments": 0,
            "PoSePenalty": 0,
            "PoSeRevivedHeight": -1,
            "PoSeBanHeight": -1,
            "revocationReason": 0,
            "ownerAddress": "yPBWCdMRY5PsS3hJzs7csbdWQVRR85yxUz",
            "votingAddress": "ySM11LUD65Bi4p1gm68XLkdWc65TBKRzvQ",
            "platformNodeID": "f2dbd9b0a1f541a7c44d34a58674d0262f5feca5",
            "platformP2PPort": p2p_port,
            "platformHTTPPort": http_port,
            "payoutAddress": "yX4Ve7Q8Y4jscV4LZJD8HVCHKyePzR3MhA",
            "pubKeyOperator": "8ed3f0c208efbcfc815cbfb94490dc68cf2e29d44dd9f8a91e20e06057aa110d7062c8ab7ccc85a9ff0c88760157f563"
        })
    }

    #[test]
    fn dmn_state_non_ip_service_reads_as_unspecified_address() {
        // A Tor or I2P primary address has no `SocketAddr` form. It must not fail the entry,
        // and with it the whole masternode list: it reads as `[::]:0`, which is what Core
        // prints for a masternode without an address.
        for service in [TOR_SERVICE, I2P_SERVICE] {
            let state: DMNState = serde_json::from_value(evo_state_json(service, 26656, 443))
                .expect("non-IP service must not fail the entry");
            assert_eq!(state.service, unspecified_service(), "{service}");
            assert_eq!(
                serde_json::to_value(&state).expect("serializable")["service"],
                "[::]:0",
                "serializes in Core's `ip:port` form"
            );
        }

        // Any IP service is kept, including IPv6 and CJDNS (fc00::/8, printed as IPv6).
        for service in ["[2001:db8::1]:9999", "[fc32:17ea:e415:c3bf:9808:149d:b5a2:c9aa]:9999"] {
            let state: DMNState = serde_json::from_value(evo_state_json(service, 26656, 443))
                .expect("expected to deserialize json");
            assert_eq!(
                state.service,
                service.parse::<SocketAddr>().expect("valid socket address"),
                "{service}"
            );
        }
    }

    #[test]
    fn malformed_service_is_still_an_error() {
        // Only a Tor or I2P host reads as `[::]:0`. Anything else that is not an `ip:port` is
        // not something Core prints, so it fails the entry rather than hiding behind `[::]:0`.
        for service in [
            "192.0.2.1",
            "192.0.2.1:99999",
            "",
            "not an address",
            "[2001:db8::1]",
            "192.0.2.1:9999 ",
            "server-1.example.com:9999",
            "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion",
            "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:99999",
        ] {
            let state = serde_json::from_value::<DMNState>(evo_state_json(service, 26656, 443));
            assert!(state.is_err(), "{service:?} must fail the entry, got {state:?}");
            let diff = serde_json::from_value::<DMNStateDiff>(json!({"service": service}));
            assert!(diff.is_err(), "{service:?} must fail the diff, got {diff:?}");
        }

        // An absent or null `service` in a diff means "unchanged".
        let diff: DMNStateDiff =
            serde_json::from_value(json!({"service": null})).expect("null service is unchanged");
        assert_eq!(diff.service, None);
    }

    #[test]
    #[allow(deprecated)]
    fn dmn_state_negative_platform_ports_read_as_absent() {
        // `-1` is Core's "no port" for an extended-address Evo with no addresses.
        let state: DMNState = serde_json::from_value(evo_state_json("[::]:0", -1, -1))
            .expect("-1 platform ports must not fail the entry");
        assert_eq!(state.legacy_platform_p2p_port, None);
        assert_eq!(state.legacy_platform_http_port, None);
        assert_eq!(state.platform_p2p_address(), None);
        assert_eq!(state.platform_http_address(), None);
    }

    #[test]
    fn dmn_state_diff_non_ip_service_reads_as_unspecified_address() {
        // A ProUpServTx that makes a Tor address the primary core P2P entry. The Tor entry
        // stays readable in `addresses`.
        let diff: DMNStateDiff = serde_json::from_value(json!({
            "service": TOR_SERVICE,
            "addresses": {
                "core_p2p": [TOR_SERVICE, "192.0.2.10:9999"]
            }
        }))
        .expect("non-IP service must not fail the diff");
        assert_eq!(diff.service, Some(unspecified_service()));
        assert_eq!(
            diff.addresses.flatten().map(|addresses| addresses.core_p2p),
            Some(vec![TOR_SERVICE.to_string(), "192.0.2.10:9999".to_string()])
        );
    }

    #[test]
    #[allow(deprecated)]
    fn dmn_state_diff_negative_platform_ports_read_as_absent() {
        // Core's diff never prints `-1` (it prints the scalar port or the live netInfo port);
        // this guards that diffs parse platform ports like full entries do.
        let diff: DMNStateDiff =
            serde_json::from_value(json!({"platformP2PPort": -1, "platformHTTPPort": -1}))
                .expect("-1 platform ports must not fail the diff");
        assert_eq!(diff.legacy_platform_p2p_port, None);
        assert_eq!(diff.legacy_platform_http_port, None);
    }

    #[test]
    #[allow(deprecated)]
    fn extaddr_evo_port_only_diff_carries_the_new_port_only_in_addresses() {
        // An extended-address Evo keeps its platform ports in `addresses` and its scalar ports
        // at 0, so a ProUpServTx that changes only a platform port reports neither
        // `platformP2PPort` nor `platformHTTPPort` in the diff.
        let diff: DMNStateDiff = serde_json::from_value(json!({
            "service": "192.0.2.20:9999",
            "addresses": {
                "core_p2p": ["192.0.2.20:9999", "[2001:db8::20]:9999"],
                "platform_p2p": ["192.0.2.20:36668"],
                "platform_https": ["192.0.2.20:1443"]
            }
        }))
        .expect("expected to deserialize json");
        assert_eq!(diff.legacy_platform_p2p_port, None);
        assert_eq!(diff.legacy_platform_http_port, None);
        assert_eq!(diff.platform_p2p_address(), Some(("192.0.2.20".to_string(), 36668)));

        let mut state: DMNState = serde_json::from_value(evo_state_json("192.0.2.20:9999", 0, 0))
            .expect("expected to deserialize json");
        state.apply_diff(diff);
        assert_eq!(state.platform_p2p_address(), Some(("192.0.2.20".to_string(), 36668)));
        assert_eq!(state.platform_http_address(), Some(("192.0.2.20".to_string(), 1443)));
    }

    #[test]
    #[allow(deprecated)]
    fn platform_ports_out_of_u32_range_are_an_error_and_null_is_absent() {
        // A port past `u32::MAX` must fail rather than wrap to a plausible port.
        let state = serde_json::from_value::<DMNState>(evo_state_json(
            "192.0.2.1:9999",
            (1i64 << 32) + 26656,
            443,
        ));
        assert!(state.is_err(), "2^32 + 26656 must not read as 26656: {state:?}");

        // `null` reads as "no port", as it did for a plain `Option<u32>`.
        let mut json = evo_state_json("192.0.2.1:9999", 26656, 443);
        json["platformP2PPort"] = serde_json::Value::Null;
        json["platformHTTPPort"] = serde_json::Value::Null;
        let state: DMNState = serde_json::from_value(json).expect("null port is absent");
        assert_eq!(state.legacy_platform_p2p_port, None);
        assert_eq!(state.legacy_platform_http_port, None);
    }

    #[test]
    fn masternode_status_non_ip_service_reads_as_unspecified_address() {
        let status: MasternodeStatus = serde_json::from_value(json!({
            "outpoint": "ff6226e6c97bfcf40b6d04e12e3f75678024988823bfba28cde2a9ac11b1a765-1",
            "service": TOR_SERVICE,
            "proTxHash": "c560a9be2be9db79e1aaa16e4dd3cd22bddcb0155f88aba68aa4797d375ef370",
            "type": "Evo",
            "collateralHash": "ff6226e6c97bfcf40b6d04e12e3f75678024988823bfba28cde2a9ac11b1a765",
            "collateralIndex": 1,
            "dmnState": evo_state_json(TOR_SERVICE, 26656, 443),
            "state": "READY",
            "status": "Ready",
            "quorumParticipation": true
        }))
        .expect("non-IP service must not fail the status");
        assert_eq!(status.service, unspecified_service());
        assert_eq!(status.dmn_state.service, unspecified_service());
    }

    #[test]
    fn quorum_masternode_list_item_non_ip_service_reads_as_unspecified_address() {
        // A `protx diff` mnList entry of a masternode whose primary address is Tor.
        let item: QuorumMasternodeListItem = serde_json::from_value(json!({
            "nVersion": 3,
            "nType": 0,
            "proRegTxHash": "c560a9be2be9db79e1aaa16e4dd3cd22bddcb0155f88aba68aa4797d375ef370",
            "confirmedHash": "000000c8d2f1a47d3cbbd3c3a4a4f0f2e04ec1d3cb14ae8f4f14f16e1ad6c9d4",
            "service": TOR_SERVICE,
            "addresses": {
                "core_p2p": [TOR_SERVICE]
            },
            "pubKeyOperator": "8ed3f0c208efbcfc815cbfb94490dc68cf2e29d44dd9f8a91e20e06057aa110d7062c8ab7ccc85a9ff0c88760157f563",
            "votingAddress": "ySM11LUD65Bi4p1gm68XLkdWc65TBKRzvQ",
            "isValid": true
        }))
        .expect("non-IP service must not fail the entry");
        assert_eq!(item.service, unspecified_service());
    }

    #[test]
    fn masternode_list_entries_with_negative_ports_or_non_ip_address_parse() {
        // `masternodelist json` with an extended-address Evo that has no addresses and a
        // masternode whose primary address is Tor. One such entry must not fail the list.
        let list: HashMap<String, Masternode> = serde_json::from_value(json!({
            "ff6226e6c97bfcf40b6d04e12e3f75678024988823bfba28cde2a9ac11b1a765-1": {
                "proTxHash": "c560a9be2be9db79e1aaa16e4dd3cd22bddcb0155f88aba68aa4797d375ef370",
                "address": "[::]:0",
                "addresses": {},
                "payee": "yX4Ve7Q8Y4jscV4LZJD8HVCHKyePzR3MhA",
                "status": "ENABLED",
                "type": "Evo",
                "platformNodeID": "f2dbd9b0a1f541a7c44d34a58674d0262f5feca5",
                "platformP2PPort": -1,
                "platformHTTPPort": -1,
                "pospenaltyscore": 0,
                "consecutivePayments": 0,
                "lastpaidtime": 0,
                "lastpaidblock": 0,
                "owneraddress": "yPBWCdMRY5PsS3hJzs7csbdWQVRR85yxUz",
                "votingaddress": "ySM11LUD65Bi4p1gm68XLkdWc65TBKRzvQ",
                "collateraladdress": "yNqYnF9sHURjwRmhZMLFGQ3WjC5DZNJMUi",
                "pubkeyoperator": "8ed3f0c208efbcfc815cbfb94490dc68cf2e29d44dd9f8a91e20e06057aa110d7062c8ab7ccc85a9ff0c88760157f563"
            },
            "35215134107b5e423d327cab12d2b4c60a9b769301096e05a95916676d2f7867-0": {
                "proTxHash": "9a8cfd0e5fa3a7467b81a5a2fa41e40f7981591cfb62d86e35db37962c128bb0",
                "address": TOR_SERVICE,
                "addresses": {
                    "core_p2p": [TOR_SERVICE]
                },
                "payee": "ybhjexnMcGckdJCyUwFu3F25zPo4mqQg1k",
                "status": "ENABLED",
                "type": "Regular",
                "pospenaltyscore": 0,
                "consecutivePayments": 3,
                "lastpaidtime": 1727700000,
                "lastpaidblock": 1641,
                "owneraddress": "yLtkvxSueGSufQZQq8L9GVHch9QRqJqGkZ",
                "votingaddress": "yLtkvxSueGSufQZQq8L9GVHch9QRqJqGkZ",
                "collateraladdress": "yd2PwFoqtEJdnJVSEzBDMxVnFVgEvJyvyY",
                "pubkeyoperator": "a792ce1af5f7bb9281053b3934cb8b08d00d075a56498e1a525388ce467f188e8a80911fd96a20982baa9b9678452534"
            }
        }))
        .expect("one such entry must not fail the list");

        let evo = &list["ff6226e6c97bfcf40b6d04e12e3f75678024988823bfba28cde2a9ac11b1a765-1"];
        assert_eq!(evo.platform_p2p_port, None);
        assert_eq!(evo.platform_http_port, None);
        assert_eq!(evo.address, unspecified_service());

        let tor = &list["35215134107b5e423d327cab12d2b4c60a9b769301096e05a95916676d2f7867-0"];
        assert_eq!(tor.address, unspecified_service());
    }

    // `protx listdiff` as Dash Core v24 prints it with `-deprecatedrpc=service`
    // (`CDeterministicMN::ToJson`, `CDeterministicMNState::ToJson`,
    // `CDeterministicMNStateDiff::ToJson`).
    // Owner payouts: a shared masternode prints `shares` and neither `ownerAddress`,
    // `payoutAddress` nor `collateralAddress` (its collateral output has no address); an
    // extended-address (version 3) masternode prints `payouts` instead of `payoutAddress`.
    //
    // addedMNs:
    //   0: shared Regular
    //   1: extended-address Regular, one payout
    //   2: extended-address Regular, Tor primary address, two payouts (P2PKH and P2SH)
    //   3: extended-address Evo with no addresses
    //   4: extended-address Evo, IPv6 primary address, two payouts
    // updatedMNs:
    //   legacy Evo raised to version 3 by a ProUpServTx: its payout address moves into
    //   `payouts` and the cleared script prints no `payoutAddress`
    //   version 3 Regular whose ProUpRegTx changes only the payouts
    //
    // Payout and share addresses, other than the legacy payout address moved into `payouts`,
    // encode repeated-byte hashes (0x11 ... 0xdd) so the expected hashes read directly; 0x77
    // is P2SH, the rest P2PKH.
    const CORE_V24_LISTDIFF: &str = r#"{
      "baseHeight": 1200,
      "blockHeight": 1260,
      "addedMNs": [
        {
          "type": "Regular",
          "proTxHash": "a4d26868017c0ccffe2efe50944ef4211834660cca834c6e9f86dec6a88246fa",
          "collateralHash": "a4d26868017c0ccffe2efe50944ef4211834660cca834c6e9f86dec6a88246fa",
          "collateralIndex": 1,
          "operatorReward": 0,
          "state": {
            "version": 3,
            "service": "192.0.2.30:9999",
            "addresses": {
              "core_p2p": ["192.0.2.30:9999"]
            },
            "registeredHeight": 1210,
            "lastPaidHeight": 0,
            "consecutivePayments": 0,
            "PoSePenalty": 0,
            "PoSeRevivedHeight": -1,
            "PoSeBanHeight": -1,
            "revocationReason": 0,
            "votingAddress": "ySM11LUD65Bi4p1gm68XLkdWc65TBKRzvQ",
            "shares": [
              {
                "amount": 60000000000,
                "refundAddress": "yMsgnH1xKGa85n4bq2imrZbG2KgrmGttAV",
                "refundScript": "76a914111111111111111111111111111111111111111188ac",
                "rewardAddress": "yPRviMJaEHGafsc5EKovpa5Nw2Jewo9mdj",
                "rewardScript": "76a914222222222222222222222222222222222222222288ac",
                "ownerAddress": "yQzAeRbC9Hy3Fy9Ydcu5naZVqivT95Ka2R"
              },
              {
                "amount": 40000000000,
                "refundAddress": "ySYQaVsp4JfVr4h22uzEkb3ckRYFHJwGq9",
                "refundScript": "76a914444444444444444444444444444444444444444488ac",
                "rewardAddress": "ySYQaVsp4JfVr4h22uzEkb3ckRYFHJwGq9",
                "rewardScript": "76a914444444444444444444444444444444444444444488ac",
                "ownerAddress": "yVetSeT3tL4R2FmxqWAYgc1rZpmqbMcFhL"
              }
            ],
            "earlyPeriodBlocks": 1000,
            "earlyPenalty": 100000000,
            "pubKeyOperator": "8ed3f0c208efbcfc815cbfb94490dc68cf2e29d44dd9f8a91e20e06057aa110d7062c8ab7ccc85a9ff0c88760157f563"
          }
        },
        {
          "type": "Regular",
          "proTxHash": "813a7c3f28817988a8e6ce66e07e43e261e78398373bfbaae94c898645111d6b",
          "collateralHash": "ff6226e6c97bfcf40b6d04e12e3f75678024988823bfba28cde2a9ac11b1a765",
          "collateralIndex": 1,
          "collateralAddress": "yNqYnF9sHURjwRmhZMLFGQ3WjC5DZNJMUi",
          "operatorReward": 0,
          "state": {
            "version": 3,
            "service": "192.0.2.31:9999",
            "addresses": {
              "core_p2p": ["192.0.2.31:9999"]
            },
            "registeredHeight": 1220,
            "lastPaidHeight": 0,
            "consecutivePayments": 0,
            "PoSePenalty": 0,
            "PoSeRevivedHeight": -1,
            "PoSeBanHeight": -1,
            "revocationReason": 0,
            "ownerAddress": "yPBWCdMRY5PsS3hJzs7csbdWQVRR85yxUz",
            "votingAddress": "ySM11LUD65Bi4p1gm68XLkdWc65TBKRzvQ",
            "payouts": [
              {
                "address": "yU6eWaARyKMxSAEVSD5PibXjf8A3TH4gqJ",
                "script": "76a914555555555555555555555555555555555555555588ac",
                "reward": 10000
              }
            ],
            "pubKeyOperator": "8ed3f0c208efbcfc815cbfb94490dc68cf2e29d44dd9f8a91e20e06057aa110d7062c8ab7ccc85a9ff0c88760157f563"
          }
        },
        {
          "type": "Regular",
          "proTxHash": "3023ffd989974768b0dfc347410ad923fa6d3f1eee90180bd0c435e81cb1a82f",
          "collateralHash": "35215134107b5e423d327cab12d2b4c60a9b769301096e05a95916676d2f7867",
          "collateralIndex": 0,
          "collateralAddress": "yd2PwFoqtEJdnJVSEzBDMxVnFVgEvJyvyY",
          "operatorReward": 0,
          "state": {
            "version": 3,
            "service": "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:9999",
            "addresses": {
              "core_p2p": [
                "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:9999",
                "192.0.2.32:9999"
              ]
            },
            "registeredHeight": 1230,
            "lastPaidHeight": 0,
            "consecutivePayments": 0,
            "PoSePenalty": 0,
            "PoSeRevivedHeight": -1,
            "PoSeBanHeight": -1,
            "revocationReason": 0,
            "ownerAddress": "yLtkvxSueGSufQZQq8L9GVHch9QRqJqGkZ",
            "votingAddress": "yLtkvxSueGSufQZQq8L9GVHch9QRqJqGkZ",
            "payouts": [
              {
                "address": "yYmNJo2HiMTLCSrue6Lrccz6PE1S1ELq2T",
                "script": "76a914888888888888888888888888888888888888888888ac",
                "reward": 7000
              },
              {
                "address": "8qK9EafotWgreuSxH2x8ySZnKVDVivy3Zf",
                "script": "a914777777777777777777777777777777777777777787",
                "reward": 3000
              }
            ],
            "pubKeyOperator": "a792ce1af5f7bb9281053b3934cb8b08d00d075a56498e1a525388ce467f188e8a80911fd96a20982baa9b9678452534"
          }
        },
        {
          "type": "Evo",
          "proTxHash": "6f1757595185032c808321af3e2e8468fae10b8f91e2a657d7a4c7122f4b2706",
          "collateralHash": "cbf3c744b1c18fe1866e79972818c98fb1a268736f1757595185032c808321af",
          "collateralIndex": 0,
          "collateralAddress": "ybhjexnMcGckdJCyUwFu3F25zPo4mqQg1k",
          "operatorReward": 0,
          "state": {
            "version": 3,
            "service": "[::]:0",
            "addresses": {},
            "registeredHeight": 1240,
            "lastPaidHeight": 0,
            "consecutivePayments": 0,
            "PoSePenalty": 0,
            "PoSeRevivedHeight": -1,
            "PoSeBanHeight": -1,
            "revocationReason": 0,
            "ownerAddress": "yPBWCdMRY5PsS3hJzs7csbdWQVRR85yxUz",
            "votingAddress": "ySM11LUD65Bi4p1gm68XLkdWc65TBKRzvQ",
            "platformNodeID": "cbf3c744b1c18fe1866e79972818c98fb1a26873",
            "platformP2PPort": -1,
            "platformHTTPPort": -1,
            "payouts": [
              {
                "address": "yaKcEsJudN9nnYQP3PS1adUDHvdE6sjNiQ",
                "script": "76a914999999999999999999999999999999999999999988ac",
                "reward": 10000
              }
            ],
            "pubKeyOperator": "8ed3f0c208efbcfc815cbfb94490dc68cf2e29d44dd9f8a91e20e06057aa110d7062c8ab7ccc85a9ff0c88760157f563"
          }
        },
        {
          "type": "Evo",
          "proTxHash": "aecd2830b843e6a84283ba290492a213e355cea7c5026e6118a21e1bfbc36783",
          "collateralHash": "59cd030a1a4cd43a53c3a600c20f64ed07399873aecd2830b843e6a84283ba29",
          "collateralIndex": 0,
          "collateralAddress": "yNqYnF9sHURjwRmhZMLFGQ3WjC5DZNJMUi",
          "operatorReward": 0,
          "state": {
            "version": 3,
            "service": "[2001:db8::4]:9999",
            "addresses": {
              "core_p2p": ["[2001:db8::4]:9999"],
              "platform_p2p": ["[2001:db8::4]:26656"],
              "platform_https": ["[2001:db8::4]:443"]
            },
            "registeredHeight": 1250,
            "lastPaidHeight": 0,
            "consecutivePayments": 0,
            "PoSePenalty": 0,
            "PoSeRevivedHeight": -1,
            "PoSeBanHeight": -1,
            "revocationReason": 0,
            "ownerAddress": "yPBWCdMRY5PsS3hJzs7csbdWQVRR85yxUz",
            "votingAddress": "ySM11LUD65Bi4p1gm68XLkdWc65TBKRzvQ",
            "platformNodeID": "4bcc85253e395ec272998a0722ac3ee1dd3965f7",
            "platformP2PPort": 26656,
            "platformHTTPPort": 443,
            "payouts": [
              {
                "address": "ybsrAwbXYNrFNdwrSgXAYdxLCdF2GdFbqY",
                "script": "76a914aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa88ac",
                "reward": 5000
              },
              {
                "address": "ydS671t9TPYhxjVKqycKWeST7KrpUM1c4t",
                "script": "76a914bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb88ac",
                "reward": 5000
              }
            ],
            "pubKeyOperator": "a792ce1af5f7bb9281053b3934cb8b08d00d075a56498e1a525388ce467f188e8a80911fd96a20982baa9b9678452534"
          }
        }
      ],
      "removedMNs": [],
      "updatedMNs": [
        {
          "ca3d32c4f2ef62eaf736bf41bb3235a832ec1eb6d8dfaccd4d3555e70f6757b0": {
            "version": 3,
            "service": "192.0.2.40:9999",
            "payouts": [
              {
                "address": "yX4Ve7Q8Y4jscV4LZJD8HVCHKyePzR3MhA",
                "script": "76a91475d57974b6e29a4a70df57a3b11195ce0a0dc81788ac",
                "reward": 10000
              }
            ],
            "platformP2PPort": 36656,
            "platformHTTPPort": 1443,
            "addresses": {
              "core_p2p": ["192.0.2.40:9999"],
              "platform_p2p": ["192.0.2.40:36656"],
              "platform_https": ["192.0.2.40:1443"]
            }
          }
        },
        {
          "27978dd892b7c876c238be1a6141461c2824f3497dd0058e160979bc8f0a0bef": {
            "payouts": [
              {
                "address": "yezL36AmNQFAYq2oFGhUUeva22UccZnF8F",
                "script": "76a914cccccccccccccccccccccccccccccccccccccccc88ac",
                "reward": 2500
              },
              {
                "address": "ygYZyATPHQwd8vaGeZndSfQgvj6Qro5WbT",
                "script": "76a914dddddddddddddddddddddddddddddddddddddddd88ac",
                "reward": 7500
              }
            ]
          }
        }
      ]
    }"#;

    /// The full state of the legacy Evo that the first `CORE_V24_LISTDIFF` diff raises to
    /// version 3, as Core v24 prints it before that diff.
    const CORE_V24_LEGACY_EVO_STATE: &str = r#"{
      "version": 2,
      "service": "192.0.2.40:9999",
      "addresses": {
        "core_p2p": ["192.0.2.40:9999"],
        "platform_https": ["192.0.2.40:443"],
        "platform_p2p": ["192.0.2.40:26656"]
      },
      "registeredHeight": 900,
      "lastPaidHeight": 1190,
      "consecutivePayments": 0,
      "PoSePenalty": 0,
      "PoSeRevivedHeight": -1,
      "PoSeBanHeight": -1,
      "revocationReason": 0,
      "ownerAddress": "yPBWCdMRY5PsS3hJzs7csbdWQVRR85yxUz",
      "votingAddress": "ySM11LUD65Bi4p1gm68XLkdWc65TBKRzvQ",
      "platformNodeID": "9e391c2c041a122a779bafe09d6c47ea600dfcbe",
      "platformP2PPort": 26656,
      "platformHTTPPort": 443,
      "payoutAddress": "yX4Ve7Q8Y4jscV4LZJD8HVCHKyePzR3MhA",
      "pubKeyOperator": "8ed3f0c208efbcfc815cbfb94490dc68cf2e29d44dd9f8a91e20e06057aa110d7062c8ab7ccc85a9ff0c88760157f563"
    }"#;

    /// The same Evo after the diff, as Core v24 prints its full state.
    const CORE_V24_RAISED_EVO_STATE: &str = r#"{
      "version": 3,
      "service": "192.0.2.40:9999",
      "addresses": {
        "core_p2p": ["192.0.2.40:9999"],
        "platform_p2p": ["192.0.2.40:36656"],
        "platform_https": ["192.0.2.40:1443"]
      },
      "registeredHeight": 900,
      "lastPaidHeight": 1190,
      "consecutivePayments": 0,
      "PoSePenalty": 0,
      "PoSeRevivedHeight": -1,
      "PoSeBanHeight": -1,
      "revocationReason": 0,
      "ownerAddress": "yPBWCdMRY5PsS3hJzs7csbdWQVRR85yxUz",
      "votingAddress": "ySM11LUD65Bi4p1gm68XLkdWc65TBKRzvQ",
      "platformNodeID": "9e391c2c041a122a779bafe09d6c47ea600dfcbe",
      "platformP2PPort": 36656,
      "platformHTTPPort": 1443,
      "payouts": [
        {
          "address": "yX4Ve7Q8Y4jscV4LZJD8HVCHKyePzR3MhA",
          "script": "76a91475d57974b6e29a4a70df57a3b11195ce0a0dc81788ac",
          "reward": 10000
        }
      ],
      "pubKeyOperator": "8ed3f0c208efbcfc815cbfb94490dc68cf2e29d44dd9f8a91e20e06057aa110d7062c8ab7ccc85a9ff0c88760157f563"
    }"#;

    fn core_v24_listdiff() -> MasternodeListDiff {
        serde_json::from_str(CORE_V24_LISTDIFF).expect("Core v24 listdiff must deserialize")
    }

    #[test]
    fn core_v24_listdiff_with_shared_and_extended_address_masternodes_deserializes() {
        let diff = core_v24_listdiff();
        assert_eq!(diff.added_mns.len(), 5);
        assert_eq!(diff.updated_mns.len(), 2);
    }

    /// `protx info` for a `CORE_V24_LISTDIFF` added masternode: the listdiff entry plus
    /// confirmations and meta info.
    fn core_v24_protx_info(added_index: usize) -> ProTxInfo {
        let listdiff: serde_json::Value =
            serde_json::from_str(CORE_V24_LISTDIFF).expect("valid json");
        let mut info = listdiff["addedMNs"][added_index].clone();
        info["confirmations"] = json!(50);
        info["metaInfo"] = json!({
            "lastDSQ": 0,
            "mixingTxCount": 0,
            "outboundAttemptCount": 0,
            "lastOutboundAttempt": 0,
            "lastOutboundAttemptElapsed": 1727700000,
            "lastOutboundSuccess": 0,
            "lastOutboundSuccessElapsed": 1727700000,
            "is_platform_banned": false,
            "platform_ban_height_updated": 0
        });
        serde_json::from_value(info).expect("Core v24 protx info must deserialize")
    }

    fn hash160(hex: &str) -> [u8; 20] {
        hex::decode(hex).expect("valid hex").try_into().expect("20 bytes")
    }

    #[test]
    fn core_v24_protx_info_has_no_collateral_address_only_for_shared_masternode() {
        assert_eq!(core_v24_protx_info(0).collateral_address, None, "shared collateral");
        assert_eq!(
            core_v24_protx_info(1).collateral_address,
            Some(hash160("1ba1ae9799af495a38619dad703a079919a48144")),
            "yNqYnF9sHURjwRmhZMLFGQ3WjC5DZNJMUi"
        );
    }

    #[test]
    fn core_v24_masternode_status_of_extended_address_masternode_deserializes() {
        let listdiff: serde_json::Value =
            serde_json::from_str(CORE_V24_LISTDIFF).expect("valid json");
        let status: MasternodeStatus = serde_json::from_value(json!({
            "outpoint": "35215134107b5e423d327cab12d2b4c60a9b769301096e05a95916676d2f7867-0",
            "service": TOR_SERVICE,
            "proTxHash": "3023ffd989974768b0dfc347410ad923fa6d3f1eee90180bd0c435e81cb1a82f",
            "type": "Regular",
            "collateralHash": "35215134107b5e423d327cab12d2b4c60a9b769301096e05a95916676d2f7867",
            "collateralIndex": 0,
            "dmnState": listdiff["addedMNs"][2]["state"],
            "state": "READY",
            "status": "Ready",
            "quorumParticipation": true
        }))
        .expect("extended-address masternode status must deserialize");
        assert_eq!(status.dmn_state.service, unspecified_service());
    }

    fn p2pkh_payout(key_hash: [u8; 20], reward: u16) -> DMNPayout {
        DMNPayout {
            address: key_hash,
            script: ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array(key_hash)),
            reward,
        }
    }

    fn p2sh_payout(script_hash: [u8; 20], reward: u16) -> DMNPayout {
        DMNPayout {
            address: script_hash,
            script: ScriptBuf::new_p2sh(&ScriptHash::from_byte_array(script_hash)),
            reward,
        }
    }

    #[test]
    fn shared_masternode_has_no_owner_payout_or_collateral_address() {
        // Its owners and reward recipients are the share holders, which are not modelled.
        let shared = &core_v24_listdiff().added_mns[0];
        assert_eq!(shared.collateral_address, None);
        assert_eq!(shared.state.owner_address, None);
        assert_eq!(shared.state.payout_address, None);
        assert_eq!(shared.state.payouts, None);
        assert_eq!(
            shared.state.voting_address,
            hash160("421c03add2c804421451c4e022258778175e60d8")
        );
    }

    #[test]
    fn extended_address_masternode_has_payouts_instead_of_payout_address() {
        let added = core_v24_listdiff().added_mns;

        let one_payout = &added[1];
        assert_eq!(one_payout.state.payout_address, None);
        assert_eq!(one_payout.state.payouts, Some(vec![p2pkh_payout([0x55; 20], 10000)]));
        assert_eq!(
            one_payout.state.owner_address,
            Some(hash160("1f67d90f35e3c5070c368ae6f3635aac357e47df"))
        );
        assert_eq!(
            one_payout.collateral_address,
            Some(hash160("1ba1ae9799af495a38619dad703a079919a48144"))
        );

        // A P2SH payout's address is its script hash; only the script tells it from a key hash.
        let two_payouts = &added[2].state;
        assert_eq!(two_payouts.payout_address, None);
        assert_eq!(
            two_payouts.payouts,
            Some(vec![p2pkh_payout([0x88; 20], 7000), p2sh_payout([0x77; 20], 3000)])
        );
        let payouts = two_payouts.payouts.as_deref().expect("payouts");
        assert!(payouts[0].script.is_p2pkh());
        assert!(payouts[1].script.is_p2sh());
    }

    #[test]
    #[allow(deprecated)]
    fn extended_address_evo_without_addresses_has_no_service_or_platform_ports() {
        let evo = &core_v24_listdiff().added_mns[3].state;
        assert_eq!(evo.service, unspecified_service());
        assert_eq!(evo.addresses, Some(MasternodeAddresses::default()));
        assert_eq!(evo.legacy_platform_p2p_port, None);
        assert_eq!(evo.legacy_platform_http_port, None);
        assert_eq!(evo.platform_p2p_address(), None);
        assert_eq!(evo.platform_http_address(), None);
        assert_eq!(evo.payouts, Some(vec![p2pkh_payout([0x99; 20], 10000)]));
    }

    #[test]
    fn tor_primary_address_reads_as_unspecified_service_and_stays_in_addresses() {
        let tor = &core_v24_listdiff().added_mns[2].state;
        assert_eq!(tor.service, unspecified_service());
        assert_eq!(
            tor.addresses.as_ref().map(|addresses| addresses.core_p2p.clone()),
            Some(vec![TOR_SERVICE.to_string(), "192.0.2.32:9999".to_string()])
        );
    }

    #[test]
    #[allow(deprecated)]
    fn ipv6_primary_address_and_platform_addresses_resolve() {
        let evo = &core_v24_listdiff().added_mns[4].state;
        assert_eq!(
            evo.service,
            "[2001:db8::4]:9999".parse::<SocketAddr>().expect("valid socket address")
        );
        assert_eq!(evo.platform_p2p_address(), Some(("[2001:db8::4]".to_string(), 26656)));
        assert_eq!(evo.platform_http_address(), Some(("[2001:db8::4]".to_string(), 443)));
        assert_eq!(evo.legacy_platform_p2p_port, Some(26656));
        assert_eq!(evo.legacy_platform_http_port, Some(443));
    }

    #[test]
    fn legacy_to_extended_address_diff_moves_payout_address_into_payouts() {
        let listdiff = core_v24_listdiff();
        let (_, diff) = &listdiff.updated_mns[0];
        let mut state: DMNState =
            serde_json::from_str(CORE_V24_LEGACY_EVO_STATE).expect("expected to deserialize json");
        let legacy_payout = state.payout_address.expect("a legacy masternode has a payout address");

        // Core clears the legacy payout script, which prints no `payoutAddress`.
        assert_eq!(diff.payout_address, None);
        assert_eq!(diff.payouts, Some(vec![p2pkh_payout(legacy_payout, 10000)]));

        state.apply_diff(diff.clone());
        assert_eq!(state.payout_address, None, "payouts replace the payout address");
        let raised: DMNState =
            serde_json::from_str(CORE_V24_RAISED_EVO_STATE).expect("expected to deserialize json");
        assert_eq!(state, raised, "applying Core's diff yields Core's new full state");
    }

    #[test]
    fn extended_address_payout_change_diff_carries_only_payouts() {
        let listdiff = core_v24_listdiff();
        let (_, diff) = &listdiff.updated_mns[1];
        let new_payouts = vec![p2pkh_payout([0xcc; 20], 2500), p2pkh_payout([0xdd; 20], 7500)];
        assert_eq!(diff.payout_address, None);
        assert_eq!(diff.payouts, Some(new_payouts.clone()));

        let mut state = listdiff.added_mns[1].state.clone();
        state.apply_diff(diff.clone());
        assert_eq!(state.payouts, Some(new_payouts));
        assert_eq!(state.payout_address, None);
    }

    #[test]
    fn apply_diff_keeps_at_most_one_of_payout_address_and_payouts() {
        // Core never moves a masternode back to a single payout address, but if a diff sets
        // one, it replaces the payouts rather than coexisting with them.
        let mut state = core_v24_listdiff().added_mns[1].state.clone();
        let diff: DMNStateDiff =
            serde_json::from_value(json!({"payoutAddress": "yVetSeT3tL4R2FmxqWAYgc1rZpmqbMcFhL"}))
                .expect("expected to deserialize json");
        state.apply_diff(diff);
        assert_eq!(state.payout_address, Some([0x66; 20]));
        assert_eq!(state.payouts, None);
    }

    fn assert_compare_then_apply_round_trips(older: &DMNState, newer: &DMNState) {
        let diff = older.compare_to_newer_dmn_state(newer).expect("the states differ");
        let mut applied = older.clone();
        applied.apply_diff(diff);
        assert_eq!(&applied, newer);
    }

    #[test]
    fn compare_then_apply_round_trips_legacy_to_extended_address() {
        let legacy: DMNState =
            serde_json::from_str(CORE_V24_LEGACY_EVO_STATE).expect("expected to deserialize json");
        let raised: DMNState =
            serde_json::from_str(CORE_V24_RAISED_EVO_STATE).expect("expected to deserialize json");
        assert_compare_then_apply_round_trips(&legacy, &raised);
    }

    #[test]
    #[allow(deprecated)]
    fn compare_then_apply_round_trips_extended_address_to_extended_address() {
        // A ProUpRegTx changing the payouts and a ProUpServTx changing the platform ports.
        let older = core_v24_listdiff().added_mns[4].state.clone();
        let mut newer = older.clone();
        newer.payouts = Some(vec![p2pkh_payout([0xcc; 20], 2500), p2pkh_payout([0xdd; 20], 7500)]);
        newer.addresses = Some(MasternodeAddresses {
            core_p2p: vec!["[2001:db8::4]:9999".to_string()],
            platform_p2p: vec!["[2001:db8::4]:36656".to_string()],
            platform_https: vec!["[2001:db8::4]:1443".to_string()],
        });
        newer.legacy_platform_p2p_port = Some(36656);
        newer.legacy_platform_http_port = Some(1443);
        assert_compare_then_apply_round_trips(&older, &newer);
    }

    #[test]
    fn compare_then_apply_round_trips_shared_masternode() {
        // A ProUpSharedRegTx changing the voting and operator keys.
        let older = core_v24_listdiff().added_mns[0].state.clone();
        let mut newer = older.clone();
        newer.voting_address = [0xee; 20];
        newer.pub_key_operator = hex::decode("a792ce1af5f7bb9281053b3934cb8b08d00d075a56498e1a525388ce467f188e8a80911fd96a20982baa9b9678452534").expect("valid hex");

        let diff = older.compare_to_newer_dmn_state(&newer).expect("the states differ");
        assert_eq!(diff.owner_address, None);
        assert_eq!(diff.payout_address, None);
        assert_eq!(diff.payouts, None);
        assert_compare_then_apply_round_trips(&older, &newer);
    }

    // Network fields of a diff as Core's diff emitter prints them (`CDeterministicMNStateDiff::
    // ToJson`), applied to Core's full state of the same masternode. The emitter prints
    // `addresses` per changed field rather than as a whole:
    // - a changed core address prints `service` and `core_p2p`; a legacy (version 1/2) Evo's
    //   platform entries, which Core renders on the primary address, are left out unless their
    //   port changed too;
    // - a legacy Evo's changed platform port alone prints `255.255.255.255:<port>`, the host
    //   standing for the primary address;
    // - emptied addresses (revocation, operator change) print `service` (`[::]:0`) and no
    //   `addresses` at all.
    // For a legacy Evo, applying a diff must give the full state Core prints afterwards,
    // whichever way the changes are batched into diffs.

    /// Core's full state of the `CORE_V24_LEGACY_EVO_STATE` Evo with the given core IP and
    /// platform ports (`GetNetInfoWithLegacyFields` renders them on the core IP).
    fn legacy_evo_full_state(ip: &str, p2p_port: u16, http_port: u16) -> DMNState {
        let mut state: serde_json::Value =
            serde_json::from_str(CORE_V24_LEGACY_EVO_STATE).expect("valid json");
        state["service"] = json!(format!("{ip}:9999"));
        state["addresses"] = json!({
            "core_p2p": [format!("{ip}:9999")],
            "platform_https": [format!("{ip}:{http_port}")],
            "platform_p2p": [format!("{ip}:{p2p_port}")]
        });
        state["platformP2PPort"] = json!(p2p_port);
        state["platformHTTPPort"] = json!(http_port);
        serde_json::from_value(state).expect("expected to deserialize json")
    }

    /// Core's full state of that Evo after a revocation: no addresses, `[::]:0` as the service,
    /// operator fields reset, and the flat platform ports left as they were.
    fn revoked_legacy_evo_full_state() -> DMNState {
        let mut state: serde_json::Value =
            serde_json::from_str(CORE_V24_LEGACY_EVO_STATE).expect("valid json");
        state["version"] = json!(1);
        state["service"] = json!("[::]:0");
        state["addresses"] = json!({});
        state["PoSeBanHeight"] = json!(1300);
        state["revocationReason"] = json!(1);
        state["platformNodeID"] = json!("0000000000000000000000000000000000000000");
        state["pubKeyOperator"] = json!("0".repeat(96));
        serde_json::from_value(state).expect("expected to deserialize json")
    }

    fn core_diff(json: serde_json::Value) -> DMNStateDiff {
        serde_json::from_value(json).expect("expected to deserialize json")
    }

    fn applied(mut state: DMNState, diffs: impl IntoIterator<Item = DMNStateDiff>) -> DMNState {
        for diff in diffs {
            state.apply_diff(diff);
        }
        state
    }

    #[test]
    fn legacy_evo_core_address_diff_moves_platform_entries_to_the_new_address() {
        // ProUpServTx changing only the core IP of a legacy Evo.
        let diff = core_diff(json!({
            "service": "192.0.2.41:9999",
            "addresses": {"core_p2p": ["192.0.2.41:9999"]}
        }));
        let state = applied(legacy_evo_full_state("192.0.2.40", 26656, 443), [diff]);
        assert_eq!(state, legacy_evo_full_state("192.0.2.41", 26656, 443));
        assert_eq!(state.platform_p2p_address(), Some(("192.0.2.41".to_string(), 26656)));
        assert_eq!(state.platform_http_address(), Some(("192.0.2.41".to_string(), 443)));
    }

    #[test]
    fn legacy_evo_port_only_diff_resolves_the_placeholder_host_to_the_primary_address() {
        // ProUpServTx changing only the platform P2P port of a legacy Evo.
        let diff = core_diff(json!({
            "platformP2PPort": 36656,
            "addresses": {"platform_p2p": ["255.255.255.255:36656"]}
        }));
        let state = applied(legacy_evo_full_state("192.0.2.40", 26656, 443), [diff]);
        assert_eq!(state, legacy_evo_full_state("192.0.2.40", 36656, 443));
        assert_eq!(state.platform_p2p_address(), Some(("192.0.2.40".to_string(), 36656)));
    }

    #[test]
    fn legacy_evo_diffs_give_the_same_state_however_they_are_batched() {
        // The core IP changes at one height and the platform P2P port at the next: one listdiff
        // across both heights, or one per height.
        let across_both = core_diff(json!({
            "service": "192.0.2.41:9999",
            "platformP2PPort": 36656,
            "addresses": {"core_p2p": ["192.0.2.41:9999"], "platform_p2p": ["192.0.2.41:36656"]}
        }));
        let address_change = core_diff(json!({
            "service": "192.0.2.41:9999",
            "addresses": {"core_p2p": ["192.0.2.41:9999"]}
        }));
        let port_change = core_diff(json!({
            "platformP2PPort": 36656,
            "addresses": {"platform_p2p": ["255.255.255.255:36656"]}
        }));

        let expected = legacy_evo_full_state("192.0.2.41", 36656, 443);
        let full = legacy_evo_full_state("192.0.2.40", 26656, 443);
        assert_eq!(applied(full.clone(), [across_both.clone()]), expected);
        assert_eq!(applied(full, [address_change.clone(), port_change.clone()]), expected);

        // A state rebuilt from stored ports alone resolves the same platform ports.
        let mut reloaded = legacy_evo_full_state("192.0.2.40", 26656, 443);
        reloaded.addresses = None;
        for diffs in [vec![across_both], vec![address_change, port_change]] {
            let state = applied(reloaded.clone(), diffs);
            assert_eq!(state.platform_p2p_address(), Some(("192.0.2.41".to_string(), 36656)));
            assert_eq!(state.platform_http_address(), Some(("192.0.2.41".to_string(), 443)));
        }
    }

    #[test]
    fn reloaded_state_without_addresses_resolves_the_legacy_ports_after_a_core_address_diff() {
        // A consumer that stores only the platform ports rebuilds the state with `addresses:
        // None`. A diff that carries only `core_p2p` must not hide those ports.
        let diff = core_diff(json!({
            "service": "192.0.2.41:9999",
            "addresses": {"core_p2p": ["192.0.2.41:9999"]}
        }));
        let mut reloaded = legacy_evo_full_state("192.0.2.40", 26656, 443);
        reloaded.addresses = None;
        let reloaded = applied(reloaded, [diff.clone()]);
        let from_full_state = applied(legacy_evo_full_state("192.0.2.40", 26656, 443), [diff]);

        assert_eq!(reloaded.platform_p2p_address(), Some(("192.0.2.41".to_string(), 26656)));
        assert_eq!(reloaded.platform_http_address(), Some(("192.0.2.41".to_string(), 443)));
        assert_eq!(reloaded.platform_p2p_address(), from_full_state.platform_p2p_address());
        assert_eq!(reloaded.platform_http_address(), from_full_state.platform_http_address());
    }

    #[test]
    #[allow(deprecated)]
    fn legacy_fallback_brackets_an_ipv6_host_like_the_nested_path() {
        // Both sources must give a host that `format!("{host}:{port}")` turns into a valid
        // socket address, so an IPv6 node IP is bracketed as nested entries are.
        let mut state = revoked_legacy_evo_full_state();
        state.service = "[2001:db8::4]:9999".parse().expect("valid socket address");
        state.addresses = None;
        let (host, port) = state.platform_p2p_address().expect("legacy port");
        assert_eq!(host, "[2001:db8::4]");
        assert!(format!("{host}:{port}").parse::<SocketAddr>().is_ok());

        state.service = "192.0.2.40:9999".parse().expect("valid socket address");
        assert_eq!(state.platform_p2p_address(), Some(("192.0.2.40".to_string(), 26656)));
    }

    #[test]
    #[allow(deprecated)]
    fn revoked_legacy_evo_resolves_its_flat_platform_ports() {
        // Core 23 and 24 print a revoked legacy Evo with `addresses: {}` (no platform entries
        // for a masternode without an address) beside its unchanged flat ports. Consumers that
        // read the flat ports keep the masternode, so the accessors fall back to them as-is.
        let revoked = revoked_legacy_evo_full_state();
        assert_eq!(revoked.addresses, Some(MasternodeAddresses::default()));
        assert_eq!(revoked.platform_p2p_address(), Some(("[::]".to_string(), 26656)));
        assert_eq!(revoked.platform_http_address(), Some(("[::]".to_string(), 443)));

        // Nested addresses with a core entry but no platform entry fall back the same way.
        let mut core_only = revoked.clone();
        core_only.addresses = Some(MasternodeAddresses {
            core_p2p: vec!["192.0.2.40:9999".to_string()],
            ..Default::default()
        });
        assert_eq!(core_only.platform_p2p_address(), Some(("[::]".to_string(), 26656)));

        // The revocation diff: `service` and no `addresses`, ports untouched.
        let diff = core_diff(json!({
            "version": 1,
            "service": "[::]:0",
            "PoSeBanHeight": 1300,
            "revocationReason": 1,
            "pubKeyOperator": "0".repeat(96),
            "platformNodeID": "0000000000000000000000000000000000000000"
        }));
        let state = applied(legacy_evo_full_state("192.0.2.40", 26656, 443), [diff]);
        assert_eq!(state, revoked, "applying Core's diff yields Core's new full state");
        assert_eq!(state.legacy_platform_p2p_port, Some(26656));
    }

    #[test]
    #[allow(deprecated)]
    fn extaddr_evo_revocation_diff_empties_its_addresses() {
        // Revoking an extended-address Evo empties its addresses; Core's diff prints `service`
        // (`[::]:0`) and no `addresses`. Its flat ports stay as Core's diff left them: a legacy
        // Evo's revocation diff looks the same, and its flat ports must survive (see
        // `revoked_legacy_evo_resolves_its_flat_platform_ports`).
        let diff = core_diff(json!({
            "service": "[::]:0",
            "PoSeBanHeight": 1300,
            "revocationReason": 1,
            "pubKeyOperator": "0".repeat(96),
            "platformNodeID": "0000000000000000000000000000000000000000"
        }));
        let raised: DMNState =
            serde_json::from_str(CORE_V24_RAISED_EVO_STATE).expect("expected to deserialize json");
        let state = applied(raised, [diff]);
        assert_eq!(state.addresses, Some(MasternodeAddresses::default()));
        assert_eq!(state.service, unspecified_service());
        assert_eq!(state.legacy_platform_p2p_port, Some(36656));
    }

    #[test]
    fn deserialize_mnsync_status() {
        let json_value = json!({
          "AssetID": 999,
          "AssetName": "MASTERNODE_SYNC_FINISHED",
          "AssetStartTime": 1507662300,
          "Attempt": 0,
          "IsBlockchainSynced": true,
          "IsSynced": true,
        });

        let result: MnSyncStatus =
            serde_json::from_value(json_value).expect("expected to deserialize json");

        println!("{:#?}", result);
    }
}
