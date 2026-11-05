// Rust Dash Library
// Originally written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//     For Bitcoin
// Updated for Dash in 2022 by
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

//! Bitcoin network messages.

use core::convert::TryFrom;
use core::{fmt, iter};

use io::Read as _;

use crate::blockdata::{block, transaction};
use crate::consensus::encode::{CheckedData, Decodable, Encodable, VarInt};
use crate::consensus::{encode, serialize};
use crate::io;
use crate::merkle_tree::MerkleBlock;
use crate::network::address::{AddrV2Message, Address};
use crate::network::{
    message_blockdata, message_bloom, message_compact_blocks, message_filter, message_headers2,
    message_network, message_qrinfo, message_sml,
};
use crate::prelude::*;
use crate::{ChainLock, InstantLock};

/// The maximum number of [super::message_blockdata::Inventory] items in an `inv` message.
///
/// This limit is not currently enforced by this implementation.
pub const MAX_INV_SIZE: usize = 50_000;

/// Maximum size, in bytes, of an encoded message
/// This by necessity should be larger than `MAX_VEC_SIZE`
pub const MAX_MSG_SIZE: usize = 5_000_000;

/// Serializer for command string
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct CommandString(Cow<'static, str>);

impl CommandString {
    /// Converts `&'static str` to `CommandString`
    ///
    /// This is more efficient for string literals than non-static conversions because it avoids
    /// allocation.
    ///
    /// # Errors
    ///
    /// Returns an error if, and only if, the string is
    /// larger than 12 characters in length.
    pub fn try_from_static(s: &'static str) -> Result<CommandString, CommandStringError> {
        Self::try_from_static_cow(s.into())
    }

    fn try_from_static_cow(cow: Cow<'static, str>) -> Result<CommandString, CommandStringError> {
        if cow.len() > 12 {
            Err(CommandStringError {
                cow,
            })
        } else {
            Ok(CommandString(cow))
        }
    }
}

impl TryFrom<String> for CommandString {
    type Error = CommandStringError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from_static_cow(value.into())
    }
}

impl TryFrom<Box<str>> for CommandString {
    type Error = CommandStringError;

    fn try_from(value: Box<str>) -> Result<Self, Self::Error> {
        Self::try_from_static_cow(String::from(value).into())
    }
}

impl<'a> TryFrom<&'a str> for CommandString {
    type Error = CommandStringError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        Self::try_from_static_cow(value.to_owned().into())
    }
}

impl core::str::FromStr for CommandString {
    type Err = CommandStringError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from_static_cow(s.to_owned().into())
    }
}

impl fmt::Display for CommandString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.0.as_ref())
    }
}

impl AsRef<str> for CommandString {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl Encodable for CommandString {
    #[inline]
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut rawbytes = [0u8; 12];
        let strbytes = self.0.as_bytes();
        debug_assert!(strbytes.len() <= 12);
        rawbytes[..strbytes.len()].copy_from_slice(strbytes);
        rawbytes.consensus_encode(w)
    }
}

impl Decodable for CommandString {
    #[inline]
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let rawbytes: [u8; 12] = Decodable::consensus_decode(r)?;
        let rv = iter::FromIterator::from_iter(rawbytes.iter().filter_map(|&u| {
            if u > 0 {
                Some(u as char)
            } else {
                None
            }
        }));
        Ok(CommandString(rv))
    }
}

/// Error returned when a command string is invalid.
///
/// This is currently returned for command strings longer than 12.
#[derive(Clone, Debug)]
pub struct CommandStringError {
    cow: Cow<'static, str>,
}

impl fmt::Display for CommandStringError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "the command string '{}' has length {} which is larger than 12",
            self.cow,
            self.cow.len()
        )
    }
}

crate::error::impl_std_error!(CommandStringError);

/// A Network message
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawNetworkMessage {
    /// Magic bytes to identify the network these messages are meant for
    pub magic: u32,
    /// The actual message data
    pub payload: NetworkMessage,
}

/// A Network message payload. Proper documentation is available on at
/// [Bitcoin Wiki: Protocol Specification](https://en.bitcoin.it/wiki/Protocol_specification)
#[derive(Clone, PartialEq, Eq, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum NetworkMessage {
    /// `version`
    Version(message_network::VersionMessage),
    /// `verack`
    Verack,
    /// `addr`
    Addr(Vec<(u32, Address)>),
    /// `inv`
    Inv(Vec<message_blockdata::Inventory>),
    /// `getdata`
    GetData(Vec<message_blockdata::Inventory>),
    /// `notfound`
    NotFound(Vec<message_blockdata::Inventory>),
    /// `getblocks`
    GetBlocks(message_blockdata::GetBlocksMessage),
    /// `getheaders`
    GetHeaders(message_blockdata::GetHeadersMessage),
    /// `mempool`
    MemPool,
    /// tx
    Tx(Box<transaction::Transaction>),
    /// `block`
    Block(block::Block),
    /// `headers`
    Headers(Vec<block::Header>),
    /// `sendheaders`
    SendHeaders,
    /// `getheaders2`
    GetHeaders2(message_blockdata::GetHeadersMessage),
    /// `sendheaders2`
    SendHeaders2,
    /// `headers2`
    Headers2(message_headers2::Headers2Message),
    /// `getaddr`
    GetAddr,
    // TODO: checkorder,
    // TODO: submitorder,
    // TODO: reply,
    /// `ping`
    Ping(u64),
    /// `pong`
    Pong(u64),
    /// `merkleblock`
    MerkleBlock(MerkleBlock),
    /// BIP 37 `filterload`
    FilterLoad(message_bloom::FilterLoad),
    /// BIP 37 `filteradd`
    FilterAdd(message_bloom::FilterAdd),
    /// BIP 37 `filterclear`
    FilterClear,
    /// BIP157 getcfilters
    GetCFilters(message_filter::GetCFilters),
    /// BIP157 cfilter
    CFilter(message_filter::CFilter),
    /// BIP157 getcfheaders
    GetCFHeaders(message_filter::GetCFHeaders),
    /// BIP157 cfheaders
    CFHeaders(message_filter::CFHeaders),
    /// BIP157 getcfcheckpt
    GetCFCheckpt(message_filter::GetCFCheckpt),
    /// BIP157 cfcheckpt
    CFCheckpt(message_filter::CFCheckpt),
    /// BIP152 sendcmpct
    SendCmpct(message_compact_blocks::SendCmpct),
    /// BIP152 cmpctblock
    CmpctBlock(message_compact_blocks::CmpctBlock),
    /// BIP152 getblocktxn
    GetBlockTxn(message_compact_blocks::GetBlockTxn),
    /// BIP152 blocktxn
    BlockTxn(message_compact_blocks::BlockTxn),
    /// `alert`
    Alert(Vec<u8>),
    /// `reject`
    Reject(message_network::Reject),
    /// `feefilter`
    FeeFilter(i64),
    /// `addrv2`
    AddrV2(Vec<AddrV2Message>),
    /// `sendaddrv2`
    SendAddrV2,
    /// `getmnlistd`
    GetMnListD(message_sml::GetMnListDiff),
    /// `mnlistdiff`
    MnListDiff(Box<message_sml::MnListDiff>),
    /// `getqrinfo`
    GetQRInfo(message_qrinfo::GetQRInfo),
    /// `qrinfo`
    QRInfo(Box<message_qrinfo::QRInfo>),
    /// `clsig`
    CLSig(ChainLock),
    /// `isdlock`
    ISLock(InstantLock),
    /// `senddsq` - Notify peer whether to send CoinJoin queue messages
    SendDsq(bool),
    /// Any other message.
    Unknown {
        /// The command of this message.
        command: CommandString,
        /// The payload of this message.
        payload: Vec<u8>,
    },
}

impl NetworkMessage {
    /// Return the message command as a static string reference.
    ///
    /// This returns `"unknown"` for [NetworkMessage::Unknown],
    /// regardless of the actual command in the unknown message.
    /// Use the [Self::command] method to get the command for unknown messages.
    pub fn cmd(&self) -> &'static str {
        match *self {
            NetworkMessage::Version(_) => "version",
            NetworkMessage::Verack => "verack",
            NetworkMessage::Addr(_) => "addr",
            NetworkMessage::Inv(_) => "inv",
            NetworkMessage::GetData(_) => "getdata",
            NetworkMessage::NotFound(_) => "notfound",
            NetworkMessage::GetBlocks(_) => "getblocks",
            NetworkMessage::GetHeaders(_) => "getheaders",
            NetworkMessage::MemPool => "mempool",
            NetworkMessage::Tx(_) => "tx",
            NetworkMessage::Block(_) => "block",
            NetworkMessage::Headers(_) => "headers",
            NetworkMessage::SendHeaders => "sendheaders",
            NetworkMessage::GetHeaders2(_) => "getheaders2",
            NetworkMessage::SendHeaders2 => "sendheaders2",
            NetworkMessage::Headers2(_) => "headers2",
            NetworkMessage::GetAddr => "getaddr",
            NetworkMessage::Ping(_) => "ping",
            NetworkMessage::Pong(_) => "pong",
            NetworkMessage::MerkleBlock(_) => "merkleblock",
            NetworkMessage::FilterLoad(_) => "filterload",
            NetworkMessage::FilterAdd(_) => "filteradd",
            NetworkMessage::FilterClear => "filterclear",
            NetworkMessage::GetCFilters(_) => "getcfilters",
            NetworkMessage::CFilter(_) => "cfilter",
            NetworkMessage::GetCFHeaders(_) => "getcfheaders",
            NetworkMessage::CFHeaders(_) => "cfheaders",
            NetworkMessage::GetCFCheckpt(_) => "getcfcheckpt",
            NetworkMessage::CFCheckpt(_) => "cfcheckpt",
            NetworkMessage::SendCmpct(_) => "sendcmpct",
            NetworkMessage::CmpctBlock(_) => "cmpctblock",
            NetworkMessage::GetBlockTxn(_) => "getblocktxn",
            NetworkMessage::BlockTxn(_) => "blocktxn",
            NetworkMessage::Alert(_) => "alert",
            NetworkMessage::Reject(_) => "reject",
            NetworkMessage::FeeFilter(_) => "feefilter",
            NetworkMessage::AddrV2(_) => "addrv2",
            NetworkMessage::SendAddrV2 => "sendaddrv2",
            NetworkMessage::GetMnListD(_) => "getmnlistd",
            NetworkMessage::MnListDiff(_) => "mnlistdiff",
            NetworkMessage::GetQRInfo(_) => "getqrinfo",
            NetworkMessage::QRInfo(_) => "qrinfo",
            NetworkMessage::CLSig(_) => "clsig",
            NetworkMessage::ISLock(_) => "isdlock",
            NetworkMessage::SendDsq(_) => "senddsq",
            NetworkMessage::Unknown {
                ..
            } => "unknown",
        }
    }

    /// Return the CommandString for the message command.
    pub fn command(&self) -> CommandString {
        match *self {
            NetworkMessage::Unknown {
                command: ref c,
                ..
            } => c.clone(),
            _ => CommandString::try_from_static(self.cmd()).expect("cmd returns valid commands"),
        }
    }

    /// Serialize the message payload without V1 framing (magic/command/checksum).
    ///
    /// This method returns the raw serialized bytes of the message payload,
    /// suitable for use with V2 (BIP324) transport or other protocols that
    /// handle framing separately.
    ///
    /// # Note on Headers serialization
    ///
    /// The `Headers` message is serialized with a trailing zero byte after each
    /// header, representing an empty transaction count (VarInt). This matches
    /// the Bitcoin/Dash protocol where headers messages reuse the block
    /// serialization format but with no transactions.
    fn consensus_encode_payload(&self) -> Vec<u8> {
        match *self {
            NetworkMessage::Version(ref dat) => serialize(dat),
            NetworkMessage::Addr(ref dat) => serialize(dat),
            NetworkMessage::Inv(ref dat) => serialize(dat),
            NetworkMessage::GetData(ref dat) => serialize(dat),
            NetworkMessage::NotFound(ref dat) => serialize(dat),
            NetworkMessage::GetBlocks(ref dat) => serialize(dat),
            NetworkMessage::GetHeaders(ref dat) => serialize(dat),
            NetworkMessage::Tx(ref dat) => serialize(&**dat),
            NetworkMessage::Block(ref dat) => serialize(dat),
            NetworkMessage::Headers(ref dat) => serialize(&HeaderSerializationWrapper(dat)),
            NetworkMessage::GetHeaders2(ref dat) => serialize(dat),
            NetworkMessage::Headers2(ref dat) => serialize(dat),
            NetworkMessage::Ping(ref dat) => serialize(dat),
            NetworkMessage::Pong(ref dat) => serialize(dat),
            NetworkMessage::MerkleBlock(ref dat) => serialize(dat),
            NetworkMessage::FilterLoad(ref dat) => serialize(dat),
            NetworkMessage::FilterAdd(ref dat) => serialize(dat),
            NetworkMessage::GetCFilters(ref dat) => serialize(dat),
            NetworkMessage::CFilter(ref dat) => serialize(dat),
            NetworkMessage::GetCFHeaders(ref dat) => serialize(dat),
            NetworkMessage::CFHeaders(ref dat) => serialize(dat),
            NetworkMessage::GetCFCheckpt(ref dat) => serialize(dat),
            NetworkMessage::CFCheckpt(ref dat) => serialize(dat),
            NetworkMessage::SendCmpct(ref dat) => serialize(dat),
            NetworkMessage::CmpctBlock(ref dat) => serialize(dat),
            NetworkMessage::GetBlockTxn(ref dat) => serialize(dat),
            NetworkMessage::BlockTxn(ref dat) => serialize(dat),
            NetworkMessage::Alert(ref dat) => serialize(dat),
            NetworkMessage::Reject(ref dat) => serialize(dat),
            NetworkMessage::FeeFilter(ref dat) => serialize(dat),
            NetworkMessage::AddrV2(ref dat) => serialize(dat),
            NetworkMessage::GetMnListD(ref dat) => serialize(dat),
            NetworkMessage::MnListDiff(ref dat) => serialize(&**dat),
            NetworkMessage::GetQRInfo(ref dat) => serialize(dat),
            NetworkMessage::QRInfo(ref dat) => serialize(&**dat),
            NetworkMessage::CLSig(ref dat) => serialize(dat),
            NetworkMessage::ISLock(ref dat) => serialize(dat),
            NetworkMessage::SendDsq(wants_dsq) => serialize(&(wants_dsq as u8)),
            NetworkMessage::Unknown {
                payload: ref data,
                ..
            } => data.clone(),
            NetworkMessage::Verack
            | NetworkMessage::SendHeaders
            | NetworkMessage::SendHeaders2
            | NetworkMessage::MemPool
            | NetworkMessage::GetAddr
            | NetworkMessage::FilterClear
            | NetworkMessage::SendAddrV2 => vec![],
        }
    }

    /// Decode a message payload from raw bytes given a command string.
    ///
    /// This method decodes the raw payload bytes into a `NetworkMessage` variant
    /// based on the command string. It handles all standard Bitcoin and Dash-specific
    /// message types, including special cases like `Headers` which has trailing
    /// transaction count bytes.
    ///
    /// This is the inverse of [`Self::consensus_encode_payload`], suitable for use with
    /// V2 (BIP324) transport or other protocols that handle framing separately.
    fn consensus_decode_payload(cmd: &str, payload: &[u8]) -> Result<Self, encode::Error> {
        let mut mem_d = io::Cursor::new(payload);
        let message = match cmd {
            "version" => {
                NetworkMessage::Version(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)
            }
            "verack" => NetworkMessage::Verack,
            "addr" => {
                NetworkMessage::Addr(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)
            }
            "inv" => {
                NetworkMessage::Inv(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)
            }
            "getdata" => {
                NetworkMessage::GetData(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)
            }
            "notfound" => NetworkMessage::NotFound(Decodable::consensus_decode_from_finite_reader(
                &mut mem_d,
            )?),
            "getblocks" => NetworkMessage::GetBlocks(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "getheaders" => NetworkMessage::GetHeaders(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "mempool" => NetworkMessage::MemPool,
            "block" => {
                // First decode just the header to get block hash for error context
                let header: block::Header =
                    Decodable::consensus_decode_from_finite_reader(&mut mem_d)?;
                let block_hash = header.block_hash();

                // Now decode the transactions
                match Vec::<transaction::Transaction>::consensus_decode_from_finite_reader(
                    &mut mem_d,
                ) {
                    Ok(txdata) => NetworkMessage::Block(block::Block {
                        header,
                        txdata,
                    }),
                    Err(e) => {
                        // Include block hash in error message for debugging
                        return Err(encode::Error::Io(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "Failed to decode transactions for block {}: {}",
                                block_hash, e
                            ),
                        )));
                    }
                }
            }
            "headers" => NetworkMessage::Headers(
                HeaderDeserializationWrapper::consensus_decode_from_finite_reader(&mut mem_d)?.0,
            ),
            "sendheaders" => NetworkMessage::SendHeaders,
            "getheaders2" => NetworkMessage::GetHeaders2(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "sendheaders2" => NetworkMessage::SendHeaders2,
            "headers2" => NetworkMessage::Headers2(Decodable::consensus_decode_from_finite_reader(
                &mut mem_d,
            )?),
            "getaddr" => NetworkMessage::GetAddr,
            "ping" => {
                NetworkMessage::Ping(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)
            }
            "pong" => {
                NetworkMessage::Pong(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)
            }
            "merkleblock" => NetworkMessage::MerkleBlock(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "filterload" => NetworkMessage::FilterLoad(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "filteradd" => NetworkMessage::FilterAdd(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "filterclear" => NetworkMessage::FilterClear,
            "tx" => NetworkMessage::Tx(Box::new(Decodable::consensus_decode_from_finite_reader(
                &mut mem_d,
            )?)),
            "getcfilters" => NetworkMessage::GetCFilters(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "cfilter" => {
                NetworkMessage::CFilter(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)
            }
            "getcfheaders" => NetworkMessage::GetCFHeaders(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "cfheaders" => NetworkMessage::CFHeaders(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "getcfcheckpt" => NetworkMessage::GetCFCheckpt(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "cfcheckpt" => NetworkMessage::CFCheckpt(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "reject" => {
                NetworkMessage::Reject(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)
            }
            "alert" => {
                NetworkMessage::Alert(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)
            }
            "feefilter" => NetworkMessage::FeeFilter(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "sendcmpct" => NetworkMessage::SendCmpct(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "cmpctblock" => NetworkMessage::CmpctBlock(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "getblocktxn" => NetworkMessage::GetBlockTxn(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "blocktxn" => NetworkMessage::BlockTxn(Decodable::consensus_decode_from_finite_reader(
                &mut mem_d,
            )?),
            "addrv2" => {
                NetworkMessage::AddrV2(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)
            }
            "sendaddrv2" => NetworkMessage::SendAddrV2,
            "getmnlistd" => NetworkMessage::GetMnListD(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "mnlistdiff" => NetworkMessage::MnListDiff(Box::new(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            )),
            "getqrinfo" => NetworkMessage::GetQRInfo(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "qrinfo" => NetworkMessage::QRInfo(Box::new(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            )),
            "clsig" => {
                NetworkMessage::CLSig(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)
            }
            "isdlock" => {
                NetworkMessage::ISLock(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)
            }
            "senddsq" => {
                let byte: u8 = Decodable::consensus_decode_from_finite_reader(&mut mem_d)?;
                NetworkMessage::SendDsq(byte != 0)
            }
            _ => NetworkMessage::Unknown {
                command: CommandString::try_from(cmd.to_string())
                    .map_err(|_| encode::Error::ParseFailed("Invalid command string"))?,
                payload: payload.to_vec(),
            },
        };
        Ok(message)
    }

    /// Encode the message as BIP324 V2 packet contents: its short ID and payload, or
    /// `0x00`, the 12-byte command and the payload if it has no short ID.
    ///
    /// The BIP324 cipher prepends its own header byte, so this is everything after it.
    ///
    /// Unlike Dash Core, this doesn't check the peer's protocol version before using a
    /// short ID added after the V2 baseline (`platformban`, from 70240), so don't send
    /// those messages to older peers.
    pub fn consensus_encode_v2(&self) -> Vec<u8> {
        let command = self.command();
        let payload = self.consensus_encode_payload();
        let mut contents = Vec::with_capacity(1 + V2_COMMAND_LEN + payload.len());
        match v2_short_id(command.as_ref()) {
            Some(id) => contents.push(id),
            None => {
                contents.push(V2_EXTENDED_ID);
                contents.extend(serialize(&command));
            }
        }
        contents.extend_from_slice(&payload);
        contents
    }

    /// Decode BIP324 V2 packet contents, as produced by [`Self::consensus_encode_v2`].
    ///
    /// Returns `Ok(None)` for contents Dash Core drops without disconnecting: an
    /// unassigned short ID (a newer peer may use IDs we don't know yet) or a malformed
    /// command. A known command whose payload doesn't decode is an error.
    pub fn consensus_decode_v2(contents: &[u8]) -> Result<Option<Self>, encode::Error> {
        let Some((&id, rest)) = contents.split_first() else {
            return Ok(None);
        };
        let decoded = if id == V2_EXTENDED_ID {
            rest.split_first_chunk::<V2_COMMAND_LEN>()
                .and_then(|(field, payload)| Some((v2_extended_command(field)?, payload)))
        } else {
            v2_command(id).map(|command| (command, rest))
        };
        match decoded {
            Some((command, payload)) => Self::consensus_decode_payload(command, payload).map(Some),
            None => Ok(None),
        }
    }
}

/// BIP324 short ID marking contents whose 12-byte command follows, as in V1.
const V2_EXTENDED_ID: u8 = 0;

/// Length of the command in extended-format V2 contents.
const V2_COMMAND_LEN: usize = 12;

/// BIP324's short message IDs from 0, in order, as in Dash Core's `V2_BITCOIN_IDS`
/// (`net.cpp`). Empty slots are assigned in BIP324 but not implemented by Dash, so
/// those messages, `feefilter` (5) among them, use the extended format.
const V2_BITCOIN_IDS: [&str; 33] = [
    "", // V2_EXTENDED_ID
    "addr",
    "block",
    "blocktxn",
    "cmpctblock",
    "", // feefilter
    "filteradd",
    "filterclear",
    "filterload",
    "getblocks",
    "getblocktxn",
    "getdata",
    "getheaders",
    "headers",
    "inv",
    "mempool",
    "merkleblock",
    "notfound",
    "ping",
    "pong",
    "sendcmpct",
    "tx",
    "getcfilters",
    "cfilter",
    "getcfheaders",
    "cfheaders",
    "getcfcheckpt",
    "cfcheckpt",
    "addrv2",
    // Assigned in BIP324, unimplemented
    "",
    "",
    "",
    "",
];

/// First short ID of Dash's reserved half of the namespace.
const V2_DASH_IDS_START: u8 = 128;

/// Dash's short message IDs from [`V2_DASH_IDS_START`], in order, as in Dash Core's
/// `V2_DASH_IDS` (`net.cpp`).
const V2_DASH_IDS: [&str; 41] = [
    "spork",
    "getsporks",
    "senddsq",
    "dsa",
    "dsi",
    "dsf",
    "dss",
    "dsc",
    "dssu",
    "dstx",
    "dsq",
    "ssc",
    "govsync",
    "govobj",
    "govobjvote",
    "getmnlistd",
    "mnlistdiff",
    "qsendrecsigs",
    "qfcommit",
    "qcontrib",
    "qcomplaint",
    "qjustify",
    "qpcommit",
    "qwatch",
    "qsigsesann",
    "qsigsinv",
    "qgetsigs",
    "qbsigs",
    "qsigrec",
    "qsigshare",
    "qgetdata",
    "qdata",
    "clsig",
    "isdlock",
    "mnauth",
    "getheaders2",
    "sendheaders2",
    "headers2",
    "getqrinfo",
    "qrinfo",
    "platformban",
];

/// The short ID Dash Core assigns `command`, if any.
fn v2_short_id(command: &str) -> Option<u8> {
    if command.is_empty() {
        return None;
    }
    let position = |ids: &[&str]| ids.iter().position(|&id| id == command);
    position(&V2_BITCOIN_IDS)
        .map(|i| i as u8)
        .or_else(|| position(&V2_DASH_IDS).map(|i| V2_DASH_IDS_START + i as u8))
}

/// The command for short ID `id`, or `None` if it's unassigned or unimplemented.
fn v2_command(id: u8) -> Option<&'static str> {
    let command = match id.checked_sub(V2_DASH_IDS_START) {
        Some(i) => V2_DASH_IDS.get(usize::from(i)),
        None => V2_BITCOIN_IDS.get(usize::from(id)),
    }?;
    (!command.is_empty()).then_some(*command)
}

/// Read the command of extended-format V2 contents, following Dash Core: printable
/// ASCII up to the first NUL, and only NULs after it.
fn v2_extended_command(field: &[u8; V2_COMMAND_LEN]) -> Option<&str> {
    let len = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    let (command, padding) = field.split_at(len);
    if command.iter().any(|&b| !(b' '..=0x7f).contains(&b)) || padding.iter().any(|&b| b != 0) {
        return None;
    }
    core::str::from_utf8(command).ok()
}

impl RawNetworkMessage {
    /// Return the message command as a static string reference.
    ///
    /// This returns `"unknown"` for [NetworkMessage::Unknown],
    /// regardless of the actual command in the unknown message.
    /// Use the [Self::command] method to get the command for unknown messages.
    pub fn cmd(&self) -> &'static str {
        self.payload.cmd()
    }

    /// Return the CommandString for the message command.
    pub fn command(&self) -> CommandString {
        self.payload.command()
    }
}

struct HeaderSerializationWrapper<'a>(&'a Vec<block::Header>);

impl<'a> Encodable for HeaderSerializationWrapper<'a> {
    #[inline]
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += VarInt(self.0.len() as u64).consensus_encode(w)?;
        for header in self.0.iter() {
            len += header.consensus_encode(w)?;
            len += 0u8.consensus_encode(w)?;
        }
        Ok(len)
    }
}

impl Encodable for RawNetworkMessage {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.magic.consensus_encode(w)?;
        len += self.command().consensus_encode(w)?;
        len += CheckedData(self.payload.consensus_encode_payload()).consensus_encode(w)?;
        Ok(len)
    }
}

/// Maximum number of headers Core sends in one `headers` message
/// (`MAX_HEADERS_UNCOMPRESSED_RESULT`).
const MAX_HEADERS_RESULTS: usize = 2000;

struct HeaderDeserializationWrapper(Vec<block::Header>);

impl Decodable for HeaderDeserializationWrapper {
    #[inline]
    fn consensus_decode_from_finite_reader<R: io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, encode::Error> {
        let len = VarInt::consensus_decode(r)?.0;
        // Core never sends more and treats more as misbehaviour
        if len > MAX_HEADERS_RESULTS as u64 {
            return Err(encode::Error::ParseFailed("headers message has too many headers"));
        }
        let mut ret = Vec::with_capacity(len as usize);
        for _ in 0..len {
            ret.push(Decodable::consensus_decode(r)?);
            if u8::consensus_decode(r)? != 0u8 {
                return Err(encode::Error::ParseFailed(
                    "Headers message should not contain transactions",
                ));
            }
        }
        Ok(HeaderDeserializationWrapper(ret))
    }

    #[inline]
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Self::consensus_decode_from_finite_reader(r.take(MAX_MSG_SIZE as u64).by_ref())
    }
}

impl Decodable for RawNetworkMessage {
    fn consensus_decode_from_finite_reader<R: io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, encode::Error> {
        let magic = Decodable::consensus_decode_from_finite_reader(r)?;
        let cmd = CommandString::consensus_decode_from_finite_reader(r)?;
        let raw_payload = match CheckedData::consensus_decode_from_finite_reader(r) {
            Ok(cd) => cd.0,
            Err(encode::Error::InvalidChecksum {
                expected,
                actual,
            }) => {
                // Include message command and magic in logging to aid diagnostics
                tracing::warn!(
                    "Invalid payload checksum for network message '{}' (magic {:#x}): expected {:02x?}, actual {:02x?}",
                    cmd.0,
                    magic,
                    expected,
                    actual
                );
                return Err(encode::Error::InvalidChecksum {
                    expected,
                    actual,
                });
            }
            Err(e) => return Err(e),
        };

        let payload = NetworkMessage::consensus_decode_payload(&cmd.0, &raw_payload)?;
        Ok(RawNetworkMessage {
            magic,
            payload,
        })
    }

    #[inline]
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Self::consensus_decode_from_finite_reader(r.take(MAX_MSG_SIZE as u64).by_ref())
    }
}

/// Tokio codec framing one [`RawNetworkMessage`] per frame. A bad checksum surfaces
/// as a decode error.
#[cfg(feature = "tokio")]
#[derive(Debug, Default, Clone, Copy)]
pub struct RawNetworkMessageCodec;

#[cfg(feature = "tokio")]
impl tokio_util::codec::Decoder for RawNetworkMessageCodec {
    type Item = RawNetworkMessage;
    type Error = encode::Error;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        use bytes::Buf as _;

        /// `magic(4) + command(12) + payload_length(4) + checksum(4)`.
        const HEADER_LEN: usize = 24;
        const LENGTH_OFFSET: usize = 16;

        if src.len() < HEADER_LEN {
            return Ok(None);
        }

        let payload_len = u32::from_le_bytes([
            src[LENGTH_OFFSET],
            src[LENGTH_OFFSET + 1],
            src[LENGTH_OFFSET + 2],
            src[LENGTH_OFFSET + 3],
        ]) as usize;

        // Reject an absurd declared length *before* reserving buffer for it.
        if payload_len > MAX_MSG_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "declared payload length exceeds MAX_MSG_SIZE",
            )
            .into());
        }

        let frame_len = HEADER_LEN + payload_len;
        if src.len() < frame_len {
            src.reserve(frame_len - src.len());
            return Ok(None);
        }

        let mut cursor = io::Cursor::new(&src[..frame_len]);
        let msg = RawNetworkMessage::consensus_decode_from_finite_reader(&mut cursor)?;
        src.advance(frame_len);

        Ok(Some(msg))
    }
}

#[cfg(feature = "tokio")]
impl tokio_util::codec::Encoder<&RawNetworkMessage> for RawNetworkMessageCodec {
    type Error = encode::Error;

    fn encode(
        &mut self,
        item: &RawNetworkMessage,
        dst: &mut bytes::BytesMut,
    ) -> Result<(), Self::Error> {
        dst.extend_from_slice(&serialize(item));
        Ok(())
    }
}

#[cfg(feature = "tokio")]
impl tokio_util::codec::Encoder<RawNetworkMessage> for RawNetworkMessageCodec {
    type Error = encode::Error;

    fn encode(
        &mut self,
        item: RawNetworkMessage,
        dst: &mut bytes::BytesMut,
    ) -> Result<(), Self::Error> {
        <Self as tokio_util::codec::Encoder<&RawNetworkMessage>>::encode(self, &item, dst)
    }
}

#[cfg(all(test, feature = "tokio"))]
mod codec_tests {
    use super::{NetworkMessage, RawNetworkMessage, RawNetworkMessageCodec};
    use bytes::BytesMut;
    use tokio_util::codec::{Decoder, Encoder};

    #[test]
    fn roundtrip_frame() {
        let msg = RawNetworkMessage {
            magic: 0xBD6B_0CBF,
            payload: NetworkMessage::Ping(0x0102_0304_0506_0708),
        };
        let mut codec = RawNetworkMessageCodec;
        let mut buf = BytesMut::new();
        codec.encode(&msg, &mut buf).unwrap();

        let decoded = codec.decode(&mut buf).unwrap().expect("full frame decodes");
        assert_eq!(decoded.magic, msg.magic);
        assert!(matches!(decoded.payload, NetworkMessage::Ping(0x0102_0304_0506_0708)));
        assert!(buf.is_empty());
    }

    #[test]
    fn partial_frame_yields_none_until_complete() {
        let msg = RawNetworkMessage {
            magic: 0xBD6B_0CBF,
            payload: NetworkMessage::Ping(42),
        };
        let mut codec = RawNetworkMessageCodec;
        let mut full = BytesMut::new();
        codec.encode(&msg, &mut full).unwrap();

        let mut partial = BytesMut::new();
        for (i, byte) in full.iter().enumerate() {
            partial.extend_from_slice(&[*byte]);
            let out = codec.decode(&mut partial).unwrap();
            if i + 1 < full.len() {
                assert!(out.is_none());
            } else {
                assert!(out.is_some());
                assert!(partial.is_empty());
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;

    #[cfg(feature = "core-block-hash-use-x11")]
    use hashes::hash_x11::Hash as X11Hash;
    use hashes::sha256d::Hash;

    use super::message_network::{Reject, RejectReason, VersionMessage};
    use super::{CommandString, NetworkMessage, RawNetworkMessage, *};
    use crate::BlockHash;
    use crate::bip152::BlockTransactionsRequest;
    use crate::blockdata::block::{self, Block};
    use crate::blockdata::script::ScriptBuf;
    use crate::blockdata::transaction::Transaction;
    use crate::consensus::encode::{deserialize, deserialize_partial, serialize};
    use crate::internal_macros::hex;
    use crate::network::address::{AddrV2, AddrV2Message, Address};
    use crate::network::constants::ServiceFlags;
    use crate::network::message_blockdata::{GetBlocksMessage, GetHeadersMessage, Inventory};
    use crate::network::message_bloom::{BloomFlags, FilterAdd, FilterLoad};
    use crate::network::message_compact_blocks::{GetBlockTxn, SendCmpct};
    use crate::network::message_sml::GetMnListDiff;
    use test_case::test_case;

    #[cfg(feature = "core-block-hash-use-x11")]
    use crate::bls_sig_utils::BLSSignature;
    #[cfg(feature = "core-block-hash-use-x11")]
    use crate::hash_types::CycleHash;
    use crate::network::message_filter::{
        CFCheckpt, CFHeaders, CFilter, GetCFCheckpt, GetCFHeaders, GetCFilters,
    };
    #[cfg(feature = "core-block-hash-use-x11")]
    use crate::pow::CompactTarget;

    fn hash(slice: [u8; 32]) -> Hash {
        Hash::from_byte_array(slice)
    }

    #[cfg(feature = "core-block-hash-use-x11")]
    fn hash_x11(slice: [u8; 32]) -> X11Hash {
        X11Hash::from_slice(&slice).unwrap()
    }

    #[cfg(not(feature = "core-block-hash-use-x11"))]
    fn hash_x11(slice: [u8; 32]) -> Hash {
        Hash::from_byte_array(slice)
    }

    #[test]
    #[cfg(feature = "core-block-hash-use-x11")]
    fn full_round_ser_der_raw_network_message_test() {
        // TODO: Impl Rand traits here to easily generate random values.
        let version_msg: VersionMessage = deserialize(&hex!("721101000100000000000000e6e0845300000000010000000000000000000000000000000000ffff0000000000000100000000000000fd87d87eeb4364f22cf54dca59412db7208d47d920cffce83ee8102f5361746f7368693a302e392e39392f2c9f040001")).unwrap();
        let tx: Transaction = deserialize(&hex!("0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000")).unwrap();
        let block: Block = deserialize(&include_bytes!("../../tests/data/testnet_block_000000008650f09124958e7352f844f9c15705171ac38ee6668534c5c238b916.raw")[..]).unwrap();
        let header: block::Header = deserialize(&hex!("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b")).unwrap();
        let script: ScriptBuf =
            deserialize(&hex!("1976a91431a420903c05a0a7de2de40c9f02ebedbacdc17288ac")).unwrap();
        let merkle_block: MerkleBlock = deserialize(&hex!("0100000079cda856b143d9db2c1caff01d1aecc8630d30625d10e8b4b8b0000000000000b50cc069d6a3e33e3ff84a5c41d9d3febe7c770fdcc96b2c3ff60abe184f196367291b4d4c86041b8fa45d630100000001b50cc069d6a3e33e3ff84a5c41d9d3febe7c770fdcc96b2c3ff60abe184f19630101")).unwrap();
        let cmptblock = deserialize(&hex!("00000030d923ad36ff2d955abab07f8a0a6e813bc6e066b973e780c5e36674cad5d1cd1f6e265f2a17a0d35cbe701fe9d06e2c6324cfe135f6233e8b767bfa3fb4479b71115dc562ffff7f2006000000000000000000000000010002000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0302ee00ffffffff0100f9029500000000015100000000")).unwrap();
        let blocktxn = deserialize(&hex!("2e93c0cff39ff605020072d96bc3a8d20b8447e294d08092351c8583e08d9b5a01020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402dc0000ffffffff0200f90295000000001976a9142b4569203694fc997e13f2c0a1383b9e16c77a0d88ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000")).unwrap();

        let msgs = vec![
            NetworkMessage::Version(version_msg),
            NetworkMessage::Verack,
            NetworkMessage::Addr(vec![(
                45,
                Address::new(&([123, 255, 000, 100], 833).into(), ServiceFlags::NETWORK),
            )]),
            NetworkMessage::Inv(vec![Inventory::Block(hash_x11([8u8; 32]).into())]),
            NetworkMessage::GetData(vec![Inventory::Transaction(hash([45u8; 32]).into())]),
            NetworkMessage::NotFound(vec![Inventory::Error]),
            NetworkMessage::GetBlocks(GetBlocksMessage::new(
                vec![hash_x11([1u8; 32]).into(), hash_x11([4u8; 32]).into()],
                hash_x11([5u8; 32]).into(),
            )),
            NetworkMessage::GetHeaders(GetHeadersMessage::new(
                vec![hash_x11([10u8; 32]).into(), hash_x11([40u8; 32]).into()],
                hash_x11([50u8; 32]).into(),
            )),
            NetworkMessage::MemPool,
            NetworkMessage::Tx(Box::new(tx)),
            NetworkMessage::Block(block),
            NetworkMessage::Headers(vec![header]),
            NetworkMessage::SendHeaders,
            NetworkMessage::GetAddr,
            NetworkMessage::Ping(15),
            NetworkMessage::Pong(23),
            NetworkMessage::MerkleBlock(merkle_block),
            NetworkMessage::FilterLoad(FilterLoad {
                filter: hex!("03614e9b050000000000000001"),
                hash_funcs: 1,
                tweak: 2,
                flags: BloomFlags::All,
            }),
            NetworkMessage::FilterAdd(FilterAdd {
                data: script.as_bytes().to_vec(),
            }),
            NetworkMessage::FilterAdd(FilterAdd {
                data: hash([29u8; 32]).as_byte_array().to_vec(),
            }),
            NetworkMessage::FilterClear,
            NetworkMessage::GetCFilters(GetCFilters {
                filter_type: 2,
                start_height: 52,
                stop_hash: hash_x11([42u8; 32]).into(),
            }),
            NetworkMessage::CFilter(CFilter {
                filter_type: 7,
                block_hash: hash_x11([25u8; 32]).into(),
                filter: vec![1, 2, 3],
            }),
            NetworkMessage::GetCFHeaders(GetCFHeaders {
                filter_type: 4,
                start_height: 102,
                stop_hash: hash_x11([47u8; 32]).into(),
            }),
            NetworkMessage::CFHeaders(CFHeaders {
                filter_type: 13,
                stop_hash: hash_x11([53u8; 32]).into(),
                previous_filter_header: hash([12u8; 32]).into(),
                filter_hashes: vec![hash([4u8; 32]).into(), hash([12u8; 32]).into()],
            }),
            NetworkMessage::GetCFCheckpt(GetCFCheckpt {
                filter_type: 17,
                stop_hash: hash_x11([25u8; 32]).into(),
            }),
            NetworkMessage::CFCheckpt(CFCheckpt {
                filter_type: 27,
                stop_hash: hash_x11([77u8; 32]).into(),
                filter_headers: vec![hash([3u8; 32]).into(), hash([99u8; 32]).into()],
            }),
            NetworkMessage::Alert(vec![45, 66, 3, 2, 6, 8, 9, 12, 3, 130]),
            NetworkMessage::Reject(Reject {
                message: "Test reject".into(),
                ccode: RejectReason::Duplicate,
                reason: "Cause".into(),
                hash: hash_x11([255u8; 32]),
            }),
            NetworkMessage::FeeFilter(1000),
            NetworkMessage::AddrV2(vec![AddrV2Message {
                addr: AddrV2::Ipv4(Ipv4Addr::new(127, 0, 0, 1)),
                port: 0,
                services: ServiceFlags::NONE,
                time: 0,
            }]),
            NetworkMessage::SendAddrV2,
            NetworkMessage::CmpctBlock(cmptblock),
            NetworkMessage::GetBlockTxn(GetBlockTxn {
                txs_request: BlockTransactionsRequest {
                    block_hash: hash_x11([11u8; 32]).into(),
                    indexes: vec![0, 1, 2, 3, 10, 3002],
                },
            }),
            NetworkMessage::BlockTxn(blocktxn),
            NetworkMessage::SendCmpct(SendCmpct {
                send_compact: true,
                version: 8333,
            }),
            NetworkMessage::Headers(vec![]),
            NetworkMessage::Headers(vec![header; 3]),
            NetworkMessage::GetHeaders2(GetHeadersMessage::new(
                vec![hash_x11([6u8; 32]).into()],
                hash_x11([7u8; 32]).into(),
            )),
            NetworkMessage::SendHeaders2,
            NetworkMessage::GetMnListD(GetMnListDiff {
                base_block_hash: hash_x11([1u8; 32]).into(),
                block_hash: hash_x11([2u8; 32]).into(),
            }),
            NetworkMessage::CLSig(ChainLock {
                block_height: 123456,
                block_hash: hash_x11([3u8; 32]).into(),
                signature: BLSSignature::from([0u8; 96]),
            }),
            NetworkMessage::ISLock(InstantLock {
                version: 1,
                inputs: vec![],
                txid: hash([4u8; 32]).into(),
                cyclehash: CycleHash::from([5u8; 32]),
                signature: BLSSignature::from([0u8; 96]),
            }),
            NetworkMessage::Unknown {
                command: CommandString::try_from_static("custom").unwrap(),
                payload: vec![0xaa, 0xbb, 0xcc, 0xdd],
            },
        ];

        for msg in msgs {
            assert_eq!(
                NetworkMessage::consensus_decode_v2(&msg.consensus_encode_v2()).unwrap().as_ref(),
                Some(&msg)
            );
            let raw_msg = RawNetworkMessage {
                magic: u32::from_le_bytes([57, 0, 0, 0]),
                payload: msg,
            };
            assert_eq!(deserialize::<RawNetworkMessage>(&serialize(&raw_msg)).unwrap(), raw_msg);
        }
    }

    #[test]
    fn commandstring_test() {
        // Test converting.
        assert_eq!(
            CommandString::try_from_static("AndrewAndrew").unwrap().as_ref(),
            "AndrewAndrew"
        );
        assert!(CommandString::try_from_static("AndrewAndrewA").is_err());

        // Test serializing.
        let cs = CommandString("Andrew".into());
        assert_eq!(serialize(&cs), vec![0x41u8, 0x6e, 0x64, 0x72, 0x65, 0x77, 0, 0, 0, 0, 0, 0]);

        // Test deserializing
        let cs: Result<CommandString, _> =
            deserialize(&[0x41u8, 0x6e, 0x64, 0x72, 0x65, 0x77, 0, 0, 0, 0, 0, 0]);
        assert!(cs.is_ok());
        assert_eq!(cs.as_ref().unwrap().to_string(), "Andrew".to_owned());
        assert_eq!(cs.unwrap(), CommandString::try_from_static("Andrew").unwrap());

        let short_cs: Result<CommandString, _> =
            deserialize(&[0x41u8, 0x6e, 0x64, 0x72, 0x65, 0x77, 0, 0, 0, 0, 0]);
        assert!(short_cs.is_err());
    }

    #[test]
    #[rustfmt::skip]
    fn serialize_verack_test() {
        assert_eq!(serialize(&RawNetworkMessage { magic: 0xd9b4bef9, payload: NetworkMessage::Verack }),
                   vec![0xf9, 0xbe, 0xb4, 0xd9, 0x76, 0x65, 0x72, 0x61,
                        0x63, 0x6B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x5d, 0xf6, 0xe0, 0xe2]);
    }

    #[test]
    #[rustfmt::skip]
    fn serialize_ping_test() {
        assert_eq!(serialize(&RawNetworkMessage { magic: 0xd9b4bef9, payload: NetworkMessage::Ping(100) }),
                   vec![0xf9, 0xbe, 0xb4, 0xd9, 0x70, 0x69, 0x6e, 0x67,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x08, 0x00, 0x00, 0x00, 0x24, 0x67, 0xf1, 0x1d,
                        0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    #[rustfmt::skip]
    fn serialize_mempool_test() {
        assert_eq!(serialize(&RawNetworkMessage { magic: 0xd9b4bef9, payload: NetworkMessage::MemPool }),
                   vec![0xf9, 0xbe, 0xb4, 0xd9, 0x6d, 0x65, 0x6d, 0x70,
                        0x6f, 0x6f, 0x6c, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x5d, 0xf6, 0xe0, 0xe2]);
    }

    #[test]
    #[rustfmt::skip]
    fn serialize_getaddr_test() {
        assert_eq!(serialize(&RawNetworkMessage { magic: 0xd9b4bef9, payload: NetworkMessage::GetAddr }),
                   vec![0xf9, 0xbe, 0xb4, 0xd9, 0x67, 0x65, 0x74, 0x61,
                        0x64, 0x64, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x5d, 0xf6, 0xe0, 0xe2]);
    }

    #[test]
    fn deserialize_getaddr_test() {
        #[rustfmt::skip]
            let msg = deserialize(&[
            0xf9, 0xbe, 0xb4, 0xd9, 0x67, 0x65, 0x74, 0x61,
            0x64, 0x64, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x5d, 0xf6, 0xe0, 0xe2
        ]);
        let preimage = RawNetworkMessage {
            magic: 0xd9b4bef9,
            payload: NetworkMessage::GetAddr,
        };
        assert!(msg.is_ok());
        let msg: RawNetworkMessage = msg.unwrap();
        assert_eq!(preimage.magic, msg.magic);
        assert_eq!(preimage.payload, msg.payload);
    }

    #[test]
    fn deserialize_version_test() {
        #[rustfmt::skip]
            let msg = deserialize::<RawNetworkMessage>(&[
            0xf9, 0xbe, 0xb4, 0xd9, 0x76, 0x65, 0x72, 0x73,
            0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x66, 0x00, 0x00, 0x00, 0xbe, 0x61, 0xb8, 0x27,
            0x7f, 0x11, 0x01, 0x00, 0x0d, 0x04, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xf0, 0x0f, 0x4d, 0x5c,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
            0x5b, 0xf0, 0x8c, 0x80, 0xb4, 0xbd, 0x0d, 0x04,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xfa, 0xa9, 0x95, 0x59, 0xcc, 0x68, 0xa1, 0xc1,
            0x10, 0x2f, 0x53, 0x61, 0x74, 0x6f, 0x73, 0x68,
            0x69, 0x3a, 0x30, 0x2e, 0x31, 0x37, 0x2e, 0x31,
            0x2f, 0x93, 0x8c, 0x08, 0x00, 0x01
        ]).expect("deserialize version message");

        assert_eq!(msg.magic, 0xd9b4bef9);
        if let NetworkMessage::Version(version_msg) = msg.payload {
            assert_eq!(version_msg.version, 70015);
            assert_eq!(
                version_msg.services,
                ServiceFlags::NETWORK
                    | ServiceFlags::BLOOM
                    | ServiceFlags::from(1 << 3)
                    | ServiceFlags::NETWORK_LIMITED
            );
            assert_eq!(version_msg.timestamp, 1548554224);
            assert_eq!(version_msg.nonce, 13952548347456104954);
            assert_eq!(version_msg.user_agent, "/Satoshi:0.17.1/");
            assert_eq!(version_msg.start_height, 560275);
            assert!(version_msg.relay);
        } else {
            panic!("Wrong message type");
        }
    }

    #[test]
    fn deserialize_partial_message_test() {
        #[rustfmt::skip]
            let data = [
            0xf9, 0xbe, 0xb4, 0xd9, 0x76, 0x65, 0x72, 0x73,
            0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x66, 0x00, 0x00, 0x00, 0xbe, 0x61, 0xb8, 0x27,
            0x7f, 0x11, 0x01, 0x00, 0x0d, 0x04, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xf0, 0x0f, 0x4d, 0x5c,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
            0x5b, 0xf0, 0x8c, 0x80, 0xb4, 0xbd, 0x0d, 0x04,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xfa, 0xa9, 0x95, 0x59, 0xcc, 0x68, 0xa1, 0xc1,
            0x10, 0x2f, 0x53, 0x61, 0x74, 0x6f, 0x73, 0x68,
            0x69, 0x3a, 0x30, 0x2e, 0x31, 0x37, 0x2e, 0x31,
            0x2f, 0x93, 0x8c, 0x08, 0x00, 0x01, 0x00, 0x00
        ];
        let (msg, consumed) =
            deserialize_partial::<RawNetworkMessage>(&data).expect("deserialize partial message");

        assert_eq!(consumed, data.to_vec().len() - 2);
        assert_eq!(msg.magic, 0xd9b4bef9);
        if let NetworkMessage::Version(version_msg) = msg.payload {
            assert_eq!(version_msg.version, 70015);
            assert_eq!(
                version_msg.services,
                ServiceFlags::NETWORK
                    | ServiceFlags::BLOOM
                    | ServiceFlags::from(1 << 3)
                    | ServiceFlags::NETWORK_LIMITED
            );
            assert_eq!(version_msg.timestamp, 1548554224);
            assert_eq!(version_msg.nonce, 13952548347456104954);
            assert_eq!(version_msg.user_agent, "/Satoshi:0.17.1/");
            assert_eq!(version_msg.start_height, 560275);
            assert!(version_msg.relay);
        } else {
            panic!("Wrong message type");
        }
    }

    #[test]
    fn test_senddsq_message_encode_decode() {
        // Test encoding and decoding SendDsq(true)
        let msg_true = NetworkMessage::SendDsq(true);
        let raw_msg = RawNetworkMessage {
            magic: crate::Network::Mainnet.magic(),
            payload: msg_true,
        };

        // Encode
        let encoded = serialize(&raw_msg);

        // Decode
        let decoded: RawNetworkMessage = deserialize(&encoded).unwrap();

        // Verify
        match decoded.payload {
            NetworkMessage::SendDsq(wants_dsq) => {
                assert!(wants_dsq);
            }
            _ => panic!("Expected SendDsq message"),
        }

        // Test encoding and decoding SendDsq(false)
        let msg_false = NetworkMessage::SendDsq(false);
        let raw_msg = RawNetworkMessage {
            magic: crate::Network::Mainnet.magic(),
            payload: msg_false,
        };

        // Encode
        let encoded = serialize(&raw_msg);

        // Decode
        let decoded: RawNetworkMessage = deserialize(&encoded).unwrap();

        // Verify
        match decoded.payload {
            NetworkMessage::SendDsq(wants_dsq) => {
                assert!(!wants_dsq);
            }
            _ => panic!("Expected SendDsq message"),
        }
    }

    #[test]
    fn test_senddsq_command_string() {
        let msg = NetworkMessage::SendDsq(true);
        assert_eq!(msg.cmd(), "senddsq");
    }

    #[test]
    fn headers_short_frame_with_huge_count_fails() {
        let payload = serialize(&VarInt(u64::MAX));
        assert!(
            HeaderDeserializationWrapper::consensus_decode_from_finite_reader(&mut &payload[..])
                .is_err()
        );
    }

    #[test_case(MAX_HEADERS_RESULTS, true; "full Core batch decodes")]
    #[test_case(MAX_HEADERS_RESULTS + 1, false; "above Core batch is rejected")]
    fn headers_count_limit(count: usize, decodes: bool) {
        let msg = RawNetworkMessage {
            magic: 0xd9b4bef9,
            payload: NetworkMessage::Headers(block::Header::dummy_batch(0..count as u32)),
        };
        let decoded = deserialize::<RawNetworkMessage>(&serialize(&msg));
        assert_eq!(decoded.ok(), decodes.then_some(msg));
    }

    #[test]
    fn test_empty_payload_messages_encode_to_nothing() {
        let messages = [
            NetworkMessage::Verack,
            NetworkMessage::SendHeaders,
            NetworkMessage::SendHeaders2,
            NetworkMessage::MemPool,
            NetworkMessage::GetAddr,
            NetworkMessage::FilterClear,
            NetworkMessage::SendAddrV2,
        ];
        for msg in messages {
            assert!(msg.consensus_encode_payload().is_empty(), "{}", msg.cmd());
        }
    }

    #[test]
    #[cfg(feature = "core-block-hash-use-x11")]
    fn test_headers_payload_has_trailing_tx_counts() {
        let header = block::Header {
            version: block::Version::from_consensus(1),
            prev_blockhash: hash_x11([1u8; 32]).into(),
            merkle_root: hash([2u8; 32]).into(),
            time: 1234567890,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce: 42,
        };

        assert_eq!(NetworkMessage::Headers(vec![]).consensus_encode_payload(), vec![0x00]);

        // varint(1) + 80-byte header + 0x00 tx count
        let encoded = NetworkMessage::Headers(vec![header]).consensus_encode_payload();
        assert_eq!(encoded.len(), 82);
        assert_eq!(encoded[81], 0x00);

        // varint(3) + 3 * (header + 0x00)
        let encoded = NetworkMessage::Headers(vec![header; 3]).consensus_encode_payload();
        assert_eq!(encoded.len(), 244);
    }

    #[test]
    fn test_unknown_payload_is_raw_bytes() {
        let unknown_msg = NetworkMessage::Unknown {
            command: CommandString::try_from_static("custom").unwrap(),
            payload: vec![0xaa, 0xbb, 0xcc, 0xdd],
        };
        // No length prefix.
        assert_eq!(unknown_msg.consensus_encode_payload(), vec![0xaa, 0xbb, 0xcc, 0xdd]);
    }

    #[test]
    fn test_v2_short_ids_match_dash_core() {
        let pinned = [
            ("addr", 1),
            ("cmpctblock", 4),
            ("filteradd", 6),
            ("ping", 18),
            ("pong", 19),
            ("addrv2", 28),
            ("spork", 128),
            ("senddsq", 130),
            ("getmnlistd", 143),
            ("clsig", 160),
            ("isdlock", 161),
            ("sendheaders2", 164),
            ("headers2", 165),
            ("qrinfo", 167),
            ("platformban", 168),
        ];
        for (command, id) in pinned {
            assert_eq!(v2_short_id(command), Some(id), "{}", command);
            assert_eq!(v2_command(id), Some(command), "{}", id);
        }
        for id in [0, 5].into_iter().chain(29..128).chain(169..=u8::MAX) {
            assert_eq!(v2_command(id), None, "short ID {} must be unassigned", id);
        }
        assert_eq!(v2_short_id("feefilter"), None);
        assert_eq!(v2_short_id("version"), None);
        assert_eq!(v2_short_id(""), None);
        for id in 1..=u8::MAX {
            if let Some(command) = v2_command(id) {
                assert_eq!(v2_short_id(command), Some(id), "{} is listed twice", command);
            }
        }
    }

    #[test]
    fn test_v2_short_format() {
        let messages = [
            NetworkMessage::Ping(0x1234567890abcdef),
            NetworkMessage::Pong(0xfedcba0987654321),
            NetworkMessage::Inv(vec![]),
            NetworkMessage::GetData(vec![]),
            NetworkMessage::NotFound(vec![]),
            NetworkMessage::MemPool,
            NetworkMessage::FilterClear,
            NetworkMessage::SendHeaders2,
            NetworkMessage::SendDsq(true),
            NetworkMessage::GetMnListD(GetMnListDiff {
                base_block_hash: BlockHash::all_zeros(),
                block_hash: BlockHash::from_byte_array([7u8; 32]),
            }),
        ];
        for message in messages {
            let encoded = message.consensus_encode_v2();
            assert_eq!(Some(encoded[0]), v2_short_id(message.cmd()), "{}", message.cmd());
        }
    }

    #[test]
    fn test_v2_extended_format() {
        let addr = Address::new(&(Ipv4Addr::LOCALHOST, 9999).into(), ServiceFlags::NONE);
        let version = NetworkMessage::Version(VersionMessage {
            version: 70015,
            services: ServiceFlags::NONE,
            timestamp: 0,
            receiver: addr.clone(),
            sender: addr,
            nonce: 0,
            user_agent: "/test/".to_string(),
            start_height: 0,
            relay: false,
            mn_auth_challenge: [0u8; 32],
            masternode_connection: false,
        });
        // An unknown command must go out under its real name, not `cmd()`'s "unknown".
        let unknown = NetworkMessage::Unknown {
            command: CommandString::try_from_static("custom").unwrap(),
            payload: vec![0xaa, 0xbb, 0xcc, 0xdd],
        };
        let messages = [
            (version, b"version\0\0\0\0\0"),
            (unknown, b"custom\0\0\0\0\0\0"),
            // feefilter's short ID slot is empty in Dash.
            (NetworkMessage::FeeFilter(1000), b"feefilter\0\0\0"),
        ];
        for (message, command) in messages {
            let encoded = message.consensus_encode_v2();
            assert_eq!(encoded[0], V2_EXTENDED_ID);
            assert_eq!(&encoded[1..1 + V2_COMMAND_LEN], &command[..]);
            assert_eq!(&encoded[1 + V2_COMMAND_LEN..], message.consensus_encode_payload());
        }
    }

    #[test]
    fn test_v2_decode_drops_what_dash_core_drops() {
        // No message ID
        assert_eq!(NetworkMessage::consensus_decode_v2(&[]).unwrap(), None);
        // Extended marker without a full 12-byte command
        assert_eq!(NetworkMessage::consensus_decode_v2(&[0, b'v', b'e', b'r']).unwrap(), None);
        // Unassigned short IDs, including feefilter's
        for id in [5u8, 29, 127, 169, 255] {
            assert_eq!(NetworkMessage::consensus_decode_v2(&[id, 1, 2]).unwrap(), None);
        }
        // Non-printable command, and a non-NUL byte after the padding starts
        let mut bad = [0u8; 1 + V2_COMMAND_LEN];
        bad[1] = 0x01;
        assert_eq!(NetworkMessage::consensus_decode_v2(&bad).unwrap(), None);
        let mut bad = [0u8; 1 + V2_COMMAND_LEN];
        bad[1..4].copy_from_slice(b"inv");
        bad[5] = b'x';
        assert_eq!(NetworkMessage::consensus_decode_v2(&bad).unwrap(), None);
    }

    #[test]
    fn test_v2_decode_rejects_malformed_payload() {
        // A ping nonce is 8 bytes.
        let ping = v2_short_id("ping").unwrap();
        assert!(NetworkMessage::consensus_decode_v2(&[ping, 1, 2, 3]).is_err());
    }
}
