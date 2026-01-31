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
    Tx(transaction::Transaction),
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
    MnListDiff(message_sml::MnListDiff),
    /// `getqrinfo`
    GetQRInfo(message_qrinfo::GetQRInfo),
    /// `qrinfo`
    QRInfo(message_qrinfo::QRInfo),
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
        len += CheckedData(match self.payload {
            NetworkMessage::Version(ref dat) => serialize(dat),
            NetworkMessage::Addr(ref dat) => serialize(dat),
            NetworkMessage::Inv(ref dat) => serialize(dat),
            NetworkMessage::GetData(ref dat) => serialize(dat),
            NetworkMessage::NotFound(ref dat) => serialize(dat),
            NetworkMessage::GetBlocks(ref dat) => serialize(dat),
            NetworkMessage::GetHeaders(ref dat) => serialize(dat),
            NetworkMessage::Tx(ref dat) => serialize(dat),
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
            NetworkMessage::FeeFilter(ref data) => serialize(data),
            NetworkMessage::AddrV2(ref dat) => serialize(dat),
            NetworkMessage::Verack
            | NetworkMessage::SendHeaders
            | NetworkMessage::SendHeaders2
            | NetworkMessage::MemPool
            | NetworkMessage::GetAddr
            | NetworkMessage::FilterClear
            | NetworkMessage::SendAddrV2 => vec![],
            NetworkMessage::Unknown {
                payload: ref data,
                ..
            } => serialize(data),
            NetworkMessage::GetMnListD(ref dat) => serialize(dat),
            NetworkMessage::MnListDiff(ref dat) => serialize(dat),
            NetworkMessage::GetQRInfo(ref dat) => serialize(dat),
            NetworkMessage::QRInfo(ref dat) => serialize(dat),
            NetworkMessage::CLSig(ref dat) => serialize(dat),
            NetworkMessage::ISLock(ref dat) => serialize(dat),
            NetworkMessage::SendDsq(wants_dsq) => serialize(&(wants_dsq as u8)),
        })
        .consensus_encode(w)?;
        Ok(len)
    }
}

struct HeaderDeserializationWrapper(Vec<block::Header>);

impl Decodable for HeaderDeserializationWrapper {
    #[inline]
    fn consensus_decode_from_finite_reader<R: io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, encode::Error> {
        let len = VarInt::consensus_decode(r)?.0;
        // should be above usual number of items to avoid
        // allocation
        let mut ret = Vec::with_capacity(core::cmp::min(1024 * 16, len as usize));
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
                log::warn!(
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

        let mut mem_d = io::Cursor::new(raw_payload);
        let payload = match &cmd.0[..] {
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
            "tx" => NetworkMessage::Tx(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?),
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
            "mnlistdiff" => NetworkMessage::MnListDiff(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "getqrinfo" => NetworkMessage::GetQRInfo(
                Decodable::consensus_decode_from_finite_reader(&mut mem_d)?,
            ),
            "qrinfo" => {
                NetworkMessage::QRInfo(Decodable::consensus_decode_from_finite_reader(&mut mem_d)?)
            }
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
                command: cmd,
                payload: mem_d.into_inner(),
            },
        };
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

#[cfg(test)]
mod test {

    use super::{CommandString, NetworkMessage, RawNetworkMessage, *};

    use crate::consensus::encode::{deserialize, deserialize_partial, serialize};

    use crate::network::constants::ServiceFlags;

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
        // Service flags: NETWORK(1) | BLOOM(4) | NETWORK_LIMITED(1024) = 1029 = 0x0405
        #[rustfmt::skip]
            let msg = deserialize::<RawNetworkMessage>(&[
            0xf9, 0xbe, 0xb4, 0xd9, 0x76, 0x65, 0x72, 0x73,
            0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x66, 0x00, 0x00, 0x00, 0x67, 0xe9, 0x70, 0x95,
            0x7f, 0x11, 0x01, 0x00, 0x05, 0x04, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xf0, 0x0f, 0x4d, 0x5c,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
            0x5b, 0xf0, 0x8c, 0x80, 0xb4, 0xbd, 0x05, 0x04,
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
                ServiceFlags::NETWORK | ServiceFlags::BLOOM | ServiceFlags::NETWORK_LIMITED
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
        // Service flags: NETWORK(1) | BLOOM(4) | NETWORK_LIMITED(1024) = 1029 = 0x0405
        #[rustfmt::skip]
            let data = [
            0xf9, 0xbe, 0xb4, 0xd9, 0x76, 0x65, 0x72, 0x73,
            0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x66, 0x00, 0x00, 0x00, 0x67, 0xe9, 0x70, 0x95,
            0x7f, 0x11, 0x01, 0x00, 0x05, 0x04, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xf0, 0x0f, 0x4d, 0x5c,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
            0x5b, 0xf0, 0x8c, 0x80, 0xb4, 0xbd, 0x05, 0x04,
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
                ServiceFlags::NETWORK | ServiceFlags::BLOOM | ServiceFlags::NETWORK_LIMITED
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
            magic: crate::Network::Dash.magic(),
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
            magic: crate::Network::Dash.magic(),
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
}
