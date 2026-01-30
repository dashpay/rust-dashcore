//! Message type enum for easier message mapping to NetworkMessage variants.
//!
//! Uses a macro to keep MessageType in sync with NetworkMessage.
//! If NetworkMessage adds a new variant, compilation will fail until
//! the variant is added here.

use crate::network::Message;
use dashcore::network::message::NetworkMessage;

/// Generates the `MessageType` enum
///
/// Implements:
///  - `From<&Message>`
///
/// Each `NetworkMessage` variant maps to a corresponding `MessageType` variant
/// (e.g., `NetworkMessage::Headers(_)` -> `MessageType::Headers`).
///
/// Syntax for entries:
/// - `Name` for unit variants (e.g., `Verack`)
/// - `Name (..)` for tuple variants with data (e.g., `Headers (..)`)
/// - `Name { .. }` for struct variants (e.g., `Unknown { .. }`)
macro_rules! define_message_types {
    ($($(#[$meta:meta])* $variant:ident $( ( $($tuple:tt)* ) )? $( { $($field:tt)* } )?),* $(,)?) => {
        /// Message types that subscribers can subscribe to.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum MessageType {
            $($(#[$meta])* $variant,)*
        }

        impl From<&Message> for MessageType {
            fn from(value: &Message) -> Self {
                match value.inner() {
                    $(NetworkMessage::$variant $( ( $($tuple)* ) )? $( { $($field)* } )? => MessageType::$variant,)*
                }
            }
        }
    };
}

define_message_types! {
    /// `version`
    Version (..),
    /// `verack`
    Verack,
    /// `addr`
    Addr (..),
    /// `inv`
    Inv (..),
    /// `getdata`
    GetData (..),
    /// `notfound`
    NotFound (..),
    /// `getblocks`
    GetBlocks (..),
    /// `getheaders`
    GetHeaders (..),
    /// `mempool`
    MemPool,
    /// `tx`
    Tx (..),
    /// `block`
    Block (..),
    /// `headers`
    Headers (..),
    /// `sendheaders`
    SendHeaders,
    /// `getheaders2`
    GetHeaders2 (..),
    /// `sendheaders2`
    SendHeaders2,
    /// `headers2`
    Headers2 (..),
    /// `getaddr`
    GetAddr,
    /// `ping`
    Ping (..),
    /// `pong`
    Pong (..),
    /// `merkleblock`
    MerkleBlock (..),
    /// `filterload`
    FilterLoad (..),
    /// `filteradd`
    FilterAdd (..),
    /// `filterclear`
    FilterClear,
    /// `getcfilters`
    GetCFilters (..),
    /// `cfilter`
    CFilter (..),
    /// `getcfheaders`
    GetCFHeaders (..),
    /// `cfheaders`
    CFHeaders (..),
    /// `getcfcheckpt`
    GetCFCheckpt (..),
    /// `cfcheckpt`
    CFCheckpt (..),
    /// `sendcmpct`
    SendCmpct (..),
    /// `cmpctblock`
    CmpctBlock (..),
    /// `getblocktxn`
    GetBlockTxn (..),
    /// `blocktxn`
    BlockTxn (..),
    /// `alert`
    Alert (..),
    /// `reject`
    Reject (..),
    /// `feefilter`
    FeeFilter (..),
    /// `addrv2`
    AddrV2 (..),
    /// `sendaddrv2`
    SendAddrV2,
    /// `getmnlistd`
    GetMnListD (..),
    /// `mnlistdiff`
    MnListDiff (..),
    /// `getqrinfo`
    GetQRInfo (..),
    /// `qrinfo`
    QRInfo (..),
    /// `clsig`
    CLSig (..),
    /// `isdlock`
    ISLock (..),
    /// `senddsq`
    SendDsq (..),
    /// Unknown message type
    Unknown { .. },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::test_socket_address;

    #[test]
    fn from_message_unit_variant() {
        let addr = test_socket_address(1);

        let msg = Message::new(addr, NetworkMessage::SendHeaders);
        assert_eq!(MessageType::from(&msg), MessageType::SendHeaders);
    }

    #[test]
    fn from_message_tuple_variant() {
        let addr = test_socket_address(1);

        let msg = Message::new(addr, NetworkMessage::Alert(vec![]));
        assert_eq!(MessageType::from(&msg), MessageType::Alert);
    }

    #[test]
    fn from_message_unknown_variant() {
        use dashcore::network::message::CommandString;

        let addr = test_socket_address(1);
        let unknown_msg = NetworkMessage::Unknown {
            command: CommandString::try_from_static("test").unwrap(),
            payload: vec![],
        };
        let msg = Message::new(addr, unknown_msg);
        assert_eq!(MessageType::from(&msg), MessageType::Unknown);
    }
}
