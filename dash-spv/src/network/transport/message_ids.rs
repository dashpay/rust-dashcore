//! BIP324 short message IDs for Dash.
//!
//! BIP324 uses 1-byte short IDs for common messages to reduce bandwidth.
//! Less common messages use extended format: 0x00 + 12-byte ASCII command.
//!
//! Dash extends BIP324 with its own message IDs in the 128-255 range:
//! - IDs 0-32: Standard BIP324 (Bitcoin) messages
//! - IDs 128-167: Dash-specific messages
//!
//! ## Design Notes
//!
//! There's intentional asymmetry between the two main functions:
//! - `short_id_to_command`: Handles ALL short IDs (for receiving messages)
//! - `network_message_to_short_id`: Only handles NetworkMessage variants that exist
//!
//! This means we can decode incoming messages with short IDs even if dashcore
//! doesn't have a dedicated NetworkMessage variant for them (they'll be decoded
//! as Unknown messages via the extended format fallback in decode_by_command).

use dashcore::network::message::NetworkMessage;

/// Extended message marker (12-byte ASCII command follows).
pub const MSG_ID_EXTENDED: u8 = 0;

// =============================================================================
// Standard BIP324 short message IDs (1-28)
// Matches Dash Core's V2_BITCOIN_IDS array
// =============================================================================
pub const MSG_ID_ADDR: u8 = 1;
pub const MSG_ID_BLOCK: u8 = 2;
pub const MSG_ID_BLOCKTXN: u8 = 3;
pub const MSG_ID_CMPCTBLOCK: u8 = 4;
// ID 5 is reserved for FEEFILTER but not implemented in Dash
pub const MSG_ID_FILTERADD: u8 = 6;
pub const MSG_ID_FILTERCLEAR: u8 = 7;
pub const MSG_ID_FILTERLOAD: u8 = 8;
pub const MSG_ID_GETBLOCKS: u8 = 9;
pub const MSG_ID_GETBLOCKTXN: u8 = 10;
pub const MSG_ID_GETDATA: u8 = 11;
pub const MSG_ID_GETHEADERS: u8 = 12;
pub const MSG_ID_HEADERS: u8 = 13;
pub const MSG_ID_INV: u8 = 14;
pub const MSG_ID_MEMPOOL: u8 = 15;
pub const MSG_ID_MERKLEBLOCK: u8 = 16;
pub const MSG_ID_NOTFOUND: u8 = 17;
pub const MSG_ID_PING: u8 = 18;
pub const MSG_ID_PONG: u8 = 19;
pub const MSG_ID_SENDCMPCT: u8 = 20;
pub const MSG_ID_TX: u8 = 21;
pub const MSG_ID_GETCFILTERS: u8 = 22;
pub const MSG_ID_CFILTER: u8 = 23;
pub const MSG_ID_GETCFHEADERS: u8 = 24;
pub const MSG_ID_CFHEADERS: u8 = 25;
pub const MSG_ID_GETCFCHECKPT: u8 = 26;
pub const MSG_ID_CFCHECKPT: u8 = 27;
pub const MSG_ID_ADDRV2: u8 = 28;
// IDs 29-32 are reserved but unimplemented in BIP324

// =============================================================================
// Dash-specific short message IDs (128-167)
// Matches Dash Core's V2_DASH_IDS array
// =============================================================================
pub const MSG_ID_SPORK: u8 = 128;
pub const MSG_ID_GETSPORKS: u8 = 129;
pub const MSG_ID_SENDDSQUEUE: u8 = 130;
pub const MSG_ID_DSACCEPT: u8 = 131;
pub const MSG_ID_DSVIN: u8 = 132;
pub const MSG_ID_DSFINALTX: u8 = 133;
pub const MSG_ID_DSSIGNFINALTX: u8 = 134;
pub const MSG_ID_DSCOMPLETE: u8 = 135;
pub const MSG_ID_DSSTATUSUPDATE: u8 = 136;
pub const MSG_ID_DSTX: u8 = 137;
pub const MSG_ID_DSQUEUE: u8 = 138;
pub const MSG_ID_SYNCSTATUSCOUNT: u8 = 139;
pub const MSG_ID_MNGOVERNANCESYNC: u8 = 140;
pub const MSG_ID_MNGOVERNANCEOBJECT: u8 = 141;
pub const MSG_ID_MNGOVERNANCEOBJECTVOTE: u8 = 142;
pub const MSG_ID_GETMNLISTDIFF: u8 = 143;
pub const MSG_ID_MNLISTDIFF: u8 = 144;
pub const MSG_ID_QSENDRECSIGS: u8 = 145;
pub const MSG_ID_QFCOMMITMENT: u8 = 146;
pub const MSG_ID_QCONTRIB: u8 = 147;
pub const MSG_ID_QCOMPLAINT: u8 = 148;
pub const MSG_ID_QJUSTIFICATION: u8 = 149;
pub const MSG_ID_QPCOMMITMENT: u8 = 150;
pub const MSG_ID_QWATCH: u8 = 151;
pub const MSG_ID_QSIGSESANN: u8 = 152;
pub const MSG_ID_QSIGSHARESINV: u8 = 153;
pub const MSG_ID_QGETSIGSHARES: u8 = 154;
pub const MSG_ID_QBSIGSHARES: u8 = 155;
pub const MSG_ID_QSIGREC: u8 = 156;
pub const MSG_ID_QSIGSHARE: u8 = 157;
pub const MSG_ID_QGETDATA: u8 = 158;
pub const MSG_ID_QDATA: u8 = 159;
pub const MSG_ID_CLSIG: u8 = 160;
pub const MSG_ID_ISDLOCK: u8 = 161;
pub const MSG_ID_MNAUTH: u8 = 162;
pub const MSG_ID_GETHEADERS2: u8 = 163;
pub const MSG_ID_SENDHEADERS2: u8 = 164;
pub const MSG_ID_HEADERS2: u8 = 165;
pub const MSG_ID_GETQUORUMROTATIONINFO: u8 = 166;
pub const MSG_ID_QUORUMROTATIONINFO: u8 = 167;

/// Get the short message ID for a NetworkMessage, if one exists.
///
/// Returns `Some(id)` for common messages that have short IDs,
/// or `None` for messages that require extended format.
pub fn network_message_to_short_id(msg: &NetworkMessage) -> Option<u8> {
    match msg {
        // Standard BIP324 messages
        NetworkMessage::Addr(_) => Some(MSG_ID_ADDR),
        NetworkMessage::Block(_) => Some(MSG_ID_BLOCK),
        NetworkMessage::BlockTxn(_) => Some(MSG_ID_BLOCKTXN),
        NetworkMessage::CmpctBlock(_) => Some(MSG_ID_CMPCTBLOCK),
        // Note: FeeFilter is ID 5 in BIP324 but not implemented in Dash
        NetworkMessage::FilterAdd(_) => Some(MSG_ID_FILTERADD),
        NetworkMessage::FilterClear => Some(MSG_ID_FILTERCLEAR),
        NetworkMessage::FilterLoad(_) => Some(MSG_ID_FILTERLOAD),
        NetworkMessage::GetBlocks(_) => Some(MSG_ID_GETBLOCKS),
        NetworkMessage::GetBlockTxn(_) => Some(MSG_ID_GETBLOCKTXN),
        NetworkMessage::GetData(_) => Some(MSG_ID_GETDATA),
        NetworkMessage::GetHeaders(_) => Some(MSG_ID_GETHEADERS),
        NetworkMessage::Headers(_) => Some(MSG_ID_HEADERS),
        NetworkMessage::Inv(_) => Some(MSG_ID_INV),
        NetworkMessage::MemPool => Some(MSG_ID_MEMPOOL),
        NetworkMessage::MerkleBlock(_) => Some(MSG_ID_MERKLEBLOCK),
        NetworkMessage::NotFound(_) => Some(MSG_ID_NOTFOUND),
        NetworkMessage::Ping(_) => Some(MSG_ID_PING),
        NetworkMessage::Pong(_) => Some(MSG_ID_PONG),
        NetworkMessage::SendCmpct(_) => Some(MSG_ID_SENDCMPCT),
        NetworkMessage::Tx(_) => Some(MSG_ID_TX),
        NetworkMessage::GetCFilters(_) => Some(MSG_ID_GETCFILTERS),
        NetworkMessage::CFilter(_) => Some(MSG_ID_CFILTER),
        NetworkMessage::GetCFHeaders(_) => Some(MSG_ID_GETCFHEADERS),
        NetworkMessage::CFHeaders(_) => Some(MSG_ID_CFHEADERS),
        NetworkMessage::GetCFCheckpt(_) => Some(MSG_ID_GETCFCHECKPT),
        NetworkMessage::CFCheckpt(_) => Some(MSG_ID_CFCHECKPT),
        NetworkMessage::AddrV2(_) => Some(MSG_ID_ADDRV2),

        // Dash-specific messages (only variants that exist in dashcore)
        NetworkMessage::SendDsq(_) => Some(MSG_ID_SENDDSQUEUE),
        NetworkMessage::GetMnListD(_) => Some(MSG_ID_GETMNLISTDIFF),
        NetworkMessage::MnListDiff(_) => Some(MSG_ID_MNLISTDIFF),
        NetworkMessage::CLSig(_) => Some(MSG_ID_CLSIG),
        NetworkMessage::ISLock(_) => Some(MSG_ID_ISDLOCK),
        NetworkMessage::GetHeaders2(_) => Some(MSG_ID_GETHEADERS2),
        NetworkMessage::SendHeaders2 => Some(MSG_ID_SENDHEADERS2),
        NetworkMessage::Headers2(_) => Some(MSG_ID_HEADERS2),
        NetworkMessage::GetQRInfo(_) => Some(MSG_ID_GETQUORUMROTATIONINFO),
        NetworkMessage::QRInfo(_) => Some(MSG_ID_QUORUMROTATIONINFO),

        // All other messages use extended format
        _ => None,
    }
}

/// Get the command string for a short message ID.
///
/// Returns `Some(command)` for valid short IDs,
/// or `None` for unknown IDs.
pub fn short_id_to_command(id: u8) -> Option<&'static str> {
    match id {
        // Standard BIP324 messages
        MSG_ID_ADDR => Some("addr"),
        MSG_ID_BLOCK => Some("block"),
        MSG_ID_BLOCKTXN => Some("blocktxn"),
        MSG_ID_CMPCTBLOCK => Some("cmpctblock"),
        MSG_ID_FILTERADD => Some("filteradd"),
        MSG_ID_FILTERCLEAR => Some("filterclear"),
        MSG_ID_FILTERLOAD => Some("filterload"),
        MSG_ID_GETBLOCKS => Some("getblocks"),
        MSG_ID_GETBLOCKTXN => Some("getblocktxn"),
        MSG_ID_GETDATA => Some("getdata"),
        MSG_ID_GETHEADERS => Some("getheaders"),
        MSG_ID_HEADERS => Some("headers"),
        MSG_ID_INV => Some("inv"),
        MSG_ID_MEMPOOL => Some("mempool"),
        MSG_ID_MERKLEBLOCK => Some("merkleblock"),
        MSG_ID_NOTFOUND => Some("notfound"),
        MSG_ID_PING => Some("ping"),
        MSG_ID_PONG => Some("pong"),
        MSG_ID_SENDCMPCT => Some("sendcmpct"),
        MSG_ID_TX => Some("tx"),
        MSG_ID_GETCFILTERS => Some("getcfilters"),
        MSG_ID_CFILTER => Some("cfilter"),
        MSG_ID_GETCFHEADERS => Some("getcfheaders"),
        MSG_ID_CFHEADERS => Some("cfheaders"),
        MSG_ID_GETCFCHECKPT => Some("getcfcheckpt"),
        MSG_ID_CFCHECKPT => Some("cfcheckpt"),
        MSG_ID_ADDRV2 => Some("addrv2"),

        // Dash-specific messages
        MSG_ID_SPORK => Some("spork"),
        MSG_ID_GETSPORKS => Some("getsporks"),
        MSG_ID_SENDDSQUEUE => Some("senddsq"),
        MSG_ID_DSACCEPT => Some("dsa"),
        MSG_ID_DSVIN => Some("dsi"),
        MSG_ID_DSFINALTX => Some("dsf"),
        MSG_ID_DSSIGNFINALTX => Some("dss"),
        MSG_ID_DSCOMPLETE => Some("dsc"),
        MSG_ID_DSSTATUSUPDATE => Some("dssu"),
        MSG_ID_DSTX => Some("dstx"),
        MSG_ID_DSQUEUE => Some("dsq"),
        MSG_ID_SYNCSTATUSCOUNT => Some("ssc"),
        MSG_ID_MNGOVERNANCESYNC => Some("govsync"),
        MSG_ID_MNGOVERNANCEOBJECT => Some("govobj"),
        MSG_ID_MNGOVERNANCEOBJECTVOTE => Some("govobjvote"),
        MSG_ID_GETMNLISTDIFF => Some("getmnlistd"),
        MSG_ID_MNLISTDIFF => Some("mnlistdiff"),
        MSG_ID_QSENDRECSIGS => Some("qsendrecsigs"),
        MSG_ID_QFCOMMITMENT => Some("qfcommit"),
        MSG_ID_QCONTRIB => Some("qcontrib"),
        MSG_ID_QCOMPLAINT => Some("qcomplaint"),
        MSG_ID_QJUSTIFICATION => Some("qjustify"),
        MSG_ID_QPCOMMITMENT => Some("qpcommit"),
        MSG_ID_QWATCH => Some("qwatch"),
        MSG_ID_QSIGSESANN => Some("qsigsesann"),
        MSG_ID_QSIGSHARESINV => Some("qsigsinv"),
        MSG_ID_QGETSIGSHARES => Some("qgetsigs"),
        MSG_ID_QBSIGSHARES => Some("qbsigs"),
        MSG_ID_QSIGREC => Some("qsigrec"),
        MSG_ID_QSIGSHARE => Some("qsigshare"),
        MSG_ID_QGETDATA => Some("qgetdata"),
        MSG_ID_QDATA => Some("qdata"),
        MSG_ID_CLSIG => Some("clsig"),
        MSG_ID_ISDLOCK => Some("isdlock"),
        MSG_ID_MNAUTH => Some("mnauth"),
        MSG_ID_GETHEADERS2 => Some("getheaders2"),
        MSG_ID_SENDHEADERS2 => Some("sendheaders2"),
        MSG_ID_HEADERS2 => Some("headers2"),
        MSG_ID_GETQUORUMROTATIONINFO => Some("getqrinfo"),
        MSG_ID_QUORUMROTATIONINFO => Some("qrinfo"),

        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ping_pong_ids() {
        assert_eq!(network_message_to_short_id(&NetworkMessage::Ping(0)), Some(MSG_ID_PING));
        assert_eq!(network_message_to_short_id(&NetworkMessage::Pong(0)), Some(MSG_ID_PONG));
    }

    #[test]
    fn test_short_id_to_command() {
        assert_eq!(short_id_to_command(MSG_ID_PING), Some("ping"));
        assert_eq!(short_id_to_command(MSG_ID_PONG), Some("pong"));
        assert_eq!(short_id_to_command(MSG_ID_BLOCK), Some("block"));
        assert_eq!(short_id_to_command(255), None);
    }

    #[test]
    fn test_dash_short_ids() {
        // Test Dash-specific short IDs
        assert_eq!(short_id_to_command(MSG_ID_SPORK), Some("spork"));
        assert_eq!(short_id_to_command(MSG_ID_SENDDSQUEUE), Some("senddsq"));
        assert_eq!(short_id_to_command(MSG_ID_CLSIG), Some("clsig"));
        assert_eq!(short_id_to_command(MSG_ID_ISDLOCK), Some("isdlock"));
        assert_eq!(short_id_to_command(MSG_ID_MNLISTDIFF), Some("mnlistdiff"));
        assert_eq!(short_id_to_command(MSG_ID_HEADERS2), Some("headers2"));
    }

    #[test]
    fn test_extended_format_for_non_short_id_messages() {
        // Version is not a short ID message
        use dashcore::network::address::Address;
        use dashcore::network::constants::ServiceFlags;
        use dashcore::network::message_network::VersionMessage;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let addr = Address::new(
            &SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8333),
            ServiceFlags::NONE,
        );

        let version = VersionMessage {
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
        };

        assert!(network_message_to_short_id(&NetworkMessage::Version(version)).is_none());
    }
}
