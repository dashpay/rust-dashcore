//! Network message handling and routing.

use dashcore::network::message::NetworkMessage;
use dashcore::network::message_headers2::Headers2Message;
use dashcore::network::message_qrinfo::{GetQRInfo, QRInfo};
use tracing;

/// Handles incoming network messages and routes them appropriately.
pub struct MessageHandler {
    stats: MessageStats,
}

impl MessageHandler {
    /// Create a new message handler.
    pub fn new() -> Self {
        Self {
            stats: MessageStats::default(),
        }
    }

    /// Handle an incoming message.
    pub async fn handle_message(&mut self, message: NetworkMessage) -> MessageHandleResult {
        self.stats.messages_received += 1;

        match message {
            NetworkMessage::Version(_) => {
                self.stats.version_messages += 1;
                MessageHandleResult::Handshake(message)
            }
            NetworkMessage::Verack => {
                self.stats.verack_messages += 1;
                MessageHandleResult::Handshake(message)
            }
            NetworkMessage::Ping(nonce) => {
                self.stats.ping_messages += 1;
                MessageHandleResult::Ping(nonce)
            }
            NetworkMessage::Pong(_) => {
                self.stats.pong_messages += 1;
                MessageHandleResult::Pong
            }
            NetworkMessage::Headers(headers) => {
                self.stats.header_messages += 1;
                MessageHandleResult::Headers(headers)
            }
            NetworkMessage::Headers2(headers2) => {
                self.stats.headers2_messages += 1;
                MessageHandleResult::Headers2(headers2)
            }
            NetworkMessage::SendHeaders2 => {
                self.stats.sendheaders2_messages += 1;
                MessageHandleResult::SendHeaders2
            }
            NetworkMessage::CFHeaders(cf_headers) => {
                self.stats.filter_header_messages += 1;
                MessageHandleResult::FilterHeaders(cf_headers)
            }
            NetworkMessage::CFCheckpt(cf_checkpt) => {
                self.stats.filter_checkpoint_messages += 1;
                MessageHandleResult::FilterCheckpoint(cf_checkpt)
            }
            NetworkMessage::CFilter(cfilter) => {
                self.stats.filter_messages += 1;
                MessageHandleResult::Filter(cfilter)
            }
            NetworkMessage::Block(block) => {
                self.stats.block_messages += 1;
                MessageHandleResult::Block(block)
            }
            NetworkMessage::MnListDiff(diff) => {
                self.stats.masternode_diff_messages += 1;
                MessageHandleResult::MasternodeDiff(diff)
            }
            NetworkMessage::Inv(inv) => {
                self.stats.inventory_messages += 1;
                MessageHandleResult::Inventory(inv)
            }
            NetworkMessage::GetData(getdata) => {
                self.stats.getdata_messages += 1;
                // TODO: Handle getdata messages properly
                MessageHandleResult::Unhandled(NetworkMessage::GetData(getdata))
            }
            NetworkMessage::CLSig(chainlock) => {
                self.stats.chainlock_messages += 1;
                MessageHandleResult::ChainLock(chainlock)
            }
            NetworkMessage::ISLock(instantlock) => {
                self.stats.instantlock_messages += 1;
                MessageHandleResult::InstantLock(instantlock)
            }
            NetworkMessage::QRInfo(qr_info) => {
                self.stats.qrinfo_messages += 1;
                MessageHandleResult::QRInfo(qr_info)
            }
            NetworkMessage::GetQRInfo(_) => {
                // We don't serve QRInfo requests, only make them
                tracing::warn!("Received unexpected GetQRInfo request");
                self.stats.other_messages += 1;
                MessageHandleResult::Unhandled(message)
            }
            other => {
                self.stats.other_messages += 1;
                tracing::debug!("Received unhandled message: {:?}", other);
                MessageHandleResult::Unhandled(other)
            }
        }
    }

    /// Get message statistics.
    pub fn stats(&self) -> &MessageStats {
        &self.stats
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.stats = MessageStats::default();
    }
}

/// Result of message handling.
#[derive(Debug)]
pub enum MessageHandleResult {
    /// Handshake message (version, verack).
    Handshake(NetworkMessage),

    /// Ping message with nonce.
    Ping(u64),

    /// Pong message.
    Pong,

    /// Block headers.
    Headers(Vec<dashcore::block::Header>),

    /// Compressed block headers.
    Headers2(Headers2Message),

    /// SendHeaders2 preference.
    SendHeaders2,

    /// Filter headers.
    FilterHeaders(dashcore::network::message_filter::CFHeaders),

    /// Filter checkpoint.
    FilterCheckpoint(dashcore::network::message_filter::CFCheckpt),

    /// Compact filter.
    Filter(dashcore::network::message_filter::CFilter),

    /// Full block.
    Block(dashcore::block::Block),

    /// Masternode list diff.
    MasternodeDiff(dashcore::network::message_sml::MnListDiff),

    /// ChainLock.
    ChainLock(dashcore::ChainLock),

    /// InstantLock.
    InstantLock(dashcore::InstantLock),

    /// Inventory message.
    Inventory(Vec<dashcore::network::message_blockdata::Inventory>),

    /// GetData message.
    GetData(Vec<dashcore::network::message_blockdata::Inventory>),

    /// QRInfo message.
    QRInfo(QRInfo),

    /// Unhandled message.
    Unhandled(NetworkMessage),
}

/// Message handling statistics.
#[derive(Debug, Default, Clone)]
pub struct MessageStats {
    pub messages_received: u64,
    pub version_messages: u64,
    pub verack_messages: u64,
    pub ping_messages: u64,
    pub pong_messages: u64,
    pub header_messages: u64,
    pub headers2_messages: u64,
    pub sendheaders2_messages: u64,
    pub filter_header_messages: u64,
    pub filter_checkpoint_messages: u64,
    pub filter_messages: u64,
    pub block_messages: u64,
    pub masternode_diff_messages: u64,
    pub chainlock_messages: u64,
    pub instantlock_messages: u64,
    pub inventory_messages: u64,
    pub getdata_messages: u64,
    pub qrinfo_messages: u64,
    pub other_messages: u64,
}
