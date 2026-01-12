use crate::error::SpvError;
use dashcore::sml::llmq_type::LLMQType;
use dashcore::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use dashcore::QuorumHash;
use std::fmt::Display;
use tokio::sync::{mpsc, oneshot};

pub type Result<T> = std::result::Result<T, SpvError>;

pub type GetQuorumByHeightResult = Result<QualifiedQuorumEntry>;

pub enum DashSpvClientCommand {
    GetQuorumByHeight {
        height: u32,
        quorum_type: LLMQType,
        quorum_hash: QuorumHash,
        sender: oneshot::Sender<GetQuorumByHeightResult>,
    },
}

impl DashSpvClientCommand {
    pub async fn send(
        self,
        context: String,
        sender: mpsc::UnboundedSender<DashSpvClientCommand>,
    ) -> Result<()> {
        sender.send(self).map_err(|error| SpvError::ChannelFailure(context, error.to_string()))?;
        Ok(())
    }
}

impl Display for DashSpvClientCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            DashSpvClientCommand::GetQuorumByHeight {
                height,
                quorum_type,
                quorum_hash,
                sender: _,
            } => format!("GetQuorumByHeight({height}, {quorum_type}, {quorum_hash})"),
        };
        write!(f, "{}", str)
    }
}
