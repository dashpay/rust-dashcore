use crate::error::{Error, Result};
use dashcore::sml::llmq_type::LLMQType;
use dashcore::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use dashcore::QuorumHash;
use std::fmt::Display;
use tokio::sync::{mpsc, oneshot};

pub type GetQuorumByHeightResult = Result<QualifiedQuorumEntry>;

async fn receive<Type>(context: String, receiver: oneshot::Receiver<Type>) -> Result<Type> {
    receiver.await.map_err(|error| Error::ChannelFailure(context, error.to_string()))
}

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
        sender.send(self).map_err(|error| Error::ChannelFailure(context, error.to_string()))?;
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

#[derive(Clone)]
pub struct DashSpvClientInterface {
    pub command_sender: mpsc::UnboundedSender<DashSpvClientCommand>,
}

impl DashSpvClientInterface {
    pub fn new(command_sender: mpsc::UnboundedSender<DashSpvClientCommand>) -> Self {
        Self {
            command_sender,
        }
    }

    pub async fn get_quorum_by_height(
        &self,
        height: u32,
        quorum_type: LLMQType,
        quorum_hash: QuorumHash,
    ) -> GetQuorumByHeightResult {
        let (sender, receiver) = oneshot::channel();
        let command = DashSpvClientCommand::GetQuorumByHeight {
            height,
            quorum_type,
            quorum_hash,
            sender,
        };
        let context = command.to_string();
        command.send(context.clone(), self.command_sender.clone()).await?;
        receive(context, receiver).await?
    }
}
