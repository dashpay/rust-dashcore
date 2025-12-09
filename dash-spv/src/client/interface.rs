use crate::error::SpvError;
use crate::sync::SharedMasternodeState;
use dashcore::sml::llmq_type::LLMQType;
use dashcore::sml::quorum_entry::qualified_quorum_entry::QualifiedQuorumEntry;
use dashcore::QuorumHash;
use std::fmt::Display;
use tokio::sync::{mpsc, oneshot};

pub type Result<T> = std::result::Result<T, SpvError>;

pub type GetQuorumByHeightResult = Result<QualifiedQuorumEntry>;

async fn receive<Type>(context: String, receiver: oneshot::Receiver<Type>) -> Result<Type> {
    receiver.await.map_err(|error| SpvError::ChannelFailure(context, error.to_string()))
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

/// Interface for interacting with a running DashSpvClient.
///
/// This struct provides both async command-based queries (via channels) and
/// direct synchronous access to quorum data (via `SharedMasternodeState`).
///
/// # Synchronous Access
///
/// For consumers that need synchronous quorum lookups (e.g., `ContextProvider`
/// implementations), use the `shared_masternode_state()` method:
///
/// ```ignore
/// let interface = client.get_interface();
/// let shared_state = interface.shared_masternode_state();
///
/// // Now you can query synchronously
/// let public_key = shared_state.get_quorum_public_key_sync(
///     height,
///     quorum_type,
///     quorum_hash,
/// )?;
/// ```
#[derive(Clone)]
pub struct DashSpvClientInterface {
    pub command_sender: mpsc::UnboundedSender<DashSpvClientCommand>,
    shared_masternode_state: SharedMasternodeState,
}

impl DashSpvClientInterface {
    /// Create a new client interface with command channel and shared state.
    pub fn new(
        command_sender: mpsc::UnboundedSender<DashSpvClientCommand>,
        shared_masternode_state: SharedMasternodeState,
    ) -> Self {
        Self {
            command_sender,
            shared_masternode_state,
        }
    }

    /// Get a quorum entry by height using async command channels.
    ///
    /// This method routes through the client's event loop. For synchronous access,
    /// use `shared_masternode_state().get_quorum_at_height_sync()` instead.
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

    /// Get the shared masternode state for synchronous access.
    ///
    /// This returns a clonable handle that can be used to query quorum data
    /// synchronously, without going through async command channels.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let shared_state = interface.shared_masternode_state();
    ///
    /// // Query synchronously - no async needed!
    /// let public_key = shared_state.get_quorum_public_key_sync(
    ///     height,
    ///     quorum_type,
    ///     quorum_hash,
    /// )?;
    /// ```
    pub fn shared_masternode_state(&self) -> SharedMasternodeState {
        self.shared_masternode_state.clone()
    }
}
