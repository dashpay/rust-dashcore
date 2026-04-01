use std::fmt::Display;

/// Unique identifier for each sync manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ManagerIdentifier {
    BlockHeader,
    FilterHeader,
    Filter,
    Block,
    Masternode,
    ChainLock,
    InstantSend,
    Mempool,
}

impl Display for ManagerIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManagerIdentifier::BlockHeader => write!(f, "BlockHeader"),
            ManagerIdentifier::FilterHeader => write!(f, "FilterHeader"),
            ManagerIdentifier::Filter => write!(f, "Filter"),
            ManagerIdentifier::Block => write!(f, "Block"),
            ManagerIdentifier::Masternode => write!(f, "Masternode"),
            ManagerIdentifier::ChainLock => write!(f, "ChainLock"),
            ManagerIdentifier::InstantSend => write!(f, "InstantSend"),
            ManagerIdentifier::Mempool => write!(f, "Mempool"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manager_identifier_display() {
        assert_eq!(ManagerIdentifier::BlockHeader.to_string(), "BlockHeader");
        assert_eq!(ManagerIdentifier::FilterHeader.to_string(), "FilterHeader");
        assert_eq!(ManagerIdentifier::Filter.to_string(), "Filter");
        assert_eq!(ManagerIdentifier::Block.to_string(), "Block");
        assert_eq!(ManagerIdentifier::Masternode.to_string(), "Masternode");
        assert_eq!(ManagerIdentifier::ChainLock.to_string(), "ChainLock");
        assert_eq!(ManagerIdentifier::InstantSend.to_string(), "InstantSend");
        assert_eq!(ManagerIdentifier::Mempool.to_string(), "Mempool");
    }
}
