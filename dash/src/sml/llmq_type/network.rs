use crate::sml::llmq_type::LLMQType;
use dash_network::Network;

/// Extension trait for Network to add LLMQ-specific methods
pub trait NetworkLLMQExt {
    fn is_llmq_type(&self) -> LLMQType;
    fn isd_llmq_type(&self) -> LLMQType;
    fn chain_locks_type(&self) -> LLMQType;
    fn platform_type(&self) -> LLMQType;
}

impl NetworkLLMQExt for Network {
    fn is_llmq_type(&self) -> LLMQType {
        match self {
            Network::Dash => LLMQType::Llmqtype50_60,
            Network::Testnet => LLMQType::Llmqtype50_60,
            Network::Devnet => LLMQType::LlmqtypeDevnet,
            Network::Regtest => LLMQType::LlmqtypeTestInstantSend,
            _ => LLMQType::LlmqtypeTestInstantSend,
        }
    }

    fn isd_llmq_type(&self) -> LLMQType {
        match self {
            Network::Dash => LLMQType::Llmqtype60_75,
            Network::Testnet => LLMQType::Llmqtype60_75,
            Network::Devnet => LLMQType::LlmqtypeDevnetDIP0024,
            Network::Regtest => LLMQType::LlmqtypeTestDIP0024,
            _ => LLMQType::LlmqtypeTestDIP0024,
        }
    }

    fn chain_locks_type(&self) -> LLMQType {
        match self {
            Network::Dash => LLMQType::Llmqtype400_60,
            Network::Testnet => LLMQType::Llmqtype50_60,
            Network::Devnet => LLMQType::LlmqtypeDevnet,
            Network::Regtest => LLMQType::LlmqtypeTest,
            _ => LLMQType::LlmqtypeTest,
        }
    }

    fn platform_type(&self) -> LLMQType {
        match self {
            Network::Dash => LLMQType::Llmqtype100_67,
            Network::Testnet => LLMQType::Llmqtype25_67,
            Network::Devnet => LLMQType::LlmqtypeDevnet,
            Network::Regtest => LLMQType::LlmqtypeTest,
            _ => LLMQType::LlmqtypeTest,
        }
    }
}
