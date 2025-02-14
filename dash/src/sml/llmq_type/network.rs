use crate::Network;
use crate::sml::llmq_type::LLMQType;

impl Network {
    pub fn is_llmq_type(&self) -> LLMQType {
        match self {
            Network::Dash => LLMQType::Llmqtype50_60,
            Network::Testnet => LLMQType::Llmqtype50_60,
            Network::Devnet => LLMQType::LlmqtypeDevnet,
            Network::Regtest => LLMQType::LlmqtypeTestInstantSend,
        }
    }

    pub fn isd_llmq_type(&self) -> LLMQType {
        match self {
            Network::Dash => LLMQType::Llmqtype60_75,
            Network::Testnet => LLMQType::Llmqtype60_75,
            Network::Devnet => LLMQType::LlmqtypeDevnetDIP0024,
            Network::Regtest => LLMQType::LlmqtypeTestDIP0024,
        }
    }

    pub fn chain_locks_type(&self) -> LLMQType {
        match self {
            Network::Dash => LLMQType::Llmqtype400_60,
            Network::Testnet => LLMQType::Llmqtype50_60,
            Network::Devnet => LLMQType::LlmqtypeDevnet,
            Network::Regtest => LLMQType::LlmqtypeTest,
        }
    }

    pub fn platform_type(&self) -> LLMQType {
        match self {
            Network::Dash => LLMQType::Llmqtype100_67,
            Network::Testnet => LLMQType::Llmqtype25_67,
            Network::Devnet => LLMQType::LlmqtypeDevnet,
            Network::Regtest => LLMQType::LlmqtypeTest,
        }
    }
}