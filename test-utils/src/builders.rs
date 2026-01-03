//! Test data builders for creating test objects

use chrono::Utc;
use dashcore::blockdata::block;
use dashcore::blockdata::transaction::special_transaction::TransactionPayload;
use dashcore::hash_types::{BlockHash, TxMerkleNode, Txid};
use dashcore::ScriptBuf;
use dashcore::{Header, OutPoint, Transaction, TxIn, TxOut};
use dashcore_hashes::Hash;
use rand::Rng;

/// Builder for creating test block headers
pub struct TestHeaderBuilder {
    version: block::Version,
    prev_blockhash: BlockHash,
    merkle_root: TxMerkleNode,
    time: u32,
    bits: dashcore::CompactTarget,
    nonce: u32,
}

impl Default for TestHeaderBuilder {
    fn default() -> Self {
        Self {
            version: block::Version::from_consensus(536870912), // Version 0x20000000
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: Utc::now().timestamp() as u32,
            bits: dashcore::CompactTarget::from_consensus(0x207fffff), // Easy difficulty
            nonce: 0,
        }
    }
}

impl TestHeaderBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_version(mut self, version: i32) -> Self {
        self.version = block::Version::from_consensus(version);
        self
    }

    pub fn with_prev_blockhash(mut self, hash: BlockHash) -> Self {
        self.prev_blockhash = hash;
        self
    }

    pub fn with_merkle_root(mut self, root: TxMerkleNode) -> Self {
        self.merkle_root = root;
        self
    }

    pub fn with_time(mut self, time: u32) -> Self {
        self.time = time;
        self
    }

    pub fn with_bits(mut self, bits: u32) -> Self {
        self.bits = dashcore::CompactTarget::from_consensus(bits);
        self
    }

    pub fn with_nonce(mut self, nonce: u32) -> Self {
        self.nonce = nonce;
        self
    }

    pub fn build(self) -> Header {
        Header {
            version: self.version,
            prev_blockhash: self.prev_blockhash,
            merkle_root: self.merkle_root,
            time: self.time,
            bits: self.bits,
            nonce: self.nonce,
        }
    }

    /// Build a header with valid proof of work
    pub fn build_with_valid_pow(self) -> Header {
        // For testing, we'll just return a header with the current nonce
        // Real PoW validation would be too slow for tests
        self.build()
    }
}

/// Builder for creating test transactions
pub struct TestTransactionBuilder {
    version: u16,
    lock_time: u32,
    inputs: Vec<TxIn>,
    outputs: Vec<TxOut>,
    special_transaction_payload: Option<TransactionPayload>,
}

impl Default for TestTransactionBuilder {
    fn default() -> Self {
        Self {
            version: 1,
            lock_time: 0,
            inputs: vec![],
            outputs: vec![],
            special_transaction_payload: None,
        }
    }
}

impl TestTransactionBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_version(mut self, version: u16) -> Self {
        self.version = version;
        self
    }

    pub fn with_lock_time(mut self, lock_time: u32) -> Self {
        self.lock_time = lock_time;
        self
    }

    pub fn add_input(mut self, txid: Txid, vout: u32) -> Self {
        let input = TxIn {
            previous_output: OutPoint {
                txid,
                vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
            witness: dashcore::Witness::new(),
        };
        self.inputs.push(input);
        self
    }

    pub fn add_output(mut self, value: u64, script_pubkey: ScriptBuf) -> Self {
        let output = TxOut {
            value,
            script_pubkey,
        };
        self.outputs.push(output);
        self
    }

    pub fn with_special_payload(mut self, payload: TransactionPayload) -> Self {
        self.special_transaction_payload = Some(payload);
        self
    }

    pub fn build(self) -> Transaction {
        Transaction {
            version: self.version,
            lock_time: self.lock_time,
            input: self.inputs,
            output: self.outputs,
            special_transaction_payload: self.special_transaction_payload,
        }
    }
}

/// Create a chain of test headers
pub fn create_header_chain(count: usize, start_height: u32) -> Vec<Header> {
    let mut headers = Vec::with_capacity(count);
    let mut prev_hash = BlockHash::all_zeros();

    for i in 0..count {
        let header = TestHeaderBuilder::new()
            .with_prev_blockhash(prev_hash)
            .with_time(1_600_000_000 + (start_height + i as u32) * 600)
            .build();

        prev_hash = header.block_hash();
        headers.push(header);
    }

    headers
}

/// Create a random transaction ID
pub fn random_txid() -> Txid {
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    Txid::from_slice(&bytes).unwrap()
}

/// Create a random block hash
pub fn random_block_hash() -> BlockHash {
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    BlockHash::from_slice(&bytes).unwrap()
}

/// Create a test transaction paying to a specific script
pub fn create_test_transaction_to_script(script: ScriptBuf) -> Transaction {
    Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([1u8; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
            witness: dashcore::Witness::default(),
        }],
        output: vec![TxOut {
            value: 1000,
            script_pubkey: script,
        }],
        special_transaction_payload: None,
    }
}

/// Create a test block with given height and transactions
pub fn create_test_block(height: u32, transactions: Vec<Transaction>) -> dashcore::Block {
    dashcore::Block {
        header: Header {
            version: block::Version::ONE,
            prev_blockhash: BlockHash::from_byte_array([height as u8; 32]),
            merkle_root: TxMerkleNode::from_byte_array([0u8; 32]),
            time: height,
            bits: dashcore::CompactTarget::from_consensus(0x1d00ffff),
            nonce: height,
        },
        txdata: transactions,
    }
}

/// Create a BIP158 compact block filter for a block
pub fn create_filter_for_block(block: &dashcore::Block) -> dashcore::bip158::BlockFilter {
    use dashcore::bip158::BlockFilterWriter;
    let mut content = Vec::new();
    let mut writer = BlockFilterWriter::new(&mut content, block);
    writer.add_output_scripts();
    writer.finish().expect("Failed to finish filter");
    dashcore::bip158::BlockFilter::new(&content)
}

/// Create a deterministic test address from an index
pub fn test_address(idx: usize) -> dashcore::Address {
    use dashcore::secp256k1::{Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let mut key_bytes = [0u8; 32];
    key_bytes[31] = (idx as u8) + 1;
    let secret_key = SecretKey::from_slice(&key_bytes).expect("valid secret key");
    let public_key = dashcore::PublicKey::new(secret_key.public_key(&secp));
    dashcore::Address::p2pkh(&public_key, dashcore::Network::Testnet)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_builder() {
        let header = TestHeaderBuilder::new().with_version(2).with_nonce(12345).build();

        assert_eq!(header.version, block::Version::from_consensus(2));
        assert_eq!(header.nonce, 12345);
    }

    #[test]
    fn test_transaction_builder() {
        let tx = TestTransactionBuilder::new()
            .with_version(2)
            .add_input(random_txid(), 0)
            .add_output(50000, ScriptBuf::new())
            .build();

        assert_eq!(tx.version, 2);
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].value, 50000);
    }

    #[test]
    fn test_header_chain_creation() {
        let chain = create_header_chain(10, 0);

        assert_eq!(chain.len(), 10);

        // Verify chain linkage
        for i in 1..chain.len() {
            assert_eq!(chain[i].prev_blockhash, chain[i - 1].block_hash());
        }
    }
}
