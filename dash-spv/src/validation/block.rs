use crate::error::{ValidationError, ValidationResult};
use crate::types::HashedBlock;
use crate::validation::Validator;

/// Validates a block's transactions against its header.
///
/// The block hash covers only the header, so a block with a different
/// transaction list still has the requested hash.
#[derive(Default)]
pub struct BlockValidator {}

impl BlockValidator {
    pub fn new() -> Self {
        Self {}
    }
}

impl Validator<&HashedBlock> for BlockValidator {
    fn validate(&self, block: &HashedBlock) -> ValidationResult<()> {
        // Also rejects a repeated txid, see `Block::check_merkle_root`.
        if !block.block().check_merkle_root() {
            return Err(ValidationError::InvalidMerkleRoot(format!(
                "transactions of block {} do not match the header merkle root",
                block.hash()
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use dashcore::{Address, Block, Network, Transaction};
    use test_case::test_case;

    use super::*;

    #[test_case(|_| {}, true; "matching transactions")]
    #[test_case(|b| b.txdata[1].output[0].value = 20, false; "changed transaction")]
    #[test_case(|b| b.txdata.push(b.txdata[2].clone()), false; "repeated txid")]
    fn test_block_validation(mutate: fn(&mut Block), valid: bool) {
        let address = Address::dummy(Network::Testnet, 0);
        let mut txdata = vec![Transaction::dummy_coinbase(&address, 50)];
        txdata.extend((0..2).map(|i| Transaction::dummy(&address, i..i + 1, &[10])));
        let mut block = Block::dummy(100, txdata);
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        mutate(&mut block);

        let result = BlockValidator::new().validate(&HashedBlock::from(block));
        if valid {
            assert!(result.is_ok(), "{result:?}");
        } else {
            assert!(matches!(result, Err(ValidationError::InvalidMerkleRoot(_))), "{result:?}");
        }
    }
}
