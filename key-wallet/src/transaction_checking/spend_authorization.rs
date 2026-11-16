use dashcore::crypto::ecdsa::{EcdsaPublicKey, EcdsaSignature};
use dashcore::ecdsa::Signature;
use dashcore::hashes::hash160;
use dashcore::script::Instruction;
use dashcore::sighash::{EcdsaSighashType, SighashCache};
use dashcore::{Transaction, TxOut};

/// A pending spend whose authorization cannot be decided by the wallet signer contract.
#[derive(Debug, PartialEq, Eq)]
pub enum SpendAuthorizationError {
    /// The transaction has no input at this index.
    InputIndexOutOfRange(usize),
    /// The funding script requires a different authorization verifier.
    UnsupportedScript,
    /// The signature does not commit to the complete transaction.
    UnsupportedSighash(u8),
}

impl core::fmt::Display for SpendAuthorizationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InputIndexOutOfRange(index) => {
                write!(f, "pending spend has no input at index {}", index)
            }
            Self::UnsupportedScript => {
                write!(f, "pending spend uses an unsupported funding script")
            }
            Self::UnsupportedSighash(mode) => {
                write!(f, "pending spend uses unsupported signature hash type {:#x}", mode)
            }
        }
    }
}

impl std::error::Error for SpendAuthorizationError {}

/// Whether input `input_index` carries the owner's P2PKH `SIGHASH_ALL` signature for `prevout`.
/// The caller takes `prevout` from the funding transaction of that input's outpoint.
/// An unsupported form or a missing input returns an error, so a pending hold is not released.
pub fn verify_input_authorization(
    transaction: &Transaction,
    input_index: usize,
    prevout: &TxOut,
) -> Result<bool, SpendAuthorizationError> {
    let Some(input) = transaction.input.get(input_index) else {
        return Err(SpendAuthorizationError::InputIndexOutOfRange(input_index));
    };
    if transaction
        .input
        .iter()
        .filter(|candidate| candidate.previous_output == input.previous_output)
        .count()
        != 1
    {
        return Ok(false);
    }
    let Some(public_key_hash) = prevout.script_pubkey.p2pkh_public_key_hash_bytes() else {
        return Err(SpendAuthorizationError::UnsupportedScript);
    };
    let mut instructions = input.script_sig.instructions();
    let (Some(Ok(Instruction::PushBytes(signature))), Some(Ok(Instruction::PushBytes(public_key)))) =
        (instructions.next(), instructions.next())
    else {
        return Ok(false);
    };
    if instructions.next().is_some() {
        return Ok(false);
    }
    let public_key_bytes = public_key.as_bytes();
    if hash160::Hash::hash(public_key_bytes).as_byte_array().as_slice() != public_key_hash {
        return Ok(false);
    }
    let Ok(public_key) = EcdsaPublicKey::from_bytes(public_key_bytes) else {
        return Ok(false);
    };
    let Some((&mode, _)) = signature.as_bytes().split_last() else {
        return Ok(false);
    };
    let Ok(signature) = Signature::from_slice(signature.as_bytes()) else {
        return Ok(false);
    };
    let signature = EcdsaSignature::from(signature.signature);
    let Ok(hash) = SighashCache::new(transaction).legacy_signature_hash(
        input_index,
        &prevout.script_pubkey,
        u32::from(mode),
    ) else {
        return Ok(false);
    };
    if public_key.verify(&hash.to_byte_array(), signature).is_err() {
        return Ok(false);
    }
    // Other modes can authorize only part of a transaction; SINGLE can even
    // produce a constant digest. They cannot authorize this durable reservation.
    if u32::from(mode) != EcdsaSighashType::All.to_u32() {
        return Err(SpendAuthorizationError::UnsupportedSighash(mode));
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managed_account::managed_account_trait::ManagedAccountTrait;
    use crate::test_utils::TestWalletContext;
    use crate::wallet::managed_wallet_info::transaction_builder::TransactionSigner;
    use dashcore::blockdata::transaction::special_transaction::{
        asset_lock::AssetLockPayload, TransactionPayload,
    };
    use dashcore::crypto::ecdsa::EcdsaSecretKey;
    use dashcore::script::{Builder, PushBytesBuf};
    use dashcore::{OutPoint, ScriptBuf, TxIn, Txid};
    use std::slice;

    fn p2pkh_prevout(public_key: &[u8]) -> TxOut {
        TxOut {
            value: 100_000,
            script_pubkey: ScriptBuf::new_p2pkh(&hash160::Hash::hash(public_key).into()),
        }
    }

    /// An unsigned spend of one input per funding output, paying back to the first owner.
    fn spend_of(prevouts: &[TxOut]) -> Transaction {
        Transaction {
            version: 1,
            lock_time: 0,
            input: (0..prevouts.len() as u32)
                .map(|vout| TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_byte_array([3; 32]),
                        vout,
                    },
                    ..Default::default()
                })
                .collect(),
            output: vec![TxOut {
                value: prevouts.iter().map(|prevout| prevout.value).sum::<u64>() - 10_000,
                script_pubkey: prevouts[0].script_pubkey.clone(),
            }],
            special_transaction_payload: None,
        }
    }

    fn signed(uncompressed: bool) -> (Transaction, TxOut) {
        let key = EcdsaSecretKey::from_bytes(&[7; 32]).unwrap();
        let public_key = if uncompressed {
            key.public_key().to_uncompressed().to_vec()
        } else {
            key.public_key().to_compressed().to_vec()
        };
        let prevout = p2pkh_prevout(&public_key);
        let mut tx = spend_of(slice::from_ref(&prevout));
        sign_input(&mut tx, 0, &prevout, &key, &public_key, 1);
        (tx, prevout)
    }

    fn sign_input(
        tx: &mut Transaction,
        input_index: usize,
        prevout: &TxOut,
        key: &EcdsaSecretKey,
        public_key: &[u8],
        mode: u8,
    ) {
        let hash = SighashCache::new(&*tx)
            .legacy_signature_hash(input_index, &prevout.script_pubkey, u32::from(mode))
            .unwrap();
        let mut signature = key.sign(&hash.to_byte_array()).with_der(|der| der.to_vec());
        signature.push(mode);
        tx.input[input_index].script_sig = Builder::new()
            .push_slice(PushBytesBuf::try_from(signature).unwrap())
            .push_slice(PushBytesBuf::try_from(public_key.to_vec()).unwrap())
            .into_script();
    }

    /// Two inputs funded by different owners, each signed by its own.
    fn signed_by_two_owners() -> (Transaction, Vec<TxOut>) {
        let keys = [[7; 32], [9; 32]].map(|bytes| EcdsaSecretKey::from_bytes(&bytes).unwrap());
        let public_keys =
            keys.iter().map(|key| key.public_key().to_compressed()).collect::<Vec<_>>();
        let prevouts =
            public_keys.iter().map(|public_key| p2pkh_prevout(public_key)).collect::<Vec<_>>();
        let mut tx = spend_of(&prevouts);
        for index in 0..2 {
            sign_input(&mut tx, index, &prevouts[index], &keys[index], &public_keys[index], 1);
        }
        (tx, prevouts)
    }

    #[test]
    fn should_authorize_each_input_only_against_its_own_funding_output() {
        let (tx, prevouts) = signed_by_two_owners();
        for index in 0..2 {
            assert_eq!(verify_input_authorization(&tx, index, &prevouts[index]), Ok(true));
            assert_eq!(verify_input_authorization(&tx, index, &prevouts[1 - index]), Ok(false));
        }

        // SIGHASH_ALL commits to every input, so changing one input revokes the other's.
        let mut resequenced = tx.clone();
        resequenced.input[1].sequence = 7;
        assert_eq!(verify_input_authorization(&resequenced, 0, &prevouts[0]), Ok(false));

        // A signature does not follow its input to another position.
        let mut reordered = tx;
        reordered.input.swap(0, 1);
        for index in 0..2 {
            assert_eq!(
                verify_input_authorization(&reordered, index, &prevouts[1 - index]),
                Ok(false)
            );
        }
    }

    #[test]
    fn should_accept_compressed_and_uncompressed_owner_signatures() {
        for uncompressed in [false, true] {
            let (tx, prevout) = signed(uncompressed);
            assert_eq!(verify_input_authorization(&tx, 0, &prevout), Ok(true));
        }
    }

    #[tokio::test]
    async fn should_accept_what_the_wallet_signer_produces() {
        let (ctx, _) = TestWalletContext::new_random().with_mempool_funding(100_000).await;
        let utxo = ctx.first_utxo().clone();
        let path = ctx.bip44_account().address_derivation_path(&utxo.address).unwrap();
        let mut unsigned = Transaction::dummy_empty();
        unsigned.input.push(TxIn {
            previous_output: utxo.outpoint,
            ..Default::default()
        });
        unsigned.output.push(TxOut {
            value: 90_000,
            script_pubkey: utxo.txout.script_pubkey.clone(),
        });
        let signed = ctx
            .wallet
            .sign_tx(unsigned, vec![utxo.clone()], move |_| Some(path.clone()))
            .await
            .unwrap();
        assert_eq!(verify_input_authorization(&signed, 0, &utxo.txout), Ok(true));
    }

    #[test]
    fn should_reject_unsigned_tampered_and_wrong_funding_claims() {
        let (tx, prevout) = signed(false);
        let mut unsigned = tx.clone();
        unsigned.input[0].script_sig = ScriptBuf::new();
        assert_eq!(verify_input_authorization(&unsigned, 0, &prevout), Ok(false));
        let mut changed = tx.clone();
        changed.output[0].value -= 1;
        assert_eq!(verify_input_authorization(&changed, 0, &prevout), Ok(false));
        changed = tx.clone();
        changed.input[0].previous_output.vout += 1;
        assert_eq!(verify_input_authorization(&changed, 0, &prevout), Ok(false));
        let (_, different_encoding) = signed(true);
        assert_eq!(verify_input_authorization(&tx, 0, &different_encoding), Ok(false));
        assert_eq!(
            verify_input_authorization(&tx, 1, &prevout),
            Err(SpendAuthorizationError::InputIndexOutOfRange(1))
        );
        // The owner signs a transaction that lists the outpoint twice.
        let key = EcdsaSecretKey::from_bytes(&[7; 32]).unwrap();
        changed = tx.clone();
        changed.input.push(tx.input[0].clone());
        sign_input(&mut changed, 0, &prevout, &key, &key.public_key().to_compressed(), 1);
        assert_eq!(verify_input_authorization(&changed, 0, &prevout), Ok(false));
    }

    #[test]
    fn should_reject_extra_script_instructions_and_malformed_signature() {
        let (mut tx, prevout) = signed(false);
        let mut bytes = tx.input[0].script_sig.as_bytes().to_vec();
        bytes.push(0);
        tx.input[0].script_sig = ScriptBuf::from_bytes(bytes);
        assert_eq!(verify_input_authorization(&tx, 0, &prevout), Ok(false));
        tx.input[0].script_sig = ScriptBuf::from_bytes(vec![1, 1, 1, 2]);
        assert_eq!(verify_input_authorization(&tx, 0, &prevout), Ok(false));
    }

    #[test]
    fn should_bind_asset_lock_payload_to_authorization() {
        let (mut tx, prevout) = signed(false);
        let key = EcdsaSecretKey::from_bytes(&[7; 32]).unwrap();
        tx.version = 3;
        tx.special_transaction_payload =
            Some(TransactionPayload::AssetLockPayloadType(AssetLockPayload::new(vec![
                prevout.clone()
            ])));
        sign_input(&mut tx, 0, &prevout, &key, &key.public_key().to_compressed(), 1);
        assert_eq!(verify_input_authorization(&tx, 0, &prevout), Ok(true));
        if let Some(TransactionPayload::AssetLockPayloadType(payload)) =
            &mut tx.special_transaction_payload
        {
            payload.credit_outputs[0].value -= 1;
        }
        assert_eq!(verify_input_authorization(&tx, 0, &prevout), Ok(false));
    }

    #[test]
    fn should_not_turn_an_unauthenticated_hash_flag_into_an_unsupported_error() {
        let (mut tx, prevout) = signed(false);
        let original = tx.input[0].script_sig.as_bytes().to_vec();
        for mode in [0, 0x82, 0xff] {
            let mut bytes = original.clone();
            let signature_len = usize::from(bytes[0]);
            bytes[signature_len] = mode;
            tx.input[0].script_sig = ScriptBuf::from_bytes(bytes);
            assert_eq!(verify_input_authorization(&tx, 0, &prevout), Ok(false));
        }
    }

    #[test]
    fn should_preserve_unsupported_authorization_as_an_error() {
        let (mut tx, prevout) = signed(false);
        let key = EcdsaSecretKey::from_bytes(&[7; 32]).unwrap();
        for mode in [0, 2, 3, 4, 0x81, 0x82, 0x83, 0xff] {
            sign_input(&mut tx, 0, &prevout, &key, &key.public_key().to_compressed(), mode);
            assert_eq!(
                verify_input_authorization(&tx, 0, &prevout),
                Err(SpendAuthorizationError::UnsupportedSighash(mode))
            );
        }
        // Without an output for input 0, SINGLE signs the constant digest 1. That signature
        // still verifies on a changed transaction, and must stay an error there.
        let mut no_outputs = tx.clone();
        no_outputs.output.clear();
        for mode in [3, 0x83] {
            sign_input(&mut no_outputs, 0, &prevout, &key, &key.public_key().to_compressed(), mode);
            no_outputs.lock_time += 1;
            assert_eq!(
                verify_input_authorization(&no_outputs, 0, &prevout),
                Err(SpendAuthorizationError::UnsupportedSighash(mode))
            );
        }
        let unknown = TxOut {
            value: prevout.value,
            script_pubkey: ScriptBuf::new(),
        };
        assert_eq!(
            verify_input_authorization(&tx, 0, &unknown),
            Err(SpendAuthorizationError::UnsupportedScript)
        );
    }
}
