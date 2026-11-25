use dashcore::blockdata::constants::MAX_SCRIPT_SIZE;
use dashcore::crypto::ecdsa::{EcdsaPublicKey, EcdsaSignature};
use dashcore::ecdsa::Signature;
use dashcore::hashes::hash160;
use dashcore::script::{Instruction, PushBytes};
use dashcore::sighash::{EcdsaSighashType, SighashCache};
use dashcore::{Transaction, TxOut};
use std::collections::BTreeMap;
use std::slice;

/// A pending spend whose authorization cannot be decided by the wallet signer contract.
#[derive(Debug, PartialEq, Eq)]
pub enum SpendAuthorizationError {
    /// The transaction has no input at this index.
    InputIndexOutOfRange(usize),
    /// The funding script requires a different authorization verifier.
    UnsupportedScript,
    /// The input script carries instructions besides the owner's signature and public key.
    UnsupportedScriptSig,
    /// The signature does not commit to the complete transaction.
    UnsupportedSighash(u8),
    /// The input script has other opcodes and lacks a plain push of the owner's key or a
    /// signature that verifies, so it may build them at run time, for example with `OP_CAT`.
    RuntimeAuthorization,
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
            Self::UnsupportedScriptSig => {
                write!(f, "pending spend uses an unsupported input script")
            }
            Self::UnsupportedSighash(mode) => {
                write!(f, "pending spend uses unsupported signature hash type {:#x}", mode)
            }
            Self::RuntimeAuthorization => {
                write!(f, "pending spend may build its authorization at run time")
            }
        }
    }
}

impl std::error::Error for SpendAuthorizationError {}

/// Whether input `input_index` carries the owner's P2PKH `SIGHASH_ALL` signature for `prevout`,
/// the funding output its outpoint names. An unsupported form, a missing input, or a script that
/// may build the key or signature at run time, for example with `OP_CAT`, returns an error.
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
    if input.script_sig.len() > MAX_SCRIPT_SIZE {
        return Ok(false);
    }
    let Ok(instructions) = input.script_sig.instructions().collect::<Result<Vec<_>, _>>() else {
        return Ok(false);
    };
    let pushes = instructions
        .iter()
        .filter_map(Instruction::push_bytes)
        .map(PushBytes::as_bytes)
        .collect::<Vec<_>>();
    let push_only = pushes.len() == instructions.len();
    let is_owner_key =
        |bytes: &&[u8]| hash160::Hash::hash(bytes).as_byte_array().as_slice() == public_key_hash;
    // A push-only input script leaves the owner's signature and key as its last two pushes.
    // Other opcodes can reorder the stack, so then any push can hold the signature.
    let (signatures, public_key) = if push_only {
        let [.., signature, public_key] = pushes.as_slice() else {
            return Ok(false);
        };
        (slice::from_ref(signature), Some(*public_key).filter(is_owner_key))
    } else {
        (pushes.as_slice(), pushes.iter().copied().find(is_owner_key))
    };
    // Without the owner's key among its pushes, a script with other opcodes may still build it.
    let Some(public_key) = public_key else {
        return if push_only {
            Ok(false)
        } else {
            Err(SpendAuthorizationError::RuntimeAuthorization)
        };
    };
    let Ok(public_key) = EcdsaPublicKey::from_bytes(public_key) else {
        return Ok(false);
    };
    // Signatures with the same hash type share a digest, which bounds the hashing per script.
    let mut digests = BTreeMap::new();
    let Some(mode) = signatures.iter().find_map(|signature| {
        let (&mode, _) = signature.split_last()?;
        let signature = EcdsaSignature::from(Signature::from_slice(signature).ok()?.signature);
        let digest = digests.entry(mode).or_insert_with(|| {
            SighashCache::new(transaction)
                .legacy_signature_hash(input_index, &prevout.script_pubkey, u32::from(mode))
                .ok()
                .map(|hash| hash.to_byte_array())
        });
        public_key.verify(&(*digest)?, signature).ok()?;
        Some(mode)
    }) else {
        return if push_only {
            Ok(false)
        } else {
            Err(SpendAuthorizationError::RuntimeAuthorization)
        };
    };
    // Other modes can authorize only part of a transaction; SINGLE can even
    // produce a constant digest. They cannot authorize this durable reservation.
    if u32::from(mode) != EcdsaSighashType::All.to_u32() {
        return Err(SpendAuthorizationError::UnsupportedSighash(mode));
    }
    // The signature hash does not commit to the input script, so anyone can add
    // instructions to an owner's signature without invalidating it.
    if !push_only || pushes.len() != 2 {
        return Err(SpendAuthorizationError::UnsupportedScriptSig);
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managed_account::managed_account_trait::ManagedAccountTrait;
    use crate::test_utils::TestWalletContext;
    use crate::wallet::managed_wallet_info::transaction_builder::TransactionSigner;
    use dashcore::crypto::ecdsa::EcdsaSecretKey;
    use dashcore::opcodes::all::{OP_CAT, OP_NOP, OP_SWAP};
    use dashcore::script::{Builder, PushBytesBuf};
    use dashcore::{Address, Network, PrivateKey, ScriptBuf, TxIn};
    use test_case::test_case;

    fn key(byte: u8) -> PrivateKey {
        PrivateKey::new(EcdsaSecretKey::from_bytes(&[byte; 32]).unwrap(), Network::Regtest)
    }

    fn sign_input(tx: &mut Transaction, index: usize, prevout: &TxOut, key: &PrivateKey, mode: u8) {
        let hash = SighashCache::new(&*tx)
            .legacy_signature_hash(index, &prevout.script_pubkey, u32::from(mode))
            .unwrap();
        let mut signature = key.inner.sign(&hash.to_byte_array()).with_der(|der| der.to_vec());
        signature.push(mode);
        tx.input[index].script_sig = Builder::new()
            .push_slice(PushBytesBuf::try_from(signature).unwrap())
            .push_key(&key.public_key())
            .into_script();
    }

    /// A spend of a P2PKH output, signed `SIGHASH_ALL` by its owner.
    fn owner_signed_spend() -> (Transaction, TxOut) {
        let owner = key(7);
        let address = Address::p2pkh(&owner.public_key(), Network::Regtest);
        let mut tx = Transaction::dummy(&address, 1..2, &[90_000]);
        let prevout = TxOut {
            value: 100_000,
            script_pubkey: address.script_pubkey(),
        };
        sign_input(&mut tx, 0, &prevout, &owner, 1);
        (tx, prevout)
    }

    #[test_case(|_, _| {}, Ok(true); "owner signature")]
    #[test_case(|tx, prevout| {
        let mut owner = key(7);
        owner.compressed = false;
        prevout.script_pubkey = ScriptBuf::new_p2pkh(&owner.public_key().pubkey_hash());
        sign_input(tx, 0, prevout, &owner, 1);
    }, Ok(true); "uncompressed owner key")]
    #[test_case(|tx, prevout| {
        let owner = key(7);
        let mut funding_key = owner.public_key();
        funding_key.compressed = false;
        prevout.script_pubkey = ScriptBuf::new_p2pkh(&funding_key.pubkey_hash());
        sign_input(tx, 0, prevout, &owner, 1);
    }, Ok(false); "compressed key for uncompressed funding key hash")]
    #[test_case(|tx, _| tx.input[0].script_sig = ScriptBuf::new(), Ok(false); "unsigned")]
    #[test_case(|tx, prevout| sign_input(tx, 0, prevout, &key(9), 1), Ok(false); "other key")]
    #[test_case(|tx, prevout| {
        tx.input.push(tx.input[0].clone());
        sign_input(tx, 0, prevout, &key(7), 1);
    }, Ok(false); "signed duplicate input")]
    #[test_case(|_, prevout| prevout.script_pubkey = ScriptBuf::new(),
        Err(SpendAuthorizationError::UnsupportedScript); "non P2PKH prevout")]
    #[test_case(|tx, _| {
        let mut bytes = tx.input[0].script_sig.to_bytes();
        bytes.resize(MAX_SCRIPT_SIZE + 1, OP_NOP.to_u8());
        tx.input[0].script_sig = ScriptBuf::from_bytes(bytes);
    }, Ok(false); "oversized input script")]
    #[test_case(|tx, _| {
        let mut bytes = tx.input[0].script_sig.to_bytes();
        bytes.push(1);
        tx.input[0].script_sig = ScriptBuf::from_bytes(bytes);
    }, Ok(false); "truncated push")]
    #[test_case(|tx, _| {
        tx.input[0].script_sig =
            Builder::new().push_slice([1]).push_key(&key(7).public_key()).into_script();
    }, Ok(false); "malformed owner signature")]
    #[test_case(|tx, _| tx.input[0].script_sig.push_slice([]), Ok(false); "missing owner at top")]
    #[test_case(|tx, _| {
        let script = &mut tx.input[0].script_sig;
        *script = ScriptBuf::from_bytes([&[0][..], script.as_bytes()].concat());
    }, Err(SpendAuthorizationError::UnsupportedScriptSig); "extra push before signature")]
    #[test_case(|tx, _| tx.input[0].script_sig.push_opcode(OP_NOP),
        Err(SpendAuthorizationError::UnsupportedScriptSig); "trailing opcode")]
    #[test_case(|tx, _| {
        let script = &mut tx.input[0].script_sig;
        let last_der_byte = usize::from(script.as_bytes()[0]) - 1;
        script.as_mut_bytes()[last_der_byte] ^= 1;
        script.push_opcode(OP_NOP);
    }, Err(SpendAuthorizationError::RuntimeAuthorization); "padded script with invalid owner signature")]
    #[test_case(|tx, _| {
        let pushes: Vec<_> = tx.input[0].script_sig.instructions().map(Result::unwrap).collect();
        let (signature, owner) = (pushes[0].push_bytes().unwrap(), pushes[1].push_bytes().unwrap());
        let (head, tail) = signature.as_bytes().split_at(10);
        tx.input[0].script_sig = Builder::new()
            .push_slice(<&PushBytes>::try_from(head).unwrap())
            .push_slice(<&PushBytes>::try_from(tail).unwrap())
            .push_opcode(OP_CAT)
            .push_slice(owner)
            .into_script();
    }, Err(SpendAuthorizationError::RuntimeAuthorization); "signature built with OP_CAT")]
    #[test_case(|tx, _| {
        let pushes: Vec<_> = tx.input[0].script_sig.instructions().map(Result::unwrap).collect();
        let (signature, owner) = (pushes[0].push_bytes().unwrap(), pushes[1].push_bytes().unwrap());
        let (head, tail) = owner.as_bytes().split_at(1);
        tx.input[0].script_sig = Builder::new()
            .push_slice(signature)
            .push_slice(<&PushBytes>::try_from(head).unwrap())
            .push_slice(<&PushBytes>::try_from(tail).unwrap())
            .push_opcode(OP_CAT)
            .into_script();
    }, Err(SpendAuthorizationError::RuntimeAuthorization); "owner key built with OP_CAT")]
    #[test_case(|tx, _| {
        let script = &mut tx.input[0].script_sig;
        let last_der_byte = usize::from(script.as_bytes()[0]) - 1;
        script.as_mut_bytes()[last_der_byte] ^= 1;
    }, Ok(false); "push-only script with invalid owner signature")]
    #[test_case(|tx, _| {
        let script = &mut tx.input[0].script_sig;
        let bytes = script.as_mut_bytes();
        let signature_push_len = 1 + usize::from(bytes[0]);
        bytes.rotate_left(signature_push_len);
        script.push_opcode(OP_SWAP);
    }, Err(SpendAuthorizationError::UnsupportedScriptSig); "reordered owner pushes")]
    #[test_case(|tx, prevout| {
        tx.output.clear();
        sign_input(tx, 0, prevout, &key(7), 3);
        tx.lock_time += 1;
    }, Err(SpendAuthorizationError::UnsupportedSighash(3)); "SINGLE without matching output")]
    #[test_case(|tx, prevout| {
        tx.output.clear();
        sign_input(tx, 0, prevout, &key(7), 0x83);
        tx.lock_time += 1;
    }, Err(SpendAuthorizationError::UnsupportedSighash(0x83)); "SINGLE ANYONECANPAY without matching output")]
    fn input_authorization(
        mutate: fn(&mut Transaction, &mut TxOut),
        expected: Result<bool, SpendAuthorizationError>,
    ) {
        let (mut tx, mut prevout) = owner_signed_spend();
        mutate(&mut tx, &mut prevout);
        assert_eq!(verify_input_authorization(&tx, 0, &prevout), expected);
    }

    #[test_case(0)]
    #[test_case(2)]
    #[test_case(3)]
    #[test_case(4)]
    #[test_case(0x81)]
    #[test_case(0x82)]
    #[test_case(0x83)]
    #[test_case(0xff)]
    fn should_keep_every_non_all_sighash_mode_unsupported(mode: u8) {
        let (signed, prevout) = owner_signed_spend();
        let mut resigned = signed.clone();
        sign_input(&mut resigned, 0, &prevout, &key(7), mode);
        assert_eq!(
            verify_input_authorization(&resigned, 0, &prevout),
            Err(SpendAuthorizationError::UnsupportedSighash(mode))
        );

        // Changing only the flag invalidates the owner's signature instead.
        let mut flagged = signed;
        let bytes = flagged.input[0].script_sig.as_mut_bytes();
        bytes[usize::from(bytes[0])] = mode;
        assert_eq!(verify_input_authorization(&flagged, 0, &prevout), Ok(false));
    }

    #[test]
    fn should_return_missing_input_index() {
        assert_eq!(
            verify_input_authorization(&Transaction::dummy_empty(), 1, &TxOut::default()),
            Err(SpendAuthorizationError::InputIndexOutOfRange(1))
        );
    }

    #[test]
    fn should_authorize_each_input_only_against_its_own_funding_output() {
        let keys = [key(7), key(9)];
        let addresses =
            keys.each_ref().map(|key| Address::p2pkh(&key.public_key(), Network::Regtest));
        let mut tx = Transaction::dummy(&addresses[0], 1..3, &[190_000]);
        let prevouts = addresses.map(|address| TxOut {
            value: 100_000,
            script_pubkey: address.script_pubkey(),
        });
        for (index, owner) in keys.iter().enumerate() {
            sign_input(&mut tx, index, &prevouts[index], owner, 1);
        }

        for index in 0..2 {
            assert_eq!(verify_input_authorization(&tx, index, &prevouts[index]), Ok(true));
            assert_eq!(verify_input_authorization(&tx, index, &prevouts[1 - index]), Ok(false));
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
}
