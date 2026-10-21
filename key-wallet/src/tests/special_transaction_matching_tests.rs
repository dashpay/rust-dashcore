//! End-to-end matching tests for the special-transaction → keys-account
//! paths exercised by this PR.
//!
//! For each special-transaction type that drives the keys-account
//! `check_*_for_match` methods on [`ManagedCoreKeysAccount`], construct a
//! transaction targeting the relevant account's address / key and assert
//! [`ManagedWalletInfo::check_core_transaction`] flags the right
//! [`AccountTypeToCheck`].
//!
//! Skipped on purpose:
//!
//! - `AssetUnlockPayloadType` and `CoinbasePayloadType` — match Standard
//!   funds-bearing accounts, not the keys-only variants this PR touches.
//! - `QuorumCommitmentPayloadType` — no key/address fields the wallet looks
//!   for, no match path.
//! - `ProviderUpdateRevocationPayloadType` — the payload has no key-hash or
//!   pubkey field for the wallet to match against.

use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::transaction_checking::transaction_router::AccountTypeToCheck;
use crate::transaction_checking::wallet_checker::WalletTransactionChecker;
use crate::transaction_checking::{BlockInfo, TransactionContext};
use crate::wallet::initialization::WalletAccountCreationOptions;
use crate::wallet::managed_wallet_info::managed_account_operations::ManagedAccountOperations;
use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use crate::wallet::managed_wallet_info::ManagedWalletInfo;
use crate::wallet::Wallet;
use crate::Network;

use dashcore::blockdata::script::ScriptBuf;
use dashcore::blockdata::transaction::outpoint::OutPoint;
use dashcore::blockdata::transaction::special_transaction::asset_lock::AssetLockPayload;
use dashcore::blockdata::transaction::special_transaction::provider_registration::{
    ProviderMasternodeType, ProviderRegistrationPayload,
};
use dashcore::blockdata::transaction::special_transaction::provider_update_registrar::ProviderUpdateRegistrarPayload;
use dashcore::blockdata::transaction::special_transaction::TransactionPayload;
use dashcore::blockdata::transaction::txin::TxIn;
use dashcore::blockdata::transaction::txout::TxOut;
use dashcore::blockdata::transaction::Transaction;
use dashcore::blockdata::witness::Witness;
use dashcore::hashes::Hash;
use dashcore::{BlockHash, Txid};

const TEST_NETWORK: Network = Network::Testnet;
const ASSET_LOCK_VALUE: u64 = 100_000_000; // 1 DASH
const TEST_HEIGHT: u32 = 100_000;

fn test_block_context() -> TransactionContext {
    TransactionContext::InBlock(BlockInfo::new(
        TEST_HEIGHT,
        BlockHash::from_slice(&[0u8; 32]).expect("32-byte block hash"),
        1_700_000_000,
    ))
}

fn make_wallet() -> (Wallet, ManagedWalletInfo) {
    let wallet = Wallet::new_random(TEST_NETWORK, WalletAccountCreationOptions::Default)
        .expect("create wallet with default account types");
    let info = ManagedWalletInfo::from_wallet_with_name(&wallet, "matching-tests".to_string(), 0);
    (wallet, info)
}

/// Build an AssetLock transaction whose `credit_outputs` pay `value` to
/// `script`. Inputs / regular outputs are placeholders the wallet won't
/// match against.
fn asset_lock_to(script: ScriptBuf, value: u64) -> Transaction {
    Transaction {
        version: 3,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([1u8; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
            witness: Witness::default(),
        }],
        output: Vec::new(),
        special_transaction_payload: Some(TransactionPayload::AssetLockPayloadType(
            AssetLockPayload {
                version: 1,
                credit_outputs: vec![TxOut {
                    value,
                    script_pubkey: script,
                }],
            },
        )),
    }
}

/// Assert the result is_relevant and contains the expected
/// `AccountTypeToCheck` among the affected accounts.
fn assert_matched_account_type(
    result: &crate::transaction_checking::wallet_checker::TransactionCheckResult,
    expected: AccountTypeToCheck,
) {
    assert!(result.is_relevant, "transaction should be relevant");
    let affected: Vec<_> = result
        .affected_accounts
        .iter()
        .map(|acc| acc.account_type_match.to_account_type_to_check())
        .collect();
    assert!(
        affected.contains(&expected),
        "expected {expected:?} in affected accounts, got {affected:?}",
    );
}

// ---------------------------------------------------------------------------
// AssetLock → keys-account variants
// ---------------------------------------------------------------------------

#[tokio::test]
async fn asset_lock_credit_output_to_identity_registration_address_matches() {
    let (mut wallet, mut info) = make_wallet();
    let xpub =
        wallet.accounts.identity_registration.as_ref().expect("default options").account_xpub;
    let address = info
        .identity_registration_managed_account_mut()
        .expect("identity registration managed")
        .next_address(Some(&xpub), true)
        .expect("derive address");

    let tx = asset_lock_to(address.script_pubkey(), ASSET_LOCK_VALUE);
    let result =
        info.check_core_transaction(&tx, test_block_context(), &mut wallet, true, true).await;

    assert_matched_account_type(&result, AccountTypeToCheck::IdentityRegistration);
    assert_eq!(
        result.total_received_for_credit_conversion, ASSET_LOCK_VALUE,
        "asset-lock credit-output value flows into credit conversion, not spendable balance",
    );
}

#[tokio::test]
async fn asset_lock_regular_output_to_identity_topup_address_matches() {
    // Note: unlike the other identity / asset-lock variants, the IdentityTopUp
    // dispatch in `account_checker::check_account_type` calls
    // `check_transaction_for_match` (regular tx outputs) rather than
    // `check_asset_lock_transaction_for_match` (credit outputs). That's a
    // pre-existing dispatch quirk independent of this PR. To exercise the
    // path the dispatch actually takes, we put the topup address on a
    // **regular output** of an AssetLock-classified transaction.
    let (mut wallet, mut info) = make_wallet();
    let registration_index = 0u32;
    // IdentityTopUp accounts are per-registration-index — not auto-created
    // by the `Default` options.
    wallet
        .add_account(
            crate::AccountType::IdentityTopUp {
                registration_index,
            },
            None,
        )
        .expect("add IdentityTopUp account");
    info.add_managed_account(
        &wallet,
        crate::AccountType::IdentityTopUp {
            registration_index,
        },
    )
    .expect("attach managed IdentityTopUp");
    let xpub = wallet
        .accounts
        .identity_topup
        .get(&registration_index)
        .expect("identity_topup[0]")
        .account_xpub;
    let address = info
        .topup_managed_account_at_registration_index_mut(registration_index)
        .expect("identity_topup[0] managed")
        .next_address(Some(&xpub), true)
        .expect("derive address");

    let mut tx = asset_lock_to(ScriptBuf::new(), ASSET_LOCK_VALUE);
    tx.output.push(TxOut {
        value: ASSET_LOCK_VALUE,
        script_pubkey: address.script_pubkey(),
    });
    let result =
        info.check_core_transaction(&tx, test_block_context(), &mut wallet, true, true).await;

    assert_matched_account_type(&result, AccountTypeToCheck::IdentityTopUp);
}

#[tokio::test]
async fn asset_lock_credit_output_to_identity_topup_not_bound_address_matches() {
    let (mut wallet, mut info) = make_wallet();
    let xpub =
        wallet.accounts.identity_topup_not_bound.as_ref().expect("default options").account_xpub;
    let address = info
        .identity_topup_not_bound_managed_account_mut()
        .expect("identity_topup_not_bound managed")
        .next_address(Some(&xpub), true)
        .expect("derive address");

    let tx = asset_lock_to(address.script_pubkey(), ASSET_LOCK_VALUE);
    let result =
        info.check_core_transaction(&tx, test_block_context(), &mut wallet, true, true).await;

    assert_matched_account_type(&result, AccountTypeToCheck::IdentityTopUpNotBound);
}

#[tokio::test]
async fn asset_lock_credit_output_to_identity_invitation_address_matches() {
    let (mut wallet, mut info) = make_wallet();
    let xpub = wallet.accounts.identity_invitation.as_ref().expect("default options").account_xpub;
    let address = info
        .identity_invitation_managed_account_mut()
        .expect("identity_invitation managed")
        .next_address(Some(&xpub), true)
        .expect("derive address");

    let tx = asset_lock_to(address.script_pubkey(), ASSET_LOCK_VALUE);
    let result =
        info.check_core_transaction(&tx, test_block_context(), &mut wallet, true, true).await;

    assert_matched_account_type(&result, AccountTypeToCheck::IdentityInvitation);
}

#[tokio::test]
async fn asset_lock_credit_output_to_asset_lock_address_topup_address_matches() {
    let (mut wallet, mut info) = make_wallet();
    let xpub =
        wallet.accounts.asset_lock_address_topup.as_ref().expect("default options").account_xpub;
    let address = info
        .accounts_mut()
        .asset_lock_address_topup
        .as_mut()
        .expect("asset_lock_address_topup managed")
        .next_address(Some(&xpub), true)
        .expect("derive address");

    let tx = asset_lock_to(address.script_pubkey(), ASSET_LOCK_VALUE);
    let result =
        info.check_core_transaction(&tx, test_block_context(), &mut wallet, true, true).await;

    assert_matched_account_type(&result, AccountTypeToCheck::AssetLockAddressTopUp);
}

#[tokio::test]
async fn asset_lock_credit_output_to_asset_lock_shielded_address_topup_address_matches() {
    let (mut wallet, mut info) = make_wallet();
    let xpub = wallet
        .accounts
        .asset_lock_shielded_address_topup
        .as_ref()
        .expect("default options")
        .account_xpub;
    let address = info
        .accounts_mut()
        .asset_lock_shielded_address_topup
        .as_mut()
        .expect("asset_lock_shielded_address_topup managed")
        .next_address(Some(&xpub), true)
        .expect("derive address");

    let tx = asset_lock_to(address.script_pubkey(), ASSET_LOCK_VALUE);
    let result =
        info.check_core_transaction(&tx, test_block_context(), &mut wallet, true, true).await;

    assert_matched_account_type(&result, AccountTypeToCheck::AssetLockShieldedAddressTopUp);
}

// ---------------------------------------------------------------------------
// ProviderRegistration → provider-key variants
// ---------------------------------------------------------------------------

/// Build a regular-masternode `ProRegTx` populated with the given key
/// hashes / public key. Fields not relevant to matching get placeholder
/// bytes.
#[allow(clippy::too_many_arguments)]
fn prov_reg_tx(
    masternode_type: ProviderMasternodeType,
    owner_key_hash: dashcore::PubkeyHash,
    voting_key_hash: dashcore::PubkeyHash,
    operator_public_key: dashcore::bls_sig_utils::BLSPublicKey,
    script_payout: ScriptBuf,
    platform_node_id: Option<dashcore::PubkeyHash>,
) -> Transaction {
    Transaction {
        version: 3,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([1u8; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
            witness: Witness::default(),
        }],
        output: vec![TxOut {
            value: 1_000_000,
            script_pubkey: ScriptBuf::new(),
        }],
        special_transaction_payload: Some(TransactionPayload::ProviderRegistrationPayloadType(
            ProviderRegistrationPayload {
                version: 1,
                masternode_type,
                masternode_mode: 0,
                collateral_outpoint: OutPoint {
                    txid: Txid::from_byte_array([1u8; 32]),
                    vout: 0,
                },
                service_address: "127.0.0.1:19999".parse().expect("service address"),
                owner_key_hash,
                operator_public_key,
                voting_key_hash,
                operator_reward: 0,
                script_payout,
                inputs_hash: dashcore::hash_types::InputsHash::from_slice(&[6u8; 32])
                    .expect("32-byte inputs hash"),
                signature: vec![7u8; 65],
                platform_node_id,
                platform_p2p_port: platform_node_id.map(|_| 26656),
                platform_http_port: platform_node_id.map(|_| 8080),
            },
        )),
    }
}

fn derive_pubkey_hash(addr: &dashcore::Address) -> dashcore::PubkeyHash {
    *addr.payload().as_pubkey_hash().expect("provider account uses P2PKH")
}

#[tokio::test]
async fn provider_registration_with_owner_key_hash_matches_provider_owner_keys() {
    let (mut wallet, mut info) = make_wallet();
    let (mut _other_wallet, mut other_info) = make_wallet();

    let owner_addr = info
        .provider_owner_keys_managed_account_mut()
        .expect("provider_owner_keys managed")
        .next_address(None, true)
        .expect("derive owner");
    let voting_addr = other_info
        .provider_voting_keys_managed_account_mut()
        .expect("other voting")
        .next_address(None, true)
        .expect("derive voting");
    let operator_pk = other_info
        .provider_operator_keys_managed_account_mut()
        .expect("other operator")
        .next_bls_operator_key(None, true)
        .expect("derive operator");

    let tx = prov_reg_tx(
        ProviderMasternodeType::Regular,
        derive_pubkey_hash(&owner_addr),
        derive_pubkey_hash(&voting_addr),
        operator_pk.0.to_compressed().into(),
        ScriptBuf::new(),
        None,
    );
    let result =
        info.check_core_transaction(&tx, test_block_context(), &mut wallet, true, true).await;

    assert_matched_account_type(&result, AccountTypeToCheck::ProviderOwnerKeys);
}

#[tokio::test]
async fn provider_registration_with_voting_key_hash_matches_provider_voting_keys() {
    let (mut wallet, mut info) = make_wallet();
    let (_other_wallet, mut other_info) = make_wallet();

    let owner_addr = other_info
        .provider_owner_keys_managed_account_mut()
        .expect("other owner")
        .next_address(None, true)
        .expect("derive owner");
    let voting_addr = info
        .provider_voting_keys_managed_account_mut()
        .expect("provider_voting_keys managed")
        .next_address(None, true)
        .expect("derive voting");
    let operator_pk = other_info
        .provider_operator_keys_managed_account_mut()
        .expect("other operator")
        .next_bls_operator_key(None, true)
        .expect("derive operator");

    let tx = prov_reg_tx(
        ProviderMasternodeType::Regular,
        derive_pubkey_hash(&owner_addr),
        derive_pubkey_hash(&voting_addr),
        operator_pk.0.to_compressed().into(),
        ScriptBuf::new(),
        None,
    );
    let result =
        info.check_core_transaction(&tx, test_block_context(), &mut wallet, true, true).await;

    assert_matched_account_type(&result, AccountTypeToCheck::ProviderVotingKeys);
}

#[cfg(feature = "bls")]
#[tokio::test]
async fn provider_registration_with_operator_public_key_matches_provider_operator_keys() {
    let (mut wallet, mut info) = make_wallet();
    let (_other_wallet, mut other_info) = make_wallet();

    let owner_addr = other_info
        .provider_owner_keys_managed_account_mut()
        .expect("other owner")
        .next_address(None, true)
        .expect("derive owner");
    let voting_addr = other_info
        .provider_voting_keys_managed_account_mut()
        .expect("other voting")
        .next_address(None, true)
        .expect("derive voting");
    let operator_pk = info
        .provider_operator_keys_managed_account_mut()
        .expect("provider_operator_keys managed")
        .next_bls_operator_key(None, true)
        .expect("derive operator");

    let tx = prov_reg_tx(
        ProviderMasternodeType::Regular,
        derive_pubkey_hash(&owner_addr),
        derive_pubkey_hash(&voting_addr),
        operator_pk.0.to_compressed().into(),
        ScriptBuf::new(),
        None,
    );
    let result =
        info.check_core_transaction(&tx, test_block_context(), &mut wallet, true, true).await;

    assert_matched_account_type(&result, AccountTypeToCheck::ProviderOperatorKeys);
}

#[cfg(feature = "eddsa")]
#[tokio::test]
async fn provider_registration_with_platform_node_id_matches_provider_platform_keys() {
    let (mut wallet, mut info) = make_wallet();
    let (_other_wallet, mut other_info) = make_wallet();

    let owner_addr = other_info
        .provider_owner_keys_managed_account_mut()
        .expect("other owner")
        .next_address(None, true)
        .expect("derive owner");
    let voting_addr = other_info
        .provider_voting_keys_managed_account_mut()
        .expect("other voting")
        .next_address(None, true)
        .expect("derive voting");
    let operator_pk = other_info
        .provider_operator_keys_managed_account_mut()
        .expect("other operator")
        .next_bls_operator_key(None, true)
        .expect("derive operator");

    let root = wallet.root_extended_priv_key().expect("root extended priv key");
    let eddsa = root.to_eddsa_extended_priv_key(TEST_NETWORK).expect("eddsa extended priv");
    let (_platform_pk, platform_info) = info
        .provider_platform_keys_managed_account_mut()
        .expect("provider_platform_keys managed")
        .next_eddsa_platform_key(eddsa, true)
        .expect("derive platform");
    let platform_node_id = derive_pubkey_hash(&platform_info.address);

    let tx = prov_reg_tx(
        ProviderMasternodeType::HighPerformance,
        derive_pubkey_hash(&owner_addr),
        derive_pubkey_hash(&voting_addr),
        operator_pk.0.to_compressed().into(),
        ScriptBuf::new(),
        Some(platform_node_id),
    );
    let result =
        info.check_core_transaction(&tx, test_block_context(), &mut wallet, true, true).await;

    assert_matched_account_type(&result, AccountTypeToCheck::ProviderPlatformKeys);
}

// ---------------------------------------------------------------------------
// ProviderUpdateRegistrar → voting / operator key changes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn provider_update_registrar_with_voting_key_change_matches_provider_voting_keys() {
    let (mut wallet, mut info) = make_wallet();

    let voting_addr = info
        .provider_voting_keys_managed_account_mut()
        .expect("provider_voting_keys managed")
        .next_address(None, true)
        .expect("derive voting");
    // Operator key sourced from a fresh wallet so it doesn't accidentally
    // match this wallet's operator account.
    let (_other_wallet, mut other_info) = make_wallet();
    let operator_pk = other_info
        .provider_operator_keys_managed_account_mut()
        .expect("other operator")
        .next_bls_operator_key(None, true)
        .expect("derive operator");

    let tx = Transaction {
        version: 3,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([1u8; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
            witness: Witness::default(),
        }],
        output: vec![TxOut {
            value: 1_000_000,
            script_pubkey: ScriptBuf::new(),
        }],
        special_transaction_payload: Some(TransactionPayload::ProviderUpdateRegistrarPayloadType(
            ProviderUpdateRegistrarPayload {
                version: 1,
                pro_tx_hash: Txid::from_byte_array([1u8; 32]),
                provider_mode: 0,
                operator_public_key: operator_pk.0.to_compressed().into(),
                voting_key_hash: derive_pubkey_hash(&voting_addr),
                script_payout: ScriptBuf::new(),
                inputs_hash: [3u8; 32].into(),
                payload_sig: vec![4u8; 65],
            },
        )),
    };
    let result =
        info.check_core_transaction(&tx, test_block_context(), &mut wallet, true, true).await;

    assert_matched_account_type(&result, AccountTypeToCheck::ProviderVotingKeys);
}

#[cfg(feature = "bls")]
#[tokio::test]
async fn provider_update_registrar_with_operator_key_change_matches_provider_operator_keys() {
    let (mut wallet, mut info) = make_wallet();

    // Voting addr from a fresh wallet so it doesn't double-match.
    let (_other_wallet, mut other_info) = make_wallet();
    let voting_addr = other_info
        .provider_voting_keys_managed_account_mut()
        .expect("other voting")
        .next_address(None, true)
        .expect("derive voting");
    let operator_pk = info
        .provider_operator_keys_managed_account_mut()
        .expect("provider_operator_keys managed")
        .next_bls_operator_key(None, true)
        .expect("derive operator");

    let tx = Transaction {
        version: 3,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([1u8; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: 0xffffffff,
            witness: Witness::default(),
        }],
        output: vec![TxOut {
            value: 1_000_000,
            script_pubkey: ScriptBuf::new(),
        }],
        special_transaction_payload: Some(TransactionPayload::ProviderUpdateRegistrarPayloadType(
            ProviderUpdateRegistrarPayload {
                version: 1,
                pro_tx_hash: Txid::from_byte_array([1u8; 32]),
                provider_mode: 0,
                operator_public_key: operator_pk.0.to_compressed().into(),
                voting_key_hash: derive_pubkey_hash(&voting_addr),
                script_payout: ScriptBuf::new(),
                inputs_hash: [3u8; 32].into(),
                payload_sig: vec![4u8; 65],
            },
        )),
    };
    let result =
        info.check_core_transaction(&tx, test_block_context(), &mut wallet, true, true).await;

    assert_matched_account_type(&result, AccountTypeToCheck::ProviderOperatorKeys);
}

// ---------------------------------------------------------------------------
// Recorded shape of a keys-account `TransactionRecord`
// ---------------------------------------------------------------------------

/// Locks in the post-PR contract: a keys-account record is a thin marker.
/// `direction = Internal`, `input_details` and `output_details` are empty
/// (the funding-side Standard / CoinJoin account's record carries those).
#[tokio::test]
async fn keys_account_record_is_thin_marker_internal_with_no_details() {
    use crate::managed_account::transaction_record::TransactionDirection;

    let (mut wallet, mut info) = make_wallet();
    let xpub =
        wallet.accounts.identity_registration.as_ref().expect("default options").account_xpub;
    let address = info
        .identity_registration_managed_account_mut()
        .expect("identity_registration managed")
        .next_address(Some(&xpub), true)
        .expect("derive address");

    let tx = asset_lock_to(address.script_pubkey(), ASSET_LOCK_VALUE);
    let txid = tx.txid();
    let _ = info.check_core_transaction(&tx, test_block_context(), &mut wallet, true, true).await;

    let stored = info
        .accounts()
        .identity_registration
        .as_ref()
        .expect("identity_registration present")
        .transactions()
        .get(&txid)
        .expect("record inserted")
        .clone();

    assert_eq!(
        stored.direction,
        TransactionDirection::Internal,
        "keys-account flows are internal: funded from a Standard/CoinJoin account in the same wallet",
    );
    assert!(
        stored.input_details.is_empty(),
        "keys-account record should not carry per-input details — those live on the funding account's record",
    );
    assert!(
        stored.output_details.is_empty(),
        "keys-account record should not carry per-output classification — those live on the funding account's record",
    );
}
