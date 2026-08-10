//! Tests for the caller-supplied funding sources on the asset-lock FFI entry
//! point.
//!
//! Which accounts an asset lock may spend from is the client library's policy,
//! so the boundary has to carry the choice rather than apply one. These cover
//! the guards that keep it that way: a caller must name at least one source, a
//! well-formed list reaches the builder untouched, and a source that can never
//! work on this entry point is rejected rather than quietly replaced.

use dash_network::ffi::FFINetwork;
use key_wallet_ffi::error::{FFIError, FFIErrorCode};
use key_wallet_ffi::transaction::{
    wallet_build_and_sign_asset_lock_transaction, FFIAccountTypePreference,
    FFIAccountTypePreferenceKind, FFIAssetLockFundingType,
};
use key_wallet_ffi::wallet_manager::{
    wallet_manager_add_wallet_from_mnemonic_with_options, wallet_manager_create,
    wallet_manager_free, wallet_manager_free_wallet_ids, wallet_manager_get_wallet,
    wallet_manager_get_wallet_ids,
};
use std::ffi::{CStr, CString};
use std::ptr;

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// The error's message as a Rust string, or empty when none was set.
fn error_message(error: &FFIError) -> String {
    if error.message.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(error.message) }.to_string_lossy().into_owned()
    }
}

fn source(kind: FFIAccountTypePreferenceKind) -> FFIAccountTypePreference {
    FFIAccountTypePreference {
        kind,
        user_identity_id: [0u8; 32],
        friend_identity_id: [0u8; 32],
    }
}

/// Drives the entry point against a freshly created (and therefore unfunded)
/// wallet, returning the error it produced.
///
/// The wallet has no UTXOs, so a call that gets past the argument guards fails
/// in coin selection instead — which is exactly what distinguishes "rejected at
/// the boundary" from "accepted and attempted".
unsafe fn call_with_sources(sources: &[FFIAccountTypePreference]) -> FFIError {
    let mut error = FFIError::default();

    let manager = wallet_manager_create(FFINetwork::Testnet, &mut error);
    assert!(!manager.is_null());

    let mnemonic = CString::new(TEST_MNEMONIC).unwrap();
    assert!(wallet_manager_add_wallet_from_mnemonic_with_options(
        manager,
        mnemonic.as_ptr(),
        ptr::null(),
        &mut error,
    ));

    let mut wallet_ids: *mut u8 = ptr::null_mut();
    let mut wallet_count: usize = 0;
    assert!(wallet_manager_get_wallet_ids(manager, &mut wallet_ids, &mut wallet_count, &mut error));
    assert_eq!(wallet_count, 1);

    let wallet = wallet_manager_get_wallet(manager, wallet_ids, &mut error);
    assert!(!wallet.is_null());

    // One credit output; the script content does not matter, since no call here
    // is expected to reach a successful build.
    let script: [u8; 25] =
        [0x76, 0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0xac];
    let script_ptr = script.as_ptr();
    let script_len = script.len();
    let amount: u64 = 100_000;
    let funding_type = FFIAssetLockFundingType::IdentityRegistration;
    let identity_index: u32 = 0;

    let mut fee_out: u64 = 0;
    let mut tx_bytes: *mut u8 = ptr::null_mut();
    let mut tx_len: usize = 0;
    let mut private_key = [0u8; 32];

    let mut call_error = FFIError::default();
    let ok = wallet_build_and_sign_asset_lock_transaction(
        manager,
        wallet,
        sources.as_ptr(),
        sources.len(),
        0,
        &funding_type,
        &identity_index,
        &script_ptr,
        &script_len,
        &amount,
        1,
        1000,
        &mut fee_out,
        &mut tx_bytes,
        &mut tx_len,
        &mut private_key,
        &mut call_error,
    );
    assert!(!ok, "an unfunded wallet cannot produce an asset lock");

    wallet_manager_free_wallet_ids(wallet_ids, wallet_count);
    wallet_manager_free(manager);

    call_error
}

/// An empty list must be rejected at the boundary rather than forwarded, where
/// it would mean `AccountTypePreference::DEFAULT` and silently reinstate a
/// funding policy this layer is not entitled to pick.
#[test]
fn an_empty_source_list_is_rejected() {
    unsafe {
        let error = call_with_sources(&[]);
        assert_eq!(error.code, FFIErrorCode::InvalidInput);
        let message = error_message(&error);
        assert!(
            message.contains("funding source"),
            "the error must name the missing argument, got: {message}"
        );
    }
}

/// A caller that names sources gets past the guards and into the build, so the
/// failure comes from the empty wallet rather than from argument validation.
#[test]
fn a_named_source_reaches_the_builder() {
    unsafe {
        let error = call_with_sources(&[
            source(FFIAccountTypePreferenceKind::BIP44),
            source(FFIAccountTypePreferenceKind::BIP32),
        ]);
        assert_ne!(
            error.code,
            FFIErrorCode::InvalidInput,
            "a pooled list is well-formed; the build must fail on funds, not on arguments"
        );
    }
}

/// CoinJoin can never fund through this entry point: it always builds a
/// non-drain lock, and mixed coins may only back a drain. A caller selecting it
/// must get told, not silently handed transparent funds instead.
#[test]
fn coinjoin_is_rejected_on_the_non_drain_entry_point() {
    unsafe {
        let error = call_with_sources(&[source(FFIAccountTypePreferenceKind::CoinJoin)]);
        let message = error_message(&error);
        assert!(
            message.contains("drain"),
            "the error must explain that CoinJoin is drain-only here, got: {message}"
        );
    }
}
