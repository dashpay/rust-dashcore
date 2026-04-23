//! C-ABI mirror of [`Network`].
//!
//! `FFINetwork` is a `#[repr(C)]` enum that `From`-converts to and from
//! [`Network`], giving consumers a stable ABI for Dash's network identity
//! across language boundaries.
//!
//! Gated behind the `ffi` feature because it pulls in `std::ffi` C-string
//! handling and exposes a `no_mangle` extern function that callers not
//! building a C-compatible library should not take on by accident.

use std::ffi;

use crate::Network;

/// FFI-compatible variant of [`Network`]. Converts to/from [`Network`] via
/// [`From`]/[`Into`].
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FFINetwork {
    Mainnet = 0,
    Testnet = 1,
    Devnet = 2,
    Regtest = 3,
}

impl From<Network> for FFINetwork {
    fn from(network: Network) -> Self {
        // Exhaustive inside the defining crate. If a new `Network` variant is
        // added this will fail to compile and `FFINetwork` must be extended
        // in lockstep (keeping C ABI stable).
        match network {
            Network::Mainnet => FFINetwork::Mainnet,
            Network::Testnet => FFINetwork::Testnet,
            Network::Devnet => FFINetwork::Devnet,
            Network::Regtest => FFINetwork::Regtest,
        }
    }
}

impl From<FFINetwork> for Network {
    fn from(network: FFINetwork) -> Self {
        match network {
            FFINetwork::Mainnet => Network::Mainnet,
            FFINetwork::Testnet => Network::Testnet,
            FFINetwork::Devnet => Network::Devnet,
            FFINetwork::Regtest => Network::Regtest,
        }
    }
}

/// Return a pointer to the canonical lowercase name of `network`.
///
/// The returned pointer is to a static null-terminated string owned by
/// `dash-network`; callers must not free it.
#[unsafe(no_mangle)]
pub extern "C" fn dashcore_network_get_name(network: FFINetwork) -> *const ffi::c_char {
    match network {
        FFINetwork::Mainnet => c"mainnet".as_ptr() as *const ffi::c_char,
        FFINetwork::Testnet => c"testnet".as_ptr() as *const ffi::c_char,
        FFINetwork::Regtest => c"regtest".as_ptr() as *const ffi::c_char,
        FFINetwork::Devnet => c"devnet".as_ptr() as *const ffi::c_char,
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CStr;

    use super::*;

    #[test]
    fn ffi_network_get_name_returns_canonical_lowercase() {
        unsafe {
            for (variant, expected) in [
                (FFINetwork::Mainnet, "mainnet"),
                (FFINetwork::Testnet, "testnet"),
                (FFINetwork::Regtest, "regtest"),
                (FFINetwork::Devnet, "devnet"),
            ] {
                let name = dashcore_network_get_name(variant);
                assert!(!name.is_null(), "{:?} returned null pointer", variant);
                assert_eq!(CStr::from_ptr(name).to_str().unwrap(), expected);
            }
        }
    }

    #[test]
    fn ffi_network_round_trips_through_network() {
        for variant in
            [FFINetwork::Mainnet, FFINetwork::Testnet, FFINetwork::Devnet, FFINetwork::Regtest]
        {
            let back: FFINetwork = Network::from(variant).into();
            assert_eq!(back, variant);
        }
    }

    #[test]
    fn ffi_network_discriminants_are_stable_abi() {
        // The numeric layout is public C ABI; tests pin it in place.
        assert_eq!(FFINetwork::Mainnet as i32, 0);
        assert_eq!(FFINetwork::Testnet as i32, 1);
        assert_eq!(FFINetwork::Devnet as i32, 2);
        assert_eq!(FFINetwork::Regtest as i32, 3);
    }
}
