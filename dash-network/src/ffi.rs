use std::ffi;

use crate::Network;

/// FFI-compatible variant of [`Network`]. Converts to/from [`Network`] via [`From`]/[`Into`].
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FFINetwork {
    Mainnet = 0,
    Testnet = 1,
    Devnet = 2,
    Regtest = 3,
}

impl From<Network> for FFINetwork {
    fn from(network: Network) -> Self {
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
    fn test_network_names() {
        unsafe {
            let name = dashcore_network_get_name(FFINetwork::Mainnet);
            assert!(!name.is_null());
            let name_str = CStr::from_ptr(name).to_str().unwrap();
            assert_eq!(name_str, "mainnet");

            let name = dashcore_network_get_name(FFINetwork::Testnet);
            assert!(!name.is_null());
            let name_str = CStr::from_ptr(name).to_str().unwrap();
            assert_eq!(name_str, "testnet");

            let name = dashcore_network_get_name(FFINetwork::Regtest);
            assert!(!name.is_null());
            let name_str = CStr::from_ptr(name).to_str().unwrap();
            assert_eq!(name_str, "regtest");

            let name = dashcore_network_get_name(FFINetwork::Devnet);
            assert!(!name.is_null());
            let name_str = CStr::from_ptr(name).to_str().unwrap();
            assert_eq!(name_str, "devnet");
        }
    }
}
