//! UTXO management

use std::os::raw::c_char;

/// UTXO structure for FFI
#[repr(C)]
pub struct FFIUTXO {
    pub txid: [u8; 32],
    pub vout: u32,
    pub amount: u64,
    pub address: *mut c_char,
    pub script_pubkey: *mut u8,
    pub script_len: usize,
    pub height: u32,
    pub confirmations: u32,
}
