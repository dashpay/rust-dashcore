#[cfg(test)]
mod tests {
    use dash_spv_ffi::*;
    use serial_test::serial;
    use std::ffi::CString;

    #[test]
    #[serial]
    fn test_watch_item_address() {
        unsafe {
            let addr = CString::new("XjSgy6PaVCB3V4KhCiCDkaVbx9ewxe9R1E").unwrap();
            let item = dash_spv_ffi_watch_item_address(addr.as_ptr());
            assert!(!item.is_null());

            let item_ref = &*item;
            assert_eq!(item_ref.item_type as i32, FFIWatchItemType::Address as i32);

            dash_spv_ffi_watch_item_destroy(item);
        }
    }

    #[test]
    #[serial]
    fn test_watch_item_script() {
        unsafe {
            // Valid P2PKH script: OP_DUP OP_HASH160 <push 20 bytes> <20-byte pubkey hash> OP_EQUALVERIFY OP_CHECKSIG
            let script_hex =
                CString::new("76a914b7c94b7c365c71dd476329c9e5205a0a39cf8e2c88ac").unwrap();
            let item = dash_spv_ffi_watch_item_script(script_hex.as_ptr());
            assert!(!item.is_null());

            let item_ref = &*item;
            assert_eq!(item_ref.item_type as i32, FFIWatchItemType::Script as i32);

            dash_spv_ffi_watch_item_destroy(item);
        }
    }

    #[test]
    #[serial]
    fn test_watch_item_outpoint() {
        unsafe {
            let txid =
                CString::new("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                    .unwrap();
            let item = dash_spv_ffi_watch_item_outpoint(txid.as_ptr(), 0);
            assert!(!item.is_null());

            let item_ref = &*item;
            assert_eq!(item_ref.item_type as i32, FFIWatchItemType::Outpoint as i32);

            dash_spv_ffi_watch_item_destroy(item);
        }
    }

    #[test]
    #[serial]
    fn test_watch_item_null_handling() {
        unsafe {
            let item = dash_spv_ffi_watch_item_address(std::ptr::null());
            assert!(item.is_null());

            let item = dash_spv_ffi_watch_item_script(std::ptr::null());
            assert!(item.is_null());

            let item = dash_spv_ffi_watch_item_outpoint(std::ptr::null(), 0);
            assert!(item.is_null());
        }
    }

    #[test]
    #[serial]
    fn test_balance_conversion() {
        let balance = dash_spv::Balance {
            confirmed: dashcore::Amount::from_sat(100000),
            pending: dashcore::Amount::from_sat(50000),
            instantlocked: dashcore::Amount::from_sat(25000),
        };

        let ffi_balance = FFIBalance::from(balance);
        assert_eq!(ffi_balance.confirmed, 100000);
        assert_eq!(ffi_balance.pending, 50000);
        assert_eq!(ffi_balance.instantlocked, 25000);
        assert_eq!(ffi_balance.total, 175000);
    }

    #[test]
    #[serial]
    fn test_utxo_conversion() {
        use dashcore::{Address, OutPoint, TxOut, Txid};
        use std::str::FromStr;

        let outpoint = OutPoint::new(
            Txid::from_str("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .unwrap(),
            0,
        );
        let address = Address::<dashcore::address::NetworkUnchecked>::from_str(
            "Xan9iCVe1q5jYRDZ4VSMCtBjq2VyQA3Dge",
        )
        .unwrap()
        .assume_checked();
        let txout = TxOut {
            value: 100000,
            script_pubkey: address.script_pubkey(),
        };

        let utxo = dash_spv::Utxo {
            outpoint,
            txout,
            address,
            height: 12345,
            is_coinbase: false,
            is_confirmed: true,
            is_instantlocked: false,
        };

        let ffi_utxo = FFIUtxo::from(utxo);
        assert_eq!(ffi_utxo.vout, 0);
        assert_eq!(ffi_utxo.amount, 100000);
        assert_eq!(ffi_utxo.height, 12345);
        assert_eq!(ffi_utxo.is_coinbase, false);
        assert_eq!(ffi_utxo.is_confirmed, true);
        assert_eq!(ffi_utxo.is_instantlocked, false);

        unsafe {
            dash_spv_ffi_utxo_destroy(Box::into_raw(Box::new(ffi_utxo)));
        }
    }
}
