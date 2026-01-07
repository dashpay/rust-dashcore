use crate::{
    Address,
    address::{NetworkChecked, NetworkUnchecked},
};

impl crate::Address {
    pub fn dummy_for_testnet() -> Address<NetworkChecked> {
        "yP8A3cbdxRtLRduy5mXDsBnJtMzHWs6ZXr"
            .parse::<Address<NetworkUnchecked>>()
            .expect("valid address")
            .assume_checked()
    }
}
