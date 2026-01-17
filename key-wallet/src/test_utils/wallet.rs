use dashcore::Network;

use crate::wallet::ManagedWalletInfo;

impl ManagedWalletInfo {
    pub fn dummy(id: u8) -> Self {
        ManagedWalletInfo::new(Network::Regtest, [id; 32])
    }
}
