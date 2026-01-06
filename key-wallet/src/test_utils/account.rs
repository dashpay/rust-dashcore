use crate::account::StandardAccountType;
use crate::managed_account::address_pool::{AddressPool, AddressPoolType, KeySource};
use crate::managed_account::managed_account_type::ManagedAccountType;
use crate::managed_account::ManagedAccount;
use crate::{DerivationPath, Network};

impl ManagedAccount {
    /// Create a test managed account with a standard BIP44 type and empty address pools
    pub fn new_test_bip44(network: Network) -> Self {
        let base_path = DerivationPath::master();

        let external_pool = AddressPool::new(
            base_path.clone(),
            AddressPoolType::External,
            20,
            network,
            &KeySource::NoKeySource,
        )
        .expect("Failed to create external address pool");

        let internal_pool = AddressPool::new(
            base_path,
            AddressPoolType::Internal,
            20,
            network,
            &KeySource::NoKeySource,
        )
        .expect("Failed to create internal address pool");

        let account_type = ManagedAccountType::Standard {
            index: 0,
            standard_account_type: StandardAccountType::BIP44Account,
            external_addresses: external_pool,
            internal_addresses: internal_pool,
        };

        ManagedAccount::new(account_type, network, false)
    }
}
