//! Complete wallet management for Dash
//!
//! This module provides comprehensive wallet functionality including
//! multiple accounts, seed management, and transaction coordination.

pub mod accounts;
pub mod backup;
pub mod balance;
#[cfg(feature = "bip38")]
pub mod bip38;
pub mod helper;
pub mod initialization;
pub mod managed_wallet_info;
pub mod metadata;
pub mod root_extended_keys;
pub mod stats;

pub use self::balance::WalletCoreBalance;
pub use self::managed_wallet_info::ManagedWalletInfo;
use self::root_extended_keys::{RootExtendedPrivKey, RootExtendedPubKey};
use crate::account::account_collection::AccountCollection;
use crate::mnemonic::Mnemonic;
use crate::seed::Seed;
use crate::Network;
#[cfg(feature = "bincode")]
use bincode_derive::{Decode, Encode};
use core::fmt;
use dashcore_hashes::{sha256, Hash};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Type of wallet based on how it was created
#[derive(Debug, Clone, Zeroize)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub enum WalletType {
    /// Standard mnemonic wallet without passphrase
    Mnemonic {
        mnemonic: Mnemonic,
        root_extended_private_key: RootExtendedPrivKey,
    },
    /// Wallet from seed bytes
    Seed {
        seed: Seed,
        root_extended_private_key: RootExtendedPrivKey,
    },
    /// Wallet from extended private key
    ExtendedPrivKey(RootExtendedPrivKey),
    /// External signable wallet (signing happens externally via a hardware device
    /// or remote signer).
    ///
    /// This variant carries no key material: the external device holds all signing
    /// keys, and the host only needs the per-account xpubs carried by
    /// [`AccountCollection`] plus derivation paths to request signatures.
    /// [`Wallet::wallet_id`] identifies the wallet — see [`Wallet::new_external_signable`].
    ExternalSignable,
    /// Watch-only wallet (no signing capability).
    ///
    /// This variant carries no key material: every Dash derivation path hits a
    /// hardened level before the account index, so a host-side root xpub cannot
    /// expand coverage to account xpubs that weren't already supplied. The
    /// per-account xpubs carried by [`AccountCollection`] are the only state
    /// needed for address generation and transaction tracking.
    /// [`Wallet::wallet_id`] identifies the wallet — see [`Wallet::new_watch_only`].
    WatchOnly,
}

/// Complete wallet implementation
///
/// This is an immutable wallet structure that only changes when accounts are added.
/// Mutable metadata like name, description, and sync status are stored separately
/// in ManagedWalletInfo.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct Wallet {
    /// Network this wallet is associated with
    pub network: Network,
    /// Unique wallet ID (SHA256 hash of root public key)
    pub wallet_id: [u8; 32],
    /// Wallet type (mnemonic, mnemonic with passphrase, or watch-only)
    pub wallet_type: WalletType,
    /// All accounts organized by network
    pub accounts: AccountCollection,
}

/// Wallet scan result
#[derive(Debug, Default)]
pub struct WalletScanResult {
    /// Accounts that had activity
    pub accounts_with_activity: Vec<u32>,
    /// Total addresses found with activity
    pub total_addresses_found: usize,
}

impl Wallet {
    /// Compute a wallet ID from a root public key.
    ///
    /// `network` controls scoping:
    ///
    /// * `Some(network)` → the **network-scoped id** (the default; this is what
    ///   wallet construction stamps into [`Wallet::wallet_id`]). It folds an
    ///   explicit network discriminant into the hash, so the same seed maps to
    ///   distinct ids per network. The preimage is:
    ///
    ///   ```text
    ///   root_public_key.serialize() || root_chain_code || DOMAIN_TAG || network_byte
    ///   ```
    ///
    ///   where `DOMAIN_TAG` is the private `NETWORK_SCOPED_WALLET_ID_DOMAIN`
    ///   constant and `network_byte` comes from the private
    ///   `network_scoped_wallet_id_discriminant` mapping (wire-stable, *not*
    ///   `Network as u8`). The tag guarantees a `Some(_)` digest can never collide
    ///   with the `None` digest.
    /// * `None` → a **network-independent id**. The preimage is exactly
    ///   `root_public_key.serialize() || root_chain_code` (no tag, no discriminant)
    ///   — useful when a caller deliberately wants one id shared across networks.
    ///
    /// Callers comparing a `Some(network)` id against a `None` id (or against a
    /// `Some(other_network)` id) for the same key must **not** expect equality —
    /// those are intentionally different digests.
    pub fn compute_wallet_id_from_root_extended_pub_key(
        root_pub_key: &RootExtendedPubKey,
        network: Option<Network>,
    ) -> [u8; 32] {
        let mut data = Vec::new();
        data.extend_from_slice(&root_pub_key.root_public_key.serialize());
        data.extend_from_slice(&root_pub_key.root_chain_code[..]);
        // A concrete network appends the domain tag + discriminant byte; with no
        // network the preimage stops here, giving a network-independent digest.
        if let Some(network) = network {
            data.extend_from_slice(Self::NETWORK_SCOPED_WALLET_ID_DOMAIN);
            data.push(Self::network_scoped_wallet_id_discriminant(network));
        }

        // Compute SHA256 hash
        let hash = sha256::Hash::hash(&data);
        hash.to_byte_array()
    }

    /// Compute this wallet's ID.
    ///
    /// The id is **network-scoped**: it folds `self.network` into the digest via
    /// [`Wallet::compute_wallet_id_from_root_extended_pub_key`]`(.., Some(self.network))`,
    /// so the same seed yields distinct ids on different networks. This is what
    /// construction stamps into `self.wallet_id`, so for full wallets the two
    /// agree.
    ///
    /// For wallet types that carry a root public key (directly or derivable from a
    /// stored root private key), this recomputes the id from that key. For the
    /// [`WalletType::WatchOnly`] and [`WalletType::ExternalSignable`] unit
    /// variants there is no root key on hand, so the id fed in at construction
    /// time (`self.wallet_id`) is returned as-is.
    pub fn compute_wallet_id(&self) -> [u8; 32] {
        match &self.wallet_type {
            WalletType::WatchOnly | WalletType::ExternalSignable => self.wallet_id,
            _ => Self::compute_wallet_id_from_root_extended_pub_key(
                &self
                    .root_extended_pub_key_cow()
                    .expect("signing wallet types always have a root public key"),
                Some(self.network),
            ),
        }
    }

    pub fn downgrade_to_external_signable(&mut self) {
        self.wallet_type = WalletType::ExternalSignable;
    }

    /// Domain-separation tag appended (with the network discriminant) when a
    /// concrete network is supplied, so a network-scoped id can never collide
    /// with the network-independent (`None`) digest. Not added for the `None`
    /// case.
    const NETWORK_SCOPED_WALLET_ID_DOMAIN: &'static [u8] = b"N";

    /// Stable, wire-stable discriminant for a network used when deriving a
    /// network-scoped wallet id.
    ///
    /// **These bytes are a wire-stable contract.** They are deliberately *not*
    /// derived from `Network as u8`: the `#[repr(u8)]` discriminant of the
    /// [`Network`] enum can drift if variants are reordered or inserted, which
    /// would silently change every persisted scoped id. The mapping here is
    /// fixed and must never change for an existing variant:
    ///
    /// | network    | byte   |
    /// |------------|--------|
    /// | `Mainnet`  | `0x00` |
    /// | `Testnet`  | `0x01` |
    /// | `Devnet`   | `0x02` |
    /// | `Regtest`  | `0x03` |
    ///
    /// There is intentionally no entry for "no network": when no network is
    /// supplied the digest is the network-independent id, which carries neither
    /// the domain tag nor a discriminant byte. Any future [`Network`] variant must
    /// be assigned a new, never-before-used byte here.
    const fn network_scoped_wallet_id_discriminant(network: Network) -> u8 {
        match network {
            Network::Mainnet => 0x00,
            Network::Testnet => 0x01,
            Network::Devnet => 0x02,
            Network::Regtest => 0x03,
        }
    }
}

impl fmt::Display for Wallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Format wallet ID as hex string (first 8 chars)
        let id_hex =
            self.wallet_id.iter().take(4).map(|b| format!("{:02x}", b)).collect::<String>();

        let total_accounts: usize = self.accounts.count();

        write!(
            f,
            "Wallet [{}...] ({}) - {} accounts",
            id_hex,
            if self.is_watch_only() {
                "watch-only"
            } else {
                "full"
            },
            total_accounts,
        )
    }
}

// Manual implementation of Zeroize for Wallet
impl Zeroize for Wallet {
    fn zeroize(&mut self) {
        self.wallet_type.zeroize();
    }
}

impl Drop for Wallet {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::account_collection::AccountCollection;
    use crate::account::{AccountType, StandardAccountType};
    use crate::mnemonic::Language;
    use crate::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;

    #[test]
    fn test_wallet_creation() {
        let wallet = Wallet::new_random(
            Network::Testnet,
            initialization::WalletAccountCreationOptions::Default,
        )
        .unwrap();
        // Default creates BIP44 account 0, CoinJoin account 0, and special accounts
        assert!(wallet.accounts.count() >= 2);
        assert!(wallet.has_mnemonic());
        assert!(!wallet.is_watch_only());
    }

    #[test]
    fn test_wallet_from_mnemonic() {
        let mnemonic = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            Language::English,
        ).unwrap();

        let wallet = Wallet::from_mnemonic(
            mnemonic,
            Network::Testnet,
            initialization::WalletAccountCreationOptions::Default,
        )
        .unwrap();

        // Default creates multiple accounts
        assert!(wallet.accounts.count() >= 2);
        let default_account = wallet.get_bip44_account(0).unwrap();
        match &default_account.account_type {
            AccountType::Standard {
                index,
                ..
            } => assert_eq!(*index, 0),
            _ => panic!("Expected standard account"),
        }
    }

    #[test]
    fn test_account_creation() {
        use std::collections::BTreeSet;

        // Create wallet with only BIP44 account 0
        let mut bip44_set = BTreeSet::new();
        bip44_set.insert(0);
        let mut wallet = Wallet::new_random(
            Network::Testnet,
            initialization::WalletAccountCreationOptions::BIP44AccountsOnly(bip44_set),
        )
        .unwrap();

        wallet
            .add_account(
                AccountType::Standard {
                    index: 1,
                    standard_account_type: StandardAccountType::BIP44Account,
                },
                None,
            )
            .unwrap();
        wallet
            .add_account(
                AccountType::CoinJoin {
                    index: 2,
                },
                None,
            )
            .unwrap();

        assert_eq!(wallet.accounts.count(), 3);
        // 1 initial + 2 created
    }

    #[test]
    fn test_address_generation() {
        // NOTE: Address generation now requires ManagedAccount integration
        // This test would need to be updated to work with the new architecture
        // where Account holds immutable state and ManagedAccount holds mutable state

        let wallet = Wallet::new_random(
            Network::Testnet,
            initialization::WalletAccountCreationOptions::Default,
        )
        .unwrap();

        // Verify we have a default account
        assert!(wallet.get_bip44_account(0).is_some());

        // Address generation and tracking would happen through ManagedAccount
        // which is not directly accessible from Wallet in this refactored version
    }

    // ✓ Test wallet creation from known mnemonic
    #[test]
    fn test_wallet_creation_from_known_mnemonic() {
        let mnemonic_phrase = "upper renew that grow pelican pave subway relief describe enforce suit hedgehog blossom dose swallow";
        let mnemonic = Mnemonic::from_phrase(mnemonic_phrase, Language::English).unwrap();

        let wallet = Wallet::from_mnemonic(
            mnemonic,
            Network::Mainnet,
            initialization::WalletAccountCreationOptions::Default,
        )
        .unwrap();

        assert!(wallet.accounts.count() >= 2); // Default creates multiple accounts
        assert!(wallet.has_mnemonic());
        assert!(!wallet.is_watch_only());
    }

    // ✓ Test wallet recovery from seed (from DashSync principles)
    #[test]
    fn test_wallet_recovery_from_seed() {
        let mnemonic_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(mnemonic_phrase, Language::English).unwrap();

        // Create first wallet
        let wallet1 = Wallet::from_mnemonic(
            mnemonic.clone(),
            Network::Testnet,
            initialization::WalletAccountCreationOptions::Default,
        )
        .unwrap();

        // Create second wallet from same mnemonic (simulating recovery)
        let wallet2 = Wallet::from_mnemonic(
            mnemonic,
            Network::Testnet,
            initialization::WalletAccountCreationOptions::Default,
        )
        .unwrap();

        // Both wallets should generate the same addresses
        let account1_1 = wallet1.accounts.standard_bip44_accounts.get(&0).unwrap();
        let account2_1 = wallet2.accounts.standard_bip44_accounts.get(&0).unwrap();

        // Should have same extended public keys
        assert_eq!(account1_1.extended_public_key(), account2_1.extended_public_key());
    }

    // ✓ Test multiple account creation
    #[test]
    fn test_multiple_account_creation() {
        let mut wallet = Wallet::new_random(
            Network::Testnet,
            initialization::WalletAccountCreationOptions::Default,
        )
        .unwrap();

        // Create different types of accounts
        wallet
            .add_account(
                AccountType::Standard {
                    index: 1,
                    standard_account_type: StandardAccountType::BIP44Account,
                },
                None,
            )
            .unwrap();
        wallet
            .add_account(
                AccountType::CoinJoin {
                    index: 2,
                },
                None,
            )
            .unwrap();

        // Default already creates IdentityRegistration, just add TopUp
        wallet
            .add_account(
                AccountType::IdentityTopUp {
                    registration_index: 0,
                },
                None,
            )
            .unwrap();

        assert_eq!(wallet.accounts.standard_bip44_accounts.len(), 2); // 2 standard accounts (0 and 1)
        assert_eq!(wallet.accounts.coinjoin_accounts.len(), 2); // 2 coinjoin accounts (0 from Default and 2)
        assert!(wallet.accounts.identity_registration.is_some());
        assert!(wallet.accounts.identity_topup.contains_key(&0));
        // 2 special accounts
    }

    // ✓ Test wallet with managed info
    #[test]
    fn test_wallet_with_managed_info() {
        let wallet = Wallet::new_random(
            Network::Testnet,
            initialization::WalletAccountCreationOptions::Default,
        )
        .unwrap();

        // Create managed info from the wallet with a non-zero birth height so the
        // seeded checkpoints are observable.
        let mut managed_info = ManagedWalletInfo::from_wallet(&wallet, 100);
        managed_info.set_name("Test Wallet".to_string());
        managed_info.set_description(Some("A test wallet".to_string()));

        // Test initial managed info
        assert_eq!(managed_info.wallet_id, wallet.wallet_id);
        assert_eq!(managed_info.name.as_ref().unwrap(), "Test Wallet");
        assert_eq!(managed_info.description.as_ref().unwrap(), "A test wallet");
        assert_eq!(managed_info.metadata.birth_height, 100);
        assert_eq!(managed_info.metadata.synced_height, 99);
        assert_eq!(managed_info.metadata.last_processed_height, 99);
        assert!(managed_info.metadata.last_synced.is_none());

        // Test updating metadata
        managed_info.update_last_synced(1234567890);
        assert_eq!(managed_info.metadata.last_synced, Some(1234567890));

        // The wallet itself remains unchanged
        assert!(wallet.accounts.count() >= 2);
        // Default creates multiple accounts
    }

    // ✓ Test watch-only wallet creation (high level)
    #[test]
    fn test_watch_only_wallet_basics() {
        // Create a regular wallet first to snapshot its id + accounts
        let wallet = Wallet::new_random(
            Network::Testnet,
            initialization::WalletAccountCreationOptions::Default,
        )
        .unwrap();

        // Snapshot the id and a single BIP44 account so the watch-only wallet
        // has something to track without needing a root xpub.
        let wallet_id = wallet.wallet_id;
        let account = wallet.get_bip44_account(0).unwrap();
        let account_xpub = account.extended_public_key();

        // Build a watch-only wallet via the unit-variant constructor.
        let mut watch_only =
            Wallet::new_watch_only(Network::Testnet, wallet_id, AccountCollection::new());

        assert!(watch_only.is_watch_only());
        assert!(!watch_only.has_mnemonic());
        assert_eq!(watch_only.wallet_id, wallet_id);

        // Watch-only wallets start with no accounts
        assert_eq!(watch_only.accounts.count(), 0);

        // But we can add accounts manually by providing their xpubs
        watch_only
            .add_account(
                AccountType::Standard {
                    index: 0,
                    standard_account_type: StandardAccountType::BIP44Account,
                },
                Some(account_xpub),
            )
            .unwrap();

        // Now the watch-only wallet has the account
        assert_eq!(watch_only.accounts.count(), 1);
        let watch_only_account = watch_only.get_bip44_account(0).unwrap();
        assert_eq!(watch_only_account.extended_public_key(), account_xpub);
    }

    // ✓ Test account retrieval and management
    #[test]
    fn test_account_management() {
        let mut wallet = Wallet::new_random(
            Network::Testnet,
            initialization::WalletAccountCreationOptions::BIP44AccountsOnly([0].into()),
        )
        .unwrap();

        // Create a second account to match original test
        wallet
            .add_account(
                AccountType::Standard {
                    index: 1,
                    standard_account_type: StandardAccountType::BIP44Account,
                },
                None,
            )
            .unwrap();

        // Test getting accounts
        assert!(wallet.get_bip44_account(0).is_some());
        assert!(wallet.get_bip44_account(1).is_some());
        assert!(wallet.get_bip44_account(2).is_none());

        // Test mutable access
        assert!(wallet.get_bip44_account_mut(0).is_some());
        assert!(wallet.get_bip44_account_mut(2).is_none());

        // Test account count
        assert_eq!(wallet.account_count(), 2);

        // Test listing accounts
        let account_indices = wallet.account_indices();
        assert_eq!(account_indices.len(), 2);
        assert!(account_indices.contains(&0));
        assert!(account_indices.contains(&1));
    }

    // ✓ Test error conditions
    #[test]
    fn test_wallet_error_conditions() {
        let mut wallet = Wallet::new_random(
            Network::Testnet,
            initialization::WalletAccountCreationOptions::Default,
        )
        .unwrap();

        // Test duplicate account creation should fail
        let result = wallet.add_account(
            AccountType::Standard {
                index: 0,
                standard_account_type: StandardAccountType::BIP44Account,
            },
            None,
        );
        assert!(result.is_err()); // Account 0 already exists

        // Default creates multiple accounts
        assert!(wallet.accounts.count() >= 2);
    }

    // ✓ Test wallet ID generation
    #[test]
    fn test_wallet_id_generation() {
        let wallet = Wallet::new_random(
            Network::Testnet,
            initialization::WalletAccountCreationOptions::Default,
        )
        .unwrap();

        // Wallet ID should be set
        assert_ne!(wallet.wallet_id, [0u8; 32]);

        // Wallet ID should be deterministic based on root public key
        let computed_id = wallet.compute_wallet_id();
        assert_eq!(wallet.wallet_id, computed_id);

        // Test that wallets from the same mnemonic have the same ID
        let mnemonic = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            Language::English,
        ).unwrap();

        let wallet1 = Wallet::from_mnemonic(
            mnemonic.clone(),
            Network::Testnet,
            initialization::WalletAccountCreationOptions::Default,
        )
        .unwrap();
        let wallet2 = Wallet::from_mnemonic(
            mnemonic,
            Network::Testnet,
            initialization::WalletAccountCreationOptions::Default,
        )
        .unwrap();

        assert_eq!(wallet1.wallet_id, wallet2.wallet_id);
    }

    // Fixed test mnemonic used by the network-scoped wallet id tests below.
    const FIXTURE_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn fixture_root_pub_key(network: Network) -> RootExtendedPubKey {
        let mnemonic = Mnemonic::from_phrase(FIXTURE_MNEMONIC, Language::English).unwrap();
        let wallet = Wallet::from_mnemonic(
            mnemonic,
            network,
            initialization::WalletAccountCreationOptions::None,
        )
        .unwrap();
        wallet.root_extended_pub_key_cow().unwrap().into_owned()
    }

    // (a) Same seed + different networks => different ids. The network-independent
    // (`None`) digest is also distinct from every concrete-network id, so all five
    // values are pairwise distinct.
    #[test]
    fn test_wallet_id_differs_by_network() {
        // The raw root key is network-independent, so derive it once and scope it
        // four different ways (plus the network-independent `None` case).
        let root = fixture_root_pub_key(Network::Mainnet);

        let mainnet =
            Wallet::compute_wallet_id_from_root_extended_pub_key(&root, Some(Network::Mainnet));
        let testnet =
            Wallet::compute_wallet_id_from_root_extended_pub_key(&root, Some(Network::Testnet));
        let devnet =
            Wallet::compute_wallet_id_from_root_extended_pub_key(&root, Some(Network::Devnet));
        let regtest =
            Wallet::compute_wallet_id_from_root_extended_pub_key(&root, Some(Network::Regtest));
        let none = Wallet::compute_wallet_id_from_root_extended_pub_key(&root, None);

        let ids = [mainnet, testnet, devnet, regtest, none];
        for i in 0..ids.len() {
            for j in (i + 1)..ids.len() {
                assert_ne!(
                    ids[i], ids[j],
                    "ids for distinct network discriminants must differ ({i} vs {j})"
                );
            }
        }
    }

    // (b) The wallet id is network-scoped by default: the same mnemonic on
    // different networks produces different `wallet_id`s, and each stamped id
    // equals the explicit `Some(network)` derivation.
    #[test]
    fn test_wallet_id_is_network_scoped_by_default() {
        let make = |network| {
            let mnemonic = Mnemonic::from_phrase(FIXTURE_MNEMONIC, Language::English).unwrap();
            Wallet::from_mnemonic(
                mnemonic,
                network,
                initialization::WalletAccountCreationOptions::None,
            )
            .unwrap()
        };

        let mainnet = make(Network::Mainnet);
        let testnet = make(Network::Testnet);

        // Same seed, different network => different stamped ids.
        assert_ne!(mainnet.wallet_id, testnet.wallet_id);

        // Each stamped id matches the explicit Some(network) derivation, and the
        // instance accessor recomputes the same value.
        let root = mainnet.root_extended_pub_key_cow().unwrap();
        assert_eq!(
            mainnet.wallet_id,
            Wallet::compute_wallet_id_from_root_extended_pub_key(&root, Some(Network::Mainnet))
        );
        assert_eq!(mainnet.compute_wallet_id(), mainnet.wallet_id);
        assert_eq!(
            testnet.wallet_id,
            Wallet::compute_wallet_id_from_root_extended_pub_key(&root, Some(Network::Testnet))
        );
        assert_eq!(testnet.compute_wallet_id(), testnet.wallet_id);
    }

    // (c) Same seed + same network => stable id across calls and across wallets.
    #[test]
    fn test_wallet_id_is_stable() {
        let mnemonic = Mnemonic::from_phrase(FIXTURE_MNEMONIC, Language::English).unwrap();
        let wallet = Wallet::from_mnemonic(
            mnemonic,
            Network::Testnet,
            initialization::WalletAccountCreationOptions::None,
        )
        .unwrap();

        let first = wallet.compute_wallet_id();
        assert_eq!(first, wallet.compute_wallet_id(), "id must be stable across calls");

        let mnemonic2 = Mnemonic::from_phrase(FIXTURE_MNEMONIC, Language::English).unwrap();
        let wallet2 = Wallet::from_mnemonic(
            mnemonic2,
            Network::Testnet,
            initialization::WalletAccountCreationOptions::None,
        )
        .unwrap();
        assert_eq!(first, wallet2.compute_wallet_id());
    }

    // (d) Known-answer tests locking the wire format so the digests can never
    // silently shift. The `None` digest pins the network-independent preimage;
    // the `Some(Mainnet)` digest pins the domain tag + discriminant byte that
    // make up the network-scoped (default) wire-stable contract.
    #[test]
    fn test_wallet_id_known_answers() {
        let root = fixture_root_pub_key(Network::Mainnet);

        // Known answers for the "abandon ... about" fixture mnemonic. The raw root
        // pubkey + chain code are network-independent, so these values are fixed
        // regardless of the network passed to from_mnemonic.
        let none = Wallet::compute_wallet_id_from_root_extended_pub_key(&root, None);
        assert_eq!(
            hex_lower(&none),
            "93401f55c5bc17629140344a2098ebdeb204dfdf1576e87605fbc7b655c86f08",
            "network-independent wallet id digest must remain byte-for-byte stable"
        );

        let mainnet =
            Wallet::compute_wallet_id_from_root_extended_pub_key(&root, Some(Network::Mainnet));
        assert_eq!(
            hex_lower(&mainnet),
            "0b91f36de2613a410303e8309b4f92a150738ae018695d2030b33e64ccea7b2e",
            "network-scoped (mainnet) wallet id digest must remain byte-for-byte stable; \
             a change here means DOMAIN_TAG or a discriminant byte shifted"
        );
    }

    // (e) A `Some(network)` scoped id must differ from the network-independent
    // (`None`) id derived from the same key.
    #[test]
    fn test_scoped_id_differs_from_network_independent() {
        let root = fixture_root_pub_key(Network::Mainnet);
        let none = Wallet::compute_wallet_id_from_root_extended_pub_key(&root, None);

        for network in [Network::Mainnet, Network::Testnet, Network::Devnet, Network::Regtest] {
            let scoped = Wallet::compute_wallet_id_from_root_extended_pub_key(&root, Some(network));
            assert_ne!(
                scoped, none,
                "scoped id ({network:?}) must never collide with the network-independent id"
            );
        }
    }

    // (f) Keyless wallet types carry no root key, so `compute_wallet_id` returns
    // the construction-time id verbatim.
    #[test]
    fn test_wallet_id_for_keyless_wallets_returns_stored_id() {
        let stored_id = [0x42u8; 32];

        let watch_only =
            Wallet::new_watch_only(Network::Testnet, stored_id, AccountCollection::new());
        assert_eq!(watch_only.compute_wallet_id(), stored_id);

        let external =
            Wallet::new_external_signable(Network::Mainnet, stored_id, AccountCollection::new());
        assert_eq!(external.compute_wallet_id(), stored_id);
    }

    fn hex_lower(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
