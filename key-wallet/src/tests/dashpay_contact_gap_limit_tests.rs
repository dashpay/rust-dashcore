//! Regression tests for DIP-15 contact address pool maintenance (issue #1032).

use dashcore::{Address, BlockHash, Transaction, TxOut};

use crate::account::derivation::AccountDerivation;
use crate::account::AccountType;
use crate::managed_account::address_pool::{AddressPool, AddressPoolType};
use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::test_utils::TestWalletContext;
use crate::transaction_checking::{BlockInfo, TransactionContext};
use crate::wallet::managed_wallet_info::managed_account_operations::ManagedAccountOperations;

const US: [u8; 32] = [0xaa; 32];
const THEM: [u8; 32] = [0xbb; 32];

/// The two chains of one friendship. DIP-15 derives them from the same pair of
/// identity ids in opposite order, and the wallet files them in separate
/// collections, so each reaches gap maintenance by its own route.
const CONTACT_CHAINS: [AccountType; 2] = [
    AccountType::DashpayReceivingFunds {
        index: 0,
        user_identity_id: US,
        friend_identity_id: THEM,
    },
    AccountType::DashpayExternalAccount {
        index: 0,
        user_identity_id: US,
        friend_identity_id: THEM,
    },
];

/// The pool a contact chain monitors, looked up by its fully-keyed account type.
fn contact_pool(ctx: &TestWalletContext, contact: AccountType) -> &AddressPool {
    ctx.managed_wallet
        .accounts
        .dashpay_receival_accounts
        .values()
        .chain(ctx.managed_wallet.accounts.dashpay_external_accounts.values())
        .find(|account| account.managed_account_type().to_account_type() == contact)
        .expect("contact account")
        .managed_account_type()
        .address_pools()[0]
}

/// A delivery in the block at `height`.
fn in_block(height: u32) -> TransactionContext {
    TransactionContext::InBlock(BlockInfo::new(
        height,
        BlockHash::from_byte_array([height as u8; 32]),
        1_700_000_000,
    ))
}

/// Pays `address` in a block, and reports whether the wallet saw it.
async fn pay(ctx: &mut TestWalletContext, address: &Address, height: u32) -> bool {
    let tx = Transaction::dummy(address, 0..1, &[29_000]);
    ctx.check_transaction(&tx, in_block(height)).await.is_relevant
}

/// A contact chain must extend as its payments arrive. Without that, the first
/// payment past the addresses built at construction lands on an address the
/// wallet never derived, and is never seen.
#[tokio::test]
async fn contact_payments_extend_the_contact_pool() {
    let mut ctx = TestWalletContext::new_random();
    for contact in CONTACT_CHAINS {
        ctx.wallet.add_account(contact, None).expect("contact account is addable");
        ctx.managed_wallet
            .add_managed_account(&ctx.wallet, contact)
            .expect("contact account is manageable");
    }
    assert_ne!(
        contact_pool(&ctx, CONTACT_CHAINS[0]).address_at_index(0),
        contact_pool(&ctx, CONTACT_CHAINS[1]).address_at_index(0),
        "reversing the identity ids must give the two directions distinct chains"
    );

    for (chain, contact) in CONTACT_CHAINS.into_iter().enumerate() {
        let height = 1_555_196 + chain as u32 * 2;
        let direction = if chain == 0 {
            "receiving"
        } else {
            "external"
        };
        let pool = contact_pool(&ctx, contact);
        let gap = pool.gap_limit();
        let last_built = pool.address_at_index(gap - 1).expect("construction fills the window");
        assert!(
            pool.address_at_index(gap).is_none(),
            "{direction}: nothing is derived past that window yet"
        );

        assert!(
            pay(&mut ctx, &last_built, height).await,
            "{direction}: payment to a monitored address is seen"
        );
        assert_eq!(
            contact_pool(&ctx, contact).highest_generated(),
            Some(gap - 1 + gap),
            "{direction}: using an address must leave a full window monitored ahead of it"
        );

        let past_the_window =
            contact_pool(&ctx, contact).address_at_index(gap).expect("the window moved");
        assert!(
            pay(&mut ctx, &past_the_window, height + 1).await,
            "{direction}: the payment past the construction window must be seen too"
        );
        assert_eq!(
            contact_pool(&ctx, contact).highest_generated(),
            Some(gap * 2),
            "{direction}: the window must keep moving, not widen once"
        );
    }
}

/// A friendship's receiving chain and the reverse of the contact's external chain share an xpub,
/// so both derive the same addresses. Each chain reports the address as used when it derives and
/// uses it within one check.
#[tokio::test]
async fn shared_contact_addresses_are_reported_used_by_each_chain() {
    let mut ctx = TestWalletContext::new_random();
    let shared = [
        AccountType::DashpayReceivingFunds {
            index: 0,
            user_identity_id: US,
            friend_identity_id: THEM,
        },
        AccountType::DashpayExternalAccount {
            index: 0,
            user_identity_id: THEM,
            friend_identity_id: US,
        },
    ];
    for contact in shared {
        ctx.wallet.add_account(contact, None).expect("contact account is addable");
        ctx.managed_wallet
            .add_managed_account(&ctx.wallet, contact)
            .expect("contact account is manageable");
    }
    let gap = contact_pool(&ctx, shared[0]).gap_limit();
    let account = ctx.wallet.accounts.account_of_type(shared[0]).expect("receiving chain");
    let address = |index| account.derive_address_at(AddressPoolType::Absent, index, None).unwrap();
    let (first, late) = (address(1), address(1 + gap));
    assert_eq!(contact_pool(&ctx, shared[1]).address_at_index(1), Some(first.clone()));
    let mut tx = Transaction::dummy(&first, 0..1, &[29_000]);
    tx.output.push(TxOut {
        value: 29_000,
        script_pubkey: late.script_pubkey(),
    });

    let result = ctx.check_transaction(&tx, in_block(1_555_200)).await;
    let reported: Vec<_> = result.new_addresses.iter().filter(|d| d.info.address == late).collect();
    assert_eq!(reported.len(), 2, "each chain derives it");
    assert!(reported.iter().all(|d| d.info.is_used()));
}
