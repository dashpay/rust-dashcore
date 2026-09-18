//! Regression test for DIP-15 contact address pool maintenance (issue #1032).

use dashcore::hashes::Hash;
use dashcore::{Address, BlockHash, Transaction};

use crate::account::AccountType;
use crate::managed_account::address_pool::AddressPool;
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

/// Pays `address` in a block, and reports whether the wallet saw it.
async fn pay(ctx: &mut TestWalletContext, address: &Address, height: u32) -> bool {
    let tx = Transaction::dummy(address, 0..1, &[29_000]);
    let context = TransactionContext::InBlock(BlockInfo::new(
        height,
        BlockHash::from_byte_array([height as u8; 32]),
        1_700_000_000,
    ));
    ctx.check_transaction(&tx, context).await.is_relevant
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
        let gap = pool.gap_limit;
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
            contact_pool(&ctx, contact).highest_generated,
            Some(gap - 1 + gap),
            "{direction}: using an address must leave a full window monitored ahead of it"
        );

        let past_the_window =
            contact_pool(&ctx, contact).address_at_index(gap).expect("the window moved");
        assert!(
            pay(&mut ctx, &past_the_window, height + 1).await,
            "{direction}: the payment past the construction window must be seen too"
        );
    }
}
