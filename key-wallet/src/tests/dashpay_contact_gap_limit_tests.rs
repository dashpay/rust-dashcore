//! Regression test for DIP-15 contact address pool maintenance (issue #1032).

use dashcore::hashes::Hash;
use dashcore::{BlockHash, Transaction};

use crate::account::AccountType;
use crate::managed_account::address_pool::AddressPool;
use crate::managed_account::managed_account_trait::ManagedAccountTrait;
use crate::test_utils::TestWalletContext;
use crate::transaction_checking::{BlockInfo, TransactionContext};
use crate::wallet::managed_wallet_info::managed_account_operations::ManagedAccountOperations;
use crate::KeySource;

const CONTACT: AccountType = AccountType::DashpayReceivingFunds {
    index: 0,
    user_identity_id: [0xaa; 32],
    friend_identity_id: [0xbb; 32],
};

fn contact_pool(ctx: &TestWalletContext) -> &AddressPool {
    ctx.managed_wallet
        .accounts
        .funds_account(&CONTACT)
        .expect("contact account")
        .managed_account_type()
        .address_pools()[0]
}

/// A contact chain must extend as its payments arrive. Without that the 21st
/// payment lands on an address the wallet never derived and is never seen.
#[tokio::test]
async fn contact_payments_extend_the_contact_pool() {
    let mut ctx = TestWalletContext::new_random();
    ctx.wallet.add_account(CONTACT, None).expect("contact account is addable");
    ctx.managed_wallet
        .add_managed_account(&ctx.wallet, CONTACT)
        .expect("contact account is manageable");
    let xpub = ctx.wallet.accounts.account_of_type(CONTACT).expect("account exists").account_xpub;

    // Index 20 sits one past the window built at construction, so only gap
    // maintenance can bring it into the pool. Derived off a throwaway clone
    // because the pool under test may never hold it.
    let past_the_window = contact_pool(&ctx)
        .clone()
        .generate_address_at_index(20, &KeySource::Public(xpub), false)
        .expect("contact chain derives");

    for index in 0..=20u32 {
        let address = if index == 20 {
            past_the_window.clone()
        } else {
            contact_pool(&ctx).address_at_index(index).expect("address is monitored")
        };
        let tx = Transaction::dummy(&address, 0..1, &[29_000]);
        let context = TransactionContext::InBlock(BlockInfo::new(
            1_555_196 + index,
            BlockHash::from_byte_array([index as u8; 32]),
            1_700_000_000,
        ));

        let result = ctx.check_transaction(&tx, context).await;

        assert!(result.is_relevant, "contact payment {index} must be seen");
        let pool = contact_pool(&ctx);
        assert_eq!(pool.highest_used, Some(index), "payment {index} must mark its address used");
        assert_eq!(
            pool.highest_generated,
            Some(index + pool.gap_limit),
            "payment {index} must leave a full window of unused addresses behind it"
        );
    }
}
