//! SPV sync tests using dashd.
//!
//! These tests verify SPV sync scenarios against a dashd instance.

#[path = "dashd_sync/helpers.rs"]
mod helpers;
#[path = "dashd_sync/setup.rs"]
mod setup;
#[path = "dashd_sync/tests_basic.rs"]
mod tests_basic;
#[path = "dashd_sync/tests_disconnect.rs"]
mod tests_disconnect;
#[path = "dashd_sync/tests_restart.rs"]
mod tests_restart;
#[path = "dashd_sync/tests_transaction.rs"]
mod tests_transaction;
