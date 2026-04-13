//! Masternode network tests using dashd.
//!
//! These tests verify SPV behavior against a pre-generated regtest masternode
//! network (1 controller + 4 masternodes with DKG cycles).
//!
//! Required environment variables:
//! - `DASHD_PATH`: path to dashd binary
//! - `DASHD_MN_DATADIR`: path to pre-generated masternode blockchain data
//! - `SKIP_DASHD_TESTS=1`: set to skip these tests

mod helpers;
mod setup;
mod tests_instantsend;
mod tests_sync;
