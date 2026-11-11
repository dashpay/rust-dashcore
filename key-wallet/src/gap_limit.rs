/// Standard gap limit for external addresses (BIP44 recommendation)
pub const DEFAULT_EXTERNAL_GAP_LIMIT: u32 = 30;

/// Standard gap limit for internal (change) addresses
pub const DEFAULT_INTERNAL_GAP_LIMIT: u32 = 30;

/// Standard gap limit for CoinJoin addresses.
///
/// Set to match dashj's `DeterministicKeyChain` lookahead
/// (`DEFAULT_LOOKAHEAD_SIZE = 100`), which is the effective discovery window
/// dashj-core (the reference wallet, `org.dashj:dashj-core:22.x`) watches for
/// CoinJoin keychains. Address discovery here is dynamic — the pool watches
/// `highest_used + gap_limit` addresses — so this bounds the largest run of
/// UNUSED CoinJoin addresses the wallet can bridge during a filter/rescan
/// before discovery stalls.
///
/// The previous value of 30 starved heavy mixers: DIP-9 CoinJoin mixing
/// sprays denominations across many sequential addresses, and a run wider
/// than 30 consecutive unused addresses caused the SDK to stop discovering —
/// it then missed both the txs that CREATED far-index UTXOs and the txs that
/// SPENT nearer ones, leaving a persistent balance mismatch vs dashj that
/// survived a clean re-creation + full rescan (dashpay/platform#4074,
/// dashpay/dash-wallet#1507). 100 restores parity with dashj's window so the
/// SDK discovers every CoinJoin tx dashj does.
///
/// Cost is modest: the CoinJoin account watches two pools (external +
/// internal), so this pre-derives and filter-matches ~200 CoinJoin addresses
/// per account instead of ~60. BIP158 filter matching is a set intersection,
/// so the extra scripts add negligible per-block work; the derivation is a
/// one-time keychain expansion.
pub const DEFAULT_COINJOIN_GAP_LIMIT: u32 = 100;

/// Standard gap limit for special purpose keys (identity, provider keys)
pub const DEFAULT_SPECIAL_GAP_LIMIT: u32 = 5;

/// Gap limit for DashPay contact chains, as recommended by DIP-15.
pub const DEFAULT_DASHPAY_GAP_LIMIT: u32 = 10;

/// Gap limit for DIP-17 platform payment addresses
pub const DIP17_GAP_LIMIT: u32 = 20;

/// Maximum gap limit to prevent excessive address generation
pub const MAX_GAP_LIMIT: u32 = 1000;
