//! External signer abstraction.
//!
//! A [`Signer`] answers signing requests for private keys the host does not
//! hold. It is the integration point for hardware wallets and remote signers
//! used with [`WalletType::ExternalSignable`](crate::wallet::WalletType::ExternalSignable):
//! the device owns every private key, and the host only sends derivation paths
//! plus either pre-computed sighashes or full transactions — depending on what
//! the device supports (see [`SignerMethod`]).
//!
//! The trait is async because hardware-wallet round-trips are inherently
//! asynchronous (USB, BLE, network). Soft-wallet implementations can wrap a
//! sync derive-and-sign in `async {}` without meaningful overhead.

use async_trait::async_trait;
use secp256k1::{ecdsa, PublicKey};

use crate::bip32::DerivationPath;

/// A signing method a [`Signer`] can perform.
///
/// Callers check which methods a signer supports via
/// [`Signer::supported_methods`] and dispatch accordingly. A remote cloud
/// signer or soft wallet typically supports [`SignerMethod::Digest`] (blind
/// sighash signing). A hardware wallet protecting the user from a
/// compromised host cannot safely sign blind digests — it needs the full
/// transaction to re-hash and display — so it advertises
/// [`SignerMethod::Transaction`] instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignerMethod {
    /// Sign a host-computed 32-byte digest. The device trusts that the
    /// digest matches the intended transaction: fast, but offers no
    /// on-device review of what's actually being signed. Suitable for
    /// trusted remote signers and HSMs; **not** suitable for hardware
    /// wallets that defend against a compromised host.
    Digest,

    /// Sign a full Dash transaction of a given [`TransactionCategory`].
    /// The signer receives the unsigned transaction plus per-input
    /// metadata, re-hashes it internally, and (for hardware wallets) may
    /// present transaction details to the user for approval.
    ///
    /// A signer advertises one variant per category it can parse and
    /// render — hardware-wallet firmware typically ships support for
    /// categories rather than individual transaction types.
    Transaction(TransactionCategory),
}

/// Category of Dash transaction, grouped by on-chain purpose.
///
/// Categories correspond to the transaction shapes a signer has to
/// understand in order to safely display and sign them. Grouping by
/// category (rather than by the raw DIP-2 type byte) matches how
/// hardware-wallet firmware tends to gate feature support: a firmware
/// release either understands "masternode lifecycle transactions" or it
/// doesn't — not one specific sub-type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransactionCategory {
    /// Classical transaction — P2PKH / P2SH value transfer, no special
    /// payload. DIP-2 type 0.
    Classical,

    /// Platform credit flow. Locks Dash on L1 to credit Platform, or
    /// unlocks credits back to L1. DIP-2 types 8 (AssetLock) and 9
    /// (AssetUnlock).
    PlatformCredits,

    /// DIP-3 masternode lifecycle. Register, update, or revoke a
    /// masternode. DIP-2 types 3 (ProRegTx), 4 (ProUpServTx), 5
    /// (ProUpRegTx), 6 (ProUpRevTx).
    MasternodeLifecycle,
}

/// Sign on behalf of keys the host does not possess.
///
/// The `Send + Sync` supertrait bounds match how callers use a signer in
/// practice: `build_asset_lock_with_signer` (and future signer-driven
/// builders) call `&signer` methods across `.await` points, so any
/// implementor that doesn't satisfy both bounds would fail to compile at
/// the call site with a cryptic "future is not `Send`/`Sync`" message.
/// Putting the bounds on the trait surfaces the requirement up front.
#[async_trait]
pub trait Signer: Send + Sync {
    /// Error produced by the underlying signing device or service.
    ///
    /// The bound is intentionally loose — only `Display + Send + Sync +
    /// 'static` — so bring-your-own error types (including `String`) work
    /// out of the box. Implementors **should** prefer a type that also
    /// implements `std::error::Error` (derived via `thiserror` or hand-
    /// rolled) so callers can chain causes and inspect source errors;
    /// this crate's call sites currently collapse the signer error to a
    /// `String` via `Display`, which works for either shape.
    type Error: std::fmt::Display + Send + Sync + 'static;

    /// Signing methods this signer can perform. A caller that needs a
    /// method the signer doesn't advertise should fail fast rather than
    /// invoke a trait method it knows will be rejected.
    ///
    /// Returned as a borrowed slice so signers can back this with a
    /// `&'static` constant when capabilities are fixed, or with a field
    /// when they're resolved at runtime (e.g. after a firmware-version
    /// handshake).
    fn supported_methods(&self) -> &[SignerMethod];

    /// Convenience: whether `method` appears in [`Self::supported_methods`].
    fn supports(&self, method: SignerMethod) -> bool {
        self.supported_methods().contains(&method)
    }

    /// Produce an ECDSA signature over `sighash` for the key at `path`,
    /// along with the compressed public key needed to assemble the scriptSig.
    ///
    /// `sighash` is the pre-computed 32-byte message digest (e.g. a legacy
    /// P2PKH sighash). The signer must not re-derive or alter it.
    ///
    /// Only valid when the signer supports [`SignerMethod::Digest`].
    async fn sign_ecdsa(
        &self,
        path: &DerivationPath,
        sighash: [u8; 32],
    ) -> Result<(ecdsa::Signature, PublicKey), Self::Error>;

    /// Return the compressed public key at `path` without signing.
    ///
    /// Used to capture per-output public keys (e.g. asset-lock credit-output
    /// keys) that the caller later references when signing Platform state
    /// transitions.
    async fn public_key(&self, path: &DerivationPath) -> Result<PublicKey, Self::Error>;
}
