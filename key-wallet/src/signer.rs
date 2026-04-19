//! External signer abstraction.
//!
//! A [`Signer`] answers signing requests for private keys the host does not
//! hold. It is the integration point for hardware wallets and remote signers
//! used with [`WalletType::ExternalSignable`](crate::wallet::WalletType::ExternalSignable):
//! the device owns every private key, and the host only sends derivation paths
//! and pre-computed sighashes.
//!
//! The trait is async because hardware-wallet round-trips are inherently
//! asynchronous (USB, BLE, network). Soft-wallet implementations can wrap a
//! sync derive-and-sign in `async {}` without meaningful overhead.

use async_trait::async_trait;
use secp256k1::{ecdsa, PublicKey};

use crate::bip32::DerivationPath;

/// Sign on behalf of keys the host does not possess.
#[async_trait]
pub trait Signer {
    /// Error produced by the underlying signing device or service.
    type Error: std::fmt::Display + Send + Sync + 'static;

    /// Produce an ECDSA signature over `sighash` for the key at `path`,
    /// along with the compressed public key needed to assemble the scriptSig.
    ///
    /// `sighash` is the pre-computed 32-byte message digest (e.g. a legacy
    /// P2PKH sighash). The signer must not re-derive or alter it.
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
