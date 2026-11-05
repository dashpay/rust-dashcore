// Rust Dash Library
// Originally written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//     For Bitcoin
// Refactored for Dash in 2022 by
//     The Dash Core Developers
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Dash TxIn.
//!
//! A TxIn is an input to a transaction.
//!

#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};

use crate::blockdata::script::{Instruction, ScriptBuf};
use crate::consensus::{Decodable, Encodable, encode};
use crate::transaction::outpoint::OutPoint;
use crate::{Address, Network, PublicKey, Witness, io};

/// A transaction input, which defines old coins to be consumed
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct TxIn {
    /// The reference to the previous output that is being used an an input.
    pub previous_output: OutPoint,
    /// The script which pushes values on the stack which will cause
    /// the referenced output's script to be accepted.
    pub script_sig: ScriptBuf,
    /// The sequence number, which suggests to miners which of two
    /// conflicting transactions should be preferred, or 0xFFFFFFFF
    /// to ignore this feature. This is generally never used since
    /// the miner behaviour cannot be enforced.
    pub sequence: u32,
    /// Witness data: an array of byte-arrays.
    /// Note that this field is *not* (de)serialized with the rest of the TxIn in
    /// Encodable/Decodable, as it is (de)serialized at the end of the full
    /// Transaction. It *is* (de)serialized with the rest of the TxIn in other
    /// (de)serialization routines.
    pub witness: Witness,
}

impl Default for TxIn {
    fn default() -> TxIn {
        TxIn {
            previous_output: OutPoint::default(),
            script_sig: ScriptBuf::new(),
            sequence: u32::MAX,
            witness: Witness::default(),
        }
    }
}

impl TxIn {
    /// Returns the P2PKH address this input claims to spend from, or `None` for
    /// a coinbase or any scriptSig that is not exactly a P2PKH spend.
    ///
    /// A P2PKH spend is a DER-shaped signature push (`0x30` tag, at most 73 bytes
    /// with the sighash byte) followed by a public key push, and nothing else.
    /// The key must be compressed or uncompressed SEC1 (prefix `0x02`, `0x03` or
    /// `0x04`). Hybrid keys (`0x06`/`0x07`) are consensus-valid but non-standard,
    /// and yield `None`.
    ///
    /// Nothing checks the signature against the spent output, so the result is
    /// only the sender the spender claims, never proof of it. The scriptSig alone
    /// also cannot rule out a P2SH input whose redeem script is a valid public key.
    pub fn claimed_p2pkh_address(&self, network: Network) -> Option<Address> {
        if self.previous_output.is_null() {
            return None;
        }
        let mut pushes = self.script_sig.instructions();
        let Some(Ok(Instruction::PushBytes(sig))) = pushes.next() else {
            return None;
        };
        let Some(Ok(Instruction::PushBytes(key))) = pushes.next() else {
            return None;
        };
        if pushes.next().is_some() {
            return None;
        }
        if sig.as_bytes().first() != Some(&0x30) || sig.len() > 73 {
            return None;
        }
        let key = PublicKey::from_slice(key.as_bytes()).ok()?;
        Some(Address::p2pkh(&key, network))
    }
}

impl Encodable for TxIn {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.previous_output.consensus_encode(w)?;
        len += self.script_sig.consensus_encode(w)?;
        len += self.sequence.consensus_encode(w)?;
        Ok(len)
    }
}
impl Decodable for TxIn {
    #[inline]
    fn consensus_decode_from_finite_reader<R: io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, encode::Error> {
        Ok(TxIn {
            previous_output: Decodable::consensus_decode_from_finite_reader(r)?,
            script_sig: Decodable::consensus_decode_from_finite_reader(r)?,
            sequence: Decodable::consensus_decode_from_finite_reader(r)?,
            witness: Witness::default(),
        })
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::Txid;
    use crate::blockdata::script::{Builder, PushBytesBuf};
    use crate::consensus::encode::deserialize;

    #[test]
    fn test_txin() {
        let txin: Result<TxIn, _> = deserialize(&hex_conservative::decode_to_vec("a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff").unwrap());
        assert!(txin.is_ok());
    }

    #[test]
    fn test_claimed_p2pkh_address() {
        let key = PublicKey::from_slice(
            &hex_conservative::decode_to_vec(
                "033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52",
            )
            .unwrap(),
        )
        .unwrap();
        let spend = |script_sig: ScriptBuf| TxIn {
            previous_output: OutPoint {
                txid: Txid::all_zeros(),
                vout: 1,
            },
            script_sig,
            ..Default::default()
        };
        let p2pkh = Builder::new().push_slice([0x30u8; 71]).push_key(&key).into_script();
        let mut hybrid = key.inner.to_uncompressed();
        hybrid[0] = 0x06 | (hybrid[64] & 1);

        // A real mainnet P2PKH input signed by `key` claims the address of `key`.
        let txin: TxIn = deserialize(&hex_conservative::decode_to_vec("a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff").unwrap()).unwrap();
        for network in [Network::Mainnet, Network::Testnet] {
            assert_eq!(txin.claimed_p2pkh_address(network), Some(Address::p2pkh(&key, network)));
        }
        assert_eq!(
            spend(p2pkh.clone()).claimed_p2pkh_address(Network::Testnet),
            Some(Address::p2pkh(&key, Network::Testnet))
        );

        // A coinbase spends nothing, whatever its scriptSig holds.
        let coinbase = TxIn {
            previous_output: OutPoint::null(),
            script_sig: p2pkh,
            ..Default::default()
        };
        assert_eq!(coinbase.claimed_p2pkh_address(Network::Mainnet), None);

        for script_sig in [
            // Three pushes ending in a valid key, as in a multi-push P2SH spend.
            Builder::new()
                .push_slice([0x30u8; 71])
                .push_slice([0x01u8; 20])
                .push_key(&key)
                .into_script(),
            // A first push that is not DER-shaped.
            Builder::new().push_slice([0xAAu8; 10]).push_key(&key).into_script(),
            // A DER-shaped push longer than any signature.
            Builder::new()
                .push_slice(PushBytesBuf::try_from(vec![0x30u8; 74]).unwrap())
                .push_key(&key)
                .into_script(),
            // A hybrid encoding of `key`.
            Builder::new().push_slice([0x30u8; 71]).push_slice(hybrid).into_script(),
            // Only the signature.
            Builder::new().push_slice([0x30u8; 71]).into_script(),
            // A lock script: opcodes, not pushes.
            Address::p2pkh(&key, Network::Mainnet).script_pubkey(),
            ScriptBuf::new(),
        ] {
            assert_eq!(spend(script_sig).claimed_p2pkh_address(Network::Mainnet), None);
        }
    }

    #[test]
    fn test_txin_default() {
        let txin = TxIn::default();
        assert_eq!(txin.previous_output, OutPoint::default());
        assert_eq!(txin.script_sig, ScriptBuf::new());
        assert_eq!(txin.sequence, 0xFFFFFFFF);
        assert_eq!(txin.previous_output, OutPoint::default());
        assert_eq!(txin.witness.len(), 0_usize);
    }
}
