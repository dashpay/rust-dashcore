//
// This file is a part of rust-dashcore.
// SPDX-License-Identifier: CC0-1.0
// See the accompanying file LICENSE or https://creativecommons.org/publicdomain/zero/1.0
//

//! The legacy asset lock decoder.
//!
//! Before this crate read special payloads strictly through their length prefix, as Dash Core
//! does, it read an asset lock's payload whatever length the prefix announced. Dash Platform
//! accepted, and charged for, instant asset lock proofs decoded that way, and has to keep decoding
//! them that way to agree with its older binaries and to replay its chain. This module keeps that
//! legacy framing apart from the transaction decoder, so that the transaction decoder can follow
//! Dash Core while the legacy framing stays as it is.

use crate::blockdata::transaction::Transaction;
use crate::blockdata::transaction::special_transaction::asset_lock::AssetLockPayload;
use crate::blockdata::transaction::special_transaction::{TransactionPayload, TransactionType};
use crate::blockdata::transaction::txin::TxIn;
use crate::blockdata::transaction::txout::TxOut;
use crate::consensus::encode::VarInt;
use crate::consensus::{Decodable, encode};
use crate::io;

impl Transaction {
    /// Deserializes a transaction with the legacy asset lock framing: an asset lock's payload is
    /// read after its length prefix, whatever length the prefix announces.
    ///
    /// For an asset lock (a version of at least 3 when read as an `i16`, and type 8) the prefix
    /// must be a minimally encoded CompactSize, but its value is ignored: the payload, a version
    /// byte and the credit outputs, is decoded from the bytes after it and must end `bytes`. Any
    /// other transaction is decoded by [`deserialize`](encode::deserialize).
    ///
    /// This is a legacy decoder. Prefer [`deserialize`](encode::deserialize), which reads a
    /// payload through its length prefix as Dash Core does. This one is for callers that must keep
    /// accepting the asset locks that earlier releases of this crate accepted, such as Dash
    /// Platform decoding instant asset lock proofs, whose InstantSend lock and signature do not
    /// cover the prefix.
    ///
    /// Its framing must never change, or its callers would stop agreeing with what they accepted
    /// before. It shares no code with the transaction and asset lock payload decoders, so a new
    /// transaction rule or payload layout there leaves it as it is. It reads inputs, outputs,
    /// witnesses and CompactSizes with this crate's decoders.
    pub fn deserialize_with_legacy_asset_lock_framing(
        bytes: &[u8],
    ) -> Result<Transaction, encode::Error> {
        let mut r = io::Cursor::new(bytes);
        let version = u16::consensus_decode_from_finite_reader(&mut r)?;
        let special_transaction_type = u16::consensus_decode(&mut r)?;
        if (version as i16) < 3 || special_transaction_type != TransactionType::AssetLock.to_u16() {
            return encode::deserialize(bytes);
        }
        let mut input = Vec::<TxIn>::consensus_decode_from_finite_reader(&mut r)?;
        // Without inputs, an asset lock is read in the BIP144 form, as a classic transaction is.
        let output = if input.is_empty() {
            match u8::consensus_decode_from_finite_reader(&mut r)? {
                1 => {
                    input = Vec::<TxIn>::consensus_decode_from_finite_reader(&mut r)?;
                    let output = Vec::<TxOut>::consensus_decode_from_finite_reader(&mut r)?;
                    for txin in input.iter_mut() {
                        txin.witness = Decodable::consensus_decode_from_finite_reader(&mut r)?;
                    }
                    if !input.is_empty() && input.iter().all(|input| input.witness.is_empty()) {
                        return Err(encode::Error::ParseFailed(
                            "witness flag set but no witnesses present",
                        ));
                    }
                    output
                }
                x => return Err(encode::Error::UnsupportedSegwitFlag(x)),
            }
        } else {
            Vec::<TxOut>::consensus_decode_from_finite_reader(&mut r)?
        };
        let lock_time = Decodable::consensus_decode_from_finite_reader(&mut r)?;
        // The payload length prefix must decode, but the length it announces is not used.
        VarInt::consensus_decode(&mut r)?;
        // The asset lock payload: a version byte, then the credit outputs, whatever the version.
        let payload_version = u8::consensus_decode(&mut r)?;
        let credit_outputs = Vec::<TxOut>::consensus_decode(&mut r)?;
        if r.position() as usize != bytes.len() {
            return Err(encode::Error::ParseFailed(
                "data not consumed entirely when explicitly deserializing",
            ));
        }
        Ok(Transaction {
            version,
            input,
            output,
            lock_time,
            special_transaction_payload: Some(TransactionPayload::AssetLockPayloadType(
                AssetLockPayload {
                    version: payload_version,
                    credit_outputs,
                },
            )),
        })
    }
}
