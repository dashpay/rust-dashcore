// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

use std::{error, fmt, io};

use crate::dashcore;
use dashcore::hashes::hex;
use dashcore::secp256k1;
use jsonrpc;
use serde_json;

pub type OldVecLen = usize;
pub type FixedSizeLen = usize;

/// The error type for errors produced in this library.
#[derive(Debug)]
pub enum Error {
    JsonRpc(jsonrpc::error::Error),
    Hex(hex::Error),
    Json(serde_json::error::Error),
    BitcoinSerialization(dashcore::consensus::encode::Error),
    Secp256k1(secp256k1::Error),
    Io(io::Error),
    InvalidAmount(dashcore::amount::ParseAmountError),
    InvalidCookieFile,
    /// The JSON result had an unexpected structure.
    UnexpectedStructure(String),
}

impl From<jsonrpc::error::Error> for Error {
    fn from(e: jsonrpc::error::Error) -> Error {
        Error::JsonRpc(e)
    }
}

impl From<hex::Error> for Error {
    fn from(e: hex::Error) -> Error {
        Error::Hex(e)
    }
}

impl From<serde_json::error::Error> for Error {
    fn from(e: serde_json::error::Error) -> Error {
        Error::Json(e)
    }
}

impl From<dashcore::consensus::encode::Error> for Error {
    fn from(e: dashcore::consensus::encode::Error) -> Error {
        Error::BitcoinSerialization(e)
    }
}

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Error {
        Error::Secp256k1(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::Io(e)
    }
}

impl From<dashcore::amount::ParseAmountError> for Error {
    fn from(e: dashcore::amount::ParseAmountError) -> Error {
        Error::InvalidAmount(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::JsonRpc(ref e) => write!(f, "JSON-RPC error: {}", e),
            Error::Hex(ref e) => write!(f, "hex decode error: {}", e),
            Error::Json(ref e) => write!(f, "JSON error: {}", e),
            Error::BitcoinSerialization(ref e) => write!(f, "Bitcoin serialization error: {}", e),
            Error::Secp256k1(ref e) => write!(f, "secp256k1 error: {}", e),
            Error::Io(ref e) => write!(f, "I/O error: {}", e),
            Error::InvalidAmount(ref e) => write!(f, "invalid amount: {}", e),
            Error::InvalidCookieFile => write!(f, "invalid cookie file"),
            Error::UnexpectedStructure(ref e) => {
                write!(f, "the JSON result had an unexpected structure: {}", e)
            }
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        "dashcore-rpc error"
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            Error::JsonRpc(ref e) => Some(e),
            Error::Hex(ref e) => Some(e),
            Error::Json(ref e) => Some(e),
            Error::BitcoinSerialization(ref e) => Some(e),
            Error::Secp256k1(ref e) => Some(e),
            Error::Io(ref e) => Some(e),
            _ => None,
        }
    }
}
