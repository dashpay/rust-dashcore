// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Bitcoin block data.
//!
//! This module defines structures and functions for storing the blocks and
//! transactions which make up the Bitcoin system.
//!

pub mod block;
pub mod constants;
pub mod locktime;
pub mod opcodes;
pub mod script;
pub mod transaction;
pub mod weight {
    pub use bitcoin_units::weight::*;
}
pub mod witness;

pub use weight::Weight;

#[cfg(test)]
mod tests {
    use super::Weight;
    #[cfg(feature = "serde")]
    use hex_conservative::hex;

    #[test]
    fn weight_layout() {
        let weight = Weight::from_wu(17_168);
        assert_eq!(weight.to_string(), "17168");
        assert_eq!(format!("{:#}", weight), "17168 wu");
        assert_eq!("17168".parse::<Weight>().unwrap(), weight);
        assert!("-1".parse::<Weight>().is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn weight_serde() {
        let config = bincode::config::standard();
        let weight = Weight::from_wu(17_168);

        assert_eq!(serde_json::to_string(&weight).unwrap(), "17168");
        assert_eq!(serde_json::from_str::<Weight>("17168").unwrap(), weight);

        assert_eq!(bincode::serde::encode_to_vec(weight, config).unwrap(), hex!("fb1043"));
        assert_eq!(
            bincode::serde::decode_from_slice::<Weight, _>(&hex!("fb1043"), config).unwrap().0,
            weight
        );
    }
}
