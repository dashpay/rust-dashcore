// Rust Bitcoin Library - Written by the rust-dash developers.
// SPDX-License-Identifier: CC0-1.0

//! Provides absolute and relative locktimes.
//!

pub mod absolute {
    pub use bitcoin_units::locktime::absolute::*;
}
pub mod relative;

use self::absolute::LockTime;
use crate::consensus::encode::{self, Decodable, Encodable};
use crate::io::{self, Read, Write};

impl Encodable for LockTime {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.to_consensus_u32().consensus_encode(w)
    }
}

impl Decodable for LockTime {
    #[inline]
    fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        u32::consensus_decode(r).map(LockTime::from_consensus)
    }
}

#[cfg(test)]
mod tests {
    use super::absolute::{Height, LockTime, MedianTimePast};
    use super::relative;
    use crate::consensus::encode::{deserialize, serialize};
    use hex_conservative::hex;

    #[test]
    fn absolute_lock_time_layout() {
        let blocks = LockTime::from_consensus(840_000);
        let seconds = LockTime::from_consensus(1_700_000_000);
        let height = Height::from_u32(840_000).unwrap();
        let time = MedianTimePast::from_u32(1_700_000_000).unwrap();
        assert_eq!(LockTime::from(height), blocks);
        assert_eq!(LockTime::from(time), seconds);
        assert_eq!(height.to_string(), "840000");
        assert_eq!(time.to_string(), "1700000000");
        assert!(blocks.is_block_height());
        assert!(seconds.is_block_time());
        assert_eq!(blocks.to_string(), "840000");
        assert_eq!(format!("{:#}", blocks), "block-height 840000");
        assert_eq!(format!("{:#}", seconds), "block-time 1700000000 (seconds since epoch)");
        assert_eq!("840000".parse::<LockTime>().unwrap(), blocks);
        assert_eq!(serialize(&blocks), hex!("40d10c00"));
        assert_eq!(deserialize::<LockTime>(&hex!("00f15365")).unwrap(), seconds);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn absolute_lock_time_serde() {
        let config = bincode::config::standard();
        let blocks = LockTime::from_consensus(840_000);
        let height = Height::from_u32(840_000).unwrap();
        let time = MedianTimePast::from_u32(1_700_000_000).unwrap();

        assert_eq!(serde_json::to_string(&blocks).unwrap(), "840000");
        assert_eq!(serde_json::from_str::<LockTime>("840000").unwrap(), blocks);
        assert_eq!(serde_json::to_string(&height).unwrap(), "840000");
        assert_eq!(serde_json::from_str::<Height>("840000").unwrap(), height);
        assert_eq!(serde_json::to_string(&time).unwrap(), "1700000000");
        assert_eq!(serde_json::from_str::<MedianTimePast>("1700000000").unwrap(), time);

        assert_eq!(bincode::serde::encode_to_vec(blocks, config).unwrap(), hex!("fc40d10c00"));
        assert_eq!(bincode::serde::encode_to_vec(height, config).unwrap(), hex!("fc40d10c00"));
        assert_eq!(bincode::serde::encode_to_vec(time, config).unwrap(), hex!("fc00f15365"));
        assert_eq!(
            bincode::serde::decode_from_slice::<LockTime, _>(&hex!("fc40d10c00"), config)
                .unwrap()
                .0,
            blocks
        );
        assert_eq!(
            bincode::serde::decode_from_slice::<Height, _>(&hex!("fc40d10c00"), config).unwrap().0,
            height
        );
        assert_eq!(
            bincode::serde::decode_from_slice::<MedianTimePast, _>(&hex!("fc00f15365"), config)
                .unwrap()
                .0,
            time
        );
    }

    #[test]
    fn relative_lock_time_layout() {
        let height = relative::Height::from_count(100);
        let time = relative::Time::from_512_second_intervals(70);
        let blocks = relative::LockTime::from(height);
        let seconds = relative::LockTime::from(time);
        assert_eq!(height.to_string(), "100");
        assert_eq!(time.to_string(), "70");
        assert_eq!(blocks.to_string(), "100");
        assert_eq!(format!("{:#}", blocks), "block-height 100");
        assert_eq!(format!("{:#}", seconds), "block-time 70 (512 second intervals)");
        assert_eq!("100".parse::<relative::Height>().unwrap(), height);
        assert_eq!("70".parse::<relative::Time>().unwrap(), time);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn relative_lock_time_serde() {
        let config = bincode::config::standard();
        let height = relative::Height::from_count(100);
        let time = relative::Time::from_512_second_intervals(70);
        let blocks = relative::LockTime::from(height);
        let seconds = relative::LockTime::from(time);

        assert_eq!(serde_json::to_string(&height).unwrap(), "100");
        assert_eq!(serde_json::from_str::<relative::Height>("100").unwrap(), height);
        assert_eq!(serde_json::to_string(&time).unwrap(), "70");
        assert_eq!(serde_json::from_str::<relative::Time>("70").unwrap(), time);
        assert_eq!(serde_json::to_string(&blocks).unwrap(), r#"{"Blocks":100}"#);
        assert_eq!(
            serde_json::from_str::<relative::LockTime>(r#"{"Blocks":100}"#).unwrap(),
            blocks
        );
        assert_eq!(serde_json::to_string(&seconds).unwrap(), r#"{"Time":70}"#);
        assert_eq!(serde_json::from_str::<relative::LockTime>(r#"{"Time":70}"#).unwrap(), seconds);

        assert_eq!(bincode::serde::encode_to_vec(height, config).unwrap(), hex!("64"));
        assert_eq!(bincode::serde::encode_to_vec(time, config).unwrap(), hex!("46"));
        assert_eq!(bincode::serde::encode_to_vec(blocks, config).unwrap(), hex!("0064"));
        assert_eq!(bincode::serde::encode_to_vec(seconds, config).unwrap(), hex!("0146"));
        assert_eq!(
            bincode::serde::decode_from_slice::<relative::LockTime, _>(&hex!("0064"), config)
                .unwrap()
                .0,
            blocks
        );
        assert_eq!(
            bincode::serde::decode_from_slice::<relative::LockTime, _>(&hex!("0146"), config)
                .unwrap()
                .0,
            seconds
        );
    }
}
