// Rust Bitcoin Library - Written by the rust-dash developers.
// SPDX-License-Identifier: CC0-1.0

//! Provides type [`LockTime`] that implements the logic around nSequence/OP_CHECKSEQUENCEVERIFY.
//!
//! There are two types of lock time: lock-by-blockheight and lock-by-blocktime, distinguished by
//! whether bit 22 of the `u32` consensus value is set.
//!

use core::fmt;

pub use bitcoin_units::locktime::relative::{
    NumberOf512Seconds as Time, NumberOfBlocks as Height, TimeOverflowError,
};

#[cfg(doc)]
use crate::relative;

/// A relative lock time value, representing either a block height or time (512 second intervals).
///
/// The `relative::LockTime` type does not have any constructors, this is by design, please use
/// `Sequence::to_relative_lock_time` to create a relative lock time.
///
/// ### Relevant BIPs
///
/// * [BIP 68 Relative lock-time using consensus-enforced sequence numbers](https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki)
/// * [BIP 112 CHECKSEQUENCEVERIFY](https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki)
#[allow(clippy::derive_ord_xor_partial_ord)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum LockTime {
    /// A block height lock time value.
    Blocks(Height),
    /// A 512 second time interval value.
    Time(Time),
}

impl LockTime {
    /// Returns true if this [`relative::LockTime`] is satisfied by either height or time.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dashcore::locktime::relative::{LockTime, Height, Time};
    ///
    /// # let height = 100;       // 100 blocks.
    /// # let intervals = 70;     // Approx 10 hours.
    /// # let current_height = || Height::from_count(height + 10);
    /// # let current_time = || Time::from_512_second_intervals(intervals + 10);
    /// # let lock = LockTime::from(Height::from_count(height));
    /// # let test_lock = LockTime::from(Height::from_count(height+10));
    ///
    /// // Users that have chain data can get the current height and time to check against a lock.
    /// let height_and_time = (current_time(), current_height());  // tuple order does not matter.
    /// assert!(lock.is_satisfied_by(current_height(), current_time()));
    /// ```
    #[inline]
    pub fn is_satisfied_by(&self, h: Height, t: Time) -> bool {
        if let Ok(true) = self.is_satisfied_by_height(h) {
            true
        } else {
            matches!(self.is_satisfied_by_time(t), Ok(true))
        }
    }

    /// Returns true if satisfaction of `other` lock time implies satisfaction of this
    /// [`relative::LockTime`].
    ///
    /// A lock time can only be satisfied by n blocks being mined or n seconds passing. If you have
    /// two lock times (same unit) then the larger lock time being satisfied implies (in a
    /// mathematical sense) the smaller one being satisfied.
    ///
    /// This function is useful when checking sequence values against a lock, first one checks the
    /// sequence represents a relative lock time by converting to `LockTime` then use this function
    /// to see if satisfaction of the newly created lock time would imply satisfaction of `self`.
    ///
    /// Can also be used to remove the smaller value of two `OP_CHECKSEQUENCEVERIFY` operations
    /// within one branch of the script.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dashcore::locktime::relative::{LockTime, Height, Time};
    ///
    /// # let height = 100;       // 100 blocks.
    /// # let lock = LockTime::from(Height::from_count(height));
    /// # let test_lock = LockTime::from(Height::from_count(height+10));
    ///
    /// assert!(lock.is_implied_by(test_lock));
    /// ```
    #[inline]
    pub fn is_implied_by(&self, other: LockTime) -> bool {
        use LockTime::*;

        match (*self, other) {
            (Blocks(this), Blocks(other)) => this <= other,
            (Time(this), Time(other)) => this <= other,
            _ => false, // Not the same units.
        }
    }

    /// Returns true if this [`relative::LockTime`] is satisfied by [`Height`].
    ///
    /// # Errors
    ///
    /// Returns an error if this lock is not lock-by-height.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dashcore::locktime::relative::{LockTime, Height, Time};
    ///
    /// let height: u16 = 100;
    /// let lock = LockTime::from(Height::from_count(height));
    /// assert!(lock.is_satisfied_by_height(Height::from_count(height+1)).expect("a height"));
    /// ```
    #[inline]
    pub fn is_satisfied_by_height(&self, h: Height) -> Result<bool, Error> {
        use LockTime::*;

        match *self {
            Blocks(ref height) => Ok(*height <= h),
            Time(ref time) => Err(Error::IncompatibleTime(*self, *time)),
        }
    }

    /// Returns true if this [`relative::LockTime`] is satisfied by [`Time`].
    ///
    /// # Errors
    ///
    /// Returns an error if this lock is not lock-by-time.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dashcore::locktime::relative::{LockTime, Height, Time};
    ///
    /// let intervals: u16 = 70; // approx 10 hours;
    /// let lock = LockTime::from(Time::from_512_second_intervals(intervals));
    /// assert!(lock.is_satisfied_by_time(Time::from_512_second_intervals(intervals + 10)).expect("a time"));
    /// ```
    #[inline]
    pub fn is_satisfied_by_time(&self, t: Time) -> Result<bool, Error> {
        use LockTime::*;

        match *self {
            Time(ref time) => Ok(*time <= t),
            Blocks(ref height) => Err(Error::IncompatibleHeight(*self, *height)),
        }
    }
}

impl From<Height> for LockTime {
    #[inline]
    fn from(h: Height) -> Self {
        LockTime::Blocks(h)
    }
}

impl From<Time> for LockTime {
    #[inline]
    fn from(t: Time) -> Self {
        LockTime::Time(t)
    }
}

impl fmt::Display for LockTime {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use LockTime::*;

        if f.alternate() {
            match *self {
                Blocks(ref h) => write!(f, "block-height {}", h),
                Time(ref t) => write!(f, "block-time {} (512 second intervals)", t),
            }
        } else {
            match *self {
                Blocks(ref h) => fmt::Display::fmt(h, f),
                Time(ref t) => fmt::Display::fmt(t, f),
            }
        }
    }
}

/// Errors related to relative lock times.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Tried to satisfy a lock-by-blocktime lock using a height value.
    IncompatibleHeight(LockTime, Height),
    /// Tried to satisfy a lock-by-blockheight lock using a time value.
    IncompatibleTime(LockTime, Time),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::IncompatibleHeight(lock, height) => {
                write!(f, "tried to satisfy lock {} with height: {}", lock, height)
            }
            Self::IncompatibleTime(lock, time) => {
                write!(f, "tried to satisfy lock {} with time: {}", lock, time)
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match *self {
            IncompatibleHeight(_, _) | IncompatibleTime(_, _) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn satisfied_by_height() {
        let height = Height::from_count(10);
        let time = Time::from_512_second_intervals(70);

        let lock = LockTime::from(height);

        assert!(!lock.is_satisfied_by(Height::from_count(9), time));
        assert!(lock.is_satisfied_by(Height::from_count(10), time));
        assert!(lock.is_satisfied_by(Height::from_count(11), time));
    }

    #[test]
    fn satisfied_by_time() {
        let height = Height::from_count(10);
        let time = Time::from_512_second_intervals(70);

        let lock = LockTime::from(time);

        assert!(!lock.is_satisfied_by(height, Time::from_512_second_intervals(69)));
        assert!(lock.is_satisfied_by(height, Time::from_512_second_intervals(70)));
        assert!(lock.is_satisfied_by(height, Time::from_512_second_intervals(71)));
    }

    #[test]
    fn height_correctly_implies() {
        let height = Height::from_count(10);
        let lock = LockTime::from(height);

        assert!(!lock.is_implied_by(LockTime::from(Height::from_count(9))));
        assert!(lock.is_implied_by(LockTime::from(Height::from_count(10))));
        assert!(lock.is_implied_by(LockTime::from(Height::from_count(11))));
    }

    #[test]
    fn time_correctly_implies() {
        let time = Time::from_512_second_intervals(70);
        let lock = LockTime::from(time);

        assert!(!lock.is_implied_by(LockTime::from(Time::from_512_second_intervals(69))));
        assert!(lock.is_implied_by(LockTime::from(Time::from_512_second_intervals(70))));
        assert!(lock.is_implied_by(LockTime::from(Time::from_512_second_intervals(71))));
    }

    #[test]
    fn incorrect_units_do_not_imply() {
        let time = Time::from_512_second_intervals(70);
        let height = Height::from_count(10);

        let lock = LockTime::from(time);
        assert!(!lock.is_implied_by(LockTime::from(height)));
    }
}
