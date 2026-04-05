//! Merge trait for composing incremental changesets.
//!
//! Types that implement [`Merge`] can accumulate successive deltas
//! and be inspected to see whether they carry any data.

use std::collections::{BTreeMap, BTreeSet};

/// A type that can absorb another instance of itself, accumulating changes.
pub trait Merge: Default {
    /// Merge `other` into `self`, consuming `other`.
    fn merge(&mut self, other: Self);

    /// Returns `true` when the value is semantically empty (no changes).
    fn is_empty(&self) -> bool;

    /// Take the contents out of `self` (leaving it empty/default) if it is
    /// non-empty, otherwise return `None`.
    fn take(&mut self) -> Option<Self>
    where
        Self: Sized,
    {
        if self.is_empty() {
            None
        } else {
            Some(std::mem::take(self))
        }
    }
}

// ---------------------------------------------------------------------------
// Blanket / standard impls
// ---------------------------------------------------------------------------

impl<K: Ord, V> Merge for BTreeMap<K, V> {
    fn merge(&mut self, other: Self) {
        self.extend(other);
    }

    fn is_empty(&self) -> bool {
        self.is_empty()
    }
}

impl<T: Ord> Merge for BTreeSet<T> {
    fn merge(&mut self, other: Self) {
        for item in other {
            self.insert(item);
        }
    }

    fn is_empty(&self) -> bool {
        self.is_empty()
    }
}

impl<T: Merge> Merge for Option<T> {
    fn merge(&mut self, other: Self) {
        match (self.as_mut(), other) {
            (Some(existing), Some(other_val)) => existing.merge(other_val),
            (None, Some(other_val)) => *self = Some(other_val),
            _ => {}
        }
    }

    fn is_empty(&self) -> bool {
        match self {
            Some(inner) => inner.is_empty(),
            None => true,
        }
    }
}

impl<T> Merge for Vec<T> {
    fn merge(&mut self, other: Self) {
        self.extend(other);
    }

    fn is_empty(&self) -> bool {
        self.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn btreemap_merge_extends() {
        let mut a: BTreeMap<&str, i32> = [("x", 1)].into_iter().collect();
        let b: BTreeMap<&str, i32> = [("y", 2), ("x", 3)].into_iter().collect();
        a.merge(b);
        // "x" should be overwritten by the `other` value (BTreeMap::extend behaviour)
        assert_eq!(a.get("x"), Some(&3));
        assert_eq!(a.get("y"), Some(&2));
        assert_eq!(a.len(), 2);
    }

    #[test]
    fn btreemap_is_empty() {
        let empty: BTreeMap<String, u32> = BTreeMap::new();
        assert!(Merge::is_empty(&empty));

        let non_empty: BTreeMap<String, u32> = [("a".into(), 1)].into_iter().collect();
        assert!(!Merge::is_empty(&non_empty));
    }

    #[test]
    fn btreeset_merge_unions() {
        let mut a: BTreeSet<u32> = [1, 2, 3].into_iter().collect();
        let b: BTreeSet<u32> = [3, 4, 5].into_iter().collect();
        a.merge(b);
        assert_eq!(a, [1, 2, 3, 4, 5].into_iter().collect());
    }

    #[test]
    fn btreeset_is_empty() {
        let empty: BTreeSet<u32> = BTreeSet::new();
        assert!(Merge::is_empty(&empty));
    }

    #[test]
    fn vec_merge_appends() {
        let mut a = vec![1, 2];
        let b = vec![3, 4];
        a.merge(b);
        assert_eq!(a, vec![1, 2, 3, 4]);
    }

    #[test]
    fn vec_is_empty() {
        let empty: Vec<u8> = vec![];
        assert!(Merge::is_empty(&empty));
        let non_empty = vec![42];
        assert!(!Merge::is_empty(&non_empty));
    }

    #[test]
    fn option_merge_some_into_none() {
        let mut a: Option<Vec<u32>> = None;
        let b: Option<Vec<u32>> = Some(vec![1]);
        a.merge(b);
        assert_eq!(a, Some(vec![1]));
    }

    #[test]
    fn option_merge_some_into_some() {
        let mut a: Option<Vec<u32>> = Some(vec![1]);
        let b: Option<Vec<u32>> = Some(vec![2]);
        a.merge(b);
        assert_eq!(a, Some(vec![1, 2]));
    }

    #[test]
    fn option_merge_none_into_some() {
        let mut a: Option<Vec<u32>> = Some(vec![1]);
        let b: Option<Vec<u32>> = None;
        a.merge(b);
        assert_eq!(a, Some(vec![1]));
    }

    #[test]
    fn option_is_empty() {
        let none: Option<Vec<u32>> = None;
        assert!(Merge::is_empty(&none));

        let some_empty: Option<Vec<u32>> = Some(vec![]);
        assert!(Merge::is_empty(&some_empty));

        let some_non_empty: Option<Vec<u32>> = Some(vec![1]);
        assert!(!Merge::is_empty(&some_non_empty));
    }

    #[test]
    fn take_returns_none_when_empty() {
        let mut v: Vec<u32> = vec![];
        assert_eq!(v.take(), None);
    }

    #[test]
    fn take_returns_some_and_resets() {
        let mut v = vec![1, 2, 3];
        let taken = v.take();
        assert_eq!(taken, Some(vec![1, 2, 3]));
        assert!(v.is_empty());
    }
}
