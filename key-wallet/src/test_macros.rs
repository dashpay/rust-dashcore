//! Test macros for key-wallet.

#[cfg(all(test, feature = "serde"))]
macro_rules! serde_round_trip {
    ($var:expr) => {{
        use serde_json;

        let encoded = serde_json::to_value(&$var).unwrap();
        let decoded = serde_json::from_value(encoded).unwrap();
        assert_eq!($var, decoded);
    }};
}
