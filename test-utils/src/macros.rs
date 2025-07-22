//! Test macros for common testing patterns

/// Macro to test serde round-trip serialization
#[macro_export]
macro_rules! test_serde_round_trip {
    ($value:expr) => {{
        let serialized = serde_json::to_string(&$value).expect("Failed to serialize");
        let deserialized = serde_json::from_str(&serialized).expect("Failed to deserialize");
        assert_eq!($value, deserialized, "Serde round-trip failed");
    }};
}

/// Macro to test binary serialization round-trip
#[macro_export]
macro_rules! test_serialize_round_trip {
    ($value:expr) => {{
        use dashcore::consensus::encode::{serialize, deserialize};
        let serialized = serialize(&$value);
        let deserialized: Result<_, _> = deserialize(&serialized);
        assert_eq!($value, deserialized.expect("Failed to deserialize"), "Binary round-trip failed");
    }};
}

/// Macro to assert an error contains a specific substring
#[macro_export]
macro_rules! assert_error_contains {
    ($result:expr, $expected:expr) => {{
        match $result {
            Ok(_) => panic!("Expected error containing '{}', but got Ok", $expected),
            Err(e) => {
                let error_str = format!("{}", e);
                if !error_str.contains($expected) {
                    panic!(
                        "Expected error to contain '{}', but got '{}'",
                        $expected, error_str
                    );
                }
            }
        }
    }};
}

/// Macro to create a test with multiple test cases
#[macro_export]
macro_rules! parameterized_test {
    ($test_name:ident, $test_fn:expr, $( ($name:expr, $($arg:expr),+) ),+ $(,)?) => {
        #[test]
        fn $test_name() {
            $(
                println!("Running test case: {}", $name);
                $test_fn($($arg),+);
            )+
        }
    };
}

/// Macro to assert two results are equal, handling both Ok and Err cases
#[macro_export]
macro_rules! assert_results_eq {
    ($left:expr, $right:expr) => {{
        match (&$left, &$right) {
            (Ok(l), Ok(r)) => assert_eq!(l, r, "Ok values not equal"),
            (Err(l), Err(r)) => assert_eq!(format!("{}", l), format!("{}", r), "Error messages not equal"),
            (Ok(_), Err(e)) => panic!("Expected Ok, got Err({})", e),
            (Err(e), Ok(_)) => panic!("Expected Err({}), got Ok", e),
        }
    }};
}

/// Macro to measure execution time of a block
#[macro_export]
macro_rules! measure_time {
    ($label:expr, $block:block) => {{
        let start = std::time::Instant::now();
        let result = $block;
        let duration = start.elapsed();
        println!("{}: {:?}", $label, duration);
        result
    }};
}

#[cfg(test)]
mod tests {
    use serde::{Serialize, Deserialize};
    
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct TestStruct {
        field: String,
    }
    
    #[test]
    fn test_serde_macro() {
        let value = TestStruct { field: "test".to_string() };
        test_serde_round_trip!(value);
    }
    
    #[test]
    fn test_error_contains_macro() {
        let result: Result<(), String> = Err("This is an error message".to_string());
        assert_error_contains!(result, "error message");
    }
    
    #[test]
    #[should_panic(expected = "Expected error")]
    fn test_error_contains_macro_with_ok() {
        let result: Result<i32, String> = Ok(42);
        assert_error_contains!(result, "anything");
    }
    
    parameterized_test!(
        test_addition,
        |a: i32, b: i32, expected: i32| {
            assert_eq!(a + b, expected);
        },
        ("1+1", 1, 1, 2),
        ("2+3", 2, 3, 5),
        ("0+0", 0, 0, 0)
    );
    
    #[test]
    fn test_measure_time_macro() {
        let result = measure_time!("Test operation", {
            std::thread::sleep(std::time::Duration::from_millis(10));
            42
        });
        assert_eq!(result, 42);
    }
}