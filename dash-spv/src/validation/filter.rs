//! Filter validation functionality.
//!
//! Provides verification of compact block filters against their
//! corresponding filter headers.

use std::collections::HashMap;

use dashcore::bip158::BlockFilter;
use dashcore::hash_types::FilterHeader;
use key_wallet_manager::wallet_manager::FilterMatchKey;
use rayon::prelude::*;

use crate::error::{ValidationError, ValidationResult};
use crate::validation::Validator;

/// Input data for filter validation.
pub struct FilterValidationInput<'a> {
    /// The filters to validate, keyed by (height, block_hash).
    pub filters: &'a HashMap<FilterMatchKey, BlockFilter>,
    /// Expected filter headers indexed by height.
    pub expected_headers: &'a HashMap<u32, FilterHeader>,
    /// Filter header at (batch_start - 1) for chaining verification.
    pub prev_filter_header: FilterHeader,
}

/// Validates compact block filters against their expected headers.
///
/// Each filter's header is computed by chaining from the previous filter header,
/// then compared against the expected header from storage. Uses rayon for
/// parallel verification.
#[derive(Default)]
pub struct FilterValidator;

impl FilterValidator {
    pub fn new() -> Self {
        Self
    }
}

impl Validator<FilterValidationInput<'_>> for FilterValidator {
    fn validate(&self, input: FilterValidationInput<'_>) -> ValidationResult<()> {
        if input.filters.is_empty() {
            return Ok(());
        }

        // Build the prev_header chain for verification.
        // Each filter at height H needs prev_header at H-1.
        // We start with prev_filter_header and chain forward using expected headers.
        let mut prev_headers: HashMap<u32, FilterHeader> = HashMap::new();

        // Sort keys by height to build chain correctly
        let mut heights: Vec<u32> = input.filters.keys().map(|k| k.height()).collect();
        heights.sort();

        // Build prev_header map
        let mut prev = input.prev_filter_header;
        for &height in &heights {
            prev_headers.insert(height, prev);
            // The expected header at this height becomes the prev for the next
            if let Some(&expected) = input.expected_headers.get(&height) {
                prev = expected;
            }
        }

        // Verify all filters in parallel
        let failures: Vec<(u32, String)> = input
            .filters
            .par_iter()
            .filter_map(|(key, filter)| {
                let height = key.height();

                // Get prev_header for this filter
                let Some(prev_header) = prev_headers.get(&height) else {
                    return Some((height, "Missing prev header".to_string()));
                };

                // Get expected header for this filter
                let Some(expected_header) = input.expected_headers.get(&height) else {
                    return Some((height, "Missing expected header".to_string()));
                };

                // Compute header from filter and compare
                let computed = filter.filter_header(prev_header);
                if computed != *expected_header {
                    return Some((
                        height,
                        format!(
                            "Header mismatch: computed {:?} != expected {:?}",
                            computed, expected_header
                        ),
                    ));
                }

                None // Verification passed
            })
            .collect();

        if !failures.is_empty() {
            let details: Vec<String> = failures
                .iter()
                .take(5) // Limit to first 5 failures for the error message
                .map(|(h, msg)| format!("height {}: {}", h, msg))
                .collect();

            tracing::error!(
                "Filter verification failed for {} filters: {:?}",
                failures.len(),
                details
            );

            return Err(ValidationError::InvalidFilterHeaderChain(format!(
                "Filter verification failed for {} filters. First failure: {}",
                failures.len(),
                details.first().unwrap_or(&"unknown".to_string())
            )));
        }

        tracing::debug!("Verified {} filters successfully", input.filters.len());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use dashcore::bip158::BlockFilter;
    use dashcore::BlockHash;
    use dashcore_hashes::Hash;
    use key_wallet_manager::wallet_manager::FilterMatchKey;

    use super::*;

    fn test_hash(n: u8) -> BlockHash {
        BlockHash::from_byte_array([n; 32])
    }

    fn zero_filter_header() -> FilterHeader {
        FilterHeader::all_zeros()
    }

    #[test]
    fn test_verify_empty_batch() {
        let validator = FilterValidator::new();
        let filters = HashMap::new();
        let headers = HashMap::new();
        let prev = zero_filter_header();

        let input = FilterValidationInput {
            filters: &filters,
            expected_headers: &headers,
            prev_filter_header: prev,
        };

        let result = validator.validate(input);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_single_filter_success() {
        let validator = FilterValidator::new();

        // Create a filter
        let filter_data = vec![0u8; 10];
        let filter = BlockFilter::new(&filter_data);
        let prev_header = zero_filter_header();

        // Compute what the expected header should be
        let expected_header = filter.filter_header(&prev_header);

        // Build inputs
        let mut filters = HashMap::new();
        let key = FilterMatchKey::new(1, test_hash(1));
        filters.insert(key, filter);

        let mut expected_headers = HashMap::new();
        expected_headers.insert(1, expected_header);

        let input = FilterValidationInput {
            filters: &filters,
            expected_headers: &expected_headers,
            prev_filter_header: prev_header,
        };

        // Verify should pass
        let result = validator.validate(input);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_single_filter_failure() {
        let validator = FilterValidator::new();

        // Create a filter
        let filter_data = vec![0u8; 10];
        let filter = BlockFilter::new(&filter_data);
        let prev_header = zero_filter_header();

        // Use a WRONG expected header
        let wrong_expected = FilterHeader::from_byte_array([0xFF; 32]);

        // Build inputs
        let mut filters = HashMap::new();
        let key = FilterMatchKey::new(1, test_hash(1));
        filters.insert(key, filter);

        let mut expected_headers = HashMap::new();
        expected_headers.insert(1, wrong_expected);

        let input = FilterValidationInput {
            filters: &filters,
            expected_headers: &expected_headers,
            prev_filter_header: prev_header,
        };

        // Verify should fail
        let result = validator.validate(input);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ValidationError::InvalidFilterHeaderChain(_)));
    }

    #[test]
    fn test_verify_multiple_filters_success() {
        let validator = FilterValidator::new();
        let prev_header = zero_filter_header();

        // Create filters and compute expected headers in chain
        let filter_data_1 = vec![1u8; 10];
        let filter_1 = BlockFilter::new(&filter_data_1);
        let expected_1 = filter_1.filter_header(&prev_header);

        let filter_data_2 = vec![2u8; 10];
        let filter_2 = BlockFilter::new(&filter_data_2);
        let expected_2 = filter_2.filter_header(&expected_1);

        let filter_data_3 = vec![3u8; 10];
        let filter_3 = BlockFilter::new(&filter_data_3);
        let expected_3 = filter_3.filter_header(&expected_2);

        // Build inputs
        let mut filters = HashMap::new();
        filters.insert(FilterMatchKey::new(1, test_hash(1)), filter_1);
        filters.insert(FilterMatchKey::new(2, test_hash(2)), filter_2);
        filters.insert(FilterMatchKey::new(3, test_hash(3)), filter_3);

        let mut expected_headers = HashMap::new();
        expected_headers.insert(1, expected_1);
        expected_headers.insert(2, expected_2);
        expected_headers.insert(3, expected_3);

        let input = FilterValidationInput {
            filters: &filters,
            expected_headers: &expected_headers,
            prev_filter_header: prev_header,
        };

        // Verify should pass
        let result = validator.validate(input);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_missing_expected_header() {
        let validator = FilterValidator::new();

        let filter_data = vec![0u8; 10];
        let filter = BlockFilter::new(&filter_data);
        let prev_header = zero_filter_header();

        // Build inputs with NO expected header
        let mut filters = HashMap::new();
        let key = FilterMatchKey::new(1, test_hash(1));
        filters.insert(key, filter);

        let expected_headers = HashMap::new(); // Empty!

        let input = FilterValidationInput {
            filters: &filters,
            expected_headers: &expected_headers,
            prev_filter_header: prev_header,
        };

        // Verify should fail
        let result = validator.validate(input);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_large_batch_parallel() {
        let validator = FilterValidator::new();

        // Create 150 filters to exercise rayon parallel verification
        let prev_header = zero_filter_header();
        let mut filters = HashMap::new();
        let mut expected_headers = HashMap::new();

        let mut prev = prev_header;
        for i in 1..=150u32 {
            let filter_data: Vec<u8> = (0..20).map(|j| ((i + j) % 256) as u8).collect();
            let filter = BlockFilter::new(&filter_data);
            let expected = filter.filter_header(&prev);
            expected_headers.insert(i, expected);
            filters.insert(FilterMatchKey::new(i, test_hash(i as u8)), filter);
            prev = expected;
        }

        let input = FilterValidationInput {
            filters: &filters,
            expected_headers: &expected_headers,
            prev_filter_header: prev_header,
        };

        let result = validator.validate(input);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_large_batch_with_failure() {
        let validator = FilterValidator::new();

        // Create batch where one filter fails verification
        let prev_header = zero_filter_header();
        let mut filters = HashMap::new();
        let mut expected_headers = HashMap::new();

        let mut prev = prev_header;
        for i in 1..=100u32 {
            let filter_data: Vec<u8> = (0..20).map(|j| ((i + j) % 256) as u8).collect();
            let filter = BlockFilter::new(&filter_data);
            let expected = filter.filter_header(&prev);

            // Corrupt one expected header in the middle
            if i == 50 {
                expected_headers.insert(i, FilterHeader::from_byte_array([0xFF; 32]));
            } else {
                expected_headers.insert(i, expected);
            }

            filters.insert(FilterMatchKey::new(i, test_hash(i as u8)), filter);
            prev = expected;
        }

        let input = FilterValidationInput {
            filters: &filters,
            expected_headers: &expected_headers,
            prev_filter_header: prev_header,
        };

        let result = validator.validate(input);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ValidationError::InvalidFilterHeaderChain(_)));
    }

    #[test]
    fn test_verify_noncontiguous_heights() {
        let validator = FilterValidator::new();

        // Verify works correctly with non-contiguous heights (gaps)
        let prev_header = zero_filter_header();
        let mut filters = HashMap::new();
        let mut expected_headers = HashMap::new();

        let heights = [10u32, 20, 30];
        let mut prev = prev_header;

        for &h in &heights {
            let filter_data = vec![h as u8; 10];
            let filter = BlockFilter::new(&filter_data);
            let expected = filter.filter_header(&prev);
            expected_headers.insert(h, expected);
            filters.insert(FilterMatchKey::new(h, test_hash(h as u8)), filter);
            prev = expected;
        }

        let input = FilterValidationInput {
            filters: &filters,
            expected_headers: &expected_headers,
            prev_filter_header: prev_header,
        };

        let result = validator.validate(input);
        assert!(result.is_ok());
    }
}
