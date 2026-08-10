#[cfg(test)]
mod transaction_tests {
    use super::super::{transaction_bytes_free, transaction_bytes_into_ffi_buffer};
    use std::ptr;

    /// Freeing a null pointer must be a safe no-op.
    #[test]
    fn transaction_bytes_free_null_is_noop() {
        unsafe {
            transaction_bytes_free(ptr::null_mut());
        }
    }

    /// Freeing a pointer produced by the FFI transaction buffer helper must
    /// recover the hidden length prefix and drop the original boxed slice.
    #[test]
    fn transaction_bytes_free_releases_prefixed_buffer() {
        let payload: Vec<u8> = (0u8..64).collect();
        let expected_len = payload.len();
        let (raw, len) = transaction_bytes_into_ffi_buffer(payload);
        assert_eq!(len, expected_len);
        assert!(!raw.is_null());

        unsafe {
            transaction_bytes_free(raw);
        }
        // Reaching this line without aborting is the success criterion;
        // double-free or layout mismatches would have tripped the allocator.
    }

    /// A zero-length transaction payload still has a hidden prefix allocation
    /// and must be freeable through the same ABI-stable function.
    #[test]
    fn transaction_bytes_free_handles_empty_buffer() {
        let (raw, len) = transaction_bytes_into_ffi_buffer(Vec::new());
        assert_eq!(len, 0);
        assert!(!raw.is_null());

        unsafe {
            transaction_bytes_free(raw);
        }
    }
}
