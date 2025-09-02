//! Test helper functions and utilities

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

/// Mock storage for testing
pub struct MockStorage<K, V> {
    data: Arc<Mutex<HashMap<K, V>>>,
}

impl<K: Eq + std::hash::Hash + Clone, V: Clone> MockStorage<K, V> {
    pub fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn insert(&self, key: K, value: V) {
        self.data.lock().unwrap().insert(key, value);
    }

    pub fn get(&self, key: &K) -> Option<V> {
        self.data.lock().unwrap().get(key).cloned()
    }

    pub fn remove(&self, key: &K) -> Option<V> {
        self.data.lock().unwrap().remove(key)
    }

    pub fn clear(&self) {
        self.data.lock().unwrap().clear();
    }

    pub fn len(&self) -> usize {
        self.data.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.lock().unwrap().is_empty()
    }
}

impl<K, V> Default for MockStorage<K, V> {
    fn default() -> Self {
        Self {
            data: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

/// Test error injection helper
pub struct ErrorInjector {
    should_fail: Arc<Mutex<bool>>,
    fail_count: Arc<Mutex<usize>>,
}

impl ErrorInjector {
    pub fn new() -> Self {
        Self {
            should_fail: Arc::new(Mutex::new(false)),
            fail_count: Arc::new(Mutex::new(0)),
        }
    }

    /// Enable error injection
    pub fn enable(&self) {
        *self.should_fail.lock().unwrap() = true;
    }

    /// Disable error injection
    pub fn disable(&self) {
        *self.should_fail.lock().unwrap() = false;
    }

    /// Set to fail after n successful calls
    pub fn fail_after(&self, n: usize) {
        *self.fail_count.lock().unwrap() = n;
    }

    /// Check if should inject error
    pub fn should_fail(&self) -> bool {
        let mut count = self.fail_count.lock().unwrap();
        if *count > 0 {
            *count -= 1;
            false
        } else {
            *self.should_fail.lock().unwrap()
        }
    }
}

impl Default for ErrorInjector {
    fn default() -> Self {
        Self::new()
    }
}

/// Assert that two byte slices are equal, with helpful error message
pub fn assert_bytes_eq(actual: &[u8], expected: &[u8]) {
    if actual != expected {
        panic!(
            "Byte arrays not equal\nActual:   {:?}\nExpected: {:?}\nActual hex:   {}\nExpected hex: {}",
            actual,
            expected,
            hex::encode(actual),
            hex::encode(expected)
        );
    }
}

/// Create a temporary directory that's cleaned up on drop
pub struct TempDir {
    path: std::path::PathBuf,
}

impl TempDir {
    pub fn new() -> std::io::Result<Self> {
        let path = std::env::temp_dir().join(format!("dashcore-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&path)?;
        Ok(Self {
            path,
        })
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Helper to run async tests with timeout
#[cfg(feature = "async")]
pub async fn with_timeout<F, T>(duration: std::time::Duration, future: F) -> Result<T, &'static str>
where
    F: std::future::Future<Output = T>,
{
    tokio::time::timeout(duration, future).await.map_err(|_| "Test timed out")
}

/// Helper to assert that a closure panics with a specific message
pub fn assert_panic_contains<F: FnOnce() + std::panic::UnwindSafe>(f: F, expected_msg: &str) {
    let result = std::panic::catch_unwind(f);
    match result {
        Ok(_) => panic!(
            "Expected panic with message containing '{}', but no panic occurred",
            expected_msg
        ),
        Err(panic_info) => {
            let msg = if let Some(s) = panic_info.downcast_ref::<String>() {
                s.clone()
            } else if let Some(s) = panic_info.downcast_ref::<&str>() {
                s.to_string()
            } else {
                format!("{:?}", panic_info)
            };

            if !msg.contains(expected_msg) {
                panic!("Expected panic message to contain '{}', but got '{}'", expected_msg, msg);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_storage() {
        let storage: MockStorage<String, i32> = MockStorage::new();

        storage.insert("key1".to_string(), 42);
        assert_eq!(storage.get(&"key1".to_string()), Some(42));
        assert_eq!(storage.len(), 1);

        storage.remove(&"key1".to_string());
        assert_eq!(storage.get(&"key1".to_string()), None);
        assert_eq!(storage.len(), 0);
    }

    #[test]
    fn test_error_injector() {
        let injector = ErrorInjector::new();

        assert!(!injector.should_fail());

        injector.enable();
        assert!(injector.should_fail());

        injector.disable();
        injector.fail_after(2);
        assert!(!injector.should_fail()); // First call
        assert!(!injector.should_fail()); // Second call
        injector.enable(); // Need to enable for the third call to fail
        assert!(injector.should_fail()); // Third call (fails)
    }

    #[test]
    fn test_assert_panic_contains() {
        assert_panic_contains(|| panic!("This is a test panic"), "test panic");
    }

    #[test]
    #[should_panic(expected = "Expected panic")]
    fn test_assert_panic_contains_no_panic() {
        assert_panic_contains(|| { /* no panic */ }, "anything");
    }
}
