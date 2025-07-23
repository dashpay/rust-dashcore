//! Parallel execution infrastructure for QRInfo synchronization.
//!
//! This module provides concurrent execution of QRInfo requests with
//! concurrency control, progress reporting, and error handling.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashcore::BlockHash;
use tokio::sync::{mpsc, Mutex, Semaphore};
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::error::{NetworkError, SyncError, SyncResult};
use crate::network::{NetworkManager, correlation::QRInfoCorrelationManager};
use crate::sync::discovery::QRInfoRequest;

/// Progress information for QRInfo synchronization.
#[derive(Debug, Clone)]
pub struct QRInfoSyncProgress {
    /// Number of completed requests.
    pub completed_requests: usize,
    /// Total number of requests.
    pub total_requests: usize,
    /// Current operation description.
    pub current_operation: String,
    /// Estimated time remaining.
    pub estimated_remaining: Duration,
}

/// Trait for processing QRInfo responses.
#[async_trait::async_trait]
pub trait QRInfoProcessor: Send + Sync {
    /// Process a received QRInfo message.
    async fn process_qr_info(
        &mut self,
        qr_info: dashcore::network::message_qrinfo::QRInfo,
    ) -> SyncResult<()>;
}

/// Manages parallel execution of QRInfo requests with concurrency control.
pub struct ParallelQRInfoExecutor {
    /// Maximum concurrent requests.
    max_concurrent: usize,
    /// Semaphore for controlling concurrency.
    semaphore: Arc<Semaphore>,
    /// Network timeout for individual requests.
    request_timeout: Duration,
    /// Progress reporting channel.
    progress_tx: Option<mpsc::UnboundedSender<QRInfoSyncProgress>>,
    /// Correlation manager for matching requests and responses.
    correlation_manager: Arc<Mutex<QRInfoCorrelationManager>>,
}

impl ParallelQRInfoExecutor {
    /// Create a new parallel executor.
    pub fn new(max_concurrent: usize, request_timeout: Duration) -> Self {
        Self {
            max_concurrent,
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            request_timeout,
            progress_tx: None,
            correlation_manager: Arc::new(Mutex::new(QRInfoCorrelationManager::new())),
        }
    }

    /// Add progress reporting capability.
    pub fn with_progress_reporting(
        mut self,
        tx: mpsc::UnboundedSender<QRInfoSyncProgress>,
    ) -> Self {
        self.progress_tx = Some(tx);
        self
    }
    
    /// Get a reference to the correlation manager for handling responses.
    pub fn correlation_manager(&self) -> Arc<Mutex<QRInfoCorrelationManager>> {
        self.correlation_manager.clone()
    }

    /// Execute multiple QRInfo requests in parallel with controlled concurrency.
    pub async fn execute_parallel_requests(
        &self,
        requests: Vec<QRInfoRequest>,
        network: Arc<Mutex<dyn NetworkManager>>,
        processor: Arc<Mutex<dyn QRInfoProcessor>>,
    ) -> Result<Vec<QRInfoResult>, ParallelExecutionError> {
        if requests.is_empty() {
            return Ok(Vec::new());
        }

        tracing::info!(
            "Starting parallel execution of {} QRInfo requests with max_concurrent={}",
            requests.len(),
            self.max_concurrent
        );

        let mut join_set = JoinSet::new();
        let total_requests = requests.len();
        let completed = Arc::new(AtomicUsize::new(0));

        // Launch parallel tasks
        for (index, request) in requests.into_iter().enumerate() {
            let semaphore = self.semaphore.clone();
            let network = network.clone();
            let processor = processor.clone();
            let completed = completed.clone();
            let progress_tx = self.progress_tx.clone();
            let timeout_duration = self.request_timeout;
            let correlation_manager = self.correlation_manager.clone();

            let task = async move {
                // Acquire semaphore permit for concurrency control
                let _permit = match semaphore.acquire().await {
                    Ok(permit) => permit,
                    Err(_) => {
                        return QRInfoResult {
                            request,
                            success: false,
                            processing_time: Instant::now(),
                            error: Some(ParallelExecutionError::SemaphoreError),
                        }
                    }
                };

                tracing::debug!(
                    "Starting QRInfo request {}/{}: heights {}-{}",
                    index + 1,
                    total_requests,
                    request.base_height,
                    request.tip_height
                );

                // Execute request with timeout
                let result = timeout(timeout_duration, async {
                    // Send network request
                    {
                        let mut net = network.lock().await;
                        net.request_qr_info(
                            vec![request.base_hash],
                            request.tip_hash,
                            request.extra_share,
                        )
                        .await?;
                    }

                    // Wait for and process response
                    let qr_info = Self::wait_for_qr_info_response(
                        correlation_manager,
                        &request,
                        timeout_duration,
                    ).await?;

                    {
                        let mut proc = processor.lock().await;
                        proc.process_qr_info(qr_info).await?;
                    }

                    Ok::<QRInfoResult, ParallelExecutionError>(QRInfoResult {
                        request: request.clone(),
                        success: true,
                        processing_time: Instant::now(),
                        error: None,
                    })
                })
                .await;

                // Update progress
                let completed_count = completed.fetch_add(1, Ordering::Relaxed) + 1;
                if let Some(ref tx) = progress_tx {
                    let _ = tx.send(QRInfoSyncProgress {
                        completed_requests: completed_count,
                        total_requests,
                        current_operation: format!("QRInfo {}/{}", completed_count, total_requests),
                        estimated_remaining: Self::estimate_remaining_time(
                            completed_count,
                            total_requests,
                            timeout_duration,
                        ),
                    });
                }

                match result {
                    Ok(Ok(success_result)) => {
                        tracing::debug!(
                            "Completed QRInfo request {}/{} successfully",
                            index + 1,
                            total_requests
                        );
                        success_result
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(
                            "QRInfo request {}/{} failed: {}",
                            index + 1,
                            total_requests,
                            e
                        );
                        QRInfoResult {
                            request,
                            success: false,
                            processing_time: Instant::now(),
                            error: Some(e),
                        }
                    }
                    Err(_) => {
                        tracing::error!(
                            "QRInfo request {}/{} timed out after {:?}",
                            index + 1,
                            total_requests,
                            timeout_duration
                        );
                        QRInfoResult {
                            request,
                            success: false,
                            processing_time: Instant::now(),
                            error: Some(ParallelExecutionError::RequestTimeout),
                        }
                    }
                }
            };

            join_set.spawn(task);
        }

        // Collect all results
        let mut results = Vec::with_capacity(total_requests);
        while let Some(task_result) = join_set.join_next().await {
            match task_result {
                Ok(qr_info_result) => results.push(qr_info_result),
                Err(e) => {
                    tracing::error!("Task execution error: {}", e);
                    return Err(ParallelExecutionError::TaskError(e.to_string()));
                }
            }
        }

        // Sort results back to original request order for consistency
        results.sort_by_key(|r| r.request.tip_height);

        let success_count = results.iter().filter(|r| r.success).count();
        let failure_count = results.len() - success_count;

        tracing::info!(
            "Parallel QRInfo execution completed: {}/{} successful, {} failed",
            success_count,
            total_requests,
            failure_count
        );

        Ok(results)
    }

    /// Wait for QRInfo response for a specific request.
    async fn wait_for_qr_info_response(
        correlation_manager: Arc<Mutex<QRInfoCorrelationManager>>,
        request: &QRInfoRequest,
        timeout_duration: Duration,
    ) -> Result<dashcore::network::message_qrinfo::QRInfo, ParallelExecutionError> {
        // Register the request and get the response receiver
        let response_rx = {
            let mut manager = correlation_manager.lock().await;
            let (_request_id, rx) = manager.register_request(request.base_hash, request.tip_hash);
            rx
        };
        
        // Wait for the response with timeout
        match timeout(timeout_duration, response_rx).await {
            Ok(Ok(Ok(qr_info))) => Ok(qr_info),
            Ok(Ok(Err(e))) => Err(ParallelExecutionError::CorrelationError(e.to_string())),
            Ok(Err(_)) => Err(ParallelExecutionError::ChannelClosed),
            Err(_) => {
                // Timeout occurred, clean up expired requests
                let mut manager = correlation_manager.lock().await;
                manager.cleanup_expired_requests(timeout_duration);
                Err(ParallelExecutionError::RequestTimeout)
            }
        }
    }

    fn estimate_remaining_time(completed: usize, total: usize, avg_time: Duration) -> Duration {
        if completed == 0 || completed >= total {
            return Duration::ZERO;
        }

        let remaining = total - completed;
        let completion_rate = completed as f32 / avg_time.as_secs_f32();
        Duration::from_secs_f32(remaining as f32 / completion_rate)
    }
}

/// Result of a QRInfo request execution.
#[derive(Debug, Clone)]
pub struct QRInfoResult {
    /// The original request.
    pub request: QRInfoRequest,
    /// Whether the request succeeded.
    pub success: bool,
    /// When the request completed.
    pub processing_time: Instant,
    /// Error if the request failed.
    pub error: Option<ParallelExecutionError>,
}

/// Errors that can occur during parallel execution.
#[derive(Debug, thiserror::Error, Clone)]
pub enum ParallelExecutionError {
    #[error("Network error: {0}")]
    Network(String),
    #[error("Processing error: {0}")]
    Processing(String),
    #[error("Request timed out")]
    Timeout,
    #[error("Semaphore error")]
    SemaphoreError,
    #[error("Task error: {0}")]
    TaskError(String),
    #[error("Not implemented: {0}")]
    NotImplemented(String),
    #[error("Request timeout")]
    RequestTimeout,
    #[error("Correlation error: {0}")]
    CorrelationError(String),
    #[error("Channel closed")]
    ChannelClosed,
}

impl From<NetworkError> for ParallelExecutionError {
    fn from(err: NetworkError) -> Self {
        ParallelExecutionError::Network(err.to_string())
    }
}

impl From<SyncError> for ParallelExecutionError {
    fn from(err: SyncError) -> Self {
        ParallelExecutionError::Processing(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    struct MockQRInfoProcessor;

    #[async_trait::async_trait]
    impl QRInfoProcessor for MockQRInfoProcessor {
        async fn process_qr_info(
            &mut self,
            _qr_info: dashcore::network::message_qrinfo::QRInfo,
        ) -> SyncResult<()> {
            Ok(())
        }
    }

    fn create_test_qr_info_request(index: u32) -> QRInfoRequest {
        QRInfoRequest {
            base_hash: BlockHash::from_byte_array([index as u8; 32]),
            tip_hash: BlockHash::from_byte_array([(index + 1) as u8; 32]),
            base_height: index * 100,
            tip_height: (index + 1) * 100,
            priority: index,
            extra_share: false,
        }
    }

    #[tokio::test]
    async fn test_parallel_executor_creation() {
        let executor = ParallelQRInfoExecutor::new(3, Duration::from_secs(5));
        assert_eq!(executor.max_concurrent, 3);
        assert_eq!(executor.request_timeout, Duration::from_secs(5));
    }

    #[tokio::test]
    async fn test_empty_request_list() {
        let executor = ParallelQRInfoExecutor::new(3, Duration::from_secs(5));
        let network = Arc::new(Mutex::new(crate::network::mock::MockNetworkManager::new()));
        let processor = Arc::new(Mutex::new(MockQRInfoProcessor));

        let results = executor
            .execute_parallel_requests(vec![], network, processor)
            .await
            .unwrap();

        assert_eq!(results.len(), 0);
    }

    #[tokio::test]
    async fn test_progress_reporting() {
        let (progress_tx, mut progress_rx) = mpsc::unbounded_channel();
        let executor = ParallelQRInfoExecutor::new(2, Duration::from_secs(1))
            .with_progress_reporting(progress_tx);

        assert!(executor.progress_tx.is_some());

        // Test that progress channel is properly set up
        drop(executor);
        assert!(progress_rx.recv().await.is_none());
    }
}