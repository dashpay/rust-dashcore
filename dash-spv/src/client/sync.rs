//! Handle async calls from sync code.
//!
//! This is a workaround for an issue in tokio, where you cannot call `block_on` from sync call that is called
//! inside a tokio runtime. This module spawns async futures in active tokio runtime, and retrieves the result
//! using a channel.

use std::future::Future;

/// Blocks on the provided future and returns the result.
///
/// This function is used to call async functions from sync code.
/// Requires the current thread to be running in a tokio runtime.
///
/// Due to limitations of tokio runtime, we cannot use `tokio::runtime::Runtime::block_on` if we are already inside a tokio runtime.
/// This function is a workaround for that limitation.
#[cfg(not(target_arch = "wasm32"))]
pub fn block_on<F>(fut: F) -> Result<F::Output, String>
where
    F: Future + Send + 'static,
    F::Output: Send,
{
    tracing::trace!("block_on: running async function from sync code");
    let rt = tokio::runtime::Handle::try_current().map_err(|e| e.to_string())?;
    let (tx, rx) = std::sync::mpsc::channel();
    tracing::trace!("block_on: Spawning worker");
    let hdl = rt.spawn(worker(fut, tx));
    tracing::trace!("block_on: Worker spawned");
    let resp = tokio::task::block_in_place(|| rx.recv()).map_err(|e| e.to_string())?;

    tracing::trace!("Response received");
    if !hdl.is_finished() {
        tracing::debug!("async-sync worker future is not finished, aborting; this should not happen, but it's fine");
        hdl.abort(); // cleanup the worker future
    }

    Ok(resp)
}

#[cfg(target_arch = "wasm32")]
pub fn block_on<F>(_fut: F) -> Result<F::Output, String>
where
    F: Future + Send + 'static,
    F::Output: Send,
{
    unimplemented!("block_on is not supported in wasm");
}

/// Worker function that runs the provided future and sends the result back to the caller using oneshot channel.
#[cfg(not(target_arch = "wasm32"))]
async fn worker<F: Future>(
    fut: F,
    // response: oneshot::Sender<F::Output>,
    response: std::sync::mpsc::Sender<F::Output>,
) -> Result<(), String> {
    tracing::trace!("Worker start");
    let result = fut.await;
    tracing::trace!("Worker async function completed, sending response");
    response.send(result).map_err(|e| e.to_string())?;
    tracing::trace!("Worker response sent");

    Ok(())
}
