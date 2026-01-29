//! Event system for inter-manager communication.
//!
//! Managers communicate via events broadcast through an `EventBus`. Each manager
//! can emit events to notify others of progress and subscribe to events to
//! react to other managers' progress.

use thiserror::Error;
use tokio::sync::broadcast;

const DEFAULT_EVENT_LIMIT: usize = 10000;

/// Event-related errors.
#[derive(Debug, Error)]
pub enum Error {
    #[error("Bus receiver failed: {0}")]
    ReceiveFailure(String),
}

type Result<T> = std::result::Result<T, Error>;

/// Event bus for broadcasting events between managers.
///
/// Uses tokio's broadcast channel for delivery. All subscribers
/// receive all events. Late subscribers do not receive past events.
#[derive(Debug, Clone)]
pub struct EventBus<T: Clone> {
    sender: broadcast::Sender<T>,
}

impl<T: Clone> EventBus<T> {
    /// Create a new event bus with the given capacity.
    ///
    /// Capacity determines how many events can be buffered before
    /// slow receivers start missing events.
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self {
            sender,
        }
    }

    /// Create a new subscriber to receive events.
    pub fn subscribe(&self) -> EventReceiver<T> {
        EventReceiver::new(self.sender.subscribe())
    }

    /// Emit an event to all subscribers.
    ///
    /// Returns the number of receivers that received the event.
    /// Ignores send errors (no receivers is not an error).
    pub fn emit(&self, events: &[T]) {
        for event in events {
            let _ = self.sender.send(event.clone());
        }
    }
}

impl<T: Clone> Default for EventBus<T> {
    fn default() -> Self {
        Self::new(DEFAULT_EVENT_LIMIT)
    }
}

#[derive(Debug)]
pub struct EventReceiver<T: Clone> {
    receiver: broadcast::Receiver<T>,
}

impl<T: Clone> EventReceiver<T> {
    pub fn new(receiver: broadcast::Receiver<T>) -> Self {
        Self {
            receiver,
        }
    }
    pub async fn recv(&mut self) -> Result<T> {
        match self.receiver.recv().await {
            Ok(event) => Ok(event),
            Err(broadcast::error::RecvError::Lagged(n)) => {
                Err(Error::ReceiveFailure(format!("lagged {} events", n)))
            }
            Err(broadcast::error::RecvError::Closed) => {
                Err(Error::ReceiveFailure("event bus closed".to_string()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::SyncEvent;

    #[test]
    fn test_event_description() {
        let event = SyncEvent::BlockHeadersStored {
            tip_height: 200,
        };
        assert!(event.description().contains("BlockHeadersStored"));
        assert!(event.description().contains("200"));
    }

    #[tokio::test]
    async fn test_sync_event_bus_emit_receive() {
        let bus = EventBus::new(16);
        let mut rx = bus.subscribe();

        let event = "Test event";

        bus.emit(&[event]);

        let received = rx.recv().await.unwrap();
        assert_eq!(received, event);
    }

    #[test]
    fn test_sync_event_bus_no_receivers() {
        let bus = EventBus::new(16);
        // Emit without any subscribers should not panic
        bus.emit(&["Test event"]);
    }

    #[tokio::test]
    async fn test_sync_event_bus_multiple_subscribers() {
        let bus = EventBus::new(16);
        let mut rx1 = bus.subscribe();
        let mut rx2 = bus.subscribe();

        bus.emit(&["Test event"]);

        // Both should receive the event
        let e1 = rx1.recv().await.unwrap();
        let e2 = rx2.recv().await.unwrap();

        assert_eq!(e1, "Test event");
        assert_eq!(e2, "Test event");
    }
}
