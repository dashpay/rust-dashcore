# Peer Reputation System

## Overview

The Dash SPV client implements a comprehensive peer reputation system to protect against malicious peers and improve network reliability. This system tracks both positive and negative peer behaviors, automatically bans misbehaving peers, and implements reputation decay over time for recovery.

## Architecture

### Core Components

1. **PeerReputationManager** (`src/network/reputation.rs`)
   - Central component managing all peer reputations
   - Thread-safe implementation using Arc<RwLock>
   - Handles reputation updates, banning logic, and persistence

2. **PeerReputation** 
   - Individual peer reputation data structure
   - Tracks score, ban status, connection history, and behavior counts

3. **Integration with MultiPeerNetworkManager**
   - Reputation checks before connecting to peers
   - Automatic reputation updates based on peer behavior
   - Reputation-based peer selection for connections

## Reputation Scoring System

### Misbehavior Scores (Positive Points = Bad)

| Behavior | Score | Description |
|----------|-------|-------------|
| `INVALID_MESSAGE` | +10 | Invalid message format or protocol violation |
| `INVALID_HEADER` | +50 | Invalid block header |
| `INVALID_FILTER` | +25 | Invalid compact filter |
| `TIMEOUT` | +5 | Timeout or slow response |
| `UNSOLICITED_DATA` | +15 | Sending unsolicited data |
| `INVALID_TRANSACTION` | +20 | Invalid transaction |
| `INVALID_MASTERNODE_DIFF` | +30 | Invalid masternode list diff |
| `INVALID_CHAINLOCK` | +40 | Invalid ChainLock |
| `DUPLICATE_MESSAGE` | +5 | Duplicate message |
| `CONNECTION_FLOOD` | +20 | Connection flood attempt |

### Positive Behavior Scores (Negative Points = Good)

| Behavior | Score | Description |
|----------|-------|-------------|
| `VALID_HEADERS` | -5 | Successfully provided valid headers |
| `VALID_FILTERS` | -3 | Successfully provided valid filters |
| `VALID_BLOCK` | -10 | Successfully provided valid block |
| `FAST_RESPONSE` | -2 | Fast response time |
| `LONG_UPTIME` | -5 | Long uptime connection |

### Thresholds and Limits

- **Ban Threshold**: 100 points (MAX_MISBEHAVIOR_SCORE)
- **Minimum Score**: -50 points (MIN_SCORE) 
- **Ban Duration**: 24 hours
- **Decay Interval**: 1 hour
- **Decay Amount**: 5 points per interval

## Features

### 1. Automatic Behavior Tracking

The system automatically tracks peer behavior during normal operations:

```rust
// Example: Headers received
match &msg {
    NetworkMessage::Headers(headers) => {
        if !headers.is_empty() {
            reputation_manager.update_reputation(
                peer_addr,
                positive_scores::VALID_HEADERS,
                "Provided valid headers",
            ).await;
        }
    }
    // ... other message types
}
```

### 2. Peer Banning

Peers are automatically banned when their score reaches 100:

```rust
// Automatic ban on threshold
if reputation.score >= MAX_MISBEHAVIOR_SCORE {
    reputation.banned_until = Some(Instant::now() + BAN_DURATION);
    reputation.ban_count += 1;
}
```

### 3. Reputation Decay

Reputation scores decay over time, allowing peers to recover:

```rust
// Applied every hour
let decay = (intervals as i32) * DECAY_AMOUNT;
self.score = (self.score - decay).max(MIN_SCORE);
```

### 4. Connection Management

The system prevents connections to banned peers:

```rust
// Check before connecting
if !self.reputation_manager.should_connect_to_peer(&addr).await {
    log::warn!("Not connecting to {} due to bad reputation", addr);
    return;
}
```

### 5. Reputation-Based Peer Selection

When selecting peers for connections, the system prioritizes peers with better reputations:

```rust
// Select best peers based on reputation
let best_peers = reputation_manager.select_best_peers(known_addresses, needed).await;
```

### 6. Persistent Storage

Reputation data is saved to disk and persists across restarts:

```rust
// Save path: <data_dir>/peer_reputation.json
reputation_manager.save_to_storage(&reputation_path).await?;
```

## Usage Examples

### Manual Peer Management

```rust
// Ban a peer manually
network_manager.ban_peer(&peer_addr, "Reason for ban").await?;

// Unban a peer
network_manager.unban_peer(&peer_addr).await;

// Get all peer reputations
let reputations = network_manager.get_peer_reputations().await;
for (addr, (score, banned)) in reputations {
    println!("{}: score={}, banned={}", addr, score, banned);
}
```

### Monitoring Reputation Events

```rust
// Get recent reputation changes
let events = reputation_manager.get_recent_events().await;
for event in events {
    println!("{}: {} points - {}", event.peer, event.change, event.reason);
}
```

## Integration Points

### 1. Connection Establishment
- Reputation checked before connecting
- Connection attempts recorded
- Successful connections tracked

### 2. Message Processing
- Valid messages improve reputation
- Invalid messages penalize reputation
- Timeouts and errors tracked

### 3. Peer Discovery
- Known peers sorted by reputation
- Banned peers excluded from selection
- DNS peers start with neutral reputation

### 4. Maintenance Loop
- Periodic reputation data persistence
- Failed pings penalize reputation
- Long-lived connections rewarded

## Testing

The reputation system includes comprehensive tests:

1. **Unit Tests** (`src/network/reputation.rs`)
   - Basic scoring logic
   - Ban/unban functionality
   - Reputation decay

2. **Integration Tests** (`tests/reputation_test.rs`)
   - Concurrent updates
   - Persistence across restarts
   - Event tracking

3. **Network Integration** (`tests/reputation_integration_test.rs`)
   - Integration with MultiPeerNetworkManager
   - Real network scenarios

## Future Enhancements

1. **Configurable Thresholds**
   - Allow users to adjust ban thresholds
   - Customizable decay rates

2. **Advanced Metrics**
   - Track bandwidth usage per peer
   - Monitor response times
   - Success rate statistics

3. **Reputation Sharing**
   - Share reputation data between nodes
   - Collaborative filtering of bad peers

4. **Machine Learning**
   - Detect patterns in misbehavior
   - Predictive peer selection

## Configuration

Currently, the reputation system uses hardcoded values. Future versions may support configuration via:

```toml
[reputation]
max_misbehavior_score = 100
ban_duration_hours = 24
decay_interval_hours = 1
decay_amount = 5
min_score = -50
```

## Logging

The reputation system logs important events:

- `INFO`: Significant reputation changes, bans
- `WARN`: Connection rejections, manual bans
- `DEBUG`: All reputation updates

Enable detailed logging with:
```bash
RUST_LOG=dash_spv::network::reputation=debug cargo run
```