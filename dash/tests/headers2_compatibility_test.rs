// Headers2 Compatibility Tests
// These tests verify the Rust implementation matches the C++ reference implementation
// for compressed block headers (DIP-0025).

use dashcore::blockdata::block::{Header, Version};
use dashcore::consensus::{deserialize, serialize};
use dashcore::hash_types::{BlockHash, TxMerkleNode};
use dashcore::network::message_headers2::{CompressedHeader, CompressionState, Headers2Message};
use dashcore::pow::CompactTarget;
use dashcore_hashes::Hash;

fn create_header(version: i32, prev_hash: [u8; 32], time: u32, bits: u32, nonce: u32) -> Header {
    Header {
        version: Version::from_consensus(version),
        prev_blockhash: BlockHash::from_byte_array(prev_hash),
        merkle_root: TxMerkleNode::from_byte_array([nonce as u8; 32]),
        time,
        bits: CompactTarget::from_consensus(bits),
        nonce,
    }
}

fn create_sequential_header(prev: &Header, time_delta: i32, nonce: u32) -> Header {
    Header {
        version: prev.version,
        prev_blockhash: prev.block_hash(),
        merkle_root: TxMerkleNode::from_byte_array([nonce as u8; 32]),
        time: (prev.time as i64 + time_delta as i64) as u32,
        bits: prev.bits,
        nonce,
    }
}

// =============================================================================
// Test: Version Offset Encoding (C++ Semantics)
// =============================================================================
// C++ (DIP-0025):
//   - offset 0 = version NOT in cache (full version follows)
//   - offset 1-7 = version at position 0-6 in list (1-indexed)

#[test]
fn test_version_offset_cpp_semantics() {
    let mut state = CompressionState::new();

    // First header - version NOT in cache, should use offset=0
    let header1 = create_header(0x20000000, [0u8; 32], 1000000, 0x1d00ffff, 1);
    let compressed1 = state.compress(&header1);

    println!("First header compression:");
    println!("  flags = 0b{:08b}", compressed1.flags.0);
    println!("  version_offset = {}", compressed1.flags.version_offset());
    println!("  has version field = {}", compressed1.version.is_some());

    // C++ semantics: offset = 0 means version IS present (not in cache)
    assert_eq!(
        compressed1.flags.version_offset(),
        0,
        "First header should have offset=0 (C++ semantics: not in cache)"
    );
    assert!(compressed1.version.is_some(), "First header should include version field");

    // Second header with SAME version - now in cache at position 0
    // C++ offset = position + 1 = 0 + 1 = 1
    let header2 = create_sequential_header(&header1, 60, 2);
    let compressed2 = state.compress(&header2);

    println!("\nSecond header (same version) compression:");
    println!("  flags = 0b{:08b}", compressed2.flags.0);
    println!("  version_offset = {}", compressed2.flags.version_offset());
    println!("  has version field = {}", compressed2.version.is_some());

    assert_eq!(
        compressed2.flags.version_offset(),
        1,
        "Second header should have offset=1 (C++ semantics: position 0 in cache)"
    );
    assert!(
        compressed2.version.is_none(),
        "Second header should NOT include version field (from cache)"
    );
}

#[test]
fn test_version_cache_mru_behavior() {
    // C++ uses a list with MRU (most recently used) behavior:
    // - When a version is found, it's moved to the FRONT of the list
    // - This affects subsequent offsets

    let mut state = CompressionState::new();

    // Add several different versions
    let versions = [0x20000000, 0x20000001, 0x20000002, 0x20000003];
    let mut prev_hash = [0u8; 32];
    let mut time = 1000000u32;

    for (i, &ver) in versions.iter().enumerate() {
        let header = create_header(ver, prev_hash, time, 0x1d00ffff, i as u32);
        prev_hash = header.block_hash().to_byte_array();
        time += 60;
        let _ = state.compress(&header);
    }

    println!("Version cache state after adding 4 versions:");
    println!("  cache = {:?}", state.version_cache);
    // Cache should be [0x20000003, 0x20000002, 0x20000001, 0x20000000]
    // (front = most recent)

    // Now reuse version 0x20000001 (at position 2)
    // After use, it should be moved to front
    let header = create_header(0x20000001, prev_hash, time, 0x1d00ffff, 100);
    let compressed = state.compress(&header);

    println!("\nReusing version 0x20000001:");
    println!("  offset = {} (should be 3 = position 2 + 1)", compressed.flags.version_offset());
    println!("  version_cache after = {:?}", state.version_cache);

    // Version was at position 2, so offset = 2 + 1 = 3
    assert_eq!(compressed.flags.version_offset(), 3);

    // After MRU reordering, 0x20000001 should now be at front
    assert_eq!(
        state.version_cache[0], 0x20000001,
        "After use, version 0x20000001 should be at front (MRU)"
    );
}

// =============================================================================
// Test: Flag Bit Semantics
// =============================================================================

#[test]
fn test_flag_semantics_prev_block_hash() {
    let mut state = CompressionState::new();

    // First header - non-sequential (genesis-like)
    let header1 = create_header(0x20000000, [0u8; 32], 1000000, 0x1d00ffff, 1);
    let compressed1 = state.compress(&header1);

    println!("First header (non-sequential prev):");
    println!("  FLAG_PREV_BLOCK_HASH bit = {}", compressed1.flags.has_prev_block_hash());
    println!("  prev_blockhash field present = {}", compressed1.prev_blockhash.is_some());

    // Flag should be SET (1) when prev_blockhash IS included
    assert!(compressed1.flags.has_prev_block_hash());
    assert!(compressed1.prev_blockhash.is_some());

    // Second header - sequential
    let header2 = create_sequential_header(&header1, 60, 2);
    let compressed2 = state.compress(&header2);

    println!("\nSecond header (sequential prev):");
    println!("  FLAG_PREV_BLOCK_HASH bit = {}", compressed2.flags.has_prev_block_hash());
    println!("  prev_blockhash field present = {}", compressed2.prev_blockhash.is_some());

    // Flag should be CLEAR (0) when prev_blockhash is OMITTED (compressed)
    assert!(!compressed2.flags.has_prev_block_hash());
    assert!(compressed2.prev_blockhash.is_none());
}

#[test]
fn test_flag_semantics_timestamp() {
    let mut state = CompressionState::new();

    // First header - must include full timestamp
    let header1 = create_header(0x20000000, [0u8; 32], 1000000, 0x1d00ffff, 1);
    let compressed1 = state.compress(&header1);

    println!("First header:");
    println!("  FLAG_TIMESTAMP bit = {}", compressed1.flags.has_full_timestamp());
    println!(
        "  time_full = {:?}, time_offset = {:?}",
        compressed1.time_full, compressed1.time_offset
    );

    assert!(compressed1.flags.has_full_timestamp());
    assert!(compressed1.time_full.is_some());
    assert!(compressed1.time_offset.is_none());

    // Second header - can use offset
    let header2 = create_sequential_header(&header1, 60, 2);
    let compressed2 = state.compress(&header2);

    println!("\nSecond header (small time delta):");
    println!("  FLAG_TIMESTAMP bit = {}", compressed2.flags.has_full_timestamp());
    println!(
        "  time_full = {:?}, time_offset = {:?}",
        compressed2.time_full, compressed2.time_offset
    );

    assert!(!compressed2.flags.has_full_timestamp());
    assert!(compressed2.time_full.is_none());
    assert!(compressed2.time_offset.is_some());
    assert_eq!(compressed2.time_offset.unwrap(), 60);
}

// =============================================================================
// Test: First Header Requirements
// =============================================================================

#[test]
fn test_first_header_fully_uncompressed() {
    let mut state = CompressionState::new();

    let header = create_header(0x20000000, [0u8; 32], 1000000, 0x1d00ffff, 1);
    let compressed = state.compress(&header);

    println!("First header flags: 0b{:08b}", compressed.flags.0);
    println!(
        "  version_offset = {} (should be 0 for uncompressed in C++)",
        compressed.flags.version_offset()
    );
    println!("  has_prev_block_hash = {}", compressed.flags.has_prev_block_hash());
    println!("  has_full_timestamp = {}", compressed.flags.has_full_timestamp());
    println!("  has_nbits = {}", compressed.flags.has_nbits());

    // First header MUST be fully uncompressed
    assert!(compressed.version.is_some(), "First header must include version");
    assert!(compressed.prev_blockhash.is_some(), "First header must include prev_blockhash");
    assert!(compressed.time_full.is_some(), "First header must include full timestamp");
    assert!(compressed.bits.is_some(), "First header must include nBits");

    // The flags should indicate uncompressed:
    assert_eq!(compressed.flags.version_offset(), 0, "version_offset must be 0");
    assert!(compressed.flags.has_prev_block_hash(), "PREV_BLOCK_HASH flag must be set");
    assert!(compressed.flags.has_full_timestamp(), "TIMESTAMP flag must be set");
    assert!(compressed.flags.has_nbits(), "NBITS flag must be set");
}

// =============================================================================
// Test: Serialization Format Verification
// =============================================================================

#[test]
fn test_serialization_roundtrip_single_header() {
    let mut compress_state = CompressionState::new();
    let mut decompress_state = CompressionState::new();

    let header = create_header(0x20000000, [0u8; 32], 1000000, 0x1d00ffff, 42);
    let compressed = compress_state.compress(&header);

    // Serialize
    let serialized = serialize(&compressed);
    println!("Serialized first header: {} bytes", serialized.len());
    println!("  hex: {}", hex::encode(&serialized));
    println!("  flags byte: 0b{:08b}", serialized[0]);

    // Deserialize
    let deserialized: CompressedHeader = deserialize(&serialized).unwrap();

    // Decompress
    let recovered = decompress_state.decompress(&deserialized).unwrap();

    assert_eq!(header, recovered, "Roundtrip failed!");
}

#[test]
fn test_serialization_format_first_header() {
    let mut state = CompressionState::new();

    let header = create_header(0x20000000, [0u8; 32], 1000000, 0x1d00ffff, 42);
    let compressed = state.compress(&header);
    let serialized = serialize(&compressed);

    println!("First header serialization:");
    println!("  Total bytes: {}", serialized.len());
    println!("  Expected: 81 bytes (fully uncompressed)");
    println!("  Flags byte: 0b{:08b}", serialized[0]);

    // Expected flags for C++: 0b00111000 (PREV_BLOCK_HASH | TIMESTAMP | NBITS, version_offset = 0)
    let expected_flags_cpp = 0b00111000u8;
    println!("  C++ expected: 0b{:08b}", expected_flags_cpp);

    assert_eq!(serialized[0], expected_flags_cpp, "Rust should now produce C++-compatible flags");
    assert_eq!(serialized.len(), 81, "First header should be 81 bytes");
}

// =============================================================================
// Test: Multiple Header Batch
// =============================================================================

#[test]
fn test_batch_compression_decompression() {
    // Create a chain of headers
    let mut headers = Vec::new();
    let mut prev_hash = [0u8; 32];
    let mut time = 1000000u32;

    for i in 0..10 {
        let header = create_header(0x20000000, prev_hash, time, 0x1d00ffff, i);
        prev_hash = header.block_hash().to_byte_array();
        time += 60;
        headers.push(header);
    }

    // Compress all headers
    let mut compress_state = CompressionState::new();
    let mut compressed = Vec::new();
    for header in &headers {
        compressed.push(compress_state.compress(header));
    }

    // Create Headers2Message and serialize
    let msg = Headers2Message::new(compressed.clone());
    let serialized = serialize(&msg);

    println!("Batch of {} headers:", headers.len());
    println!("  Uncompressed size: {} bytes", headers.len() * 80);
    println!("  Compressed size: {} bytes", serialized.len());
    println!(
        "  Savings: {:.1}%",
        (1.0 - serialized.len() as f64 / (headers.len() * 80) as f64) * 100.0
    );

    // Deserialize
    let deserialized: Headers2Message = deserialize(&serialized).unwrap();

    // Decompress
    let mut decompress_state = CompressionState::new();
    let mut recovered = Vec::new();
    for (i, comp) in deserialized.headers.iter().enumerate() {
        match decompress_state.decompress(comp) {
            Ok(h) => recovered.push(h),
            Err(e) => panic!("Decompression failed at header {}: {:?}", i, e),
        }
    }

    // Verify
    assert_eq!(headers.len(), recovered.len());
    for (i, (orig, rec)) in headers.iter().zip(recovered.iter()).enumerate() {
        assert_eq!(orig, rec, "Mismatch at header {}", i);
    }
}

// =============================================================================
// Test: C++ Compatibility
// =============================================================================

#[test]
fn test_cpp_compatible_first_header_decompression() {
    // Create the exact byte sequence that C++ would send for a first header:
    // flags = 0b00111000 (PREV_BLOCK_HASH=1, TIMESTAMP=1, NBITS=1, version_offset=0)

    let mut data = Vec::new();

    // Flags: C++ uses 0 for "version not in cache" - now Rust does too!
    let cpp_flags = 0b00111000u8;
    data.push(cpp_flags);

    // Version (little endian)
    data.extend_from_slice(&0x20000000i32.to_le_bytes());

    // prev_blockhash (32 bytes of zeros)
    data.extend_from_slice(&[0u8; 32]);

    // merkle_root (32 bytes)
    data.extend_from_slice(&[1u8; 32]);

    // timestamp (4 bytes)
    data.extend_from_slice(&1000000u32.to_le_bytes());

    // nBits (4 bytes)
    data.extend_from_slice(&0x1d00ffffu32.to_le_bytes());

    // nonce (4 bytes)
    data.extend_from_slice(&42u32.to_le_bytes());

    println!("C++ compatible header bytes ({} bytes):", data.len());
    println!("  flags: 0b{:08b}", cpp_flags);
    println!("  version_offset in flags: {}", cpp_flags & 0b111);

    // Deserialize with Rust
    let result: Result<CompressedHeader, _> = deserialize(&data);

    match result {
        Ok(compressed) => {
            println!("\nDeserialization succeeded:");
            println!("  flags.version_offset() = {}", compressed.flags.version_offset());
            println!("  version field = {:?}", compressed.version);

            assert_eq!(compressed.flags.version_offset(), 0);
            assert!(compressed.version.is_some());
            assert_eq!(compressed.version.unwrap(), 0x20000000);

            // Decompress
            let mut state = CompressionState::new();
            let header = state.decompress(&compressed).expect("Decompression should succeed");

            println!("\nDecompression succeeded:");
            println!("  version = 0x{:08x}", header.version.to_consensus());

            assert_eq!(header.version.to_consensus(), 0x20000000);
        }
        Err(e) => {
            panic!("Deserialization failed: {:?}", e);
        }
    }
}

#[test]
fn test_rust_produces_cpp_compatible_output() {
    // Verify Rust now produces output that C++ can understand
    let mut state = CompressionState::new();
    let header = create_header(0x20000000, [0u8; 32], 1000000, 0x1d00ffff, 42);
    let compressed = state.compress(&header);
    let serialized = serialize(&compressed);

    println!("Rust-produced first header:");
    println!("  flags byte: 0b{:08b}", serialized[0]);
    println!("  version_offset: {}", serialized[0] & 0b111);

    println!("\nC++ expects for first header:");
    println!("  flags byte: 0b00111000");
    println!("  version_offset: 0 (means uncompressed)");

    // They should now match!
    assert_eq!(
        serialized[0] & 0b111,
        0,
        "Rust should use version_offset=0 for uncompressed (C++ compatible)"
    );
    assert_eq!(serialized[0], 0b00111000, "Rust should produce exact same flags as C++");
}

// =============================================================================
// Test: Edge Cases
// =============================================================================

#[test]
fn test_version_cache_overflow() {
    // Test what happens when we add more than 7 unique versions
    let mut state = CompressionState::new();

    let mut prev_hash = [0u8; 32];
    let mut time = 1000000u32;

    // Add 10 unique versions - first header is always uncompressed
    for i in 0..10 {
        let header = create_header(0x20000000 + i, prev_hash, time, 0x1d00ffff, i as u32);
        prev_hash = header.block_hash().to_byte_array();
        time += 60;

        let compressed = state.compress(&header);
        println!(
            "Header {} (version 0x{:08x}): offset={}, has_version={}",
            i,
            0x20000000 + i,
            compressed.flags.version_offset(),
            compressed.version.is_some()
        );

        // All headers should have offset=0 (not in cache) since each has unique version
        assert_eq!(compressed.flags.version_offset(), 0);
        assert!(compressed.version.is_some());
    }

    // Cache should only contain last 7 versions
    assert_eq!(state.version_cache.len(), 7);
}

#[test]
fn test_genesis_sync_scenario() {
    // Simulate receiving headers starting from genesis
    // First header must be fully uncompressed

    println!("Genesis sync scenario:");
    println!("  First header MUST be fully uncompressed");

    let mut state = CompressionState::new();

    // Simulate first header (genesis successor)
    let genesis_successor = create_header(0x20000000, [0u8; 32], 1000000, 0x1d00ffff, 0);
    let compressed = state.compress(&genesis_successor);

    // First header must be fully uncompressed for receiver to decode
    assert!(compressed.version.is_some(), "First header must include version");
    assert!(compressed.prev_blockhash.is_some(), "First header must include prev_blockhash");
    assert!(compressed.time_full.is_some(), "First header must include timestamp");
    assert!(compressed.bits.is_some(), "First header must include nBits");

    // A receiver with fresh state should be able to decompress
    let mut receiver_state = CompressionState::new();
    let result = receiver_state.decompress(&compressed);
    assert!(result.is_ok(), "Receiver should be able to decompress first header");
    assert_eq!(result.unwrap(), genesis_successor);
}
