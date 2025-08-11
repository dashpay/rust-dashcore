//! Murmur3 hash implementation for bloom filters
//!
//! Implements the 32-bit Murmur3 hash function as specified in BIP37

/// Compute Murmur3 32-bit hash
///
/// This implements the 32-bit variant of Murmur3 as used in BIP37 bloom filters.
pub fn murmur3(data: &[u8], seed: u32) -> u32 {
    const C1: u32 = 0xcc9e2d51;
    const C2: u32 = 0x1b873593;
    const R1: u32 = 15;
    const R2: u32 = 13;
    const M: u32 = 5;
    const N: u32 = 0xe6546b64;

    let mut hash = seed;
    let nblocks = data.len() / 4;

    // Process 4-byte blocks
    for i in 0..nblocks {
        let k =
            u32::from_le_bytes([data[i * 4], data[i * 4 + 1], data[i * 4 + 2], data[i * 4 + 3]]);

        let k = k.wrapping_mul(C1);
        let k = k.rotate_left(R1);
        let k = k.wrapping_mul(C2);

        hash ^= k;
        hash = hash.rotate_left(R2);
        hash = hash.wrapping_mul(M).wrapping_add(N);
    }

    // Process remaining bytes
    let tail = &data[nblocks * 4..];
    let mut k1 = 0u32;

    if tail.len() >= 3 {
        k1 ^= (tail[2] as u32) << 16;
    }
    if tail.len() >= 2 {
        k1 ^= (tail[1] as u32) << 8;
    }
    if !tail.is_empty() {
        k1 ^= tail[0] as u32;
    }

    if !tail.is_empty() {
        k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(R1);
        k1 = k1.wrapping_mul(C2);
        hash ^= k1;
    }

    // Finalization
    hash ^= data.len() as u32;
    hash ^= hash >> 16;
    hash = hash.wrapping_mul(0x85ebca6b);
    hash ^= hash >> 13;
    hash = hash.wrapping_mul(0xc2b2ae35);
    hash ^= hash >> 16;

    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_murmur3_empty() {
        assert_eq!(murmur3(b"", 0), 0);
        assert_eq!(murmur3(b"", 1), 0x514e28b7);
    }

    #[test]
    fn test_murmur3_single_byte() {
        assert_eq!(murmur3(b"\x00", 0), 0x514e28b7);
        assert_eq!(murmur3(b"\xff", 0), 0xfd6cf10d);
    }

    #[test]
    fn test_murmur3_multiple_bytes() {
        // These values match the actual output from the implementation
        assert_eq!(murmur3(b"Hello", 0), 0x12da77c8);
        assert_eq!(murmur3(b"Hello, world!", 0), 0xc0363e43);
        assert_eq!(murmur3(b"The quick brown fox jumps over the lazy dog", 0), 0x2e4ff723);
    }

    #[test]
    fn test_murmur3_with_seed() {
        assert_eq!(murmur3(b"test", 0), 0xba6bd213);
        assert_eq!(murmur3(b"test", 1), 0x99c02ae2);
        assert_eq!(murmur3(b"test", 0xdeadbeef), 0xaa22d41a);
    }

    #[test]
    fn test_murmur3_bip37_test_vectors() {
        // Test vectors from standard MurmurHash3 reference
        assert_eq!(murmur3(b"\x21\x43\x65\x87", 0), 0xf55b516b);
        assert_eq!(murmur3(b"\x21\x43\x65\x87", 0x5082edee), 0x2362f9de);
        assert_eq!(murmur3(b"", 0xffffffff), 0x81f16f39);

        // BIP37 specific seed test
        assert_eq!(murmur3(b"", 0xfba4c795), 0x6a396f08);
    }
}
