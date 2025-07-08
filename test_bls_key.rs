// Test file to verify BLS public key access pattern
#[derive(Debug)]
struct BLSPublicKey([u8; 48]);

impl AsRef<[u8; 48]> for BLSPublicKey {
    fn as_ref(&self) -> &[u8; 48] {
        &self.0
    }
}

impl AsRef<[u8]> for BLSPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

fn test_bls_key_access() {
    let key = BLSPublicKey([0u8; 48]);
    
    // Get reference to array
    let compressed_ref: &[u8; 48] = key.as_ref();
    println!("Compressed ref: {:?}", compressed_ref.len());
    
    // Get owned copy
    let compressed_owned: [u8; 48] = *key.as_ref();
    println!("Compressed owned: {:?}", compressed_owned.len());
    
    // This simulates the actual code pattern
    let public_key_bytes: [u8; 48] = *key.as_ref();
    println!("Public key bytes: {:?}", public_key_bytes.len());
}

fn main() {
    test_bls_key_access();
    println!("BLS key access pattern is correct!");
}