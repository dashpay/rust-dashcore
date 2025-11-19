use dashcore::hashes::{Hash, sha256d};

fn sha2_checksum(data: &[u8]) -> [u8; 4] {
    let checksum = <sha256d::Hash as Hash>::hash(data);
    [checksum[0], checksum[1], checksum[2], checksum[3]]
}

fn main() {
    let empty_data = &[];
    let checksum = sha2_checksum(empty_data);
    println\!("SHA256D checksum for empty data: {:02x?}", checksum);
}
EOF < /dev/null
