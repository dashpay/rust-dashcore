use dashcore::hash_types::FilterHeader;
use dashcore::network::message_filter::CFHeaders;
use dashcore_hashes::{sha256d, Hash};

/// Compute filter headers from a CFHeaders message.
///
/// Each filter header is computed by chaining:
/// `header[i] = sha256d(filter_hash[i] || header[i-1])`
pub(super) fn compute_filter_headers(cfheaders: &CFHeaders) -> Vec<FilterHeader> {
    let mut prev_header = cfheaders.previous_filter_header;
    let mut computed_headers = Vec::with_capacity(cfheaders.filter_hashes.len());

    for filter_hash in &cfheaders.filter_hashes {
        let mut data = [0u8; 64];
        data[..32].copy_from_slice(filter_hash.as_byte_array());
        data[32..].copy_from_slice(prev_header.as_byte_array());
        let header = FilterHeader::from_byte_array(sha256d::Hash::hash(&data).to_byte_array());
        computed_headers.push(header);
        prev_header = header;
    }

    computed_headers
}
