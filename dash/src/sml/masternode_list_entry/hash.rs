use hashes::{Hash, sha256d};

use crate::sml::masternode_list_entry::MasternodeListEntry;

impl MasternodeListEntry {
    pub fn calculate_entry_hash(&self) -> sha256d::Hash {
        let mut writer = Vec::new();
        self.consensus_encode_body(&mut writer).expect("encoding failed");
        sha256d::Hash::hash(&writer)
    }
}

#[cfg(test)]
mod tests {
    use hashes::Hash;

    use crate::consensus::deserialize;
    use crate::network::message_sml::MnListDiff;

    // Ground-truth entry hashes produced by Dash Core's `CSimplifiedMNListEntry::CalcHash`
    // (`CHashWriter(SER_GETHASH, ...)`) for the matching entries in this fixture. `SER_GETHASH`
    // omits the `SER_NETWORK`-gated leading `version`, so the pre-image is the wire body without
    // that field. Hashing the full wire (with `version`) yields different values and fails here.
    // The first case is a `version` 1 entry, the second a `version` 2 Evo entry, exercising both
    // the legacy path and the `nType`/platform fields.
    #[test]
    fn entry_hash_matches_core_calc_hash() {
        let bytes: &[u8] =
            include_bytes!("../../../tests/data/test_DML_diffs/mn_list_diff_0_2227096.bin");
        let diff: MnListDiff = deserialize(bytes).expect("expected to deserialize");

        let cases = [
            (
                "0008858d870b0aa7967c39a551fc953e4e7fa602f19ba1fc805c218f87f41cb6",
                "759c929f9d225554a09a8ad817bfaf555847547097495e08d3ba316529b65426",
            ),
            (
                "000c898c950a9c4a4d1eb3c227ab6d65ab652b44010e25f6dbe7a673e4bb52de",
                "045c5f8ae528d32d0e694ddb9d652794d41b89db5f7eaee703beef62b35e4903",
            ),
        ];

        for (pro_reg_tx_hash_hex, expected_entry_hash_hex) in cases {
            let entry = diff
                .new_masternodes
                .iter()
                .find(|e| hex::encode(e.pro_reg_tx_hash.to_byte_array()) == pro_reg_tx_hash_hex)
                .expect("expected entry present in fixture");

            assert_eq!(
                hex::encode(entry.calculate_entry_hash().to_byte_array()),
                expected_entry_hash_hex,
                "entry hash for {} must match Dash Core's CalcHash",
                pro_reg_tx_hash_hex
            );
        }
    }
}
