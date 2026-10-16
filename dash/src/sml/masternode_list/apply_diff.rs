use std::sync::Arc;

use crate::Network;
use crate::bls_sig_utils::BLSSignature;
use crate::network::message_sml::MnListDiff;
use crate::prelude::CoreBlockHeight;
use crate::sml::error::SmlError;
use crate::sml::llmq_entry_verification::{
    LLMQEntryVerificationSkipStatus, LLMQEntryVerificationStatus,
};
use crate::sml::masternode_list::MasternodeList;
use crate::sml::quorum_entry::qualified_quorum_entry::{
    QualifiedQuorumEntry, VerifyingChainLockSignaturesType,
};

impl MasternodeList {
    /// Applies an `MnListDiff` to update the current masternode list.
    ///
    /// This function processes a masternode list diff (`MnListDiff`) and applies
    /// the changes to the existing masternode list. It performs the following operations:
    /// - Ensures the base block hash matches the expected value.
    /// - Removes deleted masternodes from the list.
    /// - Adds or updates new masternodes.
    /// - Removes deleted quorums.
    /// - Adds or updates new quorums.
    ///
    /// # Parameters
    ///
    /// - `diff`: The `MnListDiff` containing the changes to apply.
    /// - `diff_end_height`: The block height at which the diff ends.
    ///
    /// # Returns
    ///
    /// - `Ok(MasternodeList)`: A new `MasternodeList` reflecting the applied changes.
    /// - `Err(SmlError)`: An error if the base block hash does not match the expected value.
    ///
    /// # Errors
    ///
    /// - Returns `SmlError::BaseBlockHashMismatch` if the `base_block_hash` of the `diff`
    ///   does not match the expected block hash of the current masternode list.
    pub fn apply_diff(
        &self,
        diff: MnListDiff,
        diff_end_height: CoreBlockHeight,
        network: Network,
    ) -> Result<MasternodeList, SmlError> {
        // Ensure the base block hash matches
        if self.block_hash != diff.base_block_hash {
            return Err(SmlError::BaseBlockHashMismatch {
                expected: self.block_hash,
                found: diff.base_block_hash,
            });
        }

        let mut updated_masternodes = Arc::clone(&self.masternodes);
        if !diff.deleted_masternodes.is_empty() || !diff.new_masternodes.is_empty() {
            let masternodes = Arc::make_mut(&mut updated_masternodes);
            for pro_tx_hash in diff.deleted_masternodes {
                masternodes.remove(&pro_tx_hash.reverse());
            }
            for new_mn in diff.new_masternodes {
                masternodes.insert(new_mn.pro_reg_tx_hash.reverse(), Arc::new(new_mn.into()));
            }
        }

        let mut shared_quorums = Arc::clone(&self.quorums);
        if diff.deleted_quorums.is_empty()
            && diff.new_quorums.is_empty()
            && diff.quorums_chainlock_signatures.is_empty()
        {
            let builder = MasternodeList::build(
                updated_masternodes,
                shared_quorums,
                diff.block_hash,
                diff_end_height,
            );
            return Ok(builder.build());
        }
        let updated_quorums = Arc::make_mut(&mut shared_quorums);

        // Remove deleted quorums
        for deleted_quorum in diff.deleted_quorums {
            if let Some(quorum_map) = updated_quorums.get_mut(&deleted_quorum.llmq_type) {
                quorum_map.remove(&deleted_quorum.quorum_hash);
                if quorum_map.is_empty() {
                    updated_quorums.remove(&deleted_quorum.llmq_type);
                }
            }
        }

        // Build a vector of optional signatures with slots matching new_quorums length
        let mut quorum_sig_lookup: Vec<Option<&BLSSignature>> = vec![None; diff.new_quorums.len()];

        // Fill each slot with the corresponding signature
        for quorum_sig_obj in &diff.quorums_chainlock_signatures {
            for &index in &quorum_sig_obj.index_set {
                if let Some(slot) = quorum_sig_lookup.get_mut(index as usize) {
                    *slot = Some(&quorum_sig_obj.signature);
                } else {
                    return Err(SmlError::InvalidIndexInSignatureSet(index));
                }
            }
        }

        // quorumsCLSigs only exists after V20 activation (protocol 70230).
        // Pre-V20 blocks have no chainlock signatures. See DIP-0029.
        let signatures_available = !quorum_sig_lookup.iter().any(Option::is_none);
        let signatures_required = diff_end_height >= network.v20_activation_height();

        if signatures_required && !signatures_available {
            return Err(SmlError::IncompleteSignatureSet);
        }

        // Add or update new quorums
        for (idx, new_quorum) in diff.new_quorums.into_iter().enumerate() {
            updated_quorums.entry(new_quorum.llmq_type).or_default().insert(
                new_quorum.quorum_hash,
                {
                    let commitment_hash = new_quorum.calculate_commitment_hash();
                    let entry_hash = new_quorum.calculate_entry_hash();
                    let verifying_chain_lock_signature =
                        if new_quorum.llmq_type.is_rotating_quorum_type() {
                            None
                        } else {
                            quorum_sig_lookup
                                .get(idx)
                                .copied()
                                .flatten()
                                .copied()
                                .map(VerifyingChainLockSignaturesType::NonRotating)
                        };
                    Arc::new(QualifiedQuorumEntry {
                        quorum_entry: new_quorum,
                        verified: LLMQEntryVerificationStatus::Skipped(
                            LLMQEntryVerificationSkipStatus::NotMarkedForVerification,
                        ),
                        commitment_hash,
                        entry_hash,
                        verifying_chain_lock_signature,
                    })
                },
            );
        }

        // Create and return the new MasternodeList
        let builder = MasternodeList::build(
            updated_masternodes,
            shared_quorums,
            diff.block_hash,
            diff_end_height,
        );

        Ok(builder.build())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::deserialize;
    use crate::sml::llmq_type::LLMQType;
    use std::collections::BTreeMap;

    #[test]
    fn apply_diff_post_v20_requires_chainlock_signatures() {
        // Create base list from first diff
        let base_diff_bytes: &[u8] =
            include_bytes!("../../../tests/data/test_DML_diffs/mn_list_diff_0_2227096.bin");
        let base_diff: MnListDiff = deserialize(base_diff_bytes).expect("expected to deserialize");

        let base_list = MasternodeList::from_diff(base_diff, 2_227_096, Network::Mainnet)
            .expect("expected to create base list");

        // Load second diff and clear signatures
        let diff_bytes: &[u8] =
            include_bytes!("../../../tests/data/test_DML_diffs/mn_list_diff_2227096_2241332.bin");
        let mut diff: MnListDiff = deserialize(diff_bytes).expect("expected to deserialize");
        diff.quorums_chainlock_signatures.clear();

        // Height 2241332 is post-V20 on mainnet (1,987,776)
        let post_v20_height = 2_241_332;
        assert!(post_v20_height >= Network::Mainnet.v20_activation_height());

        let result = base_list.apply_diff(diff, post_v20_height, Network::Mainnet);

        assert!(
            matches!(result, Err(SmlError::IncompleteSignatureSet)),
            "Post-V20 apply_diff should require chainlock signatures"
        );
    }

    #[test]
    fn apply_diff_pre_v20_allows_missing_chainlock_signatures() {
        // Create base list from first diff at pre-V20 height
        let base_diff_bytes: &[u8] =
            include_bytes!("../../../tests/data/test_DML_diffs/mn_list_diff_0_2227096.bin");
        let base_diff: MnListDiff = deserialize(base_diff_bytes).expect("expected to deserialize");

        let base_height = 1_800_000u32;
        let base_list = MasternodeList::from_diff(base_diff, base_height, Network::Mainnet)
            .expect("expected to create base list");

        // Load second diff and clear signatures
        let diff_bytes: &[u8] =
            include_bytes!("../../../tests/data/test_DML_diffs/mn_list_diff_2227096_2241332.bin");
        let mut diff: MnListDiff = deserialize(diff_bytes).expect("expected to deserialize");

        // Fix base_block_hash to match our base list
        diff.base_block_hash = base_list.block_hash;
        diff.quorums_chainlock_signatures.clear();

        // Use a pre-V20 height on mainnet
        let pre_v20_height = 1_900_000u32;
        assert!(pre_v20_height < Network::Mainnet.v20_activation_height());

        let result = base_list.apply_diff(diff, pre_v20_height, Network::Mainnet);

        assert!(
            result.is_ok(),
            "Pre-V20 apply_diff should allow missing chainlock signatures: {:?}",
            result.err()
        );
    }

    /// Each non-rotating quorum a diff brings keeps the ChainLock signature
    /// its `quorumsCLSigs` group assigns it. A rotating one gets none, not even
    /// its own group's: Core keys it to the quorum's work block, which a lone
    /// diff does not carry.
    #[test]
    fn apply_diff_attaches_each_quorums_chain_lock_signature() {
        let base_diff: MnListDiff = deserialize(include_bytes!(
            "../../../tests/data/test_DML_diffs/mn_list_diff_0_2227096.bin"
        ))
        .expect("expected to deserialize");
        let base_list = MasternodeList::from_diff(base_diff, 2_227_096, Network::Mainnet)
            .expect("expected to create base list");
        let diff: MnListDiff = deserialize(include_bytes!(
            "../../../tests/data/test_DML_diffs/mn_list_diff_2227096_2241332.bin"
        ))
        .expect("expected to deserialize");
        let signed_rotating: Vec<_> = diff
            .new_quorums
            .iter()
            .enumerate()
            .filter(|(idx, quorum)| {
                quorum.llmq_type.is_rotating_quorum_type()
                    && diff
                        .quorums_chainlock_signatures
                        .iter()
                        .any(|group| group.index_set.contains(&(*idx as u16)))
            })
            .map(|(_, quorum)| (quorum.llmq_type, quorum.quorum_hash))
            .collect();
        assert!(!signed_rotating.is_empty(), "the diff brings signed rotating quorums");
        let masternode_list = base_list
            .apply_diff(diff, 2_241_332, Network::Mainnet)
            .expect("expected to apply diff");

        for (llmq_type, quorum_hash) in signed_rotating {
            assert_eq!(
                masternode_list.quorums[&llmq_type][&quorum_hash].verifying_chain_lock_signature,
                None,
                "rotating quorum {quorum_hash} must carry no ChainLock signature"
            );
        }

        let expected_signatures: BTreeMap<&str, Vec<u8>> = BTreeMap::from([
            ("000000000000000fcc3b58235989afa1962b6d6f238a2201190452123231a704", hex_conservative::decode_to_vec("8ba84befb59e4f16160ca69a5a4785b314bd3f2ed9ae435daacdba23b3079b0fabc909f159ec80243b8ccc4c95f63bdb1176749b83fffc429be426e899982bc50e15f4d923df91b341c2cfdf47620a7ee35502593b1484b9f444466e04da52fd").unwrap()),
            ("000000000000000887fa15abc502ec49ec3b318fd79fc7fdfda514f67b895009", hex_conservative::decode_to_vec("b03d75ae15fdaa3fbc72cf548f3cece8be6ad266ae7f4f79755537c80fe0a4b641cf6391ac17105d97d602e86e81d4e80331f9b5fb616cec399230d4b9b7ef9896885b1ad78109973ad5855ea5684994740b7ed710b4b72173c5e170b3df2a46").unwrap()),
            ("00000000000000133c9d6e64823bdfd80d7640b255faea18ce1d6419b55e3314", hex_conservative::decode_to_vec("909ca60a8923b631d7d939d005431097a6974eef0e03a09a58c8e6a846c74ca94720eeda407cb20271e8f6e12ec23d0905da732fd1a50e8d1df414aad2094e28eb6dc24b64338add8e6085590c4c5849a9003eeaee91408f5bd4b41eaf1039e3").unwrap()),
            ("00000000000000179e5ed3711a8257dcbb0d17f7d5c52c92a9a122ca574f7b1c", hex_conservative::decode_to_vec("885a2ba9ad907d9421c38af7aec35dff7be85d1788ccaef760056e1eef890b83b8a8e1e898dade5d3f52cfbc3b7b9eb5188d15283a43b68fcc1c75920727597ab905a0c18d9d9c335dc66a5cbeb1874f5bb54c4219096800ccfe3dacf3240fe6").unwrap()),
            ("0000000000000014a54ccad3b51e1fc6fded48dea59c5dbc17bcb58b5aa95320", hex_conservative::decode_to_vec("8d9bc1065ff57b53302667a1564955ec32e823c0e74272e2e6f45e9bce3f9555bc772ce636cdc0e7ba15bd2f181f669a17e8893f0327fdb6e1af7e74cbdfaa96a630acbd161e110ee3e22dc788c96564ed754594f6d7b02447bf8ef0dae5a93c").unwrap()),
            ("000000000000000e7463a65d312855272e68bb03acd989ef36027d584951ca27", hex_conservative::decode_to_vec("802f1cc00ded6f81d1904de5b5d8cfbf28a3165cc9f8f8569720293f400dc81a8427af171c31c63cc29d943c40a1545c03c8a3e3154573f166305f05dd8c7fac2b8abff00d950c042713a2b913748931e9a04fc757a7597f175dca96b753c4e8").unwrap()),
            ("00000000000000194f5c21458d718d8b1a2e11a6d4b3a1c1183d70123b8deb36", hex_conservative::decode_to_vec("a46a067f15cb6525cfaa702b585f77115d59642a04032206430325db517522ce4076885859b591b5abcbe6843c1f08e502e4aad1f8124c1bab95ad0feaabe16dff1b0181dd8d7869d6be4e5cf82480cedb76471377c760016d56e5446fe9dc40").unwrap()),
            ("0000000000000009bd850bce5941826fdce7a2583644d6c197348b15151cb33c", hex_conservative::decode_to_vec("97f84875bbe040af2ddd38e10c9df84cd2e0ddbc1caa693de2807e42209997f3ed9a6d2a23da02e255de409ae430d7fa121c61ae650b6654e0cabe6e3fe3e1bb557c48fdefb8a6a60d68d2d4ded7b6e4799567942529f3caafbc98a74d4359b8").unwrap()),
            ("0000000000000004d810f16edf5e672ee7fb4fe46342a9c28de54db62802334e", hex_conservative::decode_to_vec("879326d10acd1f4299c87e5dfd7832913631afa90ef4aaa31e61d8e5d74b5ed3f1f461918b17cbf1a9a124667ceba0b00745f67b1eb127f5156fbf43145b973bf7ce56da3b3e6f99e5fee0fb863fdafeaa13bad78204933edf5dd74963d22c6b").unwrap()),
            ("0000000000000027727e5c45130cef688c056ad1ce1740b6eeb5e7a8a556d24f", hex_conservative::decode_to_vec("829e508a99823b607256ab4297cacc1b7580d49e1e18a2af24aacf157c25f4195be9f7600507e3f5f4a502f08beeb75a048ff280a555705b899733431a7997ac6f98f63c259f83f65fa2548d23b42dbcbd3fcaf17fcdaee183c354f1cb046942").unwrap()),
            ("000000000000000e6d139ec023a1fbb12a7a19d7ab5db1c34322445494685b52", hex_conservative::decode_to_vec("8d230edbed207dcb3ff28c72c14a72f1d79f6e8b8345ff6e7b71caa063750193dac0d8047fa89889f517d3579505282115b9078c6ca85cc66a91db407001c9247902456b239a721975f1930cea8e489fae5e2bc714445e86d3d7d58c6b86aa9f").unwrap()),
            ("000000000000002910000426717f2e2fe13659de4199ebd2ad0df8acaa40ec55", hex_conservative::decode_to_vec("b82ac105dadd8f22edc80be0d9a3f0565735aec0f5350bd961d01e3b95ad8b6410a15cb97b99fc04e5cbc11e315c2af50eca9ac3829b2321c2c3043eed03f31a8ed91ca1dc25c45c06f74ad6ca399c7e6462bd96c75e4f688ae5fa28e09591db").unwrap()),
            ("00000000000000034d13700c17a966c7d4da13134d3928460922dc2122934d5f", hex_conservative::decode_to_vec("aeabf173f885c401dd859d5e743dfa60106ac416e57d2870aa06241ad0133397b88484d7e9f95154a9167537e1dd524f18127854aa270088007b23155c22f6dd07d6696b2fea4599ed72b7be62e0bad519e296da38cd9db0b29dbcde5888be0c").unwrap()),
            ("00000000000000059bbc2b37c8d846653c3c7e213ca2507b74b1139fee57346b", hex_conservative::decode_to_vec("b867cacbf145215502344a36a46839255b39c44129da259ad1eb1dab1c33b5ad6cd4e9a34f083590ed7a8153c12ed05c03f170b87dc16cff6a031519dbc60ae83a4713f8fdfeef7b1be66258b053b2865957b61a4d4cea445799a4cfe8ca7590").unwrap()),
            ("000000000000003c41c3b18552e0dbddd59ca4e9235ae6799c0f88d5d39b3375", hex_conservative::decode_to_vec("b05f472ea28f41961dbadd4bfc33ad46120a8a5c082b46f88598f263f47033b252f5eb5fb10fd67cb9ca8790c56848550a06661332abc72cd1e1e9bb2e6cc63219f0b05faa981589cddc5dec57118db637c1819f5da023e78db930c4347e3799").unwrap()),
            ("0000000000000004beb237cb0c284418129d337ccbacf0ce4bcacaef052aa17b", hex_conservative::decode_to_vec("8305847336eea1f9f502216ba03203b7614a4e6038b315a5342bc100a3bb9fc075df88415c5f9dcb88c35145e7ee44ba178012da65826fb4c6ab7c986dc50daccf383a57d8c8476dd864c24fb8a7c7c040a6dc57c238ee499733b6006b0611b4").unwrap()),
            ("0000000000000028c15e263548139cef64e9fcebc6d793bd9448d30797c14f80", hex_conservative::decode_to_vec("a3c7d6d59248387269a928f4b37dad3f6559cae800acecf8e1502c5a7e2862d501013a91f30e7d7f2a63055adefeb7ae16de6020d4b6281c69b80381ee2e8c93b6a148d1934ac10cc71b5dd441bee988b2ee51022c345286ae4b241b149446bd").unwrap()),
            ("000000000000000ff31a80c31e6773c572e797cae876b6603b587915d738dc89", hex_conservative::decode_to_vec("b8bbddd9f5214880d65cf7d096cb213b1f5bdd991669487e45812e4efaea8fe0cdc9642c7e9e9d4f8ebc0c1dd607c9eb19bdab1aed6eb4c52789ad7c41e2ce80fd1b8bef393b421089c9ab8b156b7917e3bd39c6b28b8e720212d94c2f7cf857").unwrap()),
            ("0000000000000019e3f9a338f32411d2f3e91e623b0bcbf327bca32b9ded4b9d", hex_conservative::decode_to_vec("a12e8c68461a3248cc038ce50fc23ebfeae3718e10ee949e763deee0cde0b9e1a637b19ab18765604ef98be4a49ce6bc0525acb92db0defcfb57d993d0cf63ccc9f4378a11ed5a6707f791ded468a04daf4fa650a0e95689261615360faf80d3").unwrap()),
            ("0000000000000025b0f8b6cd855cab58429ee158ddfd32358ab55b98e53feaa2", hex_conservative::decode_to_vec("b0f7402bd4c6c3926431d7c3bcb56ef52caf1d4edc7ab5d01ddd10ac6023aaccc9f336d22eb5c8e2930339875e9159cc0b54de90e5aa28d9bc4db4b3a7e5d6ea1c3c84b6817a5f13557d57b9f841494a831d8e58114710e853454847d1ab53d5").unwrap()),
            ("000000000000001912a0ac17300c5b7bfd1385a418137c3bc8d273ac3d9f85d7", hex_conservative::decode_to_vec("ab751a79ea12c823745cccb7600b8aad50b72c0ac0d090e156a84755fe8a8eee9a8e57d076728428fa9d98f571be99d20a93090f1f310a78b66d26668672448b5e564a110640487ec508677faf1f79c14dcee34404e6d8c1c8037151f4ec7e4d").unwrap()),
            ("000000000000001d3789f5d1e7318b4350f20bdf1ea4beeeedf26780312114db", hex_conservative::decode_to_vec("ac6edba765e86f2d3c86083c2919bd285e3a635413f2783a7261a0447a135827c73b635277265255cb678df3aa275986198a174c9fa39e499d0a26f45a7a8e3a7559ddebe200c13a96c060a5f7bc689d5fb93f68be9d6113d94acbbab714c52c").unwrap()),
            ("0000000000000010b28f1ea61bf3ff88cd2fef7e33a5f1868fb555ec682636eb", hex_conservative::decode_to_vec("b96908533c42ecb7e540cec408f5d2aec93d97df37de695b9e92b50145a001153b3392c7aeab697a168e813c566dace007410e6159db92453732b067c0f22a2df413b113c47e43ace3906572db46b451565531c0a39a6ad9f5fb7e761273d7bb").unwrap()),
            ("0000000000000026d8a2480f338951dfedc5e7abdd3704500a10b4a188c89bf8", hex_conservative::decode_to_vec("af13e196c300afce6ced40fa32851d1ff8646e2a1c0f03fc83cce88a44291a400fe8026dcb95edc9f2485b2596731c8e092fd313265269ffb5c5b0d13c4f0cda75ae69db27829c400cd25c2b55ca929ab8ac7a2b29f859e69800796c3d98c5a2").unwrap())
        ]);

        let quorums = masternode_list
            .quorums
            .get(&LLMQType::Llmqtype100_67)
            .expect("expected quorums of type Llmqtype100_67");
        assert!(!quorums.is_empty(), "Expected at least one quorum");

        for (quorum_hash, quorum) in quorums {
            let quorum_hash_hex = format!("{:x}", quorum_hash);
            let Some(VerifyingChainLockSignaturesType::NonRotating(actual_signature)) =
                quorum.verifying_chain_lock_signature
            else {
                panic!("expected non rotating");
            };

            if let Some(expected_signature) = expected_signatures.get(quorum_hash_hex.as_str()) {
                let actual_sig_bytes = actual_signature.as_bytes();

                assert_eq!(
                    &actual_sig_bytes[..],
                    *expected_signature,
                    "Signature mismatch for quorum {}",
                    quorum_hash_hex
                );
            } else {
                panic!(
                    "Unexpected quorum hash {} found in test but not in expected values!",
                    quorum_hash_hex
                );
            }
        }
    }

    /// A diff that changes neither masternodes nor quorums shares both maps
    /// with its base list.
    #[test]
    fn a_diff_that_changes_nothing_shares_the_lists_maps() {
        let base = MasternodeList::empty(crate::BlockHash::dummy(1), 1);
        let next =
            base.apply_diff(MnListDiff::dummy_between(1, 2), 2, Network::Mainnet).expect("applies");

        assert!(Arc::ptr_eq(&base.masternodes, &next.masternodes));
        assert!(Arc::ptr_eq(&base.quorums, &next.quorums));
    }
}
