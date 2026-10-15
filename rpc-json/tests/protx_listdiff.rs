//! `protx listdiff` output recorded from Dash Core v23.1.8 and v24.0.0-rc.3 on regtest
//! (`tests/data/protx_listdiff/README.md`), followed the way a client keeps a masternode list:
//! start from the full list at the first height and apply each block's diff.

use std::collections::BTreeMap;

use dashcore_rpc_json::dashcore::ProTxHash;
use dashcore_rpc_json::dashcore::hashes::{Hash, hash160};
use dashcore_rpc_json::{DMNState, DMNStateDiff, MasternodeListDiff};
use serde_json::Value;

/// The block registering the recorded masternodes; every later block up to `LAST_HEIGHT` is one
/// recorded step.
const FIRST_HEIGHT: u32 = 302;
const LAST_HEIGHT: u32 = 310;
/// Block of the ProUpRegTx changing MN1's operator key, which resets its operator payout.
const MN1_OPERATOR_CHANGE_HEIGHT: u32 = 305;
/// Block of the ProUpServTx by MN1's new operator, which revives MN1.
const MN1_REVIVE_HEIGHT: u32 = 306;
/// Block of the ProUpRevTx revoking MN2's operator, which resets its operator payout.
const MN2_REVOCATION_HEIGHT: u32 = 310;

macro_rules! fixture {
    ($version:literal, $name:literal) => {
        include_str!(concat!("data/protx_listdiff/", $version, "/", $name, ".json"))
    };
}

macro_rules! recording {
    ($version:literal) => {
        Recording {
            version: $version,
            metadata: fixture!($version, "recording"),
            full_lists: [
                fixture!($version, "listdiff_1_302"),
                fixture!($version, "listdiff_1_303"),
                fixture!($version, "listdiff_1_304"),
                fixture!($version, "listdiff_1_305"),
                fixture!($version, "listdiff_1_306"),
                fixture!($version, "listdiff_1_307"),
                fixture!($version, "listdiff_1_308"),
                fixture!($version, "listdiff_1_309"),
                fixture!($version, "listdiff_1_310"),
            ],
            block_diffs: [
                fixture!($version, "listdiff_302_303"),
                fixture!($version, "listdiff_303_304"),
                fixture!($version, "listdiff_304_305"),
                fixture!($version, "listdiff_305_306"),
                fixture!($version, "listdiff_306_307"),
                fixture!($version, "listdiff_307_308"),
                fixture!($version, "listdiff_308_309"),
                fixture!($version, "listdiff_309_310"),
            ],
            whole_diff: fixture!($version, "listdiff_302_310"),
        }
    };
}

type MasternodeList = BTreeMap<ProTxHash, DMNState>;

struct Recording {
    version: &'static str,
    metadata: &'static str,
    /// `protx listdiff 1 h` for every recorded height.
    full_lists: [&'static str; (LAST_HEIGHT - FIRST_HEIGHT + 1) as usize],
    /// `protx listdiff h-1 h` for every block after the first.
    block_diffs: [&'static str; (LAST_HEIGHT - FIRST_HEIGHT) as usize],
    /// `protx listdiff 302 310`.
    whole_diff: &'static str,
}

fn recordings() -> [Recording; 2] {
    [recording!("v23.1.8"), recording!("v24.0.0-rc.3")]
}

fn parse_diff(json: &str) -> MasternodeListDiff {
    serde_json::from_str(json).expect("expected Core's protx listdiff to deserialize")
}

fn masternode_state<'a>(
    list: &'a MasternodeList,
    pro_tx_hash: &ProTxHash,
    context: &str,
) -> &'a DMNState {
    list.get(pro_tx_hash).unwrap_or_else(|| panic!("{context}: {pro_tx_hash} is not listed"))
}

fn updated_entry<'a>(diff: &'a MasternodeListDiff, pro_tx_hash: &ProTxHash) -> &'a DMNStateDiff {
    &diff
        .updated_mns
        .iter()
        .find(|(hash, _)| hash == pro_tx_hash)
        .unwrap_or_else(|| panic!("expected {pro_tx_hash} to be updated in this diff"))
        .1
}

fn apply(list: &mut MasternodeList, diff: MasternodeListDiff) {
    for masternode in diff.added_mns {
        list.insert(masternode.pro_tx_hash, masternode.state);
    }
    for pro_tx_hash in diff.removed_mns {
        list.remove(&pro_tx_hash);
    }
    for (pro_tx_hash, state_diff) in diff.updated_mns {
        list.get_mut(&pro_tx_hash)
            .expect("an updated masternode is in the list")
            .apply_diff(state_diff);
    }
}

impl Recording {
    fn metadata(&self) -> Value {
        serde_json::from_str(self.metadata).expect("expected recording.json to deserialize")
    }

    fn masternode(&self, name: &str) -> ProTxHash {
        serde_json::from_value(self.metadata()["masternodes"][name].clone())
            .expect("expected a recorded pro tx hash")
    }

    /// The 20-byte hash Core pays to for a recorded payout address: the key hash inside a
    /// P2PKH `scriptPubKey`, or the hash of a P2SH redeem script.
    fn address_hash(&self, label: &str) -> [u8; 20] {
        let address = &self.metadata()["addresses"][label];
        if let Some(script) = address["scriptPubKey"].as_str() {
            let script =
                hex_conservative::decode_to_vec(script).expect("expected a hex scriptPubKey");
            assert!(
                script.len() == 25
                    && script.starts_with(&[0x76, 0xa9, 0x14])
                    && script.ends_with(&[0x88, 0xac]),
                "expected a P2PKH scriptPubKey for {label}"
            );
            script[3..23].try_into().expect("20 bytes")
        } else {
            let redeem_script = address["redeemScript"].as_str().expect("expected a redeem script");
            let redeem_script = hex_conservative::decode_to_vec(redeem_script)
                .expect("expected a hex redeem script");
            hash160::Hash::hash(&redeem_script).to_byte_array()
        }
    }

    fn full_list(&self, height: u32) -> MasternodeList {
        let diff = parse_diff(self.full_lists[(height - FIRST_HEIGHT) as usize]);
        assert_eq!((diff.base_height, diff.block_height), (1, height), "{}", self.version);
        diff.added_mns.into_iter().map(|mn| (mn.pro_tx_hash, mn.state)).collect()
    }

    fn block_diff(&self, height: u32) -> MasternodeListDiff {
        let diff = parse_diff(self.block_diffs[(height - FIRST_HEIGHT - 1) as usize]);
        assert_eq!((diff.base_height, diff.block_height), (height - 1, height), "{}", self.version);
        diff
    }

    /// The full list at the first height with the block diffs up to `height` applied.
    fn followed_list(&self, height: u32) -> MasternodeList {
        let mut list = self.full_list(FIRST_HEIGHT);
        for block in FIRST_HEIGHT + 1..=height {
            apply(&mut list, self.block_diff(block));
        }
        list
    }

    /// Core's full list at `height`, except that an operator payout Core reset in that block
    /// keeps the payout it had: no diff prints such a reset.
    fn full_list_without_payout_resets(&self, height: u32) -> MasternodeList {
        let mut list = self.full_list(height);
        for (masternode, reset_height) in
            [("MN1", MN1_OPERATOR_CHANGE_HEIGHT), ("MN2", MN2_REVOCATION_HEIGHT)]
        {
            if height == reset_height {
                let pro_tx_hash = self.masternode(masternode);
                let previous_payout =
                    masternode_state(&self.full_list(height - 1), &pro_tx_hash, self.version)
                        .operator_payout_address;
                list.get_mut(&pro_tx_hash).expect("listed").operator_payout_address =
                    previous_payout;
            }
        }
        list
    }
}

#[test]
fn each_recording_holds_the_blocks_these_tests_name() {
    for recording in recordings() {
        let metadata = recording.metadata();
        let steps = metadata["steps"].as_array().expect("expected steps");
        let heights: Vec<(u64, u64)> = steps
            .iter()
            .map(|step| (step["from"].as_u64().expect("from"), step["to"].as_u64().expect("to")))
            .collect();
        let expected: Vec<(u64, u64)> = (FIRST_HEIGHT..LAST_HEIGHT)
            .map(|height| (height.into(), (height + 1).into()))
            .collect();
        assert_eq!(heights, expected, "{}", recording.version);
        let step = |height: u32| {
            steps[(height - FIRST_HEIGHT - 1) as usize]["step"].as_str().expect("a step label")
        };
        assert!(
            step(MN1_OPERATOR_CHANGE_HEIGHT).contains("changes the operator key"),
            "{}",
            recording.version
        );
        assert!(step(MN1_REVIVE_HEIGHT).contains("revive"), "{}", recording.version);
        assert!(step(MN2_REVOCATION_HEIGHT).contains("revokes"), "{}", recording.version);
    }
}

#[test]
fn a_block_diff_carries_the_operator_payout_a_pro_up_serv_tx_sets() {
    for recording in recordings() {
        let diff = recording.block_diff(303);
        for (masternode, label) in
            [("MN1", "mn1_operator_payout_p2pkh"), ("MN2", "mn2_operator_payout_p2pkh")]
        {
            assert_eq!(
                updated_entry(&diff, &recording.masternode(masternode)).operator_payout_address,
                Some(Some(recording.address_hash(label))),
                "{} {masternode}",
                recording.version
            );
        }
    }
}

#[test]
fn a_block_diff_carries_a_p2sh_operator_payout_as_its_script_hash() {
    for recording in recordings() {
        let diff = recording.block_diff(304);
        assert_eq!(
            updated_entry(&diff, &recording.masternode("MN1")).operator_payout_address,
            Some(Some(recording.address_hash("mn1_operator_payout_p2sh"))),
            "{}",
            recording.version
        );
    }
}

#[test]
fn a_revive_diff_carries_the_new_operators_payout_with_the_revived_height() {
    for recording in recordings() {
        let diff = recording.block_diff(MN1_REVIVE_HEIGHT);
        let entry = updated_entry(&diff, &recording.masternode("MN1"));
        assert_eq!(
            (entry.pose_revived_height, entry.pose_ban_height, entry.operator_payout_address),
            (
                Some(MN1_REVIVE_HEIGHT),
                Some(None),
                Some(Some(recording.address_hash("mn1_new_operator_payout_p2pkh")))
            ),
            "{}",
            recording.version
        );
    }
}

/// Core prints a diff field only when it changed, so a list followed through diffs must keep
/// every field a diff leaves out: it equals Core's full list at every height, except for the
/// operator payout resets no diff prints. Core prints `PoSeRevivedHeight` only in a diff that
/// spans the revive, so MN1's payment after its revive is where a cleared revived height shows.
#[test]
fn following_the_block_diffs_reproduces_cores_full_lists_but_the_operator_payout_resets() {
    for recording in recordings() {
        for height in FIRST_HEIGHT..=LAST_HEIGHT {
            assert_eq!(
                recording.followed_list(height),
                recording.full_list_without_payout_resets(height),
                "{} at {height}",
                recording.version
            );
        }
    }
}

/// Core empties the operator payout on an operator key change and on a revocation, and prints a
/// diff field only when it can encode the new value, so the diff of that block carries no
/// payout. `apply_diff` applies only what a diff prints, so a list followed through diffs keeps
/// the last payout Core printed; only Core's full list shows the reset. (A diff over several
/// blocks can also span a reset followed by a ProUpServTx setting the same payout again: it
/// prints the new operator key and no payout while Core has one.)
#[test]
fn a_block_diff_cannot_show_an_operator_payout_reset_so_the_last_payout_stays() {
    for recording in recordings() {
        for (masternode, height) in
            [("MN1", MN1_OPERATOR_CHANGE_HEIGHT), ("MN2", MN2_REVOCATION_HEIGHT)]
        {
            let context = format!("{} {masternode} at {height}", recording.version);
            let pro_tx_hash = recording.masternode(masternode);
            let previous_payout =
                masternode_state(&recording.full_list(height - 1), &pro_tx_hash, &context)
                    .operator_payout_address;
            assert!(previous_payout.is_some(), "{context}");
            assert_eq!(
                masternode_state(&recording.full_list(height), &pro_tx_hash, &context)
                    .operator_payout_address,
                None,
                "{context}"
            );
            assert_eq!(
                updated_entry(&recording.block_diff(height), &pro_tx_hash).operator_payout_address,
                None,
                "{context}"
            );
            assert_eq!(
                masternode_state(&recording.followed_list(height), &pro_tx_hash, &context)
                    .operator_payout_address,
                previous_payout,
                "{context}"
            );
        }
    }
}

/// A diff over several blocks shows only the net change of each field: MN2's payout, set and
/// then reset inside the window, does not appear at all, and the list ends exactly where Core's
/// does.
#[test]
fn one_diff_over_every_recorded_block_ends_at_cores_full_list() {
    for recording in recordings() {
        let whole_diff = parse_diff(recording.whole_diff);
        assert_eq!(
            updated_entry(&whole_diff, &recording.masternode("MN2")).operator_payout_address,
            None,
            "{}",
            recording.version
        );
        let mut list = recording.full_list(FIRST_HEIGHT);
        apply(&mut list, whole_diff);
        assert_eq!(list, recording.full_list(LAST_HEIGHT), "{}", recording.version);
    }
}
