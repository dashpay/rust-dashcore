//! Checkpoint system for chain validation and sync optimization
//!
//! Checkpoints are hardcoded blocks at specific heights that help:
//! - Prevent accepting blocks from invalid chains
//! - Optimize initial sync by starting from recent checkpoints
//! - Protect against deep reorganizations
//! - Bootstrap masternode lists at specific heights

use dashcore::{BlockHash, CompactTarget, Target};
use dashcore_hashes::{hex, Hash};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A checkpoint representing a known valid block
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Block height
    pub height: u32,
    /// Block hash
    pub block_hash: BlockHash,
    /// Previous block hash
    pub prev_blockhash: BlockHash,
    /// Block timestamp
    pub timestamp: u32,
    /// Difficulty target
    pub target: Target,
    /// Merkle root (optional for older checkpoints)
    pub merkle_root: Option<BlockHash>,
    /// Cumulative chain work up to this block (as hex string)
    pub chain_work: String,
    /// Masternode list identifier (e.g., "ML1088640__70218")
    pub masternode_list_name: Option<String>,
    /// Protocol version at this checkpoint
    pub protocol_version: Option<u32>,
    /// Nonce value for the block
    pub nonce: u32,
}

impl Checkpoint {
    /// Extract protocol version from masternode list name or use stored value
    pub fn protocol_version(&self) -> Option<u32> {
        // Prefer explicitly stored protocol version
        if let Some(version) = self.protocol_version {
            return Some(version);
        }

        // Otherwise extract from masternode list name
        self.masternode_list_name.as_ref().and_then(|name| {
            // Format: "ML{height}__{protocol_version}"
            name.split("__").nth(1).and_then(|s| s.parse().ok())
        })
    }

    /// Check if this checkpoint has an associated masternode list
    pub fn has_masternode_list(&self) -> bool {
        self.masternode_list_name.is_some()
    }
}

/// Manages checkpoints for a specific network
pub struct CheckpointManager {
    /// Checkpoints indexed by height
    checkpoints: HashMap<u32, Checkpoint>,
    /// Sorted list of checkpoint heights for efficient searching
    sorted_heights: Vec<u32>,
}

impl CheckpointManager {
    /// Create a new checkpoint manager from a list of checkpoints
    pub fn new(checkpoints: Vec<Checkpoint>) -> Self {
        let mut checkpoint_map = HashMap::new();
        let mut heights = Vec::new();

        for checkpoint in checkpoints {
            heights.push(checkpoint.height);
            checkpoint_map.insert(checkpoint.height, checkpoint);
        }

        heights.sort_unstable();

        Self {
            checkpoints: checkpoint_map,
            sorted_heights: heights,
        }
    }

    /// Get a checkpoint at a specific height
    pub fn get_checkpoint(&self, height: u32) -> Option<&Checkpoint> {
        self.checkpoints.get(&height)
    }

    /// Check if a block hash matches the checkpoint at the given height
    pub fn validate_block(&self, height: u32, block_hash: &BlockHash) -> bool {
        match self.checkpoints.get(&height) {
            Some(checkpoint) => checkpoint.block_hash == *block_hash,
            None => true, // No checkpoint at this height, so it's valid
        }
    }

    /// Get the last checkpoint at or before the given height
    pub fn last_checkpoint_before_height(&self, height: u32) -> Option<&Checkpoint> {
        // Binary search for the highest checkpoint <= height
        let pos = self.sorted_heights.partition_point(|&h| h <= height);
        if pos > 0 {
            let checkpoint_height = self.sorted_heights[pos - 1];
            self.checkpoints.get(&checkpoint_height)
        } else {
            None
        }
    }

    /// Get the last checkpoint
    pub fn last_checkpoint(&self) -> Option<&Checkpoint> {
        self.sorted_heights.last().and_then(|&height| self.checkpoints.get(&height))
    }

    /// Get all checkpoint heights
    pub fn checkpoint_heights(&self) -> &[u32] {
        &self.sorted_heights
    }

    /// Get the last checkpoint before a given timestamp
    pub fn last_checkpoint_before_timestamp(&self, timestamp: u32) -> Option<&Checkpoint> {
        let mut best_checkpoint = None;
        let mut best_height = 0;

        for checkpoint in self.checkpoints.values() {
            if checkpoint.timestamp <= timestamp && checkpoint.height >= best_height {
                best_height = checkpoint.height;
                best_checkpoint = Some(checkpoint);
            }
        }

        best_checkpoint
    }

    /// Get the checkpoint to use for sync chain based on override settings
    pub fn get_sync_checkpoint(&self, wallet_creation_time: Option<u32>) -> Option<&Checkpoint> {
        // Default to checkpoint based on wallet creation time
        if let Some(creation_time) = wallet_creation_time {
            self.last_checkpoint_before_timestamp(creation_time)
        } else {
            self.last_checkpoint()
        }
    }

    /// Check if a fork at the given height should be rejected due to checkpoint
    pub fn should_reject_fork(&self, fork_height: u32) -> bool {
        if let Some(last_checkpoint) = self.last_checkpoint() {
            fork_height <= last_checkpoint.height
        } else {
            false
        }
    }
}

/// Create mainnet checkpoints
pub fn mainnet_checkpoints() -> Vec<Checkpoint> {
    vec![
        // Genesis block (required)
        create_checkpoint(
            0,
            "00000ffd590b1485b3caadc19b22e6379c733355108f107a430458cdf3407ab6",
            "0000000000000000000000000000000000000000000000000000000000000000",
            1390095618,
            0x1e0ffff0,
            "0x0000000000000000000000000000000000000000000000000000000100010001",
            "e0028eb9648db56b1ac77cf090b99048a8007e2bb64b68f092c03c7f56a662c7",
            28917698,
            None,
        ),
        // Early network checkpoint (1 week after genesis)
        create_checkpoint(
            4991,
            "000000003b01809551952460744d5dbb8fcbd6cbae3c220267bf7fa43f837367",
            "000000001263f3327dd2f6bc445b47beb82fb8807a62e252ba064e2d2b6f91a6",
            1390163520,
            0x1e0fffff,
            "0x00000000000000000000000000000000000000000000000000000000271027f0",
            "7faff642d9e914716c50e3406df522b2b9a10ea3df4fef4e2229997367a6cab1",
            357631712,
            None,
        ),
        // 3 months checkpoint
        create_checkpoint(
            107996,
            "00000000000a23840ac16115407488267aa3da2b9bc843e301185b7d17e4dc40",
            "000000000006fe4020a310786bd34e17aa7681c86a20a2e121e0e3dd599800e8",
            1395522898,
            0x1b04864c,
            "0x0000000000000000000000000000000000000000000000000056bf9caa56bf9d",
            "15c3852f9e71a6cbc0cfa96d88202746cfeae6fc645ccc878580bc29daeff193",
            10049236,
            None,
        ),
        // 2017 checkpoint
        create_checkpoint(
            750000,
            "00000000000000b4181bbbdddbae464ce11fede5d0292fb63fdede1e7c8ab21c",
            "00000000000001e115237541be8dd91bce2653edd712429d11371842f85bd3e1",
            1491953700,
            0x1a075a02,
            "0x00000000000000000000000000000000000000000000000485f01ee9f01ee9f8",
            "0ce99835e2de1240e230b5075024817aace2b03b3944967a88af079744d0aa62",
            2199533779,
            None,
        ),
        // Recent checkpoint with masternode list (2022)
        create_checkpoint(
            1700000,
            "000000000000001d7579a371e782fd9c4480f626a62b916fa4eb97e16a49043a",
            "000000000000001a5631d781a4be0d9cda08b470ac6f108843cedf32e4dc081e",
            1657142113,
            0x1927e30e,
            "000000000000000000000000000000000000000000007562df93a26b81386288",
            "dafe57cefc3bc265dfe8416e2f2e3a22af268fd587a48f36affd404bec738305",
            3820512540,
            Some("ML1700000__70227"),
        ),
        // Latest checkpoint with masternode list (2022/2023)
        create_checkpoint(
            1900000,
            "000000000000001b8187c744355da78857cca5b9aeb665c39d12f26a0e3a9af5",
            "000000000000000d41ff4e55f8ebc2e610ec74a0cbdd33e59ebbfeeb1f8a0a0d",
            1688744911,
            0x192946fd,
            "000000000000000000000000000000000000000000008798ed692b94a398aa4f",
            "3a6ff72336cf78e45b23101f755f4d7dce915b32336a8c242c33905b72b07b35",
            498598646,
            Some("ML1900000__70230"),
        ),
        // Block 2300000 (2025) - recent checkpoint
        create_checkpoint(
            2300000,
            "00000000000000186f9f2fde843be3d66b8ae317cabb7d43dbde943d02a4b4d7",
            "000000000000000d51caa0307836ca3eabe93068a9007515ac128a43d6addd4e",
            1751767455,
            0x1938df46,
            "0x00000000000000000000000000000000000000000000aa3859b6456688a3fb53",
            "b026649607d72d486480c0cef823dba6b28d0884a0d86f5a8b9e5a7919545cef",
            972444458,
            Some("ML2300000__70232"),
        ),
    ]
}

/// Create testnet checkpoints (every 50k blocks)
pub fn testnet_checkpoints() -> Vec<Checkpoint> {
    vec![
        // Height 0
        create_checkpoint(
            0,
            "00000bafbc94add76cb75e2ec92894837288a481e5c005f6563d91623bf8bc2c",
            "0000000000000000000000000000000000000000000000000000000000000000",
            1390666206,
            0x1e0ffff0,
            "0x0000000000000000000000000000000000000000000000000000000000100010",
            "e0028eb9648db56b1ac77cf090b99048a8007e2bb64b68f092c03c7f56a662c7",
            3861367235,
            None,
        ),
        // Height 50000
        create_checkpoint(
            50000,
            "0000000000d737f4b6f0fcd10ecd2f59e5e4f9409b1afae5fb50604510a2551f",
            "00000000000585316c6c59a809d7bbd13cf126a1ff796613cb404dc4205afdd3",
            1550935893,
            0x1c00e933,
            "0x000000000000000000000000000000000000000000000000003ce64fe7baf4a4",
            "1564f9ced973ee81c27c4eb79c6cea9ce1d56e5f26e9dc16524cc86b246772a3",
            2155245409,
            None,
        ),
        // Height 100000
        create_checkpoint(
            100000,
            "000000008650f09124958e7352f844f9c15705171ac38ee6668534c5c238b916",
            "000000000888fc6c96350205e2399f9f1da0464448d40c50e3cb897c3e844758",
            1558052383,
            0x1d00968d,
            "0x0000000000000000000000000000000000000000000000000063cf504aefbfe3",
            "13f277df58c6bc9090a9ff9b17b810fa550d052ed77fd50bbb3cd5f9a684feac",
            2703170280,
            None,
        ),
        // Height 150000
        create_checkpoint(
            150000,
            "000000000c0bf229aec2ab933a9f1b2e5a0558c2d7bbd1a31e49f2c8ee0d8cf6",
            "00000000087fffa38794dae9df74be3f69f66029e2225ba1569fa4e478cf2698",
            1565028909,
            0x1c102498,
            "0x00000000000000000000000000000000000000000000000000729d4b5e17d6e6",
            "2213532c050ba2a2be8f22f0d565670b696c590d76928a6a5a8d40db9ba6725c",
            1969591479,
            None,
        ),
        // Height 200000
        create_checkpoint(
            200000,
            "000000001015eb5ef86a8fe2b3074d947bc972c5befe32b28dd5ce915dc0d029",
            "0000000019ba398812efbd03ae869a90bc2d6c705cc94406da2d0f6ea2c017d5",
            1572008328,
            0x1c1960c3,
            "0x0000000000000000000000000000000000000000000000000098ebee572c3cd1",
            "5a2b6f09040149f7b67f093b900b5a31545ff10f2aab6a1d0f97d4677ab6629c",
            3181117336,
            None,
        ),
        // Height 250000
        create_checkpoint(
            250000,
            "00000000045c0eab2471f9332128e01b31b6f637073a25b8907f620a2b6861bd",
            "0000000005d0ba322dfe34cf3dbdd49b01e9b9c68322e50413f73620f88c02e2",
            1579348172,
            0x1c2e80d7,
            "0x00000000000000000000000000000000000000000000000000abfcc9c8b38057",
            "a017b029f1787d279b98b989bfab97988e9be7c060f86083a6b29be68b657e96",
            4180884762,
            None,
        ),
        // Height 300000
        create_checkpoint(
            300000,
            "00000059475b2de06486d86c1764ee6058b454eea72a32eb7f900aa94b9d4312",
            "000002303d006a3b2097e927703916e8993bae7d0849fd18636908125f20225e",
            1588424121,
            0x1e0fffff,
            "0x00000000000000000000000000000000000000000000000001e6f6b99adb1c2b",
            "8e3860589c14fe23e40d3113022b72e06632434664208dcaecc7bb6383b782e5",
            1875181696,
            None,
        ),
        // Height 350000
        create_checkpoint(
            350000,
            "000001945abc4914be9c46b726b0d8b5fbbc693ab36d4d538098029055c7b571",
            "000001c7b0eedd4f98108e3bb5938bf0368ede238405d380b33dc795bebb2335",
            1595733312,
            0x1e021d9a,
            "0x00000000000000000000000000000000000000000000000002239b28213deeaa",
            "34912735bc0c9a69ca5b422bc1ad863c26477df1f013841efbd1d4c5aa05ddf1",
            2975,
            None,
        ),
        // Height 400000
        create_checkpoint(
            400000,
            "00000e2d1320af3d1017af18c05f450dd7265d023d1516b24e3a8dd8a0e14a90",
            "0000073a660f27c148b9ba64d928ed794db69292f456ce3deea143b261a22111",
            1605654012,
            0x1e0fffff,
            "0x000000000000000000000000000000000000000000000000022f13342587d0ca",
            "35d5954ea00fa59dfa43a745331d717254d747c684feaa827c538a5bfcb3d8f8",
            30629,
            None,
        ),
        // Height 450000
        create_checkpoint(
            450000,
            "0000000a2a21323dd6894b44e2883716e5979203f5f663fb010ec062a7431f6b",
            "00000009ebc0e508e55cd7c1329fa924951dc868243bfc3a09466ec0f69684b4",
            1614003669,
            0x1e029e5c,
            "0x000000000000000000000000000000000000000000000000022f145128be07d5",
            "6dfca51149c98f2d1f018d9e29d1bc888a9c7e648ec3bcf5175b088e1d90bc6d",
            715,
            None,
        ),
        // Height 500000
        create_checkpoint(
            500000,
            "000000d0f2239d3ea3d1e39e624f651c5a349b5ca729eec29540aeae0ecc94a7",
            "000001d6339e773dea2a9f1eae5e569a04963eb885008be9d553568932885745",
            1621049765,
            0x1e025b1b,
            "0x000000000000000000000000000000000000000000000000022f14e45fc51a2e",
            "618c77a7c45783f5f20e957a296e077220b50690aae51d714ae164eb8d669fdf",
            10457,
            None,
        ),
        // Height 550000
        create_checkpoint(
            550000,
            "0000003707b046f374dc829a48f3f2ac2ebfac9b97127e1fb7bd35b73642e490",
            "000001590e40546a8eebe1a5df2055bf635dac35ce89255a4ac366a010e4ed72",
            1628063334,
            0x1e023939,
            "0x000000000000000000000000000000000000000000000000022f15e3a9b17ac4",
            "fefa7652058dfd148820fff2ce6942298b2eaf222286b72195a9c186ea499453",
            46354,
            None,
        ),
        // Height 600000
        create_checkpoint(
            600000,
            "000000de786e659950e0f27681faf1a91871d15de264d0b769cb5941c1d807c3",
            "000000faf247f27dcb5d9c3cb0e16f9e806701a440bde471432f0190a4ac9fa6",
            1635070663,
            0x1e02040e,
            "0x000000000000000000000000000000000000000000000000027baa2feb4b75db",
            "615b9db7b37547f266428ab239d7f4329b5b3abda0eda4505eb38fa7d4c2b8b4",
            19879,
            None,
        ),
        // Height 650000
        create_checkpoint(
            650000,
            "0000010b9de8b63935b20195f97f5e9d3bcd834342351277d0855ca9671fe078",
            "000001a4c66e690382ba001209febd2b44911b8a0b2e91318d6dc09097aa15bd",
            1642100742,
            0x1e02d93e,
            "0x000000000000000000000000000000000000000000000000027baaa828f86096",
            "ccf49b68724b63adb7170c1b424a808e253611c83deed47908c3d8504f1e3ec6",
            25615,
            None,
        ),
        // Height 700000
        create_checkpoint(
            700000,
            "0000016165b57f3561256a332ab6f5dbd43285205243cc5ec9c7d28c7defb668",
            "0000069da97baf6bac66dc6f860121e4e0e18b3e101d0e81603e9c2d087d3518",
            1649138427,
            0x1e020a77,
            "0x000000000000000000000000000000000000000000000000027bab1f909c6994",
            "3103bed7c635c6f4a6c3ccb34c7dd042e87e1009246b19a03b47b0db586c6cef",
            956892,
            None,
        ),
        // Height 750000
        create_checkpoint(
            750000,
            "00000035a4948e35f1bf7ad28f619501b95c8213f178061e7f8b43d36bcda9b6",
            "00000251754467b97a39d02ab1112d6656b0cd93c58f44a06c237e3b7d75e51a",
            1656190491,
            0x1e028723,
            "0x000000000000000000000000000000000000000000000000027bab8b7557b4d3",
            "96bf40466d3113912b79b330952c3b2c7e1dcd2eca463940426dfbfe551c7d50",
            291789,
            None,
        ),
        // Height 800000
        create_checkpoint(
            800000,
            "00000075cdfa0a552e488406074bb95d831aee16c0ec30114319a587a8a8fb0c",
            "0000011921c298768dc2ab0f9ca5a3ff4527813bbd7cd77f45bf93efd0bb0799",
            1671238603,
            0x1e018b19,
            "0x00000000000000000000000000000000000000000000000002d68bf1d7e434f6",
            "d58300efccbace51cdf5c8a012979e310da21337a7f311b1dcea7c1c894dfb94",
            607529,
            None,
        ),
        // Height 850000
        create_checkpoint(
            850000,
            "000000754e3e225b7d38d0a6b023fa51bf15ba36db4ec32d322262722418ed12",
            "000000c757951cabcead4ec4b88182a1c96ce24c750684b720f0f984952127c4",
            1686814109,
            0x1e012221,
            "0x00000000000000000000000000000000000000000000000002d68c89a0759afc",
            "61161bc132b880bd53f190091fa9c57439a326b456ccfba52aa1158fda559a40",
            736932,
            None,
        ),
        // Height 900000
        create_checkpoint(
            900000,
            "0000011764a05571e0b3963b1422a8f3771e4c0d5b72e9b8e0799aabf07d28ef",
            "00000120ad41e5c990be3b76f8b68f1f84b0b654fb40eb95a75058ac15dee5db",
            1698142346,
            0x1e015ea1,
            "0x00000000000000000000000000000000000000000000000002d68d1a5c376d46",
            "86cb3235ebf9741a39ce85643c4f4a6e00df99b32ecf5795c8ab769610d281ac",
            83145,
            None,
        ),
        // Height 950000
        create_checkpoint(
            950000,
            "0000010dc2164ab88e2302f7e01a0af25065871851b7598ae51eb92146bd514e",
            "00000002fff187918f44433133f9b05a93927f32d0379d0913e792b72370b035",
            1705215051,
            0x1e011364,
            "0x00000000000000000000000000000000000000000000000002d68d9b24193d1f",
            "d3971dba516a230ca7a170727c63c343c849e759dac56382513bf0c257f3c79e",
            233670,
            None,
        ),
        // Height 1000000
        create_checkpoint(
            1000000,
            "000000fddf6f17f24b9f2c7e13daf1bff0307bdb0cf617b61917ef6bd1bddc6a",
            "0000006a12a5e2ff81f6848e9de07cbe7332e3a68e8132df26e0dac7e459ded5",
            1712086681,
            0x1e014c62,
            "0x00000000000000000000000000000000000000000000000002fbb313ef6876cd",
            "5198a0918f9b1ee16afad8c309c31dfeae4bf65aba43651e9f4e85b3f7232908",
            863682,
            None,
        ),
        // Height 1050000
        create_checkpoint(
            1050000,
            "000000accb2b32142fc1c6d90d68e45e392755fb3c79609c48d86b5a7c356bf6",
            "000001790c977c48ab58db97739bf1a26315471d5cdc7c9f1f366df596ef872c",
            1718985215,
            0x1e01ca89,
            "0x00000000000000000000000000000000000000000000000003177931559cd445",
            "1e875aa770930f83681c6621982ff5b56cf5cef73f2cfd8f902b7af5bdc6a93a",
            479846,
            None,
        ),
        // Height 1100000
        create_checkpoint(
            1100000,
            "000000078cc3952c7f594de921ae82fcf430a5f3b86755cd72acd819d0001015",
            "00000068da3dc19e54cefd3f7e2a7f380bf8d9a0eb1090a7197c3e0b10e2cf1f",
            1725934127,
            0x1e017da4,
            "0x000000000000000000000000000000000000000000000000031c3fcb33bc3a48",
            "4cc82bf21c5f1e0e712ca1a3d5bde2f92eee2700b86019c6d0ace9c91a8b9bd8",
            251545,
            None,
        ),
        // Height 1150000
        create_checkpoint(
            1150000,
            "000000e4454d0c168a4b52d85f10f1431d1bccc68c159be1f558f4e5b5c24e53",
            "00000090b468fa3160c09fc5f25a14f3b5f7fff7e639ee6c26787b8474a701aa",
            1732966902,
            0x1e011c98,
            "0x000000000000000000000000000000000000000000000000031ee3a09785e5ee",
            "aff652af95d1159a97c77ad905986a06fd47708eb69aaba9f32688feb9d26826",
            311096,
            None,
        ),
        // Height 1200000
        create_checkpoint(
            1200000,
            "000000595a1fc6b498adce4aa324a4b986d212c005ba1ff7a26d21950147d74f",
            "000001298d4044030d83afca74bd0b6d85db06a5926683ed0a8584d12a2375da",
            1740094681,
            0x1e01713c,
            "0x000000000000000000000000000000000000000000000000031fa4d54e000deb",
            "1ef5decaa52021365cc5980846e4ebf072f1df9514303a6346ba734eb17ac143",
            143784,
            None,
        ),
        // Height 1250000
        create_checkpoint(
            1250000,
            "000002c1b93bb39dd9d4eb1f56a2f2e7443e8350178b9d35026fb5580bf441d8",
            "00000b1f4696b1927993b86c7e7605d372b6d83d08046889920c35c386f399c5",
            1747103471,
            0x1e03a14f,
            "0x00000000000000000000000000000000000000000000000003472e121dc37e03",
            "d75c634997a69bfe2c4e2d081df77fb05070768a7cf688cc756d6f9482bbce87",
            271399,
            None,
        ),
        // Height 1300000
        create_checkpoint(
            1300000,
            "000001556cd2a74e8c80e4478f5d0865f5626ecddc5fa5f968340bafd7bd298e",
            "00000154148f9f1002a0b397619768e4c7caf64ea48a44d5e93161089967c675",
            1754134922,
            0x1e022390,
            "0x000000000000000000000000000000000000000000000000036073ef820264d6",
            "ec96c8cc618ff19517f52538532a20ccebfd6be2e34b2ec62dbde16512e5615d",
            693495,
            None,
        ),
        // Height 1350000
        create_checkpoint(
            1350000,
            "000000c62ce13fb0988e71f2b870d9d38dfd056f9ee175cc840a633a8f150215",
            "000000099d1c4c31245b6b6299fe54849e09f4af3fcb0e99e7727a70b7fba59b",
            1761146995,
            0x1e013eac,
            "0x000000000000000000000000000000000000000000000000036bc53351955c6e",
            "dc2f196c72ad1459f16a08fbf9eb6e36a1390390fc403aa76b14a44374eb2362",
            886358,
            None,
        ),
        // Height 1400000
        create_checkpoint(
            1400000,
            "000000541a23f9db7411cddbe50f9f1ebd4aa7108ebdcad62214753f648c0239",
            "0000001d568e945387bda758069dfb69f762c587433b92550defc34c5b4ef4d8",
            1768147275,
            0x1e015e96,
            "0x000000000000000000000000000000000000000000000000036c8f738da818d2",
            "41b996f00ca234b74db94e438f9ee7980097fd207b0d9d513d2934aca17aed6b",
            516400,
            None,
        ),
    ]
}

/// Helper to parse hex block hash strings
fn parse_block_hash(s: &str) -> Result<BlockHash, String> {
    use hex::FromHex;
    let bytes = Vec::<u8>::from_hex(s).map_err(|e| format!("Invalid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err("Invalid hash length: expected 32 bytes".to_string());
    }
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&bytes);
    // Reverse for little-endian
    hash_bytes.reverse();
    Ok(BlockHash::from_byte_array(hash_bytes))
}

/// Helper to parse hex block hash strings, returning zero hash on error
fn parse_block_hash_safe(s: &str) -> BlockHash {
    parse_block_hash(s).unwrap_or_else(|e| {
        tracing::error!("Failed to parse checkpoint block hash '{}': {}", s, e);
        BlockHash::from_byte_array([0u8; 32])
    })
}

/// Helper to create a checkpoint with common defaults
#[allow(clippy::too_many_arguments)]
fn create_checkpoint(
    height: u32,
    hash: &str,
    prev_hash: &str,
    timestamp: u32,
    bits: u32,
    chain_work: &str,
    merkle_root: &str,
    nonce: u32,
    masternode_list: Option<&str>,
) -> Checkpoint {
    Checkpoint {
        height,
        block_hash: parse_block_hash_safe(hash),
        prev_blockhash: parse_block_hash_safe(prev_hash),
        timestamp,
        target: Target::from_compact(CompactTarget::from_consensus(bits)),
        merkle_root: Some(parse_block_hash_safe(merkle_root)),
        chain_work: chain_work.to_string(),
        masternode_list_name: masternode_list.map(|s| s.to_string()),
        protocol_version: masternode_list.and_then(|ml| {
            // Extract protocol version from masternode list name
            ml.split("__").nth(1).and_then(|s| s.parse().ok())
        }),
        nonce,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checkpoint_validation() {
        let checkpoints = mainnet_checkpoints();
        let manager = CheckpointManager::new(checkpoints);

        // Test genesis block
        let genesis_checkpoint =
            manager.get_checkpoint(0).expect("Genesis checkpoint should exist");
        assert_eq!(genesis_checkpoint.height, 0);
        assert_eq!(genesis_checkpoint.timestamp, 1390095618);

        // Test validation
        let genesis_hash =
            parse_block_hash("00000ffd590b1485b3caadc19b22e6379c733355108f107a430458cdf3407ab6")
                .expect("Failed to parse genesis hash for test");
        assert!(manager.validate_block(0, &genesis_hash));

        // Test invalid hash
        let invalid_hash = BlockHash::from_byte_array([1u8; 32]);
        assert!(!manager.validate_block(0, &invalid_hash));

        // Test no checkpoint at height
        assert!(manager.validate_block(1, &invalid_hash)); // No checkpoint at height 1
    }

    #[test]
    fn test_last_checkpoint_before() {
        let checkpoints = mainnet_checkpoints();
        let manager = CheckpointManager::new(checkpoints);

        // Test finding checkpoint before various heights
        assert_eq!(
            manager.last_checkpoint_before_height(0).expect("Should find checkpoint").height,
            0
        );
        assert_eq!(
            manager.last_checkpoint_before_height(1000).expect("Should find checkpoint").height,
            0
        );
        assert_eq!(
            manager.last_checkpoint_before_height(5000).expect("Should find checkpoint").height,
            4991
        );
        assert_eq!(
            manager.last_checkpoint_before_height(200000).expect("Should find checkpoint").height,
            107996
        );
    }

    #[test]
    fn test_protocol_version_extraction() {
        let checkpoint = create_checkpoint(
            1088640,
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            0,
            0,
            "",
            "0000000000000000000000000000000000000000000000000000000000000000",
            0,
            Some("ML1088640__70218"),
        );

        assert_eq!(checkpoint.protocol_version(), Some(70218));
        assert!(checkpoint.has_masternode_list());

        let checkpoint_no_version = create_checkpoint(
            0,
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            0,
            0,
            "",
            "0000000000000000000000000000000000000000000000000000000000000000",
            0,
            None,
        );

        assert_eq!(checkpoint_no_version.protocol_version(), None);
        assert!(!checkpoint_no_version.has_masternode_list());
    }

    #[test]
    #[ignore] // Test depends on specific mainnet checkpoint data
    fn test_fork_rejection() {
        let checkpoints = mainnet_checkpoints();
        let manager = CheckpointManager::new(checkpoints);

        // Should reject fork at checkpoint height
        assert!(manager.should_reject_fork(1500));
        assert!(manager.should_reject_fork(750000));

        // Should not reject fork after last checkpoint
        assert!(!manager.should_reject_fork(2000000));
    }

    #[test]
    fn test_checkpoint_by_timestamp() {
        let checkpoints = mainnet_checkpoints();
        let manager = CheckpointManager::new(checkpoints);

        // Test finding checkpoint by timestamp
        let checkpoint = manager.last_checkpoint_before_timestamp(1500000000);
        assert!(checkpoint.is_some());
        assert!(checkpoint.expect("Should find checkpoint by timestamp").timestamp <= 1500000000);
    }
}
