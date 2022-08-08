// Rust Dash Library
// Written for Dash in 2022 by
//     The Dash Core Developers
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Dash Provider Registration Special Transaction.
//!
//! The provider registration special transaction is used to register a masternode.
//! It is defined in DIP3 https://github.com/dashpay/dips/blob/master/dip-0003.md.
//!
//! The ProRegTx contains 2 public key IDs and one BLS public key, which represent 3 different
//! roles in the masternode and define update and voting rights. A "public key ID" refers to the
//! hash160 of an ECDSA public key. The keys are:
//!
//! KeyIdOwner (renamed to owner_key_hash): This is the public key ID of the masternode or
//! collateral owner. It is different than the key used in the collateral output. Only the owner
//! is allowed to issue ProUpRegTx transactions.
//!
//! PubKeyOperator (renamed to operator_public_key): This is the BLS public key of the masternode
//! operator. Only the operator is allowed to issue ProUpServTx transactions. The operator key is
//! also used while operating the masternode to sign masternode related P2P messages, quorum
//! related messages and governance trigger votes. Messages signed with this key are only valid
//! while the masternode is in the valid set.
//!
//! KeyIdVoting (renamed to voting_key_hash): This is the public key ID used for proposal voting.
//! Votes signed with this key are valid while the masternode is in the registered set.

use std::io;
use std::io::{Error, Write};
use hashes::Hash;
use ::{OutPoint, Script};
use consensus::{Decodable, Encodable, encode};
use ::{InputsHash};
use ::{Address, Network};
use blockdata::transaction::special_transaction::SpecialTransactionBasePayloadEncodable;
use bls_sig_utils::BLSPublicKey;
use ::{PubkeyHash, SpecialTransactionPayloadHash};
use util::address::Payload;
use VarInt;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct ProviderRegistrationPayload {
    version: u16,
    provider_type: u16,
    provider_mode: u16,
    collateral_outpoint: OutPoint,
    ip_address: u128,
    port: u16,
    owner_key_hash: PubkeyHash,
    operator_public_key: BLSPublicKey,
    voting_key_hash: PubkeyHash,
    operator_reward: u16,
    script_payout: Script,
    inputs_hash: InputsHash,
    payload_sig: Vec<u8>,
}

impl ProviderRegistrationPayload {
    pub fn payout_address(&self, network: Network) -> Result<Address, encode::Error> {
        Address::from_script(&self.script_payout, network).ok_or(encode::Error::NonStandardScriptPayout(self.script_payout.clone()))
    }
    pub fn owner_address(&self, network: Network) -> Address {
        Address {
            payload: Payload::PubkeyHash(self.owner_key_hash),
            network,
        }
    }
    pub fn voting_address(&self, network: Network) -> Address {
        Address {
            payload: Payload::PubkeyHash(self.voting_key_hash),
            network,
        }
    }
    pub fn payload_collateral_string(&self, network: Network) -> Result<String, encode::Error> {
        let mut base_payload_hash = self.base_payload_hash().to_vec();
        base_payload_hash.reverse();
        Ok(format!("{}|{}|{}|{}|{}", self.payout_address(network)?, self.operator_reward, self.owner_address(network), self.voting_address(network), hex::encode(base_payload_hash)))
    }
}

impl SpecialTransactionBasePayloadEncodable for ProviderRegistrationPayload {
    fn base_payload_data_encode<S: Write>(&self, mut s: S) -> Result<usize, Error> {
        let mut len = 0;
        len += self.version.consensus_encode(&mut s)?;
        len += self.provider_type.consensus_encode(&mut s)?;
        len += self.provider_mode.consensus_encode(&mut s)?;
        len += self.collateral_outpoint.consensus_encode(&mut s)?;
        len += self.ip_address.consensus_encode(&mut s)?;
        len += self.port.consensus_encode(&mut s)?;
        len += self.owner_key_hash.consensus_encode(&mut s)?;
        len += self.operator_public_key.consensus_encode(&mut s)?;
        len += self.voting_key_hash.consensus_encode(&mut s)?;
        len += self.operator_reward.consensus_encode(&mut s)?;
        len += self.script_payout.consensus_encode(&mut s)?;
        len += self.inputs_hash.consensus_encode(&mut s)?;
        Ok(len)
    }

    fn base_payload_hash(&self) -> SpecialTransactionPayloadHash {
        let mut engine = SpecialTransactionPayloadHash::engine();
        self.base_payload_data_encode(&mut engine).expect("engines don't error");
        SpecialTransactionPayloadHash::from_engine(engine)
    }
}

impl Encodable for ProviderRegistrationPayload {
    fn consensus_encode<S: Write>(&self, mut s: S) -> Result<usize, Error> {
        let mut len = 0;
        len += self.base_payload_data_encode(&mut s)?;
        len += self.payload_sig.consensus_encode(&mut s)?;
        Ok(len)
    }
}

impl Decodable for ProviderRegistrationPayload {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let _len = VarInt::consensus_decode(&mut d)?;
        let version = u16::consensus_decode(&mut d)?;
        let provider_type = u16::consensus_decode(&mut d)?;
        let provider_mode = u16::consensus_decode(&mut d)?;
        let collateral_outpoint = OutPoint::consensus_decode(&mut d)?;
        let ip_address = u128::consensus_decode(&mut d)?;
        let port = u16::consensus_decode(&mut d)?.reverse_bits();
        let owner_key_hash = PubkeyHash::consensus_decode(&mut d)?;
        let operator_public_key = BLSPublicKey::consensus_decode(&mut d)?;
        let voting_key_hash = PubkeyHash::consensus_decode(&mut d)?;
        let operator_reward = u16::consensus_decode(&mut d)?;
        let script_payout = Script::consensus_decode(&mut d)?;
        let inputs_hash = InputsHash::consensus_decode(&mut d)?;
        let payload_sig = Vec::<u8>::consensus_decode(&mut d)?;

        Ok(ProviderRegistrationPayload {
            version,
            provider_type,
            provider_mode,
            collateral_outpoint,
            ip_address,
            port,
            owner_key_hash,
            operator_public_key,
            voting_key_hash,
            operator_reward,
            script_payout,
            inputs_hash,
            payload_sig,
        })
    }
}

#[cfg(test)]
mod tests {
    use hashes::hex::{FromHex};
    use consensus::{deserialize};
    use ::{Transaction};
    use ::{InputsHash, Txid};
    use ::{Network, OutPoint};
    use util::misc::signed_msg_hash;
    use hex;
    //use blockdata::transaction::special_transaction::SpecialTransactionBasePayloadEncodable;

    #[test]
    fn test_collateral_provider_registration_transaction() {
        // This is a test for testnet
        let network = Network::Testnet;

        // let seed_phrase = "enemy check owner stumble unaware debris suffer peanut good fabric bleak outside";
        //
        // let mnemonic = Mnemonic::parse_in_normalized(Language::English, seed_phrase).expect("expected mnemonic");
        // let seed = mnemonic.to_seed("");
        //
        // assert_eq!(hex::ToHex(seed), "44cb0848958cb77898e464d18e3c70e2a437b343a894defa6010c5056a2b4a1caa01d04760871b578721b0a797fd1aacdfcd77f1870dddb34f1b204d5dbe07c0");

        let expected_transaction_bytes = hex::decode("0300010001ca9a43051750da7c5f858008f2ff7732d15691e48eb7f845c791e5dca78bab58010000006b483045022100fe8fec0b3880bcac29614348887769b0b589908e3f5ec55a6cf478a6652e736502202f30430806a6690524e4dd599ba498e5ff100dea6a872ebb89c2fd651caa71ed012103d85b25d6886f0b3b8ce1eef63b720b518fad0b8e103eba4e85b6980bfdda2dfdffffffff018e37807e090000001976a9144ee1d4e5d61ac40a13b357ac6e368997079678c888ac00000000fd1201010000000000ca9a43051750da7c5f858008f2ff7732d15691e48eb7f845c791e5dca78bab580000000000000000000000000000ffff010205064e1f3dd03f9ec192b5f275a433bfc90f468ee1a3eb4c157b10706659e25eb362b5d902d809f9160b1688e201ee6e94b40f9b5062d7074683ef05a2d5efb7793c47059c878dfad38a30fafe61575db40f05ab0a08d55119b0aad300001976a9144fbc8fb6e11e253d77e5a9c987418e89cf4a63d288ac3477990b757387cb0406168c2720acf55f83603736a314a37d01b135b873a27b411fb37e49c1ff2b8057713939a5513e6e711a71cff2e517e6224df724ed750aef1b7f9ad9ec612b4a7250232e1e400da718a9501e1d9a5565526e4b1ff68c028763").unwrap();

        let expected_transaction: Transaction = deserialize(expected_transaction_bytes.as_slice()).expect("expected a transaction");

        let expected_provider_registration_payload = expected_transaction.special_transaction_payload.unwrap().to_provider_registration_payload().expect("expected to get a provider registration payload");
        //    protx register_prepare
        //    58ab8ba7dce591c745f8b78ee49156d13277fff20880855f7cda501705439aca
        //    0
        //    1.2.5.6:19999
        //    yRxHYGLf9G4UVYdtAoB2iAzR3sxxVaZB6y
        //    97762493aef0bcba1925870abf51dc21f4bc2b8c410c79b7589590e6869a0e04
        //    yfbxyP4ctRJR1rs3A8C3PdXA4Wtcrw7zTi
        //    0
        //    ycBFJGv7V95aSs6XvMewFyp1AMngeRHBwy

        let tx_id = Txid::from_hex("e65f550356250100513aa9c260400562ac8ee1b93ae1cc1214cc9f6830227b51").expect("expected to decode tx id");
        let input_transaction_hash_value = InputsHash::from_hex("ca9a43051750da7c5f858008f2ff7732d15691e48eb7f845c791e5dca78bab58").expect("expected to decode inputs hash");
        let input_address0 = "yQxPwSSicYgXiU22k4Ysq464VxRtgbnvpJ";
        let input_private_key0 = "cVfGhHY18Dx1EfZxFRkrvzVpB3wPtJGJWW6QvEtzMcfXSShoZyWV";
        let output_address0 = "yTWY6DsS4HBGs2JwDtnvVcpykLkbvtjUte";
        let collateral_address = "yeNVS6tFeQNXJVkjv6nm6gb7PtTERV5dGh";
        let collateral_hash = Txid::from_hex("58ab8ba7dce591c745f8b78ee49156d13277fff20880855f7cda501705439aca").expect("expected to decode collateral hash");
        let collateral_index = 0;
        let reversed_collateral = OutPoint::new(collateral_hash, collateral_index);
        let payout_address = "yTb47qEBpNmgXvYYsHEN4nh8yJwa5iC4Cs";

        // DSAccount *collateralAccount = [providerRegistrationTransactionFromMessage.chain accountContainingAddress:collateralAddress];
        //
        // DSAccount *inputAccount = [providerRegistrationTransactionFromMessage.chain accountContainingAddress:inputAddress0];
        // DSFundsDerivationPath *inputDerivationPath = (DSFundsDerivationPath *)[inputAccount derivationPathContainingAddress:inputAddress0];
        //
        // DSKey *inputPrivateKey = [inputDerivationPath privateKeyForKnownAddress:inputAddress0 fromSeed:seed];

        let payload_collateral_string = expected_provider_registration_payload.payload_collateral_string(network).expect("expected to produce a payload collateral string");
        let message_digest = signed_msg_hash(payload_collateral_string.as_str());

        //assert_eq!(expected_provider_registration_payload.inputs_hash.to_hex(), "7ba273b835b1017da314a3363760835ff5ac20278c160604cb8773750b997734", "inputs hash calculation has issues");
        //assert_eq!(expected_provider_registration_payload.base_payload_hash().to_hex(), "71e973f79003accd202b9a2ab2613ac6ced601b26684e82f561f6684fef2f102", "Payload hash calculation has issues");

        assert_eq!("yTb47qEBpNmgXvYYsHEN4nh8yJwa5iC4Cs|0|yRxHYGLf9G4UVYdtAoB2iAzR3sxxVaZB6y|yfbxyP4ctRJR1rs3A8C3PdXA4Wtcrw7zTi|71e973f79003accd202b9a2ab2613ac6ced601b26684e82f561f6684fef2f102", payload_collateral_string, "provider transaction collateral string doesn't match");


//     let base64signature = "H7N+ScH/K4BXcTk5pVE+bnEacc/y5RfmIk33JO11Cu8bf5rZ7GErSnJQIy4eQA2nGKlQHh2aVWVSbksf9owCh2M=";
//
//     DSFundsDerivationPath *derivationPath = (DSFundsDerivationPath *)[collateralAccount derivationPathContainingAddress:collateralAddress];
//
//     NSIndexPath *indexPath = [derivationPath indexPathForKnownAddress:collateralAddress];
//     DSECDSAKey *key = (DSECDSAKey *)[derivationPath privateKeyAtIndexPath:indexPath fromSeed:seed];
//     NSData *signatureData = [key compactSign:messageDigest];
//     let signature = [signatureData base64EncodedStringWithOptions:0];
//
//     XCTAssertEqualObjects(signature, base64signature, "Signatures don't match up");
//
//
//     XCTAssertEqualObjects(providerRegistrationTransactionFromMessage.payloadSignature, signatureData, "Signatures don't match up");
//
//     DSAuthenticationKeysDerivationPath *providerOwnerKeysDerivationPath = [DSAuthenticationKeysDerivationPath providerOwnerKeysDerivationPathForWallet:wallet];
//     if (!providerOwnerKeysDerivationPath.hasExtendedPublicKey) {
// [providerOwnerKeysDerivationPath generateExtendedPublicKeyFromSeed:seed storeUnderWalletUniqueId:nil];
// }
//     DSAuthenticationKeysDerivationPath *providerOperatorKeysDerivationPath = [DSAuthenticationKeysDerivationPath providerOperatorKeysDerivationPathForWallet:wallet];
//     if (!providerOperatorKeysDerivationPath.hasExtendedPublicKey) {
// [providerOperatorKeysDerivationPath generateExtendedPublicKeyFromSeed:seed storeUnderWalletUniqueId:nil];
// }
//     DSAuthenticationKeysDerivationPath *providerVotingKeysDerivationPath = [DSAuthenticationKeysDerivationPath providerVotingKeysDerivationPathForWallet:wallet];
//     if (!providerVotingKeysDerivationPath.hasExtendedPublicKey) {
// [providerVotingKeysDerivationPath generateExtendedPublicKeyFromSeed:seed storeUnderWalletUniqueId:nil];
// }
//
//     DSECDSAKey *ownerKey = (DSECDSAKey *)[providerOwnerKeysDerivationPath privateKeyAtIndex:0 fromSeed:seed];
//     UInt160 votingKeyHash = [providerVotingKeysDerivationPath publicKeyDataAtIndex:0].hash160;
//     UInt384 operatorKey = [providerOperatorKeysDerivationPath publicKeyDataAtIndex:0].UInt384;
//
//     NSMutableData *scriptPayout = [NSMutableData data];
//     [scriptPayout appendScriptPubKeyForAddress:payoutAddress forChain:wallet.chain];
//
//     UInt128 ipAddress = {.u32 = {0, 0, CFSwapInt32HostToBig(0xffff), 0}};
//     struct in_addr addrV4;
//     if (inet_aton(["1.2.5.6" UTF8String], &addrV4) != 0) {
// uint32_t ip = ntohl(addrV4.s_addr);
// ipAddress.u32[3] = CFSwapInt32HostToBig(ip);
// }
//
//     NSMutableData *inputScript = [NSMutableData data];
//
//     [inputScript appendScriptPubKeyForAddress:inputAddress0 forChain:chain];
//
//     DSProviderRegistrationTransaction *providerRegistrationTransaction = [[DSProviderRegistrationTransaction alloc] initWithInputHashes:@[input_transaction_hash_value] inputIndexes:@[@1] inputScripts:@[inputScript] inputSequences:@[@(TXIN_SEQUENCE)] outputAddresses:@[output_address0] outputAmounts:@[@40777037710] providerRegistrationTransactionVersion:1 type:0 mode:0 collateralOutpoint:reversedCollateral ipAddress:ipAddress port:19999 ownerKeyHash:ownerKey.publicKeyData.hash160 operatorKey:operatorKey votingKeyHash:votingKeyHash operatorReward:0 scriptPayout:scriptPayout onChain:chain];
//
//
//     providerRegistrationTransaction.payloadSignature = signatureData;
//
//     [providerRegistrationTransaction signWithPrivateKeys:@[inputPrivateKey]];
//
//     [providerRegistrationTransactionFromMessage setInputAddress:inputAddress0 atIndex:0];
//
//         assert_eq!(providerRegistrationTransaction.payloadData, providerRegistrationTransactionFromMessage.payloadData, "Provider payload data doesn't match up");
//
//         assert_eq!(providerRegistrationTransaction.payloadCollateralString, providerRegistrationTransactionFromMessage.payloadCollateralString, "Provider payload collateral strings don't match up");
//
//         assert_eq!(providerRegistrationTransaction.port, providerRegistrationTransactionFromMessage.port, "Provider transaction port doesn't match up");
//
//         assert_eq!(providerRegistrationTransaction.inputs, providerRegistrationTransactionFromMessage.inputs, "Provider transaction inputs are having an issue");
//         assert_eq!(providerRegistrationTransaction.outputs, providerRegistrationTransactionFromMessage.outputs, "Provider transaction outputs are having an issue");
//
//         assert_eq!(uint384_hex(providerRegistrationTransaction.operatorKey), uint384_hex(providerRegistrationTransactionFromMessage.operatorKey), "Provider transaction operator key is having an issue");
//
//         assert_eq!(providerRegistrationTransaction.operatorReward, providerRegistrationTransactionFromMessage.operatorReward, "Provider transaction operator Address is having an issue");
//
//         assert_eq!(providerRegistrationTransaction.ownerAddress, providerRegistrationTransactionFromMessage.ownerAddress, "Provider transaction owner Address is having an issue");
//
//         assert_eq!(providerRegistrationTransaction.votingAddress, providerRegistrationTransactionFromMessage.votingAddress, "Provider transaction voting Address is having an issue");
//
//         assert_eq!(providerRegistrationTransaction.toData, hexData, "Provider transaction does not match it's data");
//
//         assert_eq!(providerRegistrationTransactionFromMessage.toData, hexData, "Provider transaction does not match it's data");
//
//         assert_eq!(uint256_reverse_hex(providerRegistrationTransactionFromMessage.txHash), tx_id_string, "Provider transaction hashes aren't correct");
    }

//
// - (void)testNoCollateralProviderRegistrationTransaction {
// DSChain *chain = [DSChain testnet];
//
// let seedPhrase = "enemy check owner stumble unaware debris suffer peanut good fabric bleak outside";
//
// NSData *seed = [[DSBIP39Mnemonic sharedInstance]
// deriveKeyFromPhrase:seedPhrase
// withPassphrase:nil];
//
// DSWallet *wallet = [DSWallet standardWalletWithSeedPhrase:seedPhrase setCreationDate:0 forChain:chain storeSeedPhrase:NO isTransient:YES];
//
// NSData *hexData = [NSData dataFromHexString:"030001000379efbe95cba05893d09f4ec51a71171a3852b54aa958ae35ce43276f5f8f1002000000006a473044022015df39c80ca8595cc197a0be692e9d158dc53bdbc8c6abca0d30c086f338c037022063becdb4f891436de3d2fb21cbf294e9dcb5c1a04bc0ba621867479e46d048cc0121030de5cb8989b6902d98017ab4d42b9244912006b0a1561c1d1ba0e2f3117a39adffffffff79efbe95cba05893d09f4ec51a71171a3852b54aa958ae35ce43276f5f8f1002010000006a47304402205c1bae23b459081b060de14133a20378243bebc05c8e2ed9acdabf6717ae7f9702204027ba0abbcce9ba5b2cb563cbff0190ba8f80e5f8fd6beb07c2c449f194c9be01210270b0f0b71472736a397975a84927314261be815d423006d1bcbc00cd693c3d81ffffffff9d925d6cd8e3a408f472e872d1c2849bc664efda8c7f68f1b3a3efde221bc474010000006a47304402203fa23ec33f91efa026b34e90b15a1fd64ff03242a6a92985b16a25b590e5bae002202d1429374b60b1180cd8b9bd0b432158524f5624d6c5d2d6db8c637c9961a21e0121024c0b09e261253dc40ed572c2d63d0b6cda89154583d75a5ab5a14fba81d70089ffffffff0200e87648170000001976a9143795a62df2eb953c1d08bc996d4089ee5d67e28b88ac438ca95a020000001976a91470ed8f5b5cfd4791c15b9d8a7f829cb6a98da18c88ac00000000d101000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffff010101014e1f3dd03f9ec192b5f275a433bfc90f468ee1a3eb4c157b10706659e25eb362b5d902d809f9160b1688e201ee6e94b40f9b5062d7074683ef05a2d5efb7793c47059c878dfad38a30fafe61575db40f05ab0a08d55119b0aad300001976a9143795a62df2eb953c1d08bc996d4089ee5d67e28b88ac14b33f2231f0df567e0dfb12899c893f5d2d05f6dcc7d9c8c27b68a71191c75400"];
// let txIdString = "717d2d4a7d583da184872f4a07e35d897a1be9dd9875b4c017c81cf772e36694";
// DSUTXO input0 = (DSUTXO){.hash = "02108f5f6f2743ce35ae58a94ab552381a17711ac54e9fd09358a0cb95beef79".hexToData.reverse.UInt256, .n = 0};
// DSUTXO input1 = (DSUTXO){.hash = "02108f5f6f2743ce35ae58a94ab552381a17711ac54e9fd09358a0cb95beef79".hexToData.reverse.UInt256, .n = 1};
// DSUTXO input2 = (DSUTXO){.hash = "74c41b22deefa3b3f1687f8cdaef64c69b84c2d172e872f408a4e3d86c5d929d".hexToData.reverse.UInt256, .n = 1};
// let inputAddress0 = "yRdHYt6nG1ooGaXK7GEbwVMteLY3m4FbVT";
// let inputAddress1 = "yWJqVcT5ot5GEcB8oYkHnnYcFG5pLiVVtd";
// let inputAddress2 = "ygQ8tG3tboQ7oZEhtDBBYtquTmVyiDe6d5";
// let outputAddress0 = "yRPMHZKviaWgqPaNP7XURemxtf7EyXNN1k";
// let outputAddress1 = "yWcZ7ePLX3yLkC3Aj9KaZvxRQkkZC6VPL8";
// let payoutAddress = "yRPMHZKviaWgqPaNP7XURemxtf7EyXNN1k";
// DSKey *inputPrivateKey0 = [wallet privateKeyForAddress:inputAddress0 fromSeed:seed];
// DSKey *inputPrivateKey1 = [wallet privateKeyForAddress:inputAddress1 fromSeed:seed];
// DSKey *inputPrivateKey2 = [wallet privateKeyForAddress:inputAddress2 fromSeed:seed];
//
// let checkInputAddress0 = [inputPrivateKey0 addressForChain:chain];
// XCTAssertEqualObjects(checkInputAddress0, inputAddress0, "Private key does not match input address");
//
// let checkInputAddress1 = [inputPrivateKey1 addressForChain:chain];
// XCTAssertEqualObjects(checkInputAddress1, inputAddress1, "Private key does not match input address");
//
// let checkInputAddress2 = [inputPrivateKey2 addressForChain:chain];
// XCTAssertEqualObjects(checkInputAddress2, inputAddress2, "Private key does not match input address");
//
// DSAuthenticationKeysDerivationPath *providerOwnerKeysDerivationPath = [DSAuthenticationKeysDerivationPath providerOwnerKeysDerivationPathForWallet:wallet];
// if (!providerOwnerKeysDerivationPath.hasExtendedPublicKey) {
// [providerOwnerKeysDerivationPath generateExtendedPublicKeyFromSeed:seed storeUnderWalletUniqueId:nil];
// }
// DSAuthenticationKeysDerivationPath *providerOperatorKeysDerivationPath = [DSAuthenticationKeysDerivationPath providerOperatorKeysDerivationPathForWallet:wallet];
// if (!providerOperatorKeysDerivationPath.hasExtendedPublicKey) {
// [providerOperatorKeysDerivationPath generateExtendedPublicKeyFromSeed:seed storeUnderWalletUniqueId:nil];
// }
// DSAuthenticationKeysDerivationPath *providerVotingKeysDerivationPath = [DSAuthenticationKeysDerivationPath providerVotingKeysDerivationPathForWallet:wallet];
// if (!providerVotingKeysDerivationPath.hasExtendedPublicKey) {
// [providerVotingKeysDerivationPath generateExtendedPublicKeyFromSeed:seed storeUnderWalletUniqueId:nil];
// }
//
// DSECDSAKey *ownerKey = (DSECDSAKey *)[providerOwnerKeysDerivationPath privateKeyAtIndex:0 fromSeed:seed];
// UInt160 votingKeyHash = [providerVotingKeysDerivationPath publicKeyDataAtIndex:0].hash160;
// UInt384 operatorKey = [providerOperatorKeysDerivationPath publicKeyDataAtIndex:0].UInt384;
//
// DSProviderRegistrationTransaction *providerRegistrationTransactionFromMessage = [[DSProviderRegistrationTransaction alloc] initWithMessage:hexData onChain:chain];
//
// XCTAssertEqualObjects(providerRegistrationTransactionFromMessage.toData, hexData, "Provider transaction does not match it's data");
//
// NSMutableData *scriptPayout = [NSMutableData data];
// [scriptPayout appendScriptPubKeyForAddress:payoutAddress forChain:wallet.chain];
//
// UInt128 ipAddress = {.u32 = {0, 0, CFSwapInt32HostToBig(0xffff), 0}};
// struct in_addr addrV4;
// if (inet_aton(["1.1.1.1" UTF8String], &addrV4) != 0) {
// uint32_t ip = ntohl(addrV4.s_addr);
// ipAddress.u32[3] = CFSwapInt32HostToBig(ip);
// }
//
// NSArray *inputHashes = @[uint256_obj(input0.hash), uint256_obj(input1.hash), uint256_obj(input2.hash)];
// NSArray *inputIndexes = @[@(input0.n), @(input1.n), @(input2.n)];
// NSArray *inputScripts = @[[NSData scriptPubKeyForAddress:inputAddress0 forChain:chain], [NSData scriptPubKeyForAddress:inputAddress1 forChain:chain], [NSData scriptPubKeyForAddress:inputAddress2 forChain:chain]];
//
// DSProviderRegistrationTransaction *providerRegistrationTransaction = [[DSProviderRegistrationTransaction alloc] initWithInputHashes:inputHashes inputIndexes:inputIndexes inputScripts:inputScripts inputSequences:@[@(TXIN_SEQUENCE), @(TXIN_SEQUENCE), @(TXIN_SEQUENCE)] outputAddresses:@[outputAddress0, outputAddress1] outputAmounts:@[@100000000000, @10110995523] providerRegistrationTransactionVersion:1 type:0 mode:0 collateralOutpoint:DSUTXO_ZERO ipAddress:ipAddress port:19999 ownerKeyHash:ownerKey.publicKeyData.hash160 operatorKey:operatorKey votingKeyHash:votingKeyHash operatorReward:0 scriptPayout:scriptPayout onChain:wallet.chain];
//
//
// [providerRegistrationTransaction updateInputsHash];
// [providerRegistrationTransaction signWithPrivateKeys:@[inputPrivateKey0, inputPrivateKey1, inputPrivateKey2]];
//
//
// XCTAssertEqualObjects(providerRegistrationTransactionFromMessage.toData.hexString, providerRegistrationTransaction.toData.hexString, "Provider transaction does not match it's data");
//
// XCTAssertEqualObjects(uint256_reverse_hex(providerRegistrationTransactionFromMessage.txHash), txIdString, "Provider transaction hashes aren't correct");
//
// XCTAssertEqualObjects(uint256_reverse_hex(providerRegistrationTransaction.txHash), txIdString, "Provider transaction hashes aren't correct");
// }
}