//! FFI-safe typed views of DIP-2 special-transaction payloads.
//!
//! [`FFISpecialTransactionPayload`] is a tagged representation of
//! `dashcore`'s `TransactionPayload`: `payload_type` carries the on-wire
//! DIP-2 transaction type (`1` = ProRegTx … `9` = AssetUnlockTx), and for
//! the four masternode provider payload kinds a matching typed struct
//! pointer is non-null. Other payload kinds (coinbase, quorum commitment,
//! asset lock/unlock, …) currently expose only the discriminant; typed
//! structs for them can be added later without breaking the layout
//! contract (consumers must key off `payload_type`).
//!
//! All heap-allocated fields are owned by the structs and freed by their
//! `Drop` impls, which run when the owning
//! [`FFITransactionRecord`](crate::managed_account::FFITransactionRecord)
//! is freed.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::os::raw::c_char;

use dashcore::blockdata::transaction::special_transaction::provider_registration::ProviderRegistrationPayload;
use dashcore::blockdata::transaction::special_transaction::provider_update_registrar::ProviderUpdateRegistrarPayload;
use dashcore::blockdata::transaction::special_transaction::provider_update_revocation::ProviderUpdateRevocationPayload;
use dashcore::blockdata::transaction::special_transaction::provider_update_service::ProviderUpdateServicePayload;
use dashcore::blockdata::transaction::special_transaction::TransactionPayload;
use dashcore::bls_sig_utils::BLSPublicKey;
use dashcore::hashes::Hash;
use dashcore::ScriptBuf;

/// Box `script`'s bytes into a raw `(ptr, len)` pair; `(null, 0)` for an
/// empty script.
fn script_to_raw(script: &ScriptBuf) -> (*mut u8, usize) {
    let bytes = script.as_bytes().to_vec().into_boxed_slice();
    let len = bytes.len();
    if len == 0 {
        (std::ptr::null_mut(), 0)
    } else {
        (Box::into_raw(bytes) as *mut u8, len)
    }
}

/// Free a `(ptr, len)` pair produced by [`script_to_raw`].
///
/// # Safety
///
/// `ptr`/`len` must come from `script_to_raw` and not have been freed yet.
unsafe fn free_raw_script(ptr: &mut *mut u8, len: &mut usize) {
    if !ptr.is_null() && *len > 0 {
        let slice_ptr = std::ptr::slice_from_raw_parts_mut(*ptr, *len);
        let _ = Box::from_raw(slice_ptr);
    }
    *ptr = std::ptr::null_mut();
    *len = 0;
}

/// Render `addr` as its canonical display string (`ip:port`), boxed as a
/// C string.
fn socket_addr_to_cstring(addr: &SocketAddr) -> *mut c_char {
    std::ffi::CString::new(addr.to_string()).unwrap_or_default().into_raw()
}

/// Normalize `addr`'s IP to 16 IPv6 octets (IPv4 addresses are mapped),
/// matching the on-wire DIP-3 service field encoding.
fn socket_addr_to_ipv6_octets(addr: &SocketAddr) -> [u8; 16] {
    match addr.ip() {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// Copy a BLS public key's 48 raw bytes.
fn bls_public_key_bytes(key: &BLSPublicKey) -> [u8; 48] {
    *AsRef::<[u8; 48]>::as_ref(key)
}

/// Reassemble a `SocketAddr` from 16 IPv6 octets + port, un-mapping
/// v4-mapped addresses so the display string reads `54.148.58.128:9999`
/// rather than `[::ffff:54.148.58.128]:9999`.
fn socket_addr_from_ipv6_octets(octets: [u8; 16], port: u16) -> SocketAddr {
    let v6 = Ipv6Addr::from(octets);
    match v6.to_ipv4_mapped() {
        Some(v4) => SocketAddr::new(IpAddr::V4(v4), port),
        None => SocketAddr::new(IpAddr::V6(v6), port),
    }
}

/// Typed view of a DIP-3 `ProRegTx` (provider registration) payload.
///
/// Byte-order notes: `collateral_txid` and hash fields use the same byte
/// order as the rest of this FFI surface (`to_byte_array`, i.e. the
/// internal little-endian hash representation). `service_ip` is the raw
/// 16-byte on-wire IPv6 form with IPv4 addresses v4-mapped
/// (`::ffff:a.b.c.d`); `service_address` is the human-readable
/// `ip:port` rendering of the same data.
#[repr(C)]
pub struct FFIProviderRegistrationPayload {
    /// ProRegTx payload version.
    pub version: u16,
    /// Masternode type: `0` = regular, `1` = high-performance (Evo).
    pub masternode_type: u16,
    /// Masternode operating mode (`0` currently).
    pub masternode_mode: u16,
    /// Collateral outpoint txid (32 bytes, `to_byte_array` order). All
    /// zeros when the collateral is an output of this transaction itself.
    pub collateral_txid: [u8; 32],
    /// Collateral outpoint output index.
    pub collateral_vout: u32,
    /// Masternode service endpoint as a display string, e.g.
    /// `"54.148.58.128:9999"`. Owned by this struct.
    pub service_address: *mut c_char,
    /// Raw service IP: 16 IPv6 octets, IPv4 addresses v4-mapped.
    pub service_ip: [u8; 16],
    /// Service port (host byte order).
    pub service_port: u16,
    /// Owner key hash160 (20 bytes).
    pub owner_key_hash: [u8; 20],
    /// Voting key hash160 (20 bytes).
    pub voting_key_hash: [u8; 20],
    /// Operator BLS public key (48 bytes).
    pub operator_public_key: [u8; 48],
    /// Operator reward in basis points (0–10000).
    pub operator_reward: u16,
    /// Payout script bytes (owned by this struct, null when empty).
    pub script_payout: *mut u8,
    /// Length of `script_payout`.
    pub script_payout_len: usize,
    /// `true` when the payload carries platform (Evo) fields; the three
    /// fields below are only meaningful in that case.
    pub has_platform_fields: bool,
    /// Platform node ID (20 bytes, zeroed when `has_platform_fields` is false).
    pub platform_node_id: [u8; 20],
    /// Platform P2P port, `-1` when absent.
    pub platform_p2p_port: i32,
    /// Platform HTTP port, `-1` when absent.
    pub platform_http_port: i32,
}

impl From<&ProviderRegistrationPayload> for FFIProviderRegistrationPayload {
    fn from(p: &ProviderRegistrationPayload) -> Self {
        let (script_payout, script_payout_len) = script_to_raw(&p.script_payout);
        FFIProviderRegistrationPayload {
            version: p.version,
            masternode_type: p.masternode_type as u16,
            masternode_mode: p.masternode_mode,
            collateral_txid: p.collateral_outpoint.txid.to_byte_array(),
            collateral_vout: p.collateral_outpoint.vout,
            service_address: socket_addr_to_cstring(&p.service_address),
            service_ip: socket_addr_to_ipv6_octets(&p.service_address),
            service_port: p.service_address.port(),
            owner_key_hash: p.owner_key_hash.to_byte_array(),
            voting_key_hash: p.voting_key_hash.to_byte_array(),
            operator_public_key: bls_public_key_bytes(&p.operator_public_key),
            operator_reward: p.operator_reward,
            script_payout,
            script_payout_len,
            has_platform_fields: p.platform_node_id.is_some(),
            platform_node_id: p.platform_node_id.map(|h| h.to_byte_array()).unwrap_or([0; 20]),
            platform_p2p_port: p.platform_p2p_port.map_or(-1, i32::from),
            platform_http_port: p.platform_http_port.map_or(-1, i32::from),
        }
    }
}

impl Drop for FFIProviderRegistrationPayload {
    fn drop(&mut self) {
        if !self.service_address.is_null() {
            let _ = unsafe { std::ffi::CString::from_raw(self.service_address) };
            self.service_address = std::ptr::null_mut();
        }
        unsafe { free_raw_script(&mut self.script_payout, &mut self.script_payout_len) };
    }
}

/// Typed view of a DIP-3 `ProUpServTx` (provider update service) payload.
///
/// Same byte-order conventions as [`FFIProviderRegistrationPayload`].
#[repr(C)]
pub struct FFIProviderUpdateServicePayload {
    /// ProUpServTx payload version.
    pub version: u16,
    /// Masternode type (`0` regular / `1` Evo), `-1` when the payload
    /// version predates the field.
    pub masternode_type: i32,
    /// ProRegTx hash of the masternode being updated (32 bytes,
    /// `to_byte_array` order).
    pub pro_tx_hash: [u8; 32],
    /// New masternode service endpoint as a display string. Owned by
    /// this struct.
    pub service_address: *mut c_char,
    /// Raw new service IP: 16 IPv6 octets, IPv4 addresses v4-mapped.
    pub service_ip: [u8; 16],
    /// New service port (host byte order).
    pub service_port: u16,
    /// Operator payout script bytes (owned by this struct, null when empty).
    pub script_payout: *mut u8,
    /// Length of `script_payout`.
    pub script_payout_len: usize,
    /// `true` when the payload carries platform (Evo) fields; the three
    /// fields below are only meaningful in that case.
    pub has_platform_fields: bool,
    /// Platform node ID (20 bytes, zeroed when `has_platform_fields` is false).
    pub platform_node_id: [u8; 20],
    /// Platform P2P port, `-1` when absent.
    pub platform_p2p_port: i32,
    /// Platform HTTP port, `-1` when absent.
    pub platform_http_port: i32,
}

impl From<&ProviderUpdateServicePayload> for FFIProviderUpdateServicePayload {
    fn from(p: &ProviderUpdateServicePayload) -> Self {
        // The wire format stores the IP as a u128 whose little-endian
        // byte view is the 16 IPv6 octets in network order (see the
        // `ProviderUpdateServicePayload` consensus round-trip tests).
        let service_ip = p.ip_address.to_le_bytes();
        let service = socket_addr_from_ipv6_octets(service_ip, p.port);
        let (script_payout, script_payout_len) = script_to_raw(&p.script_payout);
        FFIProviderUpdateServicePayload {
            version: p.version,
            masternode_type: p.mn_type.map_or(-1, i32::from),
            pro_tx_hash: p.pro_tx_hash.to_byte_array(),
            service_address: socket_addr_to_cstring(&service),
            service_ip,
            service_port: p.port,
            script_payout,
            script_payout_len,
            has_platform_fields: p.platform_node_id.is_some(),
            platform_node_id: p.platform_node_id.unwrap_or([0; 20]),
            platform_p2p_port: p.platform_p2p_port.map_or(-1, i32::from),
            platform_http_port: p.platform_http_port.map_or(-1, i32::from),
        }
    }
}

impl Drop for FFIProviderUpdateServicePayload {
    fn drop(&mut self) {
        if !self.service_address.is_null() {
            let _ = unsafe { std::ffi::CString::from_raw(self.service_address) };
            self.service_address = std::ptr::null_mut();
        }
        unsafe { free_raw_script(&mut self.script_payout, &mut self.script_payout_len) };
    }
}

/// Typed view of a DIP-3 `ProUpRegTx` (provider update registrar) payload.
#[repr(C)]
pub struct FFIProviderUpdateRegistrarPayload {
    /// ProUpRegTx payload version.
    pub version: u16,
    /// ProRegTx hash of the masternode being updated (32 bytes,
    /// `to_byte_array` order).
    pub pro_tx_hash: [u8; 32],
    /// Masternode operating mode (`0` currently).
    pub provider_mode: u16,
    /// New operator BLS public key (48 bytes).
    pub operator_public_key: [u8; 48],
    /// New voting key hash160 (20 bytes).
    pub voting_key_hash: [u8; 20],
    /// New payout script bytes (owned by this struct, null when empty).
    pub script_payout: *mut u8,
    /// Length of `script_payout`.
    pub script_payout_len: usize,
}

impl From<&ProviderUpdateRegistrarPayload> for FFIProviderUpdateRegistrarPayload {
    fn from(p: &ProviderUpdateRegistrarPayload) -> Self {
        let (script_payout, script_payout_len) = script_to_raw(&p.script_payout);
        FFIProviderUpdateRegistrarPayload {
            version: p.version,
            pro_tx_hash: p.pro_tx_hash.to_byte_array(),
            provider_mode: p.provider_mode,
            operator_public_key: bls_public_key_bytes(&p.operator_public_key),
            voting_key_hash: p.voting_key_hash.to_byte_array(),
            script_payout,
            script_payout_len,
        }
    }
}

impl Drop for FFIProviderUpdateRegistrarPayload {
    fn drop(&mut self) {
        unsafe { free_raw_script(&mut self.script_payout, &mut self.script_payout_len) };
    }
}

/// Typed view of a DIP-3 `ProUpRevTx` (provider update revocation) payload.
#[repr(C)]
pub struct FFIProviderUpdateRevocationPayload {
    /// ProUpRevTx payload version.
    pub version: u16,
    /// ProRegTx hash of the masternode being revoked (32 bytes,
    /// `to_byte_array` order).
    pub pro_tx_hash: [u8; 32],
    /// Revocation reason (`0` not specified, `1` termination of service,
    /// `2` compromised keys, `3` change of keys).
    pub reason: u16,
}

impl From<&ProviderUpdateRevocationPayload> for FFIProviderUpdateRevocationPayload {
    fn from(p: &ProviderUpdateRevocationPayload) -> Self {
        FFIProviderUpdateRevocationPayload {
            version: p.version,
            pro_tx_hash: p.pro_tx_hash.to_byte_array(),
            reason: p.reason,
        }
    }
}

/// Tagged FFI view of a transaction's DIP-2 special payload.
///
/// `payload_type` is the on-wire DIP-2 transaction type (`1` ProRegTx,
/// `2` ProUpServTx, `3` ProUpRegTx, `4` ProUpRevTx, `5` CbTx, `6` QcTx,
/// `7` MnHfTx, `8` AssetLockTx, `9` AssetUnlockTx; pre-DIP-0002
/// transactions with non-standard type bytes surface their raw value).
/// For the four provider payload kinds the matching struct pointer is
/// non-null; exactly one pointer is ever non-null. All pointers are owned
/// by this struct and freed with it.
#[repr(C)]
pub struct FFISpecialTransactionPayload {
    /// On-wire DIP-2 transaction type discriminant.
    pub payload_type: u16,
    /// Non-null iff `payload_type == 1` (ProRegTx).
    pub provider_registration: *mut FFIProviderRegistrationPayload,
    /// Non-null iff `payload_type == 2` (ProUpServTx).
    pub provider_update_service: *mut FFIProviderUpdateServicePayload,
    /// Non-null iff `payload_type == 3` (ProUpRegTx).
    pub provider_update_registrar: *mut FFIProviderUpdateRegistrarPayload,
    /// Non-null iff `payload_type == 4` (ProUpRevTx).
    pub provider_update_revocation: *mut FFIProviderUpdateRevocationPayload,
}

impl From<&TransactionPayload> for FFISpecialTransactionPayload {
    fn from(payload: &TransactionPayload) -> Self {
        let mut ffi = FFISpecialTransactionPayload {
            payload_type: payload.get_type().to_u16(),
            provider_registration: std::ptr::null_mut(),
            provider_update_service: std::ptr::null_mut(),
            provider_update_registrar: std::ptr::null_mut(),
            provider_update_revocation: std::ptr::null_mut(),
        };
        match payload {
            TransactionPayload::ProviderRegistrationPayloadType(p) => {
                ffi.provider_registration = Box::into_raw(Box::new(p.into()));
            }
            TransactionPayload::ProviderUpdateServicePayloadType(p) => {
                ffi.provider_update_service = Box::into_raw(Box::new(p.into()));
            }
            TransactionPayload::ProviderUpdateRegistrarPayloadType(p) => {
                ffi.provider_update_registrar = Box::into_raw(Box::new(p.into()));
            }
            TransactionPayload::ProviderUpdateRevocationPayloadType(p) => {
                ffi.provider_update_revocation = Box::into_raw(Box::new(p.into()));
            }
            // Only the discriminant is exposed for the remaining payload
            // kinds; typed structs can be added later.
            _ => {}
        }
        ffi
    }
}

impl Drop for FFISpecialTransactionPayload {
    fn drop(&mut self) {
        if !self.provider_registration.is_null() {
            let _ = unsafe { Box::from_raw(self.provider_registration) };
            self.provider_registration = std::ptr::null_mut();
        }
        if !self.provider_update_service.is_null() {
            let _ = unsafe { Box::from_raw(self.provider_update_service) };
            self.provider_update_service = std::ptr::null_mut();
        }
        if !self.provider_update_registrar.is_null() {
            let _ = unsafe { Box::from_raw(self.provider_update_registrar) };
            self.provider_update_registrar = std::ptr::null_mut();
        }
        if !self.provider_update_revocation.is_null() {
            let _ = unsafe { Box::from_raw(self.provider_update_revocation) };
            self.provider_update_revocation = std::ptr::null_mut();
        }
    }
}

/// Mainnet-shape ProRegTx payload for tests: owner/voting hash160 and
/// service endpoint from the masternode registration referenced in
/// issue #875.
#[cfg(test)]
pub(crate) fn mainnet_shape_proreg_payload() -> ProviderRegistrationPayload {
    use dashcore::blockdata::transaction::special_transaction::provider_registration::ProviderMasternodeType;
    use std::str::FromStr;

    let key_hash = dashcore::PubkeyHash::from_hex("70993555a01f7e8d6179d6135b5c56809d2d1d36")
        .expect("hash160");
    ProviderRegistrationPayload {
        version: 1,
        masternode_type: ProviderMasternodeType::Regular,
        masternode_mode: 0,
        collateral_outpoint: dashcore::OutPoint {
            txid: dashcore::Txid::from_hex(
                "e0ab1fc3cbe921a2a026e5c9c17d1e5b1b1c460ac4b60964d97b0e6ba9a5f719",
            )
            .expect("txid"),
            vout: 1,
        },
        service_address: SocketAddr::from_str("54.148.58.128:9999").expect("socket addr"),
        owner_key_hash: key_hash,
        operator_public_key: BLSPublicKey::from([0x11; 48]),
        voting_key_hash: key_hash,
        operator_reward: 250,
        script_payout: ScriptBuf::from_hex("76a914fef33f56f709ba6b08d073932f925afedb606d0288ac")
            .expect("script"),
        inputs_hash: dashcore::hash_types::InputsHash::from_slice(&[0x22; 32])
            .expect("inputs hash"),
        signature: vec![0x33; 65],
        platform_node_id: None,
        platform_p2p_port: None,
        platform_http_port: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashcore::bls_sig_utils::BLSSignature;
    use dashcore::hash_types::InputsHash;
    use dashcore::hashes::hex::FromHex;
    use dashcore::Txid;
    use std::ffi::CStr;

    #[test]
    fn proreg_payload_exposes_service_and_keys() {
        let payload =
            TransactionPayload::ProviderRegistrationPayloadType(mainnet_shape_proreg_payload());
        let ffi = FFISpecialTransactionPayload::from(&payload);

        assert_eq!(ffi.payload_type, 1);
        assert!(ffi.provider_update_service.is_null());
        assert!(ffi.provider_update_registrar.is_null());
        assert!(ffi.provider_update_revocation.is_null());

        let reg = unsafe { &*ffi.provider_registration };
        let service = unsafe { CStr::from_ptr(reg.service_address) }.to_str().expect("utf8");
        assert_eq!(service, "54.148.58.128:9999");
        assert_eq!(reg.service_port, 9999);
        let mut expected_ip = [0u8; 16];
        expected_ip[10] = 0xff;
        expected_ip[11] = 0xff;
        expected_ip[12..].copy_from_slice(&[54, 148, 58, 128]);
        assert_eq!(reg.service_ip, expected_ip);

        let expected_hash =
            <[u8; 20]>::from_hex("70993555a01f7e8d6179d6135b5c56809d2d1d36").expect("hash160");
        assert_eq!(reg.owner_key_hash, expected_hash);
        assert_eq!(reg.voting_key_hash, expected_hash);
        assert_eq!(reg.operator_public_key, [0x11; 48]);
        assert_eq!(reg.operator_reward, 250);
        assert_eq!(reg.masternode_type, 0);
        assert_eq!(reg.collateral_vout, 1);
        assert!(!reg.has_platform_fields);
        assert_eq!(reg.platform_p2p_port, -1);

        let script =
            unsafe { std::slice::from_raw_parts(reg.script_payout, reg.script_payout_len) };
        assert_eq!(
            script,
            Vec::<u8>::from_hex("76a914fef33f56f709ba6b08d073932f925afedb606d0288ac")
                .expect("script hex")
                .as_slice()
        );
    }

    #[test]
    fn proupserv_payload_exposes_new_service_address() {
        // 54.148.58.128 as a v4-mapped IPv6, little-endian u128 view.
        let mut octets = [0u8; 16];
        octets[10] = 0xff;
        octets[11] = 0xff;
        octets[12..].copy_from_slice(&[54, 148, 58, 128]);

        let payload =
            TransactionPayload::ProviderUpdateServicePayloadType(ProviderUpdateServicePayload {
                version: 1,
                mn_type: None,
                pro_tx_hash: Txid::from_slice(&[0x44; 32]).expect("txid"),
                ip_address: u128::from_le_bytes(octets),
                port: 19999,
                script_payout: dashcore::ScriptBuf::new(),
                inputs_hash: InputsHash::from_slice(&[0x55; 32]).expect("inputs hash"),
                platform_node_id: None,
                platform_p2p_port: None,
                platform_http_port: None,
                payload_sig: BLSSignature::from([0x66; 96]),
            });
        let ffi = FFISpecialTransactionPayload::from(&payload);

        assert_eq!(ffi.payload_type, 2);
        assert!(ffi.provider_registration.is_null());
        let upserv = unsafe { &*ffi.provider_update_service };
        let service = unsafe { CStr::from_ptr(upserv.service_address) }.to_str().expect("utf8");
        assert_eq!(service, "54.148.58.128:19999");
        assert_eq!(upserv.service_ip, octets);
        assert_eq!(upserv.service_port, 19999);
        assert_eq!(upserv.pro_tx_hash, [0x44; 32]);
        assert_eq!(upserv.masternode_type, -1);
        assert!(upserv.script_payout.is_null(), "empty payout script must be null");
        assert_eq!(upserv.script_payout_len, 0);
    }

    #[test]
    fn prouprev_payload_exposes_reason() {
        let payload = TransactionPayload::ProviderUpdateRevocationPayloadType(
            ProviderUpdateRevocationPayload {
                version: 1,
                pro_tx_hash: Txid::from_slice(&[0x77; 32]).expect("txid"),
                reason: 2,
                inputs_hash: InputsHash::from_slice(&[0x88; 32]).expect("inputs hash"),
                payload_sig: BLSSignature::from([0x99; 96]),
            },
        );
        let ffi = FFISpecialTransactionPayload::from(&payload);

        assert_eq!(ffi.payload_type, 4);
        let rev = unsafe { &*ffi.provider_update_revocation };
        assert_eq!(rev.pro_tx_hash, [0x77; 32]);
        assert_eq!(rev.reason, 2);
    }

    #[test]
    fn unsupported_payload_kind_exposes_discriminant_only() {
        use dashcore::blockdata::transaction::special_transaction::coinbase::CoinbasePayload;
        use dashcore::hash_types::{MerkleRootMasternodeList, MerkleRootQuorums};

        let payload = TransactionPayload::CoinbasePayloadType(CoinbasePayload {
            version: 2,
            height: 100,
            merkle_root_masternode_list: MerkleRootMasternodeList::from_slice(&[0; 32])
                .expect("hash"),
            merkle_root_quorums: MerkleRootQuorums::from_slice(&[0; 32]).expect("hash"),
            best_cl_height: None,
            best_cl_signature: None,
            asset_locked_amount: None,
        });
        let ffi = FFISpecialTransactionPayload::from(&payload);

        assert_eq!(ffi.payload_type, 5);
        assert!(ffi.provider_registration.is_null());
        assert!(ffi.provider_update_service.is_null());
        assert!(ffi.provider_update_registrar.is_null());
        assert!(ffi.provider_update_revocation.is_null());
    }
}
