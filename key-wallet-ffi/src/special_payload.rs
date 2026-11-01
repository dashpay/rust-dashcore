//! FFI-safe typed views of DIP-2 special-transaction payloads.
//!
//! [`FFISpecialTransactionPayload`] is a tagged representation of
//! `dashcore`'s `TransactionPayload`: `payload_type` carries the on-wire
//! DIP-2 transaction type (`1` = ProRegTx … `12` = ProUpSharedRegTx), and for
//! five masternode provider payload kinds (ProRegTx, ProUpServTx, ProUpRegTx,
//! ProUpRevTx, ProUpShareTx) a matching typed struct pointer is non-null.
//! Other payload kinds (coinbase, quorum commitment, asset lock/unlock,
//! ProDisTx, ProUpSharedRegTx, …) currently expose only the discriminant; typed
//! structs for them can be added later without breaking the layout
//! contract (consumers must key off `payload_type`).
//!
//! All heap-allocated fields are owned by the structs and freed by their
//! `Drop` impls, which run when the owning
//! [`FFITransactionRecord`](crate::managed_account::FFITransactionRecord)
//! is freed.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::os::raw::c_char;

use dashcore::blockdata::transaction::special_transaction::provider_registration::{
    CollateralShare, MasternodePayoutShare, ProviderRegistrationPayload,
};
use dashcore::blockdata::transaction::special_transaction::provider_update_registrar::ProviderUpdateRegistrarPayload;
use dashcore::blockdata::transaction::special_transaction::provider_update_revocation::ProviderUpdateRevocationPayload;
use dashcore::blockdata::transaction::special_transaction::provider_update_service::ProviderUpdateServicePayload;
use dashcore::blockdata::transaction::special_transaction::provider_update_share::ProviderUpdateSharePayload;
use dashcore::blockdata::transaction::special_transaction::TransactionPayload;
use dashcore::bls_sig_utils::BLSPublicKey;
use dashcore::hashes::Hash;
use dashcore::ScriptBuf;

/// Box `items` into a raw `(ptr, len)` pair; `(null, 0)` when empty.
fn vec_to_raw<T>(items: Vec<T>) -> (*mut T, usize) {
    let items = items.into_boxed_slice();
    let len = items.len();
    if len == 0 {
        (std::ptr::null_mut(), 0)
    } else {
        (Box::into_raw(items) as *mut T, len)
    }
}

/// Free (and drop the items of) a `(ptr, len)` pair produced by [`vec_to_raw`].
///
/// # Safety
///
/// `ptr`/`len` must come from `vec_to_raw` and not have been freed yet.
unsafe fn free_raw<T>(ptr: &mut *mut T, len: &mut usize) {
    if !ptr.is_null() && *len > 0 {
        let slice_ptr = std::ptr::slice_from_raw_parts_mut(*ptr, *len);
        let _ = Box::from_raw(slice_ptr);
    }
    *ptr = std::ptr::null_mut();
    *len = 0;
}

/// Box `script`'s bytes into a raw `(ptr, len)` pair; `(null, 0)` for an
/// empty script.
fn script_to_raw(script: &ScriptBuf) -> (*mut u8, usize) {
    vec_to_raw(script.to_bytes())
}

/// Box version 3 (DIP-0026) owner payouts; `(null, 0)` when there are none.
fn payouts_to_raw(
    payouts: Option<&Vec<MasternodePayoutShare>>,
) -> (*mut FFIMasternodePayoutShare, usize) {
    vec_to_raw(payouts.into_iter().flatten().map(FFIMasternodePayoutShare::from).collect())
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

/// One version 3 (DIP-0026) owner payout: a script and its share of the
/// owner reward.
#[repr(C)]
pub struct FFIMasternodePayoutShare {
    /// Payout script bytes (owned by this struct, null when empty).
    pub script_payout: *mut u8,
    /// Length of `script_payout`.
    pub script_payout_len: usize,
    /// Share of the owner reward in basis points.
    pub reward: u16,
}

impl From<&MasternodePayoutShare> for FFIMasternodePayoutShare {
    fn from(p: &MasternodePayoutShare) -> Self {
        let (script_payout, script_payout_len) = script_to_raw(&p.script_payout);
        FFIMasternodePayoutShare {
            script_payout,
            script_payout_len,
            reward: p.reward,
        }
    }
}

impl Drop for FFIMasternodePayoutShare {
    fn drop(&mut self) {
        unsafe { free_raw(&mut self.script_payout, &mut self.script_payout_len) };
    }
}

/// One share of a version 3 shared-collateral registration.
#[repr(C)]
pub struct FFICollateralShare {
    /// Contributed amount in duffs.
    pub amount: i64,
    /// Refund script bytes (owned by this struct, null when empty).
    pub script_refund: *mut u8,
    /// Length of `script_refund`.
    pub script_refund_len: usize,
    /// Reward script bytes (owned by this struct). Null when empty: the
    /// share's rewards are then paid to `script_refund`.
    pub script_reward: *mut u8,
    /// Length of `script_reward`.
    pub script_reward_len: usize,
    /// Share owner key hash160 (20 bytes).
    pub owner_key_hash: [u8; 20],
}

impl From<&CollateralShare> for FFICollateralShare {
    fn from(s: &CollateralShare) -> Self {
        let (script_refund, script_refund_len) = script_to_raw(&s.script_refund);
        let (script_reward, script_reward_len) = script_to_raw(&s.script_reward);
        FFICollateralShare {
            amount: s.amount,
            script_refund,
            script_refund_len,
            script_reward,
            script_reward_len,
            owner_key_hash: s.owner_key_hash.to_byte_array(),
        }
    }
}

impl Drop for FFICollateralShare {
    fn drop(&mut self) {
        unsafe {
            free_raw(&mut self.script_refund, &mut self.script_refund_len);
            free_raw(&mut self.script_reward, &mut self.script_reward_len);
        }
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
    /// Payout script bytes (owned by this struct, null when empty). Empty
    /// from version 3, whose owner payouts are in `payouts`.
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
    /// Version 3 (DIP-0026) owner payouts (owned by this struct, null when
    /// there are none).
    pub payouts: *mut FFIMasternodePayoutShare,
    /// Number of entries in `payouts`.
    pub payouts_count: usize,
    /// `true` for a shared-collateral registration (version 3 with at least
    /// one share; Dash Core's `IsShared`). The four fields below are only
    /// meaningful in that case.
    pub has_shared_collateral: bool,
    /// The collateral shares (owned by this struct, null when there are none).
    pub shares: *mut FFICollateralShare,
    /// Number of entries in `shares`.
    pub shares_count: usize,
    /// Blocks after registration within which a leaving share pays `early_penalty`.
    pub early_period_blocks: u32,
    /// Penalty in duffs for leaving within `early_period_blocks`.
    pub early_penalty: i64,
}

impl From<&ProviderRegistrationPayload> for FFIProviderRegistrationPayload {
    fn from(p: &ProviderRegistrationPayload) -> Self {
        let service = p
            .service_address
            .primary_service_address()
            .unwrap_or_else(|| SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0));
        let (script_payout, script_payout_len) = script_to_raw(&p.script_payout);
        let (payouts, payouts_count) = payouts_to_raw(p.payouts.as_ref());
        let shared = p.shared_collateral.as_ref();
        let (shares, shares_count) = vec_to_raw(
            shared.into_iter().flat_map(|s| &s.shares).map(FFICollateralShare::from).collect(),
        );
        FFIProviderRegistrationPayload {
            version: p.version,
            masternode_type: p.masternode_type as u16,
            masternode_mode: p.masternode_mode,
            collateral_txid: p.collateral_outpoint.txid.to_byte_array(),
            collateral_vout: p.collateral_outpoint.vout,
            service_address: socket_addr_to_cstring(&service),
            service_ip: socket_addr_to_ipv6_octets(&service),
            service_port: service.port(),
            owner_key_hash: p.owner_key_hash.to_byte_array(),
            voting_key_hash: p.voting_key_hash.to_byte_array(),
            operator_public_key: bls_public_key_bytes(&p.operator_public_key),
            operator_reward: p.operator_reward,
            script_payout,
            script_payout_len,
            has_platform_fields: p.platform_node_id.is_some(),
            platform_node_id: p.platform_node_id.map(|id| id.to_byte_array()).unwrap_or([0; 20]),
            platform_p2p_port: p.platform_p2p_port.map_or(-1, i32::from),
            platform_http_port: p.platform_http_port.map_or(-1, i32::from),
            payouts,
            payouts_count,
            has_shared_collateral: shared.is_some_and(|s| !s.shares.is_empty()),
            shares,
            shares_count,
            early_period_blocks: shared.map_or(0, |s| s.early_period_blocks),
            early_penalty: shared.map_or(0, |s| s.early_penalty),
        }
    }
}

impl Drop for FFIProviderRegistrationPayload {
    fn drop(&mut self) {
        if !self.service_address.is_null() {
            let _ = unsafe { std::ffi::CString::from_raw(self.service_address) };
            self.service_address = std::ptr::null_mut();
        }
        unsafe {
            free_raw(&mut self.script_payout, &mut self.script_payout_len);
            free_raw(&mut self.payouts, &mut self.payouts_count);
            free_raw(&mut self.shares, &mut self.shares_count);
        }
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
    /// this struct. For a version 3 payload, the primary Core P2P address of
    /// its extended addresses, `[::]:0` when it has no IPv4/IPv6 one.
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
        let service = p
            .service_address
            .primary_service_address()
            .unwrap_or_else(|| SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0));
        let (script_payout, script_payout_len) = script_to_raw(&p.script_payout);
        FFIProviderUpdateServicePayload {
            version: p.version,
            masternode_type: p.mn_type.map_or(-1, i32::from),
            pro_tx_hash: p.pro_tx_hash.to_byte_array(),
            service_address: socket_addr_to_cstring(&service),
            service_ip: socket_addr_to_ipv6_octets(&service),
            service_port: service.port(),
            script_payout,
            script_payout_len,
            has_platform_fields: p.platform_node_id.is_some(),
            platform_node_id: p.platform_node_id.map(|id| id.to_byte_array()).unwrap_or([0; 20]),
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
        unsafe { free_raw(&mut self.script_payout, &mut self.script_payout_len) };
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
    /// Empty from version 3, whose owner payouts are in `payouts`.
    pub script_payout: *mut u8,
    /// Length of `script_payout`.
    pub script_payout_len: usize,
    /// New version 3 (DIP-0026) owner payouts (owned by this struct, null
    /// when there are none).
    pub payouts: *mut FFIMasternodePayoutShare,
    /// Number of entries in `payouts`.
    pub payouts_count: usize,
}

impl From<&ProviderUpdateRegistrarPayload> for FFIProviderUpdateRegistrarPayload {
    fn from(p: &ProviderUpdateRegistrarPayload) -> Self {
        let (script_payout, script_payout_len) = script_to_raw(&p.script_payout);
        let (payouts, payouts_count) = payouts_to_raw(p.payouts.as_ref());
        FFIProviderUpdateRegistrarPayload {
            version: p.version,
            pro_tx_hash: p.pro_tx_hash.to_byte_array(),
            provider_mode: p.provider_mode,
            operator_public_key: bls_public_key_bytes(&p.operator_public_key),
            voting_key_hash: p.voting_key_hash.to_byte_array(),
            script_payout,
            script_payout_len,
            payouts,
            payouts_count,
        }
    }
}

impl Drop for FFIProviderUpdateRegistrarPayload {
    fn drop(&mut self) {
        unsafe {
            free_raw(&mut self.script_payout, &mut self.script_payout_len);
            free_raw(&mut self.payouts, &mut self.payouts_count);
        }
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

/// Typed view of a `ProUpShareTx` (provider update share) payload.
#[repr(C)]
pub struct FFIProviderUpdateSharePayload {
    /// ProUpShareTx payload version.
    pub version: u16,
    /// ProRegTx hash of the shared masternode (32 bytes, `to_byte_array` order).
    pub pro_tx_hash: [u8; 32],
    /// Index of the updated share in the registration's shares.
    pub share_index: u16,
    /// New reward script bytes (owned by this struct, null when empty, which
    /// Dash Core rejects). Setting it to the share's refund script resets
    /// the rewards to it.
    pub script_reward: *mut u8,
    /// Length of `script_reward`.
    pub script_reward_len: usize,
}

impl From<&ProviderUpdateSharePayload> for FFIProviderUpdateSharePayload {
    fn from(p: &ProviderUpdateSharePayload) -> Self {
        let (script_reward, script_reward_len) = script_to_raw(&p.script_reward);
        FFIProviderUpdateSharePayload {
            version: p.version,
            pro_tx_hash: p.pro_tx_hash.to_byte_array(),
            share_index: p.share_index,
            script_reward,
            script_reward_len,
        }
    }
}

impl Drop for FFIProviderUpdateSharePayload {
    fn drop(&mut self) {
        unsafe { free_raw(&mut self.script_reward, &mut self.script_reward_len) };
    }
}

/// Tagged FFI view of a transaction's DIP-2 special payload.
///
/// `payload_type` is the on-wire DIP-2 transaction type (`1` ProRegTx,
/// `2` ProUpServTx, `3` ProUpRegTx, `4` ProUpRevTx, `5` CbTx, `6` QcTx,
/// `7` MnHfTx, `8` AssetLockTx, `9` AssetUnlockTx, `10` ProDisTx, `11`
/// ProUpShareTx, `12` ProUpSharedRegTx; pre-DIP-0002 transactions with
/// non-standard type bytes surface their raw value). For the five typed
/// provider payload kinds (types 1–4 and 11) the matching struct pointer is
/// non-null, unless the payload was kept raw because its layout is unknown;
/// at most one pointer is ever non-null. All pointers are owned by this
/// struct and freed with it.
#[repr(C)]
pub struct FFISpecialTransactionPayload {
    /// On-wire DIP-2 transaction type discriminant.
    pub payload_type: u16,
    /// Non-null only if `payload_type == 1` (ProRegTx) and the payload decoded.
    pub provider_registration: *mut FFIProviderRegistrationPayload,
    /// Non-null only if `payload_type == 2` (ProUpServTx) and the payload decoded.
    pub provider_update_service: *mut FFIProviderUpdateServicePayload,
    /// Non-null only if `payload_type == 3` (ProUpRegTx) and the payload decoded.
    pub provider_update_registrar: *mut FFIProviderUpdateRegistrarPayload,
    /// Non-null only if `payload_type == 4` (ProUpRevTx) and the payload decoded.
    pub provider_update_revocation: *mut FFIProviderUpdateRevocationPayload,
    /// Non-null only if `payload_type == 11` (ProUpShareTx) and the payload decoded.
    pub provider_update_share: *mut FFIProviderUpdateSharePayload,
}

impl From<&TransactionPayload> for FFISpecialTransactionPayload {
    fn from(payload: &TransactionPayload) -> Self {
        let mut ffi = FFISpecialTransactionPayload {
            payload_type: payload.get_type().to_u16(),
            provider_registration: std::ptr::null_mut(),
            provider_update_service: std::ptr::null_mut(),
            provider_update_registrar: std::ptr::null_mut(),
            provider_update_revocation: std::ptr::null_mut(),
            provider_update_share: std::ptr::null_mut(),
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
            TransactionPayload::ProviderUpdateSharePayloadType(p) => {
                ffi.provider_update_share = Box::into_raw(Box::new(p.into()));
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
        if !self.provider_update_share.is_null() {
            let _ = unsafe { Box::from_raw(self.provider_update_share) };
            self.provider_update_share = std::ptr::null_mut();
        }
    }
}

/// Mainnet-shape ProRegTx payload for tests: owner/voting hash160 and
/// service endpoint from the masternode registration referenced in
/// issue #875.
#[cfg(test)]
pub(crate) fn mainnet_shape_proreg_payload() -> ProviderRegistrationPayload {
    use dashcore::blockdata::transaction::special_transaction::provider_registration::ProviderMasternodeType;
    use dashcore::sml::masternode_list_entry::MasternodeNetInfo;
    use std::str::FromStr;

    let key_hash = dashcore::PubkeyHash::from_str("70993555a01f7e8d6179d6135b5c56809d2d1d36")
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
        service_address: MasternodeNetInfo::Legacy(
            SocketAddr::from_str("54.148.58.128:9999").expect("socket addr"),
        ),
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
        payouts: None,
        shared_collateral: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashcore::blockdata::transaction::special_transaction::provider_registration::SharedCollateral;
    use dashcore::bls_sig_utils::BLSSignature;
    use dashcore::hash_types::InputsHash;
    use dashcore::sml::masternode_list_entry::MasternodeNetInfo;
    use dashcore::Txid;
    use std::ffi::CStr;

    /// The bytes of an owned `(ptr, len)` script; empty for `(null, 0)`.
    fn script_bytes<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
        if ptr.is_null() {
            assert_eq!(len, 0);
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(ptr, len) }
        }
    }

    fn payout(script: &[u8], reward: u16) -> MasternodePayoutShare {
        MasternodePayoutShare {
            script_payout: ScriptBuf::from_bytes(script.to_vec()),
            reward,
        }
    }

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
            hex_conservative::decode_to_array::<20>("70993555a01f7e8d6179d6135b5c56809d2d1d36")
                .expect("hash160");
        assert_eq!(reg.owner_key_hash, expected_hash);
        assert_eq!(reg.voting_key_hash, expected_hash);
        assert_eq!(reg.operator_public_key, [0x11; 48]);
        assert_eq!(reg.operator_reward, 250);
        assert_eq!(reg.masternode_type, 0);
        assert_eq!(reg.collateral_vout, 1);
        assert!(!reg.has_platform_fields);
        assert_eq!(reg.platform_p2p_port, -1);
        assert!(reg.payouts.is_null());
        assert_eq!(reg.payouts_count, 0);
        assert!(!reg.has_shared_collateral);
        assert!(reg.shares.is_null());
        assert_eq!(reg.shares_count, 0);

        let script =
            unsafe { std::slice::from_raw_parts(reg.script_payout, reg.script_payout_len) };
        assert_eq!(
            script,
            hex_conservative::decode_to_vec("76a914fef33f56f709ba6b08d073932f925afedb606d0288ac")
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
                service_address: MasternodeNetInfo::Legacy(
                    "54.148.58.128:19999".parse().expect("socket address"),
                ),
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
            merkle_root_asset_unlocks: None,
        });
        let ffi = FFISpecialTransactionPayload::from(&payload);

        assert_eq!(ffi.payload_type, 5);
        assert!(ffi.provider_registration.is_null());
        assert!(ffi.provider_update_service.is_null());
        assert!(ffi.provider_update_registrar.is_null());
        assert!(ffi.provider_update_revocation.is_null());
        assert!(ffi.provider_update_share.is_null());
    }

    #[test]
    fn proreg_v3_payload_exposes_payouts_and_shares() {
        let mut reg = mainnet_shape_proreg_payload();
        reg.version = 3;
        reg.script_payout = ScriptBuf::new();
        reg.payouts = Some(vec![payout(&[0xa1; 25], 4000), payout(&[0xa2; 23], 6000)]);
        let share = |refund: u8, reward: &[u8], owner: u8| CollateralShare {
            amount: 50_000_000_000 + i64::from(owner),
            script_refund: ScriptBuf::from_bytes(vec![refund; 25]),
            script_reward: ScriptBuf::from_bytes(reward.to_vec()),
            owner_key_hash: dashcore::PubkeyHash::from_byte_array([owner; 20]),
        };
        reg.shared_collateral = Some(SharedCollateral {
            shares: vec![share(0xb1, &[], 1), share(0xb2, &[0xc2; 25], 2)],
            join_sigs: Vec::new(),
            early_period_blocks: 16_616,
            early_penalty: 1_000_000,
        });
        let ffi = FFISpecialTransactionPayload::from(
            &TransactionPayload::ProviderRegistrationPayloadType(reg),
        );

        let reg = unsafe { &*ffi.provider_registration };
        assert!(reg.script_payout.is_null());
        assert_eq!(reg.payouts_count, 2);
        let payouts = unsafe { std::slice::from_raw_parts(reg.payouts, reg.payouts_count) };
        assert_eq!(
            script_bytes(payouts[0].script_payout, payouts[0].script_payout_len),
            [0xa1; 25]
        );
        assert_eq!(payouts[0].reward, 4000);
        assert_eq!(
            script_bytes(payouts[1].script_payout, payouts[1].script_payout_len),
            [0xa2; 23]
        );
        assert_eq!(payouts[1].reward, 6000);

        assert!(reg.has_shared_collateral);
        assert_eq!(reg.early_period_blocks, 16_616);
        assert_eq!(reg.early_penalty, 1_000_000);
        assert_eq!(reg.shares_count, 2);
        let shares = unsafe { std::slice::from_raw_parts(reg.shares, reg.shares_count) };
        assert_eq!(shares[0].amount, 50_000_000_001);
        assert_eq!(script_bytes(shares[0].script_refund, shares[0].script_refund_len), [0xb1; 25]);
        assert!(shares[0].script_reward.is_null(), "an empty reward script must be null");
        assert_eq!(shares[0].owner_key_hash, [1; 20]);
        assert_eq!(script_bytes(shares[1].script_refund, shares[1].script_refund_len), [0xb2; 25]);
        assert_eq!(script_bytes(shares[1].script_reward, shares[1].script_reward_len), [0xc2; 25]);
        assert_eq!(shares[1].owner_key_hash, [2; 20]);
    }

    #[test]
    fn decoded_single_owner_v3_proreg_is_not_shared() {
        use dashcore::consensus::{deserialize, serialize};
        use dashcore::sml::masternode_list_entry::net_info::ExtNetInfo;

        let mut reg = mainnet_shape_proreg_payload();
        reg.version = 3;
        reg.service_address = MasternodeNetInfo::Extended(ExtNetInfo {
            version: 1,
            purposes: Vec::new(),
        });
        reg.script_payout = ScriptBuf::new();
        reg.payouts = Some(vec![payout(&[0xa1; 25], 10_000)]);
        reg.shared_collateral = Some(SharedCollateral::default());
        // Decoding gives every version 3 payload a (here empty) shared collateral.
        let decoded: ProviderRegistrationPayload = deserialize(&serialize(&reg)).expect("decode");
        assert!(decoded.shared_collateral.is_some());
        let ffi = FFISpecialTransactionPayload::from(
            &TransactionPayload::ProviderRegistrationPayloadType(decoded),
        );

        let reg = unsafe { &*ffi.provider_registration };
        assert!(!reg.has_shared_collateral);
        assert!(reg.shares.is_null());
        assert_eq!(reg.shares_count, 0);
        assert_eq!(reg.payouts_count, 1);
    }

    #[test]
    fn proupreg_v3_payload_exposes_payouts() {
        let mut payload = ProviderUpdateRegistrarPayload::new(
            Txid::from_slice(&[0x44; 32]).expect("txid"),
            0,
            BLSPublicKey::from([0x11; 48]),
            dashcore::PubkeyHash::from_byte_array([0x22; 20]),
            ScriptBuf::new(),
            InputsHash::from_slice(&[0x55; 32]).expect("inputs hash"),
            vec![0x66; 65],
        );
        payload.version = 3;
        payload.payouts = Some(vec![payout(&[0xa1; 25], 10_000)]);
        let ffi = FFISpecialTransactionPayload::from(
            &TransactionPayload::ProviderUpdateRegistrarPayloadType(payload),
        );

        assert_eq!(ffi.payload_type, 3);
        let upreg = unsafe { &*ffi.provider_update_registrar };
        assert!(upreg.script_payout.is_null());
        assert_eq!(upreg.payouts_count, 1);
        let payouts = unsafe { std::slice::from_raw_parts(upreg.payouts, upreg.payouts_count) };
        assert_eq!(
            script_bytes(payouts[0].script_payout, payouts[0].script_payout_len),
            [0xa1; 25]
        );
        assert_eq!(payouts[0].reward, 10_000);
    }

    #[test]
    fn proupshare_payload_exposes_reward_script() {
        let payload =
            TransactionPayload::ProviderUpdateSharePayloadType(ProviderUpdateSharePayload {
                version: 1,
                pro_tx_hash: Txid::from_slice(&[0x77; 32]).expect("txid"),
                share_index: 3,
                script_reward: ScriptBuf::from_bytes(vec![0xc3; 25]),
                inputs_hash: InputsHash::from_slice(&[0x88; 32]).expect("inputs hash"),
                payload_sig: vec![0x99; 65],
            });
        let ffi = FFISpecialTransactionPayload::from(&payload);

        assert_eq!(ffi.payload_type, 11);
        assert!(ffi.provider_registration.is_null());
        assert!(ffi.provider_update_registrar.is_null());
        let upshare = unsafe { &*ffi.provider_update_share };
        assert_eq!(upshare.version, 1);
        assert_eq!(upshare.pro_tx_hash, [0x77; 32]);
        assert_eq!(upshare.share_index, 3);
        assert_eq!(script_bytes(upshare.script_reward, upshare.script_reward_len), [0xc3; 25]);
    }
}
