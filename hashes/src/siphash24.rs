// Bitcoin Hashes Library
// Written in 2019 by
//   The rust-dash developers
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

// This module is largely copied from the rust-siphash sip.rs file;
// while rust-siphash is licensed under Apache, that file specifically
// was written entirely by Steven Roose, who is re-licensing its
// contents here as CC0.

//! SipHash 2-4 implementation.
//!

use core::ops::Index;
use core::slice::SliceIndex;
use core::{cmp, mem, ptr, str};

use crate::{Error, Hash as _, HashEngine as _};

// Lane-vector types for the per-arch SIMD batchers, so helper signatures stay readable.
#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::uint64x2_t;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::__m256i;

crate::internal_macros::hash_type! {
    64,
    false,
    "Output of the SipHash24 hash function.",
    "crate::util::json_hex_string::len_8"
}

#[cfg(not(fuzzing))]
fn from_engine(e: HashEngine) -> Hash {
    Hash::from_u64(Hash::from_engine_to_u64(e))
}

#[cfg(fuzzing)]
fn from_engine(e: HashEngine) -> Hash {
    let state = e.midstate();
    Hash::from_u64(state.v0 ^ state.v1 ^ state.v2 ^ state.v3)
}

/// One scalar SipRound over the four state words. The reference the SIMD kernels
/// ([`sip_round_avx2`], [`sip_round_neon`]) reproduce lane-for-lane.
#[inline]
fn sip_round_scalar(mut v0: u64, mut v1: u64, mut v2: u64, mut v3: u64) -> (u64, u64, u64, u64) {
    v0 = v0.wrapping_add(v1);
    v1 = v1.rotate_left(13);
    v1 ^= v0;
    v0 = v0.rotate_left(32);
    v2 = v2.wrapping_add(v3);
    v3 = v3.rotate_left(16);
    v3 ^= v2;
    v0 = v0.wrapping_add(v3);
    v3 = v3.rotate_left(21);
    v3 ^= v0;
    v2 = v2.wrapping_add(v1);
    v1 = v1.rotate_left(17);
    v1 ^= v2;
    v2 = v2.rotate_left(32);
    (v0, v1, v2, v3)
}

/// Load an integer of the desired type from a byte stream, in LE order. Uses
/// `copy_nonoverlapping` to let the compiler generate the most efficient way
/// to load it from a possibly unaligned address.
///
/// Unsafe because: unchecked indexing at `i..i+size_of(int_ty)`.
macro_rules! load_int_le {
    ($buf:expr, $i:expr, $int_ty:ident) => {{
        debug_assert!($i + mem::size_of::<$int_ty>() <= $buf.len());
        let mut data = 0 as $int_ty;
        unsafe {
            ptr::copy_nonoverlapping(
                $buf.get_unchecked($i),
                &mut data as *mut _ as *mut u8,
                mem::size_of::<$int_ty>(),
            );
        }
        data.to_le()
    }};
}

/// Internal state of the [`HashEngine`].
#[derive(Debug, Clone)]
pub struct State {
    // v0, v2 and v1, v3 show up in pairs in the algorithm,
    // and simd implementations of SipHash will use vectors
    // of v02 and v13. By placing them in this order in the struct,
    // the compiler can pick up on just a few simd optimizations by itself.
    v0: u64,
    v2: u64,
    v1: u64,
    v3: u64,
}

/// Engine to compute the SipHash24 hash function.
#[derive(Debug, Clone)]
pub struct HashEngine {
    k0: u64,
    k1: u64,
    length: usize, // how many bytes we've processed
    state: State,  // hash State
    tail: u64,     // unprocessed bytes le
    ntail: usize,  // how many bytes in tail are valid
}

impl HashEngine {
    /// Creates a new SipHash24 engine with keys.
    pub fn with_keys(k0: u64, k1: u64) -> HashEngine {
        HashEngine {
            k0,
            k1,
            length: 0,
            state: State {
                v0: k0 ^ 0x736f6d6570736575,
                v1: k1 ^ 0x646f72616e646f6d,
                v2: k0 ^ 0x6c7967656e657261,
                v3: k1 ^ 0x7465646279746573,
            },
            tail: 0,
            ntail: 0,
        }
    }

    /// Creates a new SipHash24 engine.
    pub fn new() -> HashEngine {
        HashEngine::with_keys(0, 0)
    }

    /// Retrieves the keys of this engine.
    pub fn keys(&self) -> (u64, u64) {
        (self.k0, self.k1)
    }

    #[inline]
    fn rounds(state: &mut State, n: usize) {
        let (mut v0, mut v1, mut v2, mut v3) = (state.v0, state.v1, state.v2, state.v3);
        for _ in 0..n {
            (v0, v1, v2, v3) = sip_round_scalar(v0, v1, v2, v3);
        }
        (state.v0, state.v1, state.v2, state.v3) = (v0, v1, v2, v3);
    }

    #[inline]
    fn c_rounds(state: &mut State) {
        HashEngine::rounds(state, 2);
    }

    #[inline]
    fn d_rounds(state: &mut State) {
        HashEngine::rounds(state, 4);
    }
}

impl Default for HashEngine {
    fn default() -> Self {
        HashEngine::new()
    }
}

impl crate::HashEngine for HashEngine {
    type MidState = State;

    fn midstate(&self) -> State {
        self.state.clone()
    }

    const BLOCK_SIZE: usize = 8;

    #[inline]
    fn input(&mut self, msg: &[u8]) {
        let length = msg.len();
        self.length += length;

        let mut needed = 0;

        if self.ntail != 0 {
            needed = 8 - self.ntail;
            self.tail |= unsafe { u8to64_le(msg, 0, cmp::min(length, needed)) } << (8 * self.ntail);
            if length < needed {
                self.ntail += length;
                return;
            } else {
                self.state.v3 ^= self.tail;
                HashEngine::c_rounds(&mut self.state);
                self.state.v0 ^= self.tail;
                self.ntail = 0;
            }
        }

        // Buffered tail is now flushed, process new input.
        let len = length - needed;
        let left = len & 0x7;

        let mut i = needed;
        while i < len - left {
            let mi = load_int_le!(msg, i, u64);

            self.state.v3 ^= mi;
            HashEngine::c_rounds(&mut self.state);
            self.state.v0 ^= mi;

            i += 8;
        }

        self.tail = unsafe { u8to64_le(msg, i, left) };
        self.ntail = left;
    }

    fn n_bytes_hashed(&self) -> usize {
        self.length
    }
}

impl Hash {
    /// Hashes the given data with an engine with the provided keys.
    pub fn hash_with_keys(k0: u64, k1: u64, data: &[u8]) -> Hash {
        let mut engine = HashEngine::with_keys(k0, k1);
        engine.input(data);
        Hash::from_engine(engine)
    }

    /// Hashes the given data directly to u64 with an engine with the provided keys.
    pub fn hash_to_u64_with_keys(k0: u64, k1: u64, data: &[u8]) -> u64 {
        let mut engine = HashEngine::with_keys(k0, k1);
        engine.input(data);
        Hash::from_engine_to_u64(engine)
    }

    /// Produces a hash as `u64` from the current state of a given engine.
    #[inline]
    pub fn from_engine_to_u64(e: HashEngine) -> u64 {
        let mut state = e.state;

        let b: u64 = ((e.length as u64 & 0xff) << 56) | e.tail;

        state.v3 ^= b;
        HashEngine::c_rounds(&mut state);
        state.v0 ^= b;

        state.v2 ^= 0xff;
        HashEngine::d_rounds(&mut state);

        state.v0 ^ state.v1 ^ state.v2 ^ state.v3
    }

    /// Returns the (little endian) 64-bit integer representation of the hash value.
    pub fn as_u64(&self) -> u64 {
        u64::from_le_bytes(self.0)
    }

    /// Creates a hash from its (little endian) 64-bit integer representation.
    pub fn from_u64(hash: u64) -> Hash {
        Hash(hash.to_le_bytes())
    }
}

/// Load an u64 using up to 7 bytes of a byte slice.
///
/// Unsafe because: unchecked indexing at `start..start+len`.
#[inline]
unsafe fn u8to64_le(buf: &[u8], start: usize, len: usize) -> u64 {
    debug_assert!(len < 8);
    let mut i = 0; // current byte index (from LSB) in the output u64
    let mut out = 0;
    if i + 3 < len {
        out = u64::from(load_int_le!(buf, start + i, u32));
        i += 4;
    }
    if i + 1 < len {
        out |= u64::from(load_int_le!(buf, start + i, u16)) << (i * 8);
        i += 2
    }
    if i < len {
        out |= u64::from(unsafe { *buf.get_unchecked(start + i) }) << (i * 8);
        i += 1;
    }
    debug_assert_eq!(i, len);
    out
}

/// Scalar SipHash-2-4 one-shot: hashes `data` under keys `(k0, k1)` to a `u64`.
/// The reference [`siphash_batch`] must match bit-for-bit.
pub fn siphash(k0: u64, k1: u64, data: &[u8]) -> u64 {
    let mut v0 = k0 ^ 0x736f6d6570736575;
    let mut v1 = k1 ^ 0x646f72616e646f6d;
    let mut v2 = k0 ^ 0x6c7967656e657261;
    let mut v3 = k1 ^ 0x7465646279746573;

    let len = data.len();
    let nfull = len / 8;
    for blk in 0..nfull {
        let m = load_int_le!(data, blk * 8, u64);
        v3 ^= m;
        (v0, v1, v2, v3) = sip_round_scalar(v0, v1, v2, v3);
        (v0, v1, v2, v3) = sip_round_scalar(v0, v1, v2, v3);
        v0 ^= m;
    }

    let left = len & 7;
    let b = ((len as u64 & 0xff) << 56) | unsafe { u8to64_le(data, nfull * 8, left) };
    v3 ^= b;
    (v0, v1, v2, v3) = sip_round_scalar(v0, v1, v2, v3);
    (v0, v1, v2, v3) = sip_round_scalar(v0, v1, v2, v3);
    v0 ^= b;

    v2 ^= 0xff;
    for _ in 0..4 {
        (v0, v1, v2, v3) = sip_round_scalar(v0, v1, v2, v3);
    }

    v0 ^ v1 ^ v2 ^ v3
}

/// Batch SipHash-2-4 over `inputs` that are all exactly `LEN` bytes, writing
/// `out[i] = siphash(k0, k1, &inputs[i])`. Uses the AVX2 (x86_64) or NEON (aarch64) batch
/// kernel when available, else the scalar one-shot; bit-identical to per-input [`siphash`].
pub fn siphash_batch<const LEN: usize>(k0: u64, k1: u64, inputs: &[[u8; LEN]], out: &mut [u64]) {
    assert!(out.len() >= inputs.len(), "output buffer too small");

    #[cfg(target_arch = "x86_64")]
    {
        if std::is_x86_feature_detected!("avx2") {
            unsafe { hash_many_wide_avx2::<LEN, AVX2_R>(k0, k1, inputs, out) };
        } else {
            siphash_each(k0, k1, inputs, out);
        }
    }

    #[cfg(target_arch = "aarch64")]
    unsafe {
        hash_many_wide_neon::<LEN, NEON_R>(k0, k1, inputs, out)
    };

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    siphash_each(k0, k1, inputs, out);
}

/// Scalar fallback for [`siphash_batch`] where no SIMD kernel applies (x86 without AVX2, and
/// targets with no vectorised path). aarch64 always batches via NEON, so it never uses this.
#[cfg(not(target_arch = "aarch64"))]
#[inline]
fn siphash_each<const LEN: usize>(k0: u64, k1: u64, inputs: &[[u8; LEN]], out: &mut [u64]) {
    for (i, inp) in inputs.iter().enumerate() {
        out[i] = siphash(k0, k1, inp);
    }
}

/// Rotate-left of each 64-bit lane by `L` (`R = 64 - L`): shift + shift + or. Lane-vector
/// (`uint64x2_t` = 2 messages) analogue of [`rotl_avx2`].
#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn sip_rotl<const L: i32, const R: i32>(x: uint64x2_t) -> uint64x2_t {
    use core::arch::aarch64::*;
    vorrq_u64(vshlq_n_u64::<L>(x), vshrq_n_u64::<R>(x))
}

/// SipRound on a lane-vector (`uint64x2_t` = 2 messages), shared by the NEON kernels.
#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn sip_round_neon(
    mut v0: uint64x2_t,
    mut v1: uint64x2_t,
    mut v2: uint64x2_t,
    mut v3: uint64x2_t,
) -> (uint64x2_t, uint64x2_t, uint64x2_t, uint64x2_t) {
    use core::arch::aarch64::*;
    v0 = vaddq_u64(v0, v1);
    v1 = sip_rotl::<13, 51>(v1);
    v1 = veorq_u64(v1, v0);
    v0 = sip_rotl::<32, 32>(v0);
    v2 = vaddq_u64(v2, v3);
    v3 = sip_rotl::<16, 48>(v3);
    v3 = veorq_u64(v3, v2);
    v0 = vaddq_u64(v0, v3);
    v3 = sip_rotl::<21, 43>(v3);
    v3 = veorq_u64(v3, v0);
    v2 = vaddq_u64(v2, v1);
    v1 = sip_rotl::<17, 47>(v1);
    v1 = veorq_u64(v1, v2);
    v2 = sip_rotl::<32, 32>(v2);
    (v0, v1, v2, v3)
}

/// ILP knob: independent `uint64x2_t` register-sets the NEON batcher keeps in flight (2
/// messages each, so batch width `2 * NEON_R` = 12). More sets hide SipHash's serial
/// per-message latency; `6` is the widest that fits aarch64's 32 registers without spilling.
#[cfg(target_arch = "aarch64")]
const NEON_R: usize = 6;

/// Hashes exactly `2 * R` equal-length inputs, keeping `R` independent `uint64x2_t`
/// register-sets in flight (2 messages each) to overlap the per-message SipHash dependency
/// chains. Writes `out[0..2*R]`. NEON analogue of [`siphash_block_avx2`] (4 lanes there).
///
/// # Safety
/// NEON is baseline on aarch64. `inputs`/`out` must have at least `2 * R` elements.
#[cfg(target_arch = "aarch64")]
#[inline]
// The `for r in 0..R` loops step the register-sets in lockstep by design; index-based.
#[allow(clippy::needless_range_loop)]
unsafe fn siphash_block_neon<const LEN: usize, const R: usize>(
    k0: u64,
    k1: u64,
    inputs: &[[u8; LEN]],
    out: &mut [u64],
) {
    use core::arch::aarch64::*;

    // Build a lane-vector {x, y} from two scalar words. `vcombine`/`vcreate` moves the GPRs
    // straight into the SIMD lanes (lane0 = x, lane1 = y), avoiding the stack round-trip a
    // `vld1q_u64([x, y])` load would incur.
    let pack = |x: u64, y: u64| -> uint64x2_t { vcombine_u64(vcreate_u64(x), vcreate_u64(y)) };

    let mut v0 = [vdupq_n_u64(k0 ^ 0x736f6d6570736575); R];
    let mut v1 = [vdupq_n_u64(k1 ^ 0x646f72616e646f6d); R];
    let mut v2 = [vdupq_n_u64(k0 ^ 0x6c7967656e657261); R];
    let mut v3 = [vdupq_n_u64(k1 ^ 0x7465646279746573); R];

    // One `uint64x2_t` per register holding lane `k`'s next 8-byte word `| extra`;
    // register `r` carries inputs `2r..2r+2`, lane order low..high = those two.
    macro_rules! words {
        ($word:expr) => {{
            let mut m = [vdupq_n_u64(0); R];
            for r in 0..R {
                let b = r * 2;
                m[r] = pack($word(&inputs[b]), $word(&inputs[b + 1]));
            }
            m
        }};
    }
    macro_rules! xor_all {
        ($dst:ident, $src:expr) => {{
            let src = $src;
            for r in 0..R {
                $dst[r] = veorq_u64($dst[r], src[r]);
            }
        }};
    }
    macro_rules! rounds {
        ($n:literal) => {
            for r in 0..R {
                let (mut a0, mut a1, mut a2, mut a3) = (v0[r], v1[r], v2[r], v3[r]);
                for _ in 0..$n {
                    (a0, a1, a2, a3) = sip_round_neon(a0, a1, a2, a3);
                }
                v0[r] = a0;
                v1[r] = a1;
                v2[r] = a2;
                v3[r] = a3;
            }
        };
    }

    // Full 8-byte message blocks.
    for blk in 0..LEN / 8 {
        let off = blk * 8;
        let m = words!(|inp: &[u8; LEN]| load_int_le!(inp, off, u64));
        xor_all!(v3, m);
        rounds!(2);
        xor_all!(v0, m);
    }

    // Final block: the leftover tail bytes with the length in the top byte.
    let lb = (LEN as u64 & 0xff) << 56;
    let off = LEN / 8 * 8;
    let left = LEN % 8;
    let b = words!(|inp: &[u8; LEN]| lb | u8to64_le(inp, off, left));
    xor_all!(v3, b);
    rounds!(2);
    xor_all!(v0, b);

    let ff = vdupq_n_u64(0xff);
    for r in 0..R {
        v2[r] = veorq_u64(v2[r], ff);
    }
    rounds!(4);

    // out lane = v0 ^ v1 ^ v2 ^ v3, written as one 128-bit store per register (lane order
    // low..high maps to out[b..b+2], matching the scalar reference).
    for r in 0..R {
        let h = veorq_u64(veorq_u64(v0[r], v1[r]), veorq_u64(v2[r], v3[r]));
        let b = r * 2;
        vst1q_u64(out[b..].as_mut_ptr(), h);
    }
}

/// Driver over the `R`-register NEON block (width `2 * R`): the tail after the wide loop is
/// drained with 2-lane (`R = 1`) blocks, then a final scalar one-shot.
///
/// # Safety
/// NEON is baseline on aarch64.
#[cfg(target_arch = "aarch64")]
unsafe fn hash_many_wide_neon<const LEN: usize, const R: usize>(
    k0: u64,
    k1: u64,
    inputs: &[[u8; LEN]],
    out: &mut [u64],
) {
    let w = 2 * R;
    let n = inputs.len();
    let mut i = 0;
    while i + w <= n {
        siphash_block_neon::<LEN, R>(k0, k1, &inputs[i..], &mut out[i..]);
        i += w;
    }
    // Drain remaining pairs through the 2-lane kernel (the same block with R = 1).
    while i + 2 <= n {
        siphash_block_neon::<LEN, 1>(k0, k1, &inputs[i..], &mut out[i..]);
        i += 2;
    }
    if i < n {
        out[i] = siphash(k0, k1, &inputs[i]);
    }
}

/// ILP knob: independent `__m256i` register-sets the AVX2 batcher keeps in flight (4
/// messages each, so batch width `4 * AVX2_R` = 12). More sets hide SipHash's serial
/// per-message latency; `3` is the widest that fits x86_64's 16 YMMs without spilling
/// (`4` spills and regresses).
#[cfg(target_arch = "x86_64")]
const AVX2_R: usize = 3;

/// Rotate-left of each 64-bit lane by `L` (`R = 64 - L`), the generic case: shift + shift + or.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn rotl_avx2<const L: i32, const R: i32>(x: __m256i) -> __m256i {
    use core::arch::x86_64::*;
    _mm256_or_si256(_mm256_slli_epi64::<L>(x), _mm256_srli_epi64::<R>(x))
}

/// SipRound on a `__m256i` holding 4 lanes (4 messages).
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn sip_round_avx2(
    mut v0: __m256i,
    mut v1: __m256i,
    mut v2: __m256i,
    mut v3: __m256i,
) -> (__m256i, __m256i, __m256i, __m256i) {
    use core::arch::x86_64::*;
    v0 = _mm256_add_epi64(v0, v1);
    v1 = rotl_avx2::<13, 51>(v1);
    v1 = _mm256_xor_si256(v1, v0);
    v0 = rotl_avx2::<32, 32>(v0);
    v2 = _mm256_add_epi64(v2, v3);
    v3 = rotl_avx2::<16, 48>(v3);
    v3 = _mm256_xor_si256(v3, v2);
    v0 = _mm256_add_epi64(v0, v3);
    v3 = rotl_avx2::<21, 43>(v3);
    v3 = _mm256_xor_si256(v3, v0);
    v2 = _mm256_add_epi64(v2, v1);
    v1 = rotl_avx2::<17, 47>(v1);
    v1 = _mm256_xor_si256(v1, v2);
    v2 = rotl_avx2::<32, 32>(v2);
    (v0, v1, v2, v3)
}

/// Hashes exactly `4 * R` equal-length inputs, keeping `R` independent `__m256i`
/// register sets in flight (4 messages each) to overlap the per-message SipHash dependency
/// chains. Writes `out[0..4*R]`.
///
/// # Safety
/// Requires AVX2. `inputs`/`out` must have at least `4 * R` elements.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
// The `for r in 0..R` loops step the register sets in lockstep by design; index-based.
#[allow(clippy::needless_range_loop)]
unsafe fn siphash_block_avx2<const LEN: usize, const R: usize>(
    k0: u64,
    k1: u64,
    inputs: &[[u8; LEN]],
    out: &mut [u64],
) {
    use core::arch::x86_64::*;

    let mut v0 = [_mm256_set1_epi64x((k0 ^ 0x736f6d6570736575) as i64); R];
    let mut v1 = [_mm256_set1_epi64x((k1 ^ 0x646f72616e646f6d) as i64); R];
    let mut v2 = [_mm256_set1_epi64x((k0 ^ 0x6c7967656e657261) as i64); R];
    let mut v3 = [_mm256_set1_epi64x((k1 ^ 0x7465646279746573) as i64); R];

    // These lockstep helpers stay macros on purpose: as functions taking `&mut [__m256i; R]`
    // the compiler spills the state arrays to the stack instead of keeping them in YMM
    // registers (measured ~4% slower), whereas the macros keep every lane as an SSA value.
    // One `__m256i` per register holds lane `k`'s next 8-byte word `| extra`;
    // register `r` carries inputs `4r..4r+4`, lane order low..high = those four.
    macro_rules! words {
        ($word:expr) => {{
            let mut m = [_mm256_setzero_si256(); R];
            for r in 0..R {
                let b = r * 4;
                m[r] = _mm256_set_epi64x(
                    $word(&inputs[b + 3]) as i64,
                    $word(&inputs[b + 2]) as i64,
                    $word(&inputs[b + 1]) as i64,
                    $word(&inputs[b]) as i64,
                );
            }
            m
        }};
    }
    macro_rules! xor_all {
        ($dst:ident, $src:expr) => {{
            let src = $src;
            for r in 0..R {
                $dst[r] = _mm256_xor_si256($dst[r], src[r]);
            }
        }};
    }
    macro_rules! rounds {
        ($n:literal) => {
            for r in 0..R {
                let (mut a0, mut a1, mut a2, mut a3) = (v0[r], v1[r], v2[r], v3[r]);
                for _ in 0..$n {
                    (a0, a1, a2, a3) = sip_round_avx2(a0, a1, a2, a3);
                }
                v0[r] = a0;
                v1[r] = a1;
                v2[r] = a2;
                v3[r] = a3;
            }
        };
    }

    // Full 8-byte message blocks.
    for blk in 0..LEN / 8 {
        let off = blk * 8;
        let m = words!(|inp: &[u8; LEN]| load_int_le!(inp, off, u64));
        xor_all!(v3, m);
        rounds!(2);
        xor_all!(v0, m);
    }

    // Final block: the leftover tail bytes with the length in the top byte.
    let lb = (LEN as u64 & 0xff) << 56;
    let off = LEN / 8 * 8;
    let left = LEN % 8;
    let b = words!(|inp: &[u8; LEN]| lb | unsafe { u8to64_le(inp, off, left) });
    xor_all!(v3, b);
    rounds!(2);
    xor_all!(v0, b);

    for r in 0..R {
        v2[r] = _mm256_xor_si256(v2[r], _mm256_set1_epi64x(0xff));
    }
    rounds!(4);

    // out lane = v0 ^ v1 ^ v2 ^ v3, written as one 256-bit store per register (lane order
    // low..high maps to out[b..b+4], matching the scalar reference).
    for r in 0..R {
        let h = _mm256_xor_si256(_mm256_xor_si256(v0[r], v1[r]), _mm256_xor_si256(v2[r], v3[r]));
        let b = r * 4;
        _mm256_storeu_si256(out[b..].as_mut_ptr() as *mut __m256i, h);
    }
}

/// Driver over the `R`-register AVX2 block (width `4 * R`): the tail after the wide loop is
/// drained with 4-lane (`R = 1`) blocks, then a final scalar one-shot. Mirrors
/// [`hash_many_wide_neon`].
///
/// # Safety
/// Requires AVX2.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn hash_many_wide_avx2<const LEN: usize, const R: usize>(
    k0: u64,
    k1: u64,
    inputs: &[[u8; LEN]],
    out: &mut [u64],
) {
    let w = 4 * R;
    let n = inputs.len();
    let mut i = 0;
    while i + w <= n {
        siphash_block_avx2::<LEN, R>(k0, k1, &inputs[i..], &mut out[i..]);
        i += w;
    }
    // Drain remaining quads through the 4-lane kernel (the same block with R = 1).
    while i + 4 <= n {
        siphash_block_avx2::<LEN, 1>(k0, k1, &inputs[i..], &mut out[i..]);
        i += 4;
    }
    while i < n {
        out[i] = siphash(k0, k1, &inputs[i]);
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::*;

    #[test]
    fn test_siphash_2_4() {
        #[rustfmt::skip]
        let vecs: [[u8; 8]; 64] = [
            [0x31, 0x0e, 0x0e, 0xdd, 0x47, 0xdb, 0x6f, 0x72],
            [0xfd, 0x67, 0xdc, 0x93, 0xc5, 0x39, 0xf8, 0x74],
            [0x5a, 0x4f, 0xa9, 0xd9, 0x09, 0x80, 0x6c, 0x0d],
            [0x2d, 0x7e, 0xfb, 0xd7, 0x96, 0x66, 0x67, 0x85],
            [0xb7, 0x87, 0x71, 0x27, 0xe0, 0x94, 0x27, 0xcf],
            [0x8d, 0xa6, 0x99, 0xcd, 0x64, 0x55, 0x76, 0x18],
            [0xce, 0xe3, 0xfe, 0x58, 0x6e, 0x46, 0xc9, 0xcb],
            [0x37, 0xd1, 0x01, 0x8b, 0xf5, 0x00, 0x02, 0xab],
            [0x62, 0x24, 0x93, 0x9a, 0x79, 0xf5, 0xf5, 0x93],
            [0xb0, 0xe4, 0xa9, 0x0b, 0xdf, 0x82, 0x00, 0x9e],
            [0xf3, 0xb9, 0xdd, 0x94, 0xc5, 0xbb, 0x5d, 0x7a],
            [0xa7, 0xad, 0x6b, 0x22, 0x46, 0x2f, 0xb3, 0xf4],
            [0xfb, 0xe5, 0x0e, 0x86, 0xbc, 0x8f, 0x1e, 0x75],
            [0x90, 0x3d, 0x84, 0xc0, 0x27, 0x56, 0xea, 0x14],
            [0xee, 0xf2, 0x7a, 0x8e, 0x90, 0xca, 0x23, 0xf7],
            [0xe5, 0x45, 0xbe, 0x49, 0x61, 0xca, 0x29, 0xa1],
            [0xdb, 0x9b, 0xc2, 0x57, 0x7f, 0xcc, 0x2a, 0x3f],
            [0x94, 0x47, 0xbe, 0x2c, 0xf5, 0xe9, 0x9a, 0x69],
            [0x9c, 0xd3, 0x8d, 0x96, 0xf0, 0xb3, 0xc1, 0x4b],
            [0xbd, 0x61, 0x79, 0xa7, 0x1d, 0xc9, 0x6d, 0xbb],
            [0x98, 0xee, 0xa2, 0x1a, 0xf2, 0x5c, 0xd6, 0xbe],
            [0xc7, 0x67, 0x3b, 0x2e, 0xb0, 0xcb, 0xf2, 0xd0],
            [0x88, 0x3e, 0xa3, 0xe3, 0x95, 0x67, 0x53, 0x93],
            [0xc8, 0xce, 0x5c, 0xcd, 0x8c, 0x03, 0x0c, 0xa8],
            [0x94, 0xaf, 0x49, 0xf6, 0xc6, 0x50, 0xad, 0xb8],
            [0xea, 0xb8, 0x85, 0x8a, 0xde, 0x92, 0xe1, 0xbc],
            [0xf3, 0x15, 0xbb, 0x5b, 0xb8, 0x35, 0xd8, 0x17],
            [0xad, 0xcf, 0x6b, 0x07, 0x63, 0x61, 0x2e, 0x2f],
            [0xa5, 0xc9, 0x1d, 0xa7, 0xac, 0xaa, 0x4d, 0xde],
            [0x71, 0x65, 0x95, 0x87, 0x66, 0x50, 0xa2, 0xa6],
            [0x28, 0xef, 0x49, 0x5c, 0x53, 0xa3, 0x87, 0xad],
            [0x42, 0xc3, 0x41, 0xd8, 0xfa, 0x92, 0xd8, 0x32],
            [0xce, 0x7c, 0xf2, 0x72, 0x2f, 0x51, 0x27, 0x71],
            [0xe3, 0x78, 0x59, 0xf9, 0x46, 0x23, 0xf3, 0xa7],
            [0x38, 0x12, 0x05, 0xbb, 0x1a, 0xb0, 0xe0, 0x12],
            [0xae, 0x97, 0xa1, 0x0f, 0xd4, 0x34, 0xe0, 0x15],
            [0xb4, 0xa3, 0x15, 0x08, 0xbe, 0xff, 0x4d, 0x31],
            [0x81, 0x39, 0x62, 0x29, 0xf0, 0x90, 0x79, 0x02],
            [0x4d, 0x0c, 0xf4, 0x9e, 0xe5, 0xd4, 0xdc, 0xca],
            [0x5c, 0x73, 0x33, 0x6a, 0x76, 0xd8, 0xbf, 0x9a],
            [0xd0, 0xa7, 0x04, 0x53, 0x6b, 0xa9, 0x3e, 0x0e],
            [0x92, 0x59, 0x58, 0xfc, 0xd6, 0x42, 0x0c, 0xad],
            [0xa9, 0x15, 0xc2, 0x9b, 0xc8, 0x06, 0x73, 0x18],
            [0x95, 0x2b, 0x79, 0xf3, 0xbc, 0x0a, 0xa6, 0xd4],
            [0xf2, 0x1d, 0xf2, 0xe4, 0x1d, 0x45, 0x35, 0xf9],
            [0x87, 0x57, 0x75, 0x19, 0x04, 0x8f, 0x53, 0xa9],
            [0x10, 0xa5, 0x6c, 0xf5, 0xdf, 0xcd, 0x9a, 0xdb],
            [0xeb, 0x75, 0x09, 0x5c, 0xcd, 0x98, 0x6c, 0xd0],
            [0x51, 0xa9, 0xcb, 0x9e, 0xcb, 0xa3, 0x12, 0xe6],
            [0x96, 0xaf, 0xad, 0xfc, 0x2c, 0xe6, 0x66, 0xc7],
            [0x72, 0xfe, 0x52, 0x97, 0x5a, 0x43, 0x64, 0xee],
            [0x5a, 0x16, 0x45, 0xb2, 0x76, 0xd5, 0x92, 0xa1],
            [0xb2, 0x74, 0xcb, 0x8e, 0xbf, 0x87, 0x87, 0x0a],
            [0x6f, 0x9b, 0xb4, 0x20, 0x3d, 0xe7, 0xb3, 0x81],
            [0xea, 0xec, 0xb2, 0xa3, 0x0b, 0x22, 0xa8, 0x7f],
            [0x99, 0x24, 0xa4, 0x3c, 0xc1, 0x31, 0x57, 0x24],
            [0xbd, 0x83, 0x8d, 0x3a, 0xaf, 0xbf, 0x8d, 0xb7],
            [0x0b, 0x1a, 0x2a, 0x32, 0x65, 0xd5, 0x1a, 0xea],
            [0x13, 0x50, 0x79, 0xa3, 0x23, 0x1c, 0xe6, 0x60],
            [0x93, 0x2b, 0x28, 0x46, 0xe4, 0xd7, 0x06, 0x66],
            [0xe1, 0x91, 0x5f, 0x5c, 0xb1, 0xec, 0xa4, 0x6c],
            [0xf3, 0x25, 0x96, 0x5c, 0xa1, 0x6d, 0x62, 0x9f],
            [0x57, 0x5f, 0xf2, 0x8e, 0x60, 0x38, 0x1b, 0xe5],
            [0x72, 0x45, 0x06, 0xeb, 0x4c, 0x32, 0x8a, 0x95],
        ];

        let k0 = 0x_07_06_05_04_03_02_01_00;
        let k1 = 0x_0f_0e_0d_0c_0b_0a_09_08;
        let mut vin = [0u8; 64];
        let mut state_inc = HashEngine::with_keys(k0, k1);

        for i in 0..64 {
            vin[i] = i as u8;
            let vec = Hash::from_slice(&vecs[i][..]).unwrap();
            let out = Hash::hash_with_keys(k0, k1, &vin[0..i]);
            assert_eq!(vec, out, "vec #{}", i);

            // The standalone one-shot must match the official vector too.
            assert_eq!(siphash(k0, k1, &vin[0..i]), u64::from_le_bytes(vecs[i]), "siphash #{}", i);

            let inc = Hash::from_engine(state_inc.clone());
            assert_eq!(vec, inc, "vec #{}", i);
            state_inc.input(&[i as u8]);
        }

        // Same 64 vectors, but each input (length `L`, bytes `0..L`) hashed in BULK:
        // a batch of identical inputs through `siphash_batch::<L>` must match the
        // official vector on every lane. `L` must be a constant, so we unroll 0..64.
        // A batch of 20 exercises the wide SIMD path (>8) plus the scalar leftovers.
        fn check_bulk<const L: usize>(k0: u64, k1: u64, expected: [u8; 8]) {
            let input: [u8; L] = core::array::from_fn(|b| b as u8);
            let batch = [input; 20];
            let mut out = [0u64; 20];
            siphash_batch::<L>(k0, k1, &batch, &mut out);
            let want = u64::from_le_bytes(expected);
            for (j, &got) in out.iter().enumerate() {
                assert_eq!(got, want, "bulk len={L} idx={j}");
            }
        }
        macro_rules! check_all_lens {
            ($($l:literal),* $(,)?) => {$( check_bulk::<$l>(k0, k1, vecs[$l]); )*};
        }
        check_all_lens!(
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
            46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
        );
    }

    // The compile-time-length batch must be bit-identical to the scalar one-shot.
    // `test_siphash_2_4` already checks every length at a single count, so the job here
    // is COUNT coverage — one case per batch size, sweeping zero/one/several wide (8-lane)
    // blocks and every leftover size 0..7, plus two large counts for many blocks. For each
    // count, every fixed LEN below (tail sizes 0..7) is hashed with pseudo-random content.
    #[test_case(0)]
    #[test_case(1)]
    #[test_case(2)]
    #[test_case(3)]
    #[test_case(4)]
    #[test_case(5)]
    #[test_case(6)]
    #[test_case(7)]
    #[test_case(8)]
    #[test_case(9)]
    #[test_case(15)]
    #[test_case(16)]
    #[test_case(17)]
    #[test_case(100)]
    #[test_case(257)]
    fn siphash_batch_matches_scalar(count: usize) {
        fn check<const LEN: usize>(count: usize) {
            let mut seed: u64 = 0x1234_5678_9abc_def0
                ^ (LEN as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15)
                ^ (count as u64).wrapping_mul(0xd6e8_feb8_6659_fd93);
            let mut next = || {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                seed
            };
            let k0 = 0x0706_0504_0302_0100u64;
            let k1 = 0x0f0e_0d0c_0b0a_0908u64;
            let inputs: Vec<[u8; LEN]> =
                (0..count).map(|_| core::array::from_fn(|_| next() as u8)).collect();
            let mut got = vec![0u64; count];
            siphash_batch::<LEN>(k0, k1, &inputs, &mut got);
            for (idx, inp) in inputs.iter().enumerate() {
                assert_eq!(got[idx], siphash(k0, k1, inp), "LEN={LEN} count={count} idx={idx}");
            }
        }

        check::<0>(count);
        check::<1>(count);
        check::<2>(count);
        check::<3>(count);
        check::<4>(count);
        check::<5>(count);
        check::<6>(count);
        check::<7>(count);
        check::<8>(count);
        check::<9>(count);
        check::<16>(count);
        check::<23>(count);
        check::<25>(count);
        check::<32>(count);
        check::<40>(count);
    }
}
