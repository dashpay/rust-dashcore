# Legacy BLS binary Serde fixture

`bls-public-key.bin` was generated using rust-dashcore revision
`40268cc0402a8933ec539f16b2d634c4e25876ad`, before the BLS migration in #1036.
It encodes the synthetic public-key bytes `0x00` through `0x2f` as a
length-prefixed, 96-character hex string. It is a serialization fixture,
not a validated cryptographic point.

To reproduce, use a standalone Cargo package with `dashcore` pointing at that
exact revision with its `serde` feature enabled, and
`bincode = { package = "grovedb-bincode", version = "=2.1.0", features = ["serde"] }`:

```rust
let key = dashcore::bls_sig_utils::BLSPublicKey::from(
    std::array::from_fn::<_, 48, _>(|i| i as u8),
);
let bytes = bincode::serde::encode_to_vec(key, bincode::config::standard()).unwrap();
std::fs::write("bls-public-key.bin", bytes).unwrap();
```

Do not regenerate this fixture with current types.
