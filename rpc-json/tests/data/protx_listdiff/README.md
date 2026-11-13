# `protx listdiff` recordings

Output of Dash Core's `protx listdiff` on a throwaway regtest node, recorded with
`record_listdiff.py` from the official macOS arm64 release binaries:

| Directory | Release archive | SHA-256 (matches the release's `SHA256SUMS.asc`) |
|---|---|---|
| `v23.1.8` | `dashcore-23.1.8-arm64-apple-darwin.tar.gz` | `a3db11790722d3ca08a5205aa985cb7a8a12f649e6bed7c46d6de480b25c14b5` |
| `v24.0.0-rc.3` | `dashcore-24.0.0-rc.3-arm64-apple-darwin.tar.gz` | `b1a63de5dd98fb1ef32e091cb02d8891c005aafb452b0a717746f1ed28ddf7ef` |

`dashd` ran with `-regtest -listen=0 -fallbackfee=0.0001 -dip3params=2:2
-testactivationheight=v20@100 -testactivationheight=mn_rr@100 -deprecatedrpc=service`.
DEPLOYMENT_V24 is not active on this regtest, so the v24.0.0-rc.3 recording has version 2
masternodes printed by Core v24's RPC.

Three regular masternodes are registered in block 302 with an operator reward. Each later block
holds one step (`recording.json` names the masternodes, the payout addresses and the steps):

| Block | Step |
|---|---|
| 303 | MN1 and MN2 set a P2PKH operator payout (ProUpServTx) |
| 304 | MN1 changes its operator payout to a P2SH address |
| 305 | MN1's owner changes the operator key (ProUpRegTx: PoSe ban, operator fields reset) |
| 306 | MN1's new operator sets a P2PKH operator payout (ProUpServTx: revive) |
| 307-309 | payments; MN1 is paid in 309 |
| 310 | MN2's operator revokes (ProUpRevTx: operator fields reset) |

The diffs show the operator payout reset on an operator key change (305) and on a revocation
(310). A ProUpServTx without an operator payout also empties it, but Core's
`protx update_service` reuses the current payout when given none, so that case is not recorded.
No recorded diff adds or removes a masternode (a revocation is an update).

Files:

- `listdiff_1_<h>.json`: the full list at height `h` (every masternode in `addedMNs`).
- `listdiff_<h-1>_<h>.json`: the diff of block `h`.
- `listdiff_302_310.json`: the whole recording as one diff.

To record again: `python3 record_listdiff.py <bin dir> <empty datadir> <output dir> <rpc port>`.
