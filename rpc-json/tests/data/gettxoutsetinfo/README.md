# `gettxoutsetinfo` recordings

The `result` of Dash Core's `gettxoutsetinfo` from two regtest nodes on the same chain:

| Directory | Binary | `dashd --version` | dashd SHA-256 |
|---|---|---|---|
| `v24.0.0` | `dashd` from the release archive `dashcore-24.0.0-x86_64-linux-gnu.tar.gz` (SHA-256 `1ffce395e035fb2ee617c92e6eeaab139ca3d10db6f83d4e816136b726512c5e`), fetched by `DASHVERSION=24.0.0 contrib/setup-dashd.py`; the archive SHA-256 matches the release asset | `v24.0.0` | `2ad05ccb0951bc127d1048bf0bfea0956a968482644ed130f8f59fbfcd732223` |
| `pr8067` | `dashd` built from dashpay/dash#8067 (the bitcoin#28685 backport) at `79238ac6a34569c482d3e3f39965c8021c5177a1`, with `./configure --without-gui --disable-wallet --disable-tests --disable-bench --disable-fuzz-binary` and g++ 15.2.0 | `v23.1.8-3147-g79238ac6a345` | `354218ea48e339871c3706043f9aa98c46a2db72707ae7e9603238d020491a2d` |

Both ran with `-regtest -disablewallet -listen=0 -coinstatsindex=1`. The v24.0.0 node mined 110
blocks to `yMsgnH1xKGa85n4bq2imrZbG2KgrmGttAV`, one `generatetoaddress` call per block, block *i*
mined at mock time 1700000000 + 60·*i*. The other node took the same blocks
through `submitblock`. Both ended at height 110 on block
`54c8c1a58a737156abd144e0c5ab012bf2548a9ad6ff0f1648fb8fcad499ede4`.

| File | Call |
|---|---|
| `default.json` | `gettxoutsetinfo`: the node's default hash type, `hash_serialized_2` on v24.0.0 and `hash_serialized_3` on the other |
| `muhash.json` | `gettxoutsetinfo muhash`, answered from the coinstatsindex (`gettxoutsetinfo muhash null true` returns the same) |
| `none.json` | `gettxoutsetinfo none`, answered from the coinstatsindex |

Each node refuses the other's serialized hash type: v24.0.0 answers `gettxoutsetinfo
hash_serialized_3` and the other node answers `gettxoutsetinfo hash_serialized_2` with error
-8, `'<hash type>' is not a valid hash_type`.
