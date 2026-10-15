"""Record `protx listdiff` fixtures from a throwaway regtest dashd.

Usage: python3 record_listdiff.py <bin dir> <empty datadir> <output dir> <rpc port>

Steps, one block each (h0 = registration block):
  h1 MN1 and MN2 set a P2PKH operator payout (ProUpServTx)
  h2 MN1 changes its operator payout to a P2SH address
  h3 MN1 owner changes the operator key (ProUpRegTx: PoSe ban + operator fields reset)
  h4 MN1 new operator sends a ProUpServTx with a new P2PKH payout (revive)
  h5.. one block at a time until MN1 is paid after its revive (payment-only entry)
  h_last MN2 operator revokes (ProUpRevTx: reset)
For every height k it saves `protx listdiff h(k-1) hk` and the full list `protx listdiff 1 hk`.
"""

import json
import os
import subprocess
import sys
import time

BIN, DATADIR, OUT, RPC_PORT = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
P2P_PORT = str(int(RPC_PORT) + 1)


def cli(*args, wallet=True):
    cmd = [os.path.join(BIN, "dash-cli"), "-regtest", f"-datadir={DATADIR}", f"-rpcport={RPC_PORT}"]
    if wallet:
        cmd.append("-rpcwallet=w")
    cmd += [str(a) for a in args]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"{' '.join(map(str, args))!r} failed: {res.stderr.strip()}")
    out = res.stdout.strip()
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return out


def mine(n=1):
    return cli("generatetoaddress", n, MINER)


def height():
    return cli("getblockcount", wallet=False)


def save(name, obj):
    with open(os.path.join(OUT, name), "w") as f:
        json.dump(obj, f, indent=2)
        f.write("\n")


os.makedirs(DATADIR, exist_ok=True)
if os.listdir(DATADIR):
    raise SystemExit(f"{DATADIR} is not empty")
os.makedirs(OUT, exist_ok=True)
subprocess.run(
    [
        os.path.join(BIN, "dashd"), "-regtest", "-daemon", f"-datadir={DATADIR}", "-listen=0",
        "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1", f"-rpcport={RPC_PORT}", f"-port={P2P_PORT}",
        "-fallbackfee=0.0001", "-dip3params=2:2", "-testactivationheight=v20@100",
        "-testactivationheight=mn_rr@100", "-deprecatedrpc=service",
    ],
    check=True,
)
try:
    for _ in range(60):
        try:
            cli("getblockcount", wallet=False)
            break
        except RuntimeError:
            time.sleep(1)
    else:
        raise RuntimeError("dashd did not answer RPC within 60 seconds")

    meta = {"subversion": cli("getnetworkinfo", wallet=False)["subversion"]}
    cli("createwallet", "w", wallet=False)
    MINER = cli("getnewaddress")
    mine(300)
    fee = cli("getnewaddress")
    cli("sendtoaddress", fee, 100)
    mine(1)

    mns = []
    for i in range(3):
        bls = cli("bls", "generate", wallet=False)
        owner, voting, payout, collateral = (cli("getnewaddress") for _ in range(4))
        pro_tx = cli(
            "protx", "register_fund", collateral, json.dumps([f"127.0.0.1:{30000 + i}"]), owner,
            bls["public"], voting, "10", payout, MINER,
        )
        mns.append({"pro_tx_hash": pro_tx, "bls": bls, "port": 30000 + i})
    mine(1)

    heights = [height()]
    save(f"listdiff_1_{heights[0]}.json", cli("protx", "listdiff", 1, heights[0], wallet=False))
    steps = []

    def step(label):
        prev, cur = heights[-1], height()
        heights.append(cur)
        save(f"listdiff_{prev}_{cur}.json", cli("protx", "listdiff", prev, cur, wallet=False))
        save(f"listdiff_1_{cur}.json", cli("protx", "listdiff", 1, cur, wallet=False))
        steps.append({"from": prev, "to": cur, "step": label})

    def update_service(mn, secret, payout):
        return cli(
            "protx", "update_service", mn["pro_tx_hash"], json.dumps([f"127.0.0.1:{mn['port']}"]),
            secret, payout, fee,
        )

    addresses = {}

    def new_address(label):
        address = cli("getnewaddress")
        addresses[label] = {"address": address, "scriptPubKey": cli("getaddressinfo", address)["scriptPubKey"]}
        return address

    update_service(mns[0], mns[0]["bls"]["secret"], new_address("mn1_operator_payout_p2pkh"))
    update_service(mns[1], mns[1]["bls"]["secret"], new_address("mn2_operator_payout_p2pkh"))
    mine(1)
    step("MN1 and MN2 set a P2PKH operator payout")

    multisig_key = cli("getaddressinfo", cli("getnewaddress"))["pubkey"]
    multisig = cli("createmultisig", 1, json.dumps([multisig_key]), wallet=False)
    addresses["mn1_operator_payout_p2sh"] = {"address": multisig["address"], "redeemScript": multisig["redeemScript"]}
    update_service(mns[0], mns[0]["bls"]["secret"], multisig["address"])
    mine(1)
    step("MN1 changes its operator payout to a P2SH address")

    new_bls = cli("bls", "generate", wallet=False)
    cli("protx", "update_registrar", mns[0]["pro_tx_hash"], new_bls["public"], "", "", fee)
    mine(1)
    step("MN1 owner changes the operator key (PoSe ban, operator fields reset)")

    update_service(mns[0], new_bls["secret"], new_address("mn1_new_operator_payout_p2pkh"))
    mine(1)
    revive_height = height()
    step("MN1 new operator sets a P2PKH operator payout (revive)")

    for _ in range(20):
        mine(1)
        state = cli("protx", "info", mns[0]["pro_tx_hash"], wallet=False)["state"]
        paid = state["lastPaidHeight"] > revive_height
        step("payment" + (" (MN1 paid)" if paid else ""))
        if paid:
            break
    else:
        raise RuntimeError("MN1 was not paid within 20 blocks of its revive")

    cli("protx", "revoke", mns[1]["pro_tx_hash"], mns[1]["bls"]["secret"], 0, fee)
    mine(1)
    step("MN2 operator revokes (operator fields reset)")

    save(f"listdiff_{heights[0]}_{heights[-1]}.json", cli("protx", "listdiff", heights[0], heights[-1], wallet=False))
    meta.update(
        {
            "masternodes": {f"MN{i + 1}": mn["pro_tx_hash"] for i, mn in enumerate(mns)},
            "addresses": addresses,
            "steps": steps,
        }
    )
    save("recording.json", meta)
    print(json.dumps(meta, indent=2))
finally:
    try:
        cli("stop", wallet=False)
    except RuntimeError as error:
        print(f"could not stop dashd: {error}", file=sys.stderr)
