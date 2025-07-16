#!/usr/bin/env python3
"""
Fetch pre-calculated masternode lists for terminal blocks from dash-cli.

This script fetches masternode list states at terminal block heights and saves them
as JSON files that can be embedded in the Rust binary.
"""

import json
import subprocess
import sys
import os
from datetime import datetime
from pathlib import Path

# Terminal block heights for different networks
TERMINAL_BLOCKS = {
    "mainnet": {
        "genesis_hash": "00000ffd590b1485b3caadc19b22e6379c733355108f107a430458cdf3407ab6",
        "blocks": [
            1088640,  # DIP3 activation
            1100000, 1150000, 1200000, 1250000, 1300000,
            1350000, 1400000, 1450000, 1500000, 1550000,
            1600000, 1650000, 1700000, 1720000, 1750000,
            1800000, 1850000, 1900000, 1950000, 2000000,
        ]
    },
    "testnet": {
        "genesis_hash": "00000bafbc94add76cb75e2ec92894837288a481e5c005f6563d91623bf8bc2c",
        "blocks": [
            387480,  # DIP3 activation on testnet
            400000, 450000, 500000, 550000, 600000,
            650000, 700000, 750000, 760000, 800000,
            850000, 900000,
        ]
    }
}

def run_dash_cli(network, *args, parse_json=True):
    """Run dash-cli command and return result."""
    cmd = ["./dash-cli"]
    if network == "testnet":
        cmd.append("-testnet")
    cmd.extend(args)
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        if parse_json:
            return json.loads(result.stdout)
        else:
            return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error running dash-cli: {e}")
        print(f"stderr: {e.stderr}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON: {e}")
        print(f"stdout: {result.stdout}")
        return None

def fetch_terminal_block_data(network, height, genesis_hash):
    """Fetch masternode list data for a specific terminal block."""
    print(f"Fetching {network} terminal block {height}...")
    
    # Get the block hash
    block_hash = run_dash_cli(network, "getblockhash", str(height), parse_json=False)
    if not block_hash:
        print(f"Failed to get block hash for height {height}")
        return None
    
    # Get masternode diff from genesis to this height
    diff_result = run_dash_cli(network, "protx", "diff", genesis_hash, str(height))
    if not diff_result:
        print(f"Failed to get masternode diff for height {height}")
        return None
    
    # Extract relevant data
    masternode_list = []
    for mn in diff_result.get("mnList", []):
        try:
            # Check for required fields and skip entry if any are missing
            required_fields = ["proRegTxHash", "service", "pubKeyOperator", "votingAddress", "isValid"]
            missing_fields = [field for field in required_fields if field not in mn]
            
            if missing_fields:
                print(f"Warning: Masternode entry missing required fields: {missing_fields}. Skipping entry.")
                continue
            
            masternode_list.append({
                "pro_tx_hash": mn["proRegTxHash"],
                "service": mn["service"],
                "pub_key_operator": mn["pubKeyOperator"],
                "voting_address": mn["votingAddress"],
                "is_valid": mn["isValid"],
                "n_type": mn.get("nType", 0),  # Default to 0 if not present
            })
        except Exception as e:
            print(f"Error processing masternode entry: {e}. Skipping entry.")
            continue
    
    return {
        "height": height,
        "block_hash": block_hash,
        "merkle_root_mn_list": diff_result["merkleRootMNList"],
        "masternode_list": masternode_list,
        "masternode_count": len(masternode_list),
        "fetched_at": int(datetime.now().timestamp()),
    }

def main():
    if len(sys.argv) < 3:
        print("Usage: fetch_terminal_blocks.py <dash-cli-path> <network>")
        print("  network: mainnet or testnet")
        sys.exit(1)
    
    dash_cli_path = sys.argv[1]
    network = sys.argv[2].lower()
    
    if network not in ["mainnet", "testnet"]:
        print("Network must be 'mainnet' or 'testnet'")
        sys.exit(1)
    
    # Change to dash-cli directory
    os.chdir(dash_cli_path)
    
    # Create output directory
    output_dir = Path(__file__).parent.parent / "data" / network
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Get network configuration
    config = TERMINAL_BLOCKS[network]
    genesis_hash = config["genesis_hash"]
    
    # Fetch data for each terminal block
    successful = 0
    failed = 0
    
    for height in config["blocks"]:
        data = fetch_terminal_block_data(network, height, genesis_hash)
        if data:
            # Save to JSON file
            output_file = output_dir / f"terminal_block_{height}.json"
            with open(output_file, "w") as f:
                json.dump(data, f, indent=2)
            print(f"✓ Saved {output_file}")
            successful += 1
        else:
            print(f"✗ Failed to fetch data for height {height}")
            failed += 1
    
    print(f"\nSummary: {successful} successful, {failed} failed")
    
    # Generate Rust code to include the data
    if successful > 0:
        rust_file = output_dir / "mod.rs"
        with open(rust_file, "w") as f:
            f.write("// Auto-generated by fetch_terminal_blocks.py\n\n")
            f.write("use super::*;\n\n")
            f.write(f"pub fn load_{network}_terminal_blocks(manager: &mut TerminalBlockDataManager) {{\n")
            
            for height in config["blocks"]:
                json_file = output_dir / f"terminal_block_{height}.json"
                if json_file.exists():
                    f.write(f'    // Terminal block {height}\n')
                    f.write('    {\n')
                    f.write(f'        let data = include_str!("terminal_block_{height}.json");\n')
                    f.write('        if let Ok(state) = serde_json::from_str::<TerminalBlockMasternodeState>(data) {\n')
                    f.write('            manager.add_state(state);\n')
                    f.write('        }\n')
                    f.write('    }\n\n')
            
            f.write("}\n")
        
        print(f"\n✓ Generated {rust_file}")

if __name__ == "__main__":
    main()