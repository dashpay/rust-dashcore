#!/usr/bin/env python3
"""
Generate FFI API documentation for dash-spv-ffi
"""

import os
import re
import sys
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional, Dict
import subprocess

@dataclass
class FFIFunction:
    name: str
    signature: str
    module: str
    doc_comment: Optional[str] = None
    safety_comment: Optional[str] = None
    params: List[str] = None
    return_type: str = None

def extract_ffi_functions(file_path: Path) -> List[FFIFunction]:
    """Extract all #[no_mangle] extern "C" functions from a Rust file.

    Uses a lightweight parser to correctly capture parameters with nested parentheses
    (e.g., function pointer types) and the return type.
    """
    functions: List[FFIFunction] = []

    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Iterate over all #[no_mangle] attribute occurrences
    for m in re.finditer(r'(?m)^\s*#\[no_mangle\]\s*$', content):
        idx = m.end()
        # Find the next extern "C" fn declaration
        fn_match = re.search(r'\bextern\s+"C"\s+fn\s+([A-Za-z0-9_]+)\s*\(', content[idx:], re.S)
        if not fn_match:
            continue
        name = fn_match.group(1)
        abs_start = idx + fn_match.start()
        paren_start = content.find('(', abs_start)
        if paren_start == -1:
            continue

        # Scan for the matching closing parenthesis with nesting
        depth = 0
        i = paren_start
        while i < len(content):
            ch = content[i]
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
                if depth == 0:
                    break
            i += 1
        if depth != 0:
            continue  # Unbalanced; skip
        paren_end = i

        params_raw = content[paren_start + 1:paren_end]

        # Find return type between paren_end and the opening brace '{'
        brace_idx = content.find('{', paren_end)
        header_tail = content[paren_end:brace_idx if brace_idx != -1 else len(content)]
        ret_match = re.search(r'->\s*([^\n{]+)', header_tail)
        return_type = ret_match.group(1).strip() if ret_match else '()'

        # Collect contiguous doc comments above #[no_mangle]
        # Walk backwards line-by-line accumulating lines starting with '///'
        doc_lines_rev: List[str] = []
        # Position of start of the #[no_mangle] line
        line_start = content.rfind('\n', 0, m.start()) + 1
        j = line_start - 1
        while j > 0:
            prev_nl = content.rfind('\n', 0, j)
            line = content[prev_nl + 1:j]
            if line.strip().startswith('///'):
                # Strip leading /// and whitespace
                doc_lines_rev.append(line.strip()[3:].strip())
                j = prev_nl
                continue
            # Allow a single blank line between doc comment blocks
            if line.strip() == '' and doc_lines_rev:
                j = prev_nl
                continue
            break
        doc_lines = list(reversed(doc_lines_rev)) if doc_lines_rev else []

        # Extract safety sub-section from doc lines
        safety_comment = None
        if doc_lines:
            joined = '\n'.join(doc_lines)
            if '# Safety' in joined:
                safety_lines: List[str] = []
                in_safety = False
                for dl in doc_lines:
                    if dl.strip().startswith('# Safety'):
                        in_safety = True
                        continue
                    if in_safety and dl.strip().startswith('#'):
                        break
                    if in_safety:
                        safety_lines.append(dl)
                safety_comment = ' '.join(safety_lines).strip() if safety_lines else None

        params_clean = re.sub(r'\s+', ' ', params_raw.strip())
        module_name = file_path.stem

        functions.append(FFIFunction(
            name=name,
            signature=f"{name}({params_clean}) -> {return_type}",
            module=module_name,
            doc_comment=' '.join(doc_lines) if doc_lines else None,
            safety_comment=safety_comment,
            params=params_clean,
            return_type=return_type,
        ))

    return functions

def categorize_functions(functions: List[FFIFunction]) -> Dict[str, List[FFIFunction]]:
    """Categorize functions by their module/purpose."""
    categories = {
        'Client Management': [],
        'Configuration': [],
        'Synchronization': [],
        'Wallet Operations': [],
        'Address Monitoring': [],
        'Transaction Management': [],
        'Balance & UTXOs': [],
        'Mempool Operations': [],
        'Platform Integration': [],
        'Event Callbacks': [],
        'Error Handling': [],
        'Utility Functions': [],
    }

    for func in functions:
        name = func.name.lower()

        if 'client_new' in name or 'client_start' in name or 'client_stop' in name or 'client_destroy' in name:
            categories['Client Management'].append(func)
        elif 'config' in name:
            categories['Configuration'].append(func)
        elif 'sync' in name:
            categories['Synchronization'].append(func)
        elif 'wallet' in name and 'manager' not in name:
            categories['Wallet Operations'].append(func)
        elif 'watch' in name or 'unwatch' in name or 'address' in name and 'balance' not in name:
            categories['Address Monitoring'].append(func)
        elif 'transaction' in name or 'broadcast' in name or 'tx' in name:
            categories['Transaction Management'].append(func)
        elif 'balance' in name or 'utxo' in name:
            categories['Balance & UTXOs'].append(func)
        elif 'mempool' in name:
            categories['Mempool Operations'].append(func)
        elif 'platform' in name or 'quorum' in name or 'core_handle' in name:
            categories['Platform Integration'].append(func)
        elif 'callback' in name or 'event' in name:
            categories['Event Callbacks'].append(func)
        elif 'error' in name or 'last_error' in name:
            categories['Error Handling'].append(func)
        else:
            categories['Utility Functions'].append(func)

    # Remove empty categories
    return {k: v for k, v in categories.items() if v}

def generate_markdown(functions: List[FFIFunction]) -> str:
    """Generate markdown documentation from FFI functions."""

    categories = categorize_functions(functions)

    md = []
    md.append("# Dash SPV FFI API Documentation")
    md.append("")
    md.append("This document provides a comprehensive reference for all FFI (Foreign Function Interface) functions available in the dash-spv-ffi library.")
    md.append("")
    md.append("**Auto-generated**: This documentation is automatically generated from the source code. Do not edit manually.")
    md.append("")
    md.append(f"**Total Functions**: {len(functions)}")
    md.append("")

    # Table of Contents
    md.append("## Table of Contents")
    md.append("")
    for category in categories.keys():
        anchor = category.lower().replace(' ', '-').replace('&', 'and')
        md.append(f"- [{category}](#{anchor})")
    md.append("")

    # Function Reference
    md.append("## Function Reference")
    md.append("")

    for category, funcs in categories.items():
        if not funcs:
            continue

        anchor = category.lower().replace(' ', '-').replace('&', 'and')
        md.append(f"### {category}")
        md.append("")
        md.append(f"Functions: {len(funcs)}")
        md.append("")

        # Create a table for each category
        md.append("| Function | Description | Module |")
        md.append("|----------|-------------|--------|")

        for func in sorted(funcs, key=lambda f: f.name):
            desc = func.doc_comment.split('.')[0] if func.doc_comment else "No description"
            desc = desc.replace('|', '\\|')  # Escape pipes in description
            if len(desc) > 80:
                # Truncate at last complete word before 77 chars to avoid mid-word breaks
                truncate_pos = desc.rfind(' ', 0, 77)
                if truncate_pos > 60:  # Only if we find a space reasonably close
                    desc = desc[:truncate_pos] + "..."
                else:
                    desc = desc[:77] + "..."
            md.append(f"| `{func.name}` | {desc} | {func.module} |")

        md.append("")

    # Detailed Function Documentation
    md.append("## Detailed Function Documentation")
    md.append("")

    for category, funcs in categories.items():
        if not funcs:
            continue

        md.append(f"### {category} - Detailed")
        md.append("")

        for func in sorted(funcs, key=lambda f: f.name):
            md.append(f"#### `{func.name}`")
            md.append("")
            md.append("```c")
            md.append(func.signature)
            md.append("```")
            md.append("")

            if func.doc_comment:
                md.append("**Description:**")
                md.append(func.doc_comment)
                md.append("")

            if func.safety_comment:
                md.append("**Safety:**")
                md.append(func.safety_comment)
                md.append("")

            md.append(f"**Module:** `{func.module}`")
            md.append("")
            md.append("---")
            md.append("")

    # Type Definitions
    md.append("## Type Definitions")
    md.append("")
    md.append("### Core Types")
    md.append("")
    md.append("- `FFIDashSpvClient` - SPV client handle")
    md.append("- `FFIClientConfig` - Client configuration")
    md.append("- `FFISyncProgress` - Synchronization progress")
    md.append("- `FFIDetailedSyncProgress` - Detailed sync progress")
    md.append("- `FFITransaction` - Transaction information")
    md.append("- `FFIUnconfirmedTransaction` - Unconfirmed transaction")
    md.append("- `FFIEventCallbacks` - Event callback structure")
    md.append("- `CoreSDKHandle` - Platform SDK integration handle")
    md.append("")

    md.append("### Enumerations")
    md.append("")
    md.append("- `FFINetwork` - Network type (Dash, Testnet, Regtest, Devnet)")
    md.append("- `FFIValidationMode` - Validation mode (None, Basic, Full)")
    md.append("- `FFIMempoolStrategy` - Mempool strategy (FetchAll, BloomFilter, Selective)")
    md.append("- `FFISyncStage` - Synchronization stage")
    md.append("")

    # Memory Management
    md.append("## Memory Management")
    md.append("")
    md.append("### Important Rules")
    md.append("")
    md.append("1. **Ownership Transfer**: Functions returning pointers transfer ownership to the caller")
    md.append("2. **Cleanup Required**: All returned pointers must be freed using the appropriate `_destroy` function")
    md.append("3. **Thread Safety**: The SPV client is thread-safe")
    md.append("4. **Error Handling**: Check return codes and use `dash_spv_ffi_get_last_error()` for details")
    md.append(
        "5. **Shared Ownership**: `dash_spv_ffi_client_get_wallet_manager()` returns `FFIWalletManager*` "
        "that must be released with `dash_spv_ffi_wallet_manager_free()`"
    )
    md.append("")

    # Usage Examples
    md.append("## Usage Examples")
    md.append("")
    md.append("### Basic SPV Client Usage")
    md.append("")
    md.append("```c")
    md.append("// Create configuration")
    md.append("FFIClientConfig* config = dash_spv_ffi_config_testnet();")
    md.append("")
    md.append("// Create client")
    md.append("FFIDashSpvClient* client = dash_spv_ffi_client_new(config);")
    md.append("")
    md.append("// Start the client")
    md.append("int32_t result = dash_spv_ffi_client_start(client);")
    md.append("if (result != 0) {")
    md.append("    const char* error = dash_spv_ffi_get_last_error();")
    md.append("    // Handle error")
    md.append("}")
    md.append("")
    md.append("// Get wallet manager (shares ownership with the client)")
    md.append("FFIWalletManager* wallet_manager = dash_spv_ffi_client_get_wallet_manager(client);")
    md.append("")
    md.append("// Clean up")
    md.append("dash_spv_ffi_client_destroy(client);")
    md.append("dash_spv_ffi_config_destroy(config);")
    md.append("```")
    md.append("")

    md.append("### Event Callbacks")
    md.append("")
    md.append("```c")
    md.append("void on_block(uint32_t height, const uint8_t (*hash)[32], void* user_data) {")
    md.append("    printf(\"New block at height %u\\n\", height);")
    md.append("}")
    md.append("")
    md.append("void on_transaction(const uint8_t (*txid)[32], bool confirmed, ")
    md.append("                    int64_t amount, const char* addresses, ")
    md.append("                    uint32_t block_height, void* user_data) {")
    md.append("    printf(\"Transaction: %lld duffs\\n\", amount);")
    md.append("}")
    md.append("")
    md.append("// Set up callbacks")
    md.append("FFIEventCallbacks callbacks = {")
    md.append("    .on_block = on_block,")
    md.append("    .on_transaction = on_transaction,")
    md.append("    .user_data = NULL")
    md.append("};")
    md.append("")
    md.append("dash_spv_ffi_client_set_event_callbacks(client, callbacks);")
    md.append("```")
    md.append("")

    return '\n'.join(md)

def main():
    # Find all Rust source files
    src_dir = Path(__file__).parent.parent / "src"

    all_functions = []

    for rust_file in src_dir.rglob("*.rs"):
        functions = extract_ffi_functions(rust_file)
        all_functions.extend(functions)

    # Generate markdown
    markdown = generate_markdown(all_functions)

    # Write to file
    output_file = Path(__file__).parent.parent / "FFI_API.md"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(markdown)

    print(f"Generated FFI documentation with {len(all_functions)} functions")
    print(f"Output: {output_file}")

    return 0

if __name__ == "__main__":
    sys.exit(main())
