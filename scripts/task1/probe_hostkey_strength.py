#!/usr/bin/env python3
"""Test 3: Host Key Strength Analysis
Extract and analyze the SSH host key length/type from the three targets.
If the RSA key is 1024-bit or DSA key is present, it may be factorable."""

import json
import os
import subprocess

TARGETS = ["120.133.131.108", "120.133.131.109", "120.133.131.110"]

def analyze_host_keys() -> dict:
    results = {"targets": {}, "shared_key": None, "key_strength": {}}

    fingerprints = {}
    for target in TARGETS:
        print(f"  Scanning {target}...")
        # Use ssh-keyscan to get host keys
        try:
            output = subprocess.run(
                ["ssh-keyscan", "-T", "5", "-t", "rsa,dsa,ecdsa,ed25519", target],
                capture_output=True, text=True, timeout=15
            )
            keys_raw = output.stdout.strip()
            results["targets"][target] = keys_raw

            # Parse key type and length
            for line in keys_raw.split("\n"):
                if not line.strip():
                    continue
                parts = line.strip().split()
                if len(parts) >= 3:
                    key_type = parts[1]  # e.g. ssh-rsa, ssh-dss
                    key_data = parts[2]

                    # Get key length using ssh-keygen
                    try:
                        tmp_path = os.path.join(os.environ.get("TMPDIR", "/tmp"),
                                                 f"task1_hostkey_{target}_{key_type}")
                        with open(tmp_path, "w") as f:
                            f.write(f"{target} {key_type} {key_data}\n")

                        len_output = subprocess.run(
                            ["ssh-keygen", "-l", "-f", tmp_path],
                            capture_output=True, text=True, timeout=5
                        )
                        fingerprint = len_output.stdout.strip()
                        results["key_strength"][f"{target}/{key_type}"] = fingerprint

                        # Track fingerprints to detect shared keys
                        if fingerprint not in fingerprints:
                            fingerprints[fingerprint] = []
                        fingerprints[fingerprint].append(f"{target}/{key_type}")

                        # Check key length
                        fp_parts = fingerprint.split()
                        if len(fp_parts) >= 1:
                            size_str = fp_parts[0]
                            try:
                                size = int(size_str)
                                if key_type == "ssh-rsa" and size <= 1024:
                                    results["key_strength"][f"{target}/{key_type}_risk"] = f"RSA {size}-bit: FACTORABLE with sufficient resources"
                                elif key_type == "ssh-dss":
                                    results["key_strength"][f"{target}/{key_type}_risk"] = f"DSA: inherently limited to 1024-bit, FACTORABLE"
                                elif key_type == "ssh-rsa" and size <= 2048:
                                    results["key_strength"][f"{target}/{key_type}_risk"] = f"RSA {size}-bit: weak, not recommended"
                            except ValueError:
                                pass

                        os.unlink(tmp_path)
                    except Exception as e:
                        results["key_strength"][f"{target}/{key_type}_error"] = str(e)[:100]

        except subprocess.TimeoutExpired:
            results["targets"][target] = "TIMEOUT"
        except Exception as e:
            results["targets"][target] = f"ERROR: {str(e)[:100]}"

    # Check if keys are shared across targets
    for fp, targets_list in fingerprints.items():
        if len(targets_list) > 1:
            results["shared_key"] = f"Fingerprint {fp} shared across: {targets_list}"
            print(f"  SHARED KEY: {fp} used by {targets_list}")

    return results


def main():
    print("=== Test 3: Host Key Strength Analysis ===")
    print()

    result = analyze_host_keys()

    print("\n=== Key Strength Results ===")
    for key, val in sorted(result["key_strength"].items()):
        print(f"  {key}: {val[:80]}")

    print(f"\nShared key: {result.get('shared_key', 'none')}")

    # Save results
    out = os.path.abspath(os.path.join(os.path.dirname(__file__),
        "..", "..", "task1", "TOOLS", "json", "task1_hostkey_analysis.json"))
    with open(out, "w") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"Saved to {out}")

    # Verdict
    risks = [k for k in result["key_strength"] if "risk" in k]
    if risks:
        print("\n!!! WEAK HOST KEY DETECTED !!!")
        for r in risks:
            print(f"  {result['key_strength'][r]}")
    else:
        print("\nHost keys appear strong (>= 2048 bit RSA or Ed25519).")


if __name__ == "__main__":
    main()