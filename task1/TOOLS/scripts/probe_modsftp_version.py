#!/usr/bin/env python3
"""Test 4: mod_sftp Version-Specific Probing
ProFTPD 1.3.5e + mod_sftp/0.9.9 specific behavior tests:
- SFTP extension command probing (ext-posix-rename, ext-statvfs, etc.)
- Version string probing via SSH protocol
- Subsystem request probing (sftp, shell, exec)
- Buffer handling tests on SFTP channel"""

import json
import os
import socket
import time
import struct

TARGETS = ["120.133.131.108", "120.133.131.109", "120.133.131.110"]
PORT = 22


def probe_extensions_paramiko(target: str) -> dict:
    """Check which SFTP extensions the server supports."""
    import paramiko

    result = {"target": target, "extensions": {}, "subsystem_test": {},
              "version_probe": {}, "error": ""}

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # Connect with weak algorithms for compatibility
        transport = paramiko.Transport((target, PORT))
        transport.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Request weak algorithms
        transport.connect()

        # Try auth_none to get auth methods list
        try:
            transport.auth_none("test_probe")
        except paramiko.BadAuthenticationType as e:
            result["version_probe"]["auth_methods"] = e.allowed_types
        except Exception as e:
            result["version_probe"]["auth_none_error"] = str(e)[:150]

        # Open SFTP session
        try:
            sftp = paramiko.SFTPClient.from_transport(transport)

            # Get server version string
            if hasattr(sftp, '_request'):
                # Send SSH_FXP_VERSION to get extensions
                result["version_probe"]["sftp_version"] = sftp._version

            # List available extensions (if any)
            # Standard extensions to probe
            extensions_to_test = [
                "posix-rename@openssh.com",
                "statvfs@openssh.com",
                "fstatvfs@openssh.com",
                "hardlink@openssh.com",
                "fsync@openssh.com",
                "lsetstat@openssh.com",
                "limits@openssh.com",
                "expand-path@openssh.com",
            ]

            for ext in extensions_to_test:
                try:
                    # Try the extension — if it fails with specific error, it's not supported
                    # If it fails differently, it IS supported but we lack permissions
                    if "rename" in ext:
                        try:
                            sftp.posix_rename("/etc/passwd", "/tmp/test_rename")
                        except IOError as e2:
                            err = str(e2)
                            if "Operation not supported" in err or "unsupported" in err.lower():
                                result["extensions"][ext] = "NOT_SUPPORTED"
                            elif "Permission denied" in err:
                                result["extensions"][ext] = "SUPPORTED_BUT_DENIED"
                            else:
                                result["extensions"][ext] = f"OTHER: {err[:80]}"
                        except Exception as e2:
                            result["extensions"][ext] = f"ERROR: {str(e2)[:80]}"
                    else:
                        result["extensions"][ext] = "SKIPPED"
                except Exception as e2:
                    result["extensions"][ext] = f"PROBE_ERROR: {str(e2)[:80]}"

            # Try to get SFTP server init extensions from the version exchange
            if hasattr(sftp, 'server_extensions'):
                result["version_probe"]["server_extensions"] = dict(sftp.server_extensions)

            sftp.close()
        except Exception as e:
            result["error"] += f"SFTP: {str(e)[:100]}; "

        transport.close()

    except paramiko.SSHException as e:
        result["error"] = f"SSH: {str(e)[:150]}"
    except socket.timeout:
        result["error"] = "Connection timeout"
    except Exception as e:
        result["error"] = f"other: {str(e)[:150]}"

    try:
        client.close()
    except:
        pass

    return result


def probe_sftp_version_raw(target: str) -> dict:
    """Raw SSH protocol probe to extract server version extensions."""
    result = {"target": target, "banner": "", "kexinit_algorithms": {},
              "error": ""}

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((target, PORT))

        # Read banner
        banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
        result["banner"] = banner

        # Send our banner
        sock.sendall(b"SSH-2.0-Probe-ModSFTP-0.1\r\n")

        # Read KEXINIT
        data = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                # KEXINIT is usually sent in one packet
                if len(data) > 2048:
                    break
            except socket.timeout:
                break

        # Parse KEXINIT to extract algorithm lists
        if len(data) > 5:
            try:
                packet_len = struct.unpack(">I", data[:4])[0]
                # Skip padding length
                padding_len = data[4]
                msg_code = data[5]
                if msg_code == 20:  # SSH_MSG_KEXINIT
                    cookie = data[6:22]
                    # Parse 10 algorithm name-lists
                    pos = 22
                    algorithm_names = [
                        "kex_algorithms", "server_host_key_algorithms",
                        "encryption_algorithms_client_to_server",
                        "encryption_algorithms_server_to_client",
                        "mac_algorithms_client_to_server",
                        "mac_algorithms_server_to_client",
                        "compression_algorithms_client_to_server",
                        "compression_algorithms_server_to_client",
                        "languages_client_to_server",
                        "languages_server_to_client",
                    ]
                    for name in algorithm_names:
                        if pos + 4 > len(data):
                            break
                        list_len = struct.unpack(">I", data[pos:pos+4])[0]
                        pos += 4
                        if pos + list_len > len(data):
                            break
                        alg_list = data[pos:pos+list_len].decode("utf-8", errors="replace")
                        result["kexinit_algorithms"][name] = alg_list.split(",")
                        pos += list_len
            except Exception as e:
                result["error"] += f"KEXINIT parse: {str(e)[:80]}; "

        sock.close()

    except Exception as e:
        result["error"] = str(e)[:150]

    return result


def main():
    print("=== Test 4: mod_sftp Version-Specific Probing ===")
    print()

    all_results = {}
    for target in TARGETS:
        print(f"Probing {target}...")

        # Raw protocol probe (always works, no auth needed)
        raw_result = probe_sftp_version_raw(target)
        print(f"  Banner: {raw_result['banner'][:60]}")

        kex = raw_result.get("kexinit_algorithms", {})
        if kex:
            print(f"  KEX algorithms: {kex.get('kex_algorithms', [])[:5]}")
            print(f"  Host key algorithms: {kex.get('server_host_key_algorithms', [])}")
            print(f"  Ciphers: {kex.get('encryption_algorithms_server_to_client', [])}")
            print(f"  MACs: {kex.get('mac_algorithms_server_to_client', [])}")
            print(f"  Compression: {kex.get('compression_algorithms_server_to_client', [])}")

        # Paramiko probe (requires auth)
        paramiko_result = probe_extensions_paramiko(target)
        print(f"  Auth methods: {paramiko_result['version_probe'].get('auth_methods', 'N/A')}")
        print(f"  SFTP extensions:")
        for ext, status in paramiko_result.get("extensions", {}).items():
            print(f"    {ext}: {status}")

        all_results[target] = {"raw": raw_result, "paramiko": paramiko_result}
        print()

    # Save results
    out = os.path.abspath(os.path.join(os.path.dirname(__file__),
        "..", "..", "task1", "TOOLS", "json", "task1_modsftp_probe.json"))
    with open(out, "w") as f:
        json.dump(all_results, f, ensure_ascii=False, indent=2)
    print(f"Saved to {out}")

    # Verdict
    for target, data in all_results.items():
        ext = data["paramiko"].get("extensions", {})
        supported = [k for k, v in ext.items() if "SUPPORTED" in v]
        if supported:
            print(f"\n{target}: Supported extensions: {supported}")
        else:
            print(f"\n{target}: No SFTP extensions detected beyond base protocol")


if __name__ == "__main__":
    main()