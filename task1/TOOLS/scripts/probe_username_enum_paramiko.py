#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import socket
from pathlib import Path

import paramiko

from lib import dump_json, make_base_record


class InvalidUsername(Exception):
    pass


def no_boolean(*args, **kwargs):
    return None


def patch_paramiko_for_enum() -> tuple[object, object]:
    original_service_accept = paramiko.auth_handler.AuthHandler._parse_service_accept
    original_userauth_failure = paramiko.auth_handler.AuthHandler._parse_userauth_failure

    def patched_service_accept(self, message):
        old_add_boolean = paramiko.message.Message.add_boolean
        paramiko.message.Message.add_boolean = no_boolean
        try:
            return original_service_accept(self, message)
        finally:
            paramiko.message.Message.add_boolean = old_add_boolean

    def patched_userauth_failure(self, message):
        raise InvalidUsername()

    paramiko.auth_handler.AuthHandler._parse_service_accept = patched_service_accept
    paramiko.auth_handler.AuthHandler._parse_userauth_failure = patched_userauth_failure
    return original_service_accept, original_userauth_failure


def restore_paramiko(original_service_accept, original_userauth_failure) -> None:
    paramiko.auth_handler.AuthHandler._parse_service_accept = original_service_accept
    paramiko.auth_handler.AuthHandler._parse_userauth_failure = original_userauth_failure


def probe_username(host: str, port: int, username: str) -> dict:
    sock = socket.socket()
    sock.settimeout(8)
    try:
        sock.connect((host, port))
    except Exception as exc:
        return {"username": username, "result": "connect_failed", "detail": repr(exc)}

    transport = paramiko.transport.Transport(sock)
    try:
        transport.start_client(timeout=8)
    except Exception as exc:
        transport.close()
        return {"username": username, "result": "negotiation_failed", "detail": repr(exc)}

    try:
        transport.auth_publickey(username, paramiko.RSAKey.generate(1024))
        return {"username": username, "result": "unexpected_success", "detail": "publickey accepted unexpectedly"}
    except InvalidUsername:
        return {"username": username, "result": "invalid_username", "detail": "custom InvalidUsername exception raised"}
    except paramiko.ssh_exception.AuthenticationException:
        return {"username": username, "result": "valid_or_indistinguishable", "detail": "authentication failed after malformed request"}
    except Exception as exc:
        return {"username": username, "result": "inconclusive_error", "detail": repr(exc)}
    finally:
        transport.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--user", action="append", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    raw_dir = run_dir / "task1" / "raw"

    original_service_accept, original_userauth_failure = patch_paramiko_for_enum()
    try:
        results = [probe_username(args.host, args.port, user) for user in args.user]
    finally:
        restore_paramiko(original_service_accept, original_userauth_failure)

    record = make_base_record(run_dir.name, "task1", "probe_username_enum_paramiko.py")
    record.update(
        {
            "host": args.host,
            "port": args.port,
            "usernames": args.user,
            "results": results,
            "paramiko_version": paramiko.__version__,
        }
    )
    dump_json(raw_dir / "username_enum_paramiko.json", record)
    print(json.dumps(record, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
