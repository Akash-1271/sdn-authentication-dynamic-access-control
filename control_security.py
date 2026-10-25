"""HMAC-authenticated, connection-bound control requests; no stored secrets."""
import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time

MAX_ENVELOPE_BYTES = 2048
FRESHNESS_SECONDS = 30


def load_secret():
    path = os.environ.get("SDN_CONTROL_SECRET_FILE")
    if not path:
        raise ValueError("SDN_CONTROL_SECRET_FILE is required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError("Control key must be a private regular file (mode 0600)")
        if info.st_size > 130:
            raise ValueError("Control key file is too large")
        raw = source.read(131)
        if len(raw) > 130:
            raise ValueError("Control key file is too large")
        raw = raw.strip()
    if not re.fullmatch(rb"[0-9a-fA-F]{64}", raw):
        raise ValueError("Control key must contain 64 hexadecimal characters")
    key = bytes.fromhex(raw.decode("ascii"))
    if len(set(key)) < 8:
        raise ValueError("Control key is not sufficiently varied; generate a random key")
    return key


def new_challenge():
    return {"v": 1, "ts": int(time.time()), "nonce": secrets.token_hex(32)}


def valid_challenge(value):
    return (isinstance(value, dict) and set(value) == {"v", "ts", "nonce"}
            and type(value["v"]) is int and value["v"] == 1
            and type(value["ts"]) is int and 0 <= value["ts"] < 2**63
            and abs(time.time() - value["ts"]) <= FRESHNESS_SECONDS
            and isinstance(value["nonce"], str)
            and re.fullmatch(r"[0-9a-f]{64}", value["nonce"]) is not None)


def canonical(payload):
    return b"sdn-control-v1\n" + json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def sign_request(command, challenge, key):
    if not valid_challenge(challenge):
        raise ValueError("Invalid or expired control challenge")
    if (not isinstance(command, str) or not command or len(command.encode()) > 1024
            or "\n" in command or "\r" in command):
        raise ValueError("Control command must be one bounded line")
    payload = dict(challenge, command=command)
    return dict(payload, mac=hmac.new(key, canonical(payload), hashlib.sha256).hexdigest())


def verify_request(envelope, challenge, key):
    if not valid_challenge(challenge) or not isinstance(envelope, dict):
        return None
    if set(envelope) != {"v", "ts", "nonce", "command", "mac"}:
        return None
    if (type(envelope["v"]) is not int or envelope["v"] != 1
            or type(envelope["ts"]) is not int or envelope["ts"] != challenge["ts"]
            or not isinstance(envelope["nonce"], str)
            or re.fullmatch(r"[0-9a-f]{64}", envelope["nonce"]) is None
            or not hmac.compare_digest(envelope["nonce"], challenge["nonce"])):
        return None
    command, mac = envelope["command"], envelope["mac"]
    if (not isinstance(command, str) or not command or len(command.encode()) > 1024
            or "\n" in command or "\r" in command
            or not isinstance(mac, str) or re.fullmatch(r"[0-9a-f]{64}", mac) is None):
        return None
    payload = {k: envelope[k] for k in ("v", "ts", "nonce", "command")}
    expected = hmac.new(key, canonical(payload), hashlib.sha256).hexdigest()
    return command if hmac.compare_digest(mac, expected) else None


def generate_key(path):
    # O_EXCL prevents overwriting an existing key; mode is private from creation.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as target:
        target.write(secrets.token_hex(32) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--generate-key", type=Path, required=True)
    args = parser.parse_args()
    generate_key(args.generate_key)
    print("Private control key created; contents not displayed")
