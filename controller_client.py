
import json
import time
from control_security import load_secret, sign_request
from net_protocol import receive_line, decode_json

import ipaddress
import os
import socket

# Ubuntu host's address on the Mininet management link.
CONTROLLER_HOST = os.environ.get(
    "SDN_CONTROLLER_HOST", "10.0.0.254"
)
CONTROLLER_PORT = int(
    os.environ.get("SDN_CONTROLLER_PORT", "9999")
)

# Allow a switch barrier timeout plus best-effort rollback and TCP overhead.
TIMEOUT_SECONDS = 8


class ControllerError(Exception):
    """Controller rejected a command or returned an invalid response."""


def validate_ipv4(address, field_name):
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError as exc:
        raise ValueError(f"Invalid {field_name}") from exc

    if parsed.version != 4:
        raise ValueError(f"{field_name} must be IPv4")


def send_command(command):
    """Send one newline-delimited command and read its acknowledgement."""
    if not command or "\n" in command or "\r" in command:
        raise ValueError("Command must be one non-empty line")

    key = load_secret()
    deadline = time.monotonic() + TIMEOUT_SECONDS
    with socket.create_connection((CONTROLLER_HOST, CONTROLLER_PORT),
                                  timeout=TIMEOUT_SECONDS) as conn:
        greeting = receive_line(conn, 512, TIMEOUT_SECONDS, deadline=deadline)
        if greeting is None or greeting.startswith("ERR "):
            raise ControllerError("Control connection rejected")
        envelope = sign_request(command, decode_json(greeting), key)
        conn.settimeout(max(0.001, deadline - time.monotonic()))
        conn.sendall(json.dumps(envelope, separators=(",", ":")).encode() + b"\n")
        response = receive_line(conn, 1024, TIMEOUT_SECONDS, deadline=deadline)
        if response is None:
            raise ConnectionError("Controller closed without a reply")

    if response == "OK":
        return response

    if response.startswith("ERR "):
        raise ControllerError(response[4:])

    raise ControllerError(f"Unexpected response: {response!r}")


def send_allow(client_ip, server_ip, service_port=8080, lease_seconds=60):
    validate_ipv4(client_ip, "client IP")
    validate_ipv4(server_ip, "server IP")

    if not 1 <= service_port <= 65535:
        raise ValueError("Invalid service port")

    if not 1 <= lease_seconds <= 3600:
        raise ValueError("Invalid lease duration")

    return send_command(
        f"ALLOW {client_ip} {server_ip} "
        f"{service_port} {lease_seconds}"
    )


def send_revoke(client_ip, server_ip, service_port=8080):
    validate_ipv4(client_ip, "client IP")
    validate_ipv4(server_ip, "server IP")

    if not 1 <= service_port <= 65535:
        raise ValueError("Invalid service port")

    return send_command(
        f"REVOKE {client_ip} {server_ip} {service_port}"
    )
