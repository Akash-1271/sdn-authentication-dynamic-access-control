
import json
import socket
import time

from net_protocol import receive_line as read_frame, decode_json

AUTH_HOST = "10.0.0.3"
AUTH_PORT = 9000

SERVICE_HOST = "10.0.0.4"
SERVICE_PORT = 8080


def receive_line(conn, *, timeout=5, deadline=None):
    """Read one bounded response within a single absolute receive budget."""
    line = read_frame(conn, 4096, timeout, deadline=deadline)
    if line is None:
        raise ConnectionError("Peer closed without a response")
    return line


def send_auth_request(request):
    """Send a JSON request to the authentication server."""
    deadline = time.monotonic() + 5
    with socket.create_connection(
        (AUTH_HOST, AUTH_PORT), timeout=5
    ) as conn:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Authentication operation deadline exceeded")
        conn.settimeout(remaining)
        message = json.dumps(request).encode("utf-8") + b"\n"
        conn.sendall(message)
        response = decode_json(receive_line(conn, deadline=deadline))
        if not isinstance(response, dict):
            raise ValueError("Expected a JSON object response")
        return response


def access_protected_service():
    """Request the protected data over TCP."""
    deadline = time.monotonic() + 3
    with socket.create_connection(
        (SERVICE_HOST, SERVICE_PORT), timeout=3
    ) as conn:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Service operation deadline exceeded")
        conn.settimeout(remaining)
        conn.sendall(b"GET_SECRET\n")
        return receive_line(conn, timeout=3, deadline=deadline)


def main():
    session_id = None
    success = False

    try:
        print("1. Logging in to the authentication server...")

        response = send_auth_request({
            "action": "LOGIN",
            "username": "alice",
            "password": "123",
        })

        if not response.get("ok"):
            print(f"[FAIL] Login rejected: {response.get('error')}")
            raise SystemExit(1)

        session_id = response["session_id"]
        print("[PASS] Login successful")
        print("[INFO] Session token received")

        print("\n2. Accessing the protected service...")

        result = access_protected_service()
        print(result)

        if result.startswith("ACCESS GRANTED"):
            print("[PASS] Protected service access succeeded")
            success = True
        else:
            print("[FAIL] Unexpected protected-service response")

    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"[ERROR] Client operation failed: {exc}")

    finally:
        if session_id:
            try:
                response = send_auth_request({
                    "action": "LOGOUT",
                    "session_id": session_id,
                })

                if response.get("ok"):
                    print("\n[PASS] Logout successful")
                else:
                    success = False
                    print(
                        f"\n[WARN] Logout response: "
                        f"{response.get('error')}"
                    )

            except (OSError, ValueError, json.JSONDecodeError) as exc:
                success = False
                print(f"\n[ERROR] Logout failed: {exc}")

    if not success:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
