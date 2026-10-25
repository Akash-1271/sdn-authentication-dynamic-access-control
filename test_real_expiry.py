import json
import socket
import time

AUTH_HOST = "10.0.0.3"
AUTH_PORT = 9000
SERVICE_HOST = "10.0.0.4"
SERVICE_PORT = 8080


def auth_request(request):
    with socket.create_connection((AUTH_HOST, AUTH_PORT), timeout=5) as conn:
        conn.settimeout(5)
        conn.sendall(json.dumps(request).encode() + b"\n")

        data = bytearray()
        while b"\n" not in data:
            chunk = conn.recv(1024)
            if not chunk:
                raise ConnectionError("Authentication server closed connection")
            data.extend(chunk)
            if len(data) > 4096:
                raise ValueError("Authentication response too large")

        line, _, _ = data.partition(b"\n")
        return json.loads(line.decode())


def probe_service():
    # Only failure to establish the TCP connection is evidence of blocking.
    try:
        conn = socket.create_connection(
            (SERVICE_HOST, SERVICE_PORT), timeout=3
        )
    except socket.timeout:
        return None

    with conn:
        conn.settimeout(3)
        conn.sendall(b"GET_SECRET\n")
        data = conn.recv(1024)
        return data.decode().strip() if data else ""


def main():
    response = auth_request({
        "action": "LOGIN",
        "username": "alice",
        "password": "123",
    })

    if not response.get("ok"):
        raise SystemExit(f"[FAIL] Login: {response}")

    if not (probe_service() or "").startswith("ACCESS GRANTED"):
        raise SystemExit("[INCONCLUSIVE] Service was not working before expiry")
    wait = response["lease_seconds"] + 2
    print(f"[PASS] Service worked after login. Waiting {wait} seconds...")
    time.sleep(wait)

    try:
        result = probe_service()
    except OSError as exc:
        print(f"[INCONCLUSIVE] Could not complete service probe: {exc}")
        raise SystemExit(2)

    if result is None:
        print("[INCONCLUSIVE] Timed out after expiry. Independently verify the service is still live and the deny flow remains.")
        raise SystemExit(2)
    else:
        print(f"[FAIL] Service connection succeeded: {result}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
