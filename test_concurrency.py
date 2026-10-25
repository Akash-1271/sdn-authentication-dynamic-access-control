
import json
import socket
from concurrent.futures import ThreadPoolExecutor

HOST = "10.0.0.3"
PORT = 9000
CLIENT_COUNT = 5


def send_request(request):
    with socket.create_connection((HOST, PORT), timeout=5) as client:
        client.settimeout(5)
        client.sendall(json.dumps(request).encode("utf-8") + b"\n")

        buffer = bytearray()

        while b"\n" not in buffer:
            chunk = client.recv(1024)
            if not chunk:
                raise ConnectionError("Server closed without a response")
            buffer.extend(chunk)

        line, _, _ = buffer.partition(b"\n")
        return json.loads(line.decode("utf-8"))


def login_client(_):
    return send_request({
        "action": "LOGIN",
        "username": "alice",
        "password": "123",
    })


def main():
    tokens = []

    with ThreadPoolExecutor(max_workers=CLIENT_COUNT) as pool:
        results = list(pool.map(login_client, range(CLIENT_COUNT)))

    for i, result in enumerate(results, start=1):
        if result.get("ok") and result.get("session_id"):
            tokens.append(result["session_id"])
            print(f"[PASS] Client {i} logged in")
        else:
            print(f"[FAIL] Client {i}: {result}")

    unique_tokens = len(set(tokens)) == CLIENT_COUNT

    if unique_tokens:
        print("[PASS] All clients received unique session tokens")
    else:
        print("[FAIL] Session tokens were missing or duplicated")

    # Logout every successfully created test session.
    cleanup_ok = True

    for token in tokens:
        try:
            response = send_request({
                "action": "LOGOUT",
                "session_id": token,
            })
            if not response.get("ok"):
                cleanup_ok = False
        except (OSError, ValueError):
            cleanup_ok = False

    if cleanup_ok and len(tokens) == CLIENT_COUNT:
        print("[PASS] All test sessions logged out")
    else:
        print("[FAIL] One or more sessions could not be cleaned up")

    success = len(tokens) == CLIENT_COUNT and unique_tokens and cleanup_ok

    print(f"\nResult: {'PASS' if success else 'FAIL'}")

    if not success:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
