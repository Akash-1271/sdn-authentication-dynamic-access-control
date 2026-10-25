
import json
import socket

HOST = "10.0.0.3"
PORT = 9000


def send_request(request):
    with socket.create_connection((HOST, PORT), timeout=3) as client:
        client.settimeout(3)
        message = json.dumps(request).encode("utf-8") + b"\n"
        client.sendall(message)

        buffer = bytearray()

        while b"\n" not in buffer:
            chunk = client.recv(1024)

            if not chunk:
                raise ConnectionError("Server closed without a response")

            buffer.extend(chunk)

            if len(buffer) > 4096:
                raise ValueError("Response too large")

        line, _, _ = buffer.partition(b"\n")
        return json.loads(line.decode("utf-8"))


def main():
    passed = 0
    total = 4
    session_token = None

    try:
        response = send_request({
            "action": "LOGIN",
            "username": "alice",
            "password": "123",
        })

        if response.get("ok") and response.get("session_id"):
            session_token = response["session_id"]
            passed += 1
            print("[PASS] Login creates a session token")
        else:
            print(f"[FAIL] Login: {response}")

        response = send_request({
            "action": "LOGIN",
            "username": "alice",
            "password": "wrong",
        })

        if response.get("ok") is False:
            passed += 1
            print("[PASS] Incorrect password rejected")
        else:
            print(f"[FAIL] Wrong password: {response}")

        response = send_request({
            "action": "LOGIN",
            "username": "nobody",
            "password": "123",
        })

        if response.get("ok") is False:
            passed += 1
            print("[PASS] Unknown username rejected")
        else:
            print(f"[FAIL] Unknown user: {response}")

        if session_token:
            response = send_request({
                "action": "LOGOUT",
                "session_id": session_token,
            })

            if response.get("ok") is True:
                passed += 1
                print("[PASS] Logout succeeds")
            else:
                print(f"[FAIL] Logout: {response}")
        else:
            print("[FAIL] Logout skipped because login failed")

    except (OSError, ValueError) as exc:
        print(f"[ERROR] {exc}")

    print(f"\nResult: {passed}/{total} tests passed.")

    if passed != total:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
