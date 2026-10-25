
import json
import os
import socket
import sys
import time

HOST = "10.0.0.3"
PORT = 9000


def send_request(request):
    with socket.create_connection((HOST, PORT), timeout=3) as client:
        client.settimeout(3)
        client.sendall(json.dumps(request).encode("utf-8") + b"\n")

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
    total = 6
    session_token = None

    try:
        # Three consecutive incorrect passwords.
        for attempt in range(1, 4):
            response = send_request({
                "action": "LOGIN",
                "username": "alice",
                "password": "wrong",
            })

            if response.get("ok") is False:
                passed += 1
                print(f"[PASS] Failed attempt {attempt} rejected")
            else:
                print(f"[FAIL] Attempt {attempt} unexpectedly succeeded")

        # Correct credentials must still be rejected during lockout.
        response = send_request({
            "action": "LOGIN",
            "username": "alice",
            "password": "123",
        })

        if (
            response.get("ok") is False
            and "locked" in response.get("error", "").lower()
        ):
            passed += 1
            print("[PASS] Valid credentials blocked during IP lockout")
        else:
            print(f"[FAIL] Expected lockout, got: {response}")

        wait = int(os.environ.get("TEST_LOCKOUT_SECONDS", "60")) + 1
        print(f"Waiting {wait} seconds for lockout recovery...")
        time.sleep(wait)

        # Correct credentials should work after lockout expires.
        response = send_request({
            "action": "LOGIN",
            "username": "alice",
            "password": "123",
        })

        if response.get("ok") and response.get("session_id"):
            passed += 1
            session_token = response["session_id"]
            print("[PASS] Login succeeds after lockout expires")
        else:
            print(f"[FAIL] Login after lockout: {response}")

        # Clean up the successful test session.
        if session_token:
            response = send_request({
                "action": "LOGOUT",
                "session_id": session_token,
            })

            if response.get("ok") is True:
                passed += 1
                print("[PASS] Test session logged out")
            else:
                print(f"[FAIL] Logout: {response}")
        else:
            print("[FAIL] Cleanup skipped: no session was created")

    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"[ERROR] Security test failed: {exc}")

    print(f"\nResult: {passed}/{total} tests passed.")

    if passed != total:
        sys.exit(1)


if __name__ == "__main__":
    main()
