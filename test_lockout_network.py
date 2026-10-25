
import json
import socket

AUTH_HOST = "10.0.0.3"
AUTH_PORT = 9000


def login(username, password):
    request = {
        "action": "LOGIN",
        "username": username,
        "password": password,
    }

    with socket.create_connection(
        (AUTH_HOST, AUTH_PORT), timeout=5
    ) as conn:
        conn.settimeout(5)
        conn.sendall(json.dumps(request).encode("utf-8") + b"\n")

        buffer = bytearray()

        while b"\n" not in buffer:
            chunk = conn.recv(1024)

            if not chunk:
                raise ConnectionError("Server closed without a response")

            buffer.extend(chunk)

            if len(buffer) > 4096:
                raise ValueError("Response too large")

        line, _, _ = buffer.partition(b"\n")
        return json.loads(line.decode("utf-8"))


def main():
    # Send three consecutive incorrect passwords.
    for attempt in range(1, 4):
        response = login("alice", "wrong-password")
        error = response.get("error", "").lower()

        if response.get("ok") is True:
            print(f"[FAIL] Incorrect password accepted on attempt {attempt}")
            raise SystemExit(1)

        if attempt < 3:
            if "invalid credentials" not in error:
                print(f"[FAIL] Unexpected response on attempt {attempt}: {response}")
                raise SystemExit(1)

            print(f"[PASS] Incorrect password attempt {attempt} rejected")

        else:
            if "lock" not in error:
                print(f"[FAIL] Third attempt did not trigger lockout: {response}")
                raise SystemExit(1)

            print("[PASS] Third failed attempt triggered IP lockout")

    # Correct credentials must be rejected while the IP is locked.
    response = login("alice", "123")
    error = response.get("error", "").lower()

    if response.get("ok") is False and "lock" in error:
        print("[PASS] Correct credentials blocked during lockout")
    else:
        print(f"[FAIL] Expected locked IP to be denied: {response}")
        raise SystemExit(1)

    print("\nResult: 4/4 checks passed.")


if __name__ == "__main__":
    main()
