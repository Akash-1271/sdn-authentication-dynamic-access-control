
import json
import socket

AUTH_HOST = "10.0.0.3"
AUTH_PORT = 9000


def main():
    request = {
        "action": "LOGIN",
        "username": "alice",
        "password": "123",
    }

    try:
        with socket.create_connection(
            (AUTH_HOST, AUTH_PORT), timeout=3
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
            response = json.loads(line.decode("utf-8"))

        print(f"Server response: {response}")

        if (
            response.get("ok") is False
            and "controller unavailable" in response.get("error", "").lower()
        ):
            print("[PASS] Login denied when controller is unavailable")
        else:
            print("[FAIL] Unexpected response; check controller state")
            raise SystemExit(1)

    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"[ERROR] Test could not complete: {exc}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
