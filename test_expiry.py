
import json
import socket
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

        line, _, _ = buffer.partition(b"\n")
        return json.loads(line.decode("utf-8"))


def main():
    login = send_request({"action": "LOGIN", "username": "alice", "password": "123"})
    if not login.get("ok"):
        raise SystemExit("[FAIL] Login did not succeed")
    wait = login["lease_seconds"] + 2
    print(f"Waiting {wait} seconds for the advertised lease to expire...")
    time.sleep(wait)
    result = send_request({"action": "LOGOUT", "session_id": login["session_id"]})
    if result.get("ok") is False and result.get("error") in {"Session expired", "Invalid session"}:
        print("[PASS] Expired session cannot be used")
    else:
        raise SystemExit("[FAIL] Unexpected expiry response")


if __name__ == "__main__":
    main()
