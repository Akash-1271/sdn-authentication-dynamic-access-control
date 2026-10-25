from net_protocol import receive_line, serve_threaded
import socket

HOST = "10.0.0.4"
PORT = 8080


def handle_client(conn, address):
    with conn:
        try:
            conn.settimeout(5)
            request = receive_line(conn, 1024, 5)
            if request is None:
                return

            if request == "GET_SECRET":
                response = "ACCESS GRANTED: Demo protected data\n"
            else:
                response = "ERROR: Unknown command\n"

            conn.sendall(response.encode("utf-8"))
            print(f"[SERVICE] Request handled from {address[0]}")

        except (OSError, UnicodeDecodeError, ValueError) as exc:
            print(f"[SERVICE ERROR] {address[0]}: {type(exc).__name__}")


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen()
        print(f"Protected service listening on {HOST}:{PORT}")

        try:
            serve_threaded(server, handle_client, max_connections=32)

        except KeyboardInterrupt:
            print("\nProtected service stopped.")


if __name__ == "__main__":
    main()
