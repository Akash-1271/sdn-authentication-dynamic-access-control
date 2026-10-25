"""Bounded single-line framing and bounded threaded TCP server lifecycle."""
import json
import socket
import threading
import time


def receive_line(conn, max_bytes, timeout, *, deadline=None):
    deadline = time.monotonic() + timeout if deadline is None else deadline
    data = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Message deadline exceeded")
        conn.settimeout(min(timeout, remaining))
        part = conn.recv(min(1024, max_bytes + 1 - len(data)))
        if not part:
            if not data:
                return None
            raise ValueError("Incomplete message")
        data.extend(part)
        line, separator, _ = data.partition(b"\n")
        if len(line) > max_bytes:
            raise ValueError("Message too large")
        if separator:
            return line.decode("utf-8").strip()
        if len(data) >= max_bytes:
            # One additional byte is required to distinguish newline from overflow.
            if len(data) > max_bytes:
                raise ValueError("Message too large")


def serve_threaded(server, handler, *, max_connections=32, busy_response=b"ERR busy\n", stop_event=None):
    slots = threading.BoundedSemaphore(max_connections)

    def worker(conn, address):
        try:
            handler(conn, address)
        finally:
            conn.close()
            slots.release()

    if stop_event is not None:
        server.settimeout(0.1)
    while stop_event is None or not stop_event.is_set():
        try:
            conn, address = server.accept()
        except socket.timeout:
            continue
        except OSError:
            if stop_event is not None and stop_event.is_set():
                return
            raise
        if not slots.acquire(blocking=False):
            with conn:
                try:
                    conn.settimeout(0.1)
                    conn.sendall(busy_response)
                except OSError:
                    pass
            continue
        try:
            threading.Thread(target=worker, args=(conn, address), daemon=True).start()
        except Exception:
            conn.close()
            slots.release()
            raise


def decode_json(frame):
    """Reject duplicate keys and non-JSON numeric constants before dispatch."""
    def object_pairs(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise ValueError("Duplicate JSON field")
            result[name] = value
        return result

    def invalid_constant(value):
        raise ValueError("Invalid JSON constant")

    return json.loads(frame, object_pairs_hook=object_pairs,
                      parse_constant=invalid_constant)
