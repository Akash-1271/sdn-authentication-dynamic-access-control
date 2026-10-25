
import json
import logging
import os
import secrets
import socket
import threading
import time

from control_security import load_secret
from net_protocol import receive_line as read_frame, serve_threaded, decode_json

from controller_client import ControllerError, send_allow, send_revoke


HOST = "10.0.0.3"
PORT = 9000
PROTECTED_SERVER_IP = "10.0.0.4"
PROTECTED_SERVER_PORT = 8080

SESSION_LEASE_SECONDS = int(os.environ.get("AUTH_LEASE_SECONDS", "60"))
LOCKOUT_SECONDS = int(os.environ.get("AUTH_LOCKOUT_SECONDS", "60"))
MAX_FAILED_ATTEMPTS = 3
MAX_MESSAGE_BYTES = 4096

DEMO_USERS = {
    "alice": "123",
    "bob": "456",
}

# Active sessions: token -> session information
sessions = {}
sessions_lock = threading.Lock()
# Serialize state transitions and their corresponding switch updates. The
# controller has one authorization rule per source IP, not one per token.
transition_lock = threading.RLock()

# Consecutive failed logins and temporary IP lockouts
failed_attempts = {}
locked_until = {}
auth_state_lock = threading.Lock()

LOG_FILE = os.environ.get("AUTH_LOG_FILE", os.path.join(os.path.dirname(__file__), "security.log"))

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("auth_server")


def receive_line(conn):
    """Read one newline-terminated JSON request."""
    return read_frame(conn, MAX_MESSAGE_BYTES, 10)


def send_json(conn, response):
    """Send a JSON response terminated by a newline."""
    conn.sendall(json.dumps(response).encode("utf-8") + b"\n")


def remaining_lockout(client_ip):
    """Return the remaining lockout time, or zero."""
    now = time.monotonic()
    expired = False

    with auth_state_lock:
        until = locked_until.get(client_ip)

        if until is None:
            return 0.0

        remaining = until - now

        if remaining <= 0:
            locked_until.pop(client_ip, None)
            failed_attempts.pop(client_ip, None)
            remaining = 0.0
            expired = True

    if expired:
        logger.info("IP_LOCKOUT_EXPIRED client_ip=%s", client_ip)

    return remaining


def register_failure(client_ip, username):
    """Record failure and lock the client IP after the limit."""
    now = time.monotonic()

    with auth_state_lock:
        until = locked_until.get(client_ip)

        if until is not None and until > now:
            return True

        if until is not None:
            locked_until.pop(client_ip, None)
            failed_attempts.pop(client_ip, None)

        count = failed_attempts.get(client_ip, 0) + 1
        failed_attempts[client_ip] = count
        is_locked = count >= MAX_FAILED_ATTEMPTS

        if is_locked:
            locked_until[client_ip] = now + LOCKOUT_SECONDS

    logger.warning(
        "LOGIN_FAILURE username=%r client_ip=%s count=%s",
        username[:128], client_ip, count,
    )

    if is_locked:
        logger.warning(
            "IP_LOCKOUT client_ip=%s duration_seconds=%s",
            client_ip, LOCKOUT_SECONDS,
        )

    return is_locked


def clear_failures(client_ip):
    """Reset the consecutive failure count after valid credentials."""
    now = time.monotonic()

    with auth_state_lock:
        until = locked_until.get(client_ip)

        if until is not None and until > now:
            return False

        locked_until.pop(client_ip, None)
        failed_attempts.pop(client_ip, None)

    return True


def end_session(session, reason):
    """Log session termination and request network revocation."""
    client_ip = session["client_ip"]

    logger.info(
        "SESSION_END reason=%s username=%s client_ip=%s",
        reason, session["username"], client_ip,
    )

    print(f"[SESSION] {reason}: {session['username']} from {client_ip}")

    now = time.monotonic()

    with sessions_lock:
        another_active_session = any(
            item["client_ip"] == client_ip
            and item["expires_at"] > now
            for item in sessions.values()
        )

    try:
        if another_active_session:
            with sessions_lock:
                expiry = max(item["expires_at"] for item in sessions.values()
                             if item["client_ip"] == client_ip
                             and item["expires_at"] > now)
            # Replace the shared flow with the remaining session's lifetime.
            send_allow(client_ip, PROTECTED_SERVER_IP, PROTECTED_SERVER_PORT,
                       max(1, int(expiry - now)))
            return True
        send_revoke(client_ip, PROTECTED_SERVER_IP, PROTECTED_SERVER_PORT)
        logger.info("SDN_REVOKE_ACK client_ip=%s", client_ip)
        print("[SDN] REVOKE acknowledged")
        return True

    except (OSError, ValueError, ControllerError) as exc:
        logger.error("SDN_REVOKE_FAILED client_ip=%s error=%s", client_ip, exc)
        print(f"[SDN ERROR] REVOKE failed: {exc}")
        return False


def expire_sessions():
    """Remove expired sessions and request revocation."""
    while True:
        time.sleep(1)
        expire_once()


def expire_once():
    """Sweep once; retain failed revocations for retry on the next sweep."""
    with transition_lock:
        now = time.monotonic()
        with sessions_lock:
            expired = [(token, item) for token, item in sessions.items()
                       if item["expires_at"] <= now]
        for token, session in expired:
            with sessions_lock:
                sessions.pop(token, None)
            if not end_session(session, "EXPIRED"):
                with sessions_lock:
                    sessions[token] = session


def handle_request(request, client_ip):
    """Process LOGIN and LOGOUT commands."""
    with transition_lock:
        return _handle_request(request, client_ip)


def _handle_request(request, client_ip):
    if not isinstance(request, dict):
        return {"ok": False, "error": "Expected a JSON object"}

    action = request.get("action")

    if action == "LOGIN":
        username = request.get("username")
        password = request.get("password")

        if not isinstance(username, str) or not isinstance(password, str):
            logger.warning("INVALID_LOGIN_FIELDS client_ip=%s", client_ip)
            return {"ok": False, "error": "Invalid request fields"}

        remaining = remaining_lockout(client_ip)

        if remaining > 0:
            return {
                "ok": False,
                "error": f"IP locked; retry in {int(remaining) + 1} seconds",
            }

        if username not in DEMO_USERS or DEMO_USERS[username] != password:
            is_locked = register_failure(client_ip, username)

            if is_locked:
                return {
                    "ok": False,
                    "error": "IP locked after consecutive failed attempts",
                }

            return {"ok": False, "error": "Invalid credentials"}

        if not clear_failures(client_ip):
            return {"ok": False, "error": "IP is temporarily locked"}

        token = secrets.token_urlsafe(32)

        session = {
            "username": username,
            "client_ip": client_ip,
            "expires_at": time.monotonic() + SESSION_LEASE_SECONDS,
        }

        # Grant network access before committing the session.
        try:
            send_allow(
                client_ip,
                PROTECTED_SERVER_IP,
                PROTECTED_SERVER_PORT,
                SESSION_LEASE_SECONDS,
            )
            logger.info("SDN_ALLOW_ACK client_ip=%s", client_ip)
            print("[SDN] ALLOW acknowledged")

        except (OSError, ValueError, ControllerError) as exc:
            logger.error("SDN_ALLOW_FAILED client_ip=%s error=%s", client_ip, exc)
            # An ACK can be lost after installation. Best-effort reconciliation
            # also restores an older session's shorter lease if one exists.
            end_session(session, "ALLOW_FAILED")
            return {
                "ok": False,
                "error": "Controller unavailable; access not granted",
            }

        with sessions_lock:
            sessions[token] = session

        logger.info("LOGIN_SUCCESS username=%s client_ip=%s", username, client_ip)
        print(f"[AUTH] Accepted login: {username} from {client_ip}")

        return {
            "ok": True,
            "message": "Authentication successful",
            "username": username,
            "session_id": token,
            "lease_seconds": SESSION_LEASE_SECONDS,
        }

    if action == "LOGOUT":
        token = request.get("session_id")

        if not isinstance(token, str) or not token:
            return {"ok": False, "error": "Missing session_id"}

        with sessions_lock:
            session = sessions.get(token)

            if session is None or session["client_ip"] != client_ip:
                session = None
                is_expired = False
            else:
                del sessions[token]
                is_expired = session["expires_at"] <= time.monotonic()

        if session is None:
            return {"ok": False, "error": "Invalid session"}

        reason = "EXPIRED" if is_expired else "LOGOUT"
        if not end_session(session, reason):
            with sessions_lock:
                sessions[token] = session
            return {"ok": False, "error": "Network revocation unconfirmed; retry logout"}

        if is_expired:
            return {"ok": False, "error": "Session expired"}

        return {"ok": True, "message": "Logged out successfully"}

    return {"ok": False, "error": "Unsupported action"}


def handle_client(conn, address):
    """Handle one request from a connected client."""
    with conn:
        conn.settimeout(10)

        try:
            line = receive_line(conn)

            if line is None:
                return

            try:
                request = decode_json(line)
                response = handle_request(request, address[0])
            except (ValueError, RecursionError):
                logger.warning("INVALID_JSON client_ip=%s", address[0])
                response = {"ok": False, "error": "Invalid JSON"}

            send_json(conn, response)

        except (OSError, UnicodeDecodeError, ValueError) as exc:
            logger.warning("CLIENT_ERROR client_ip=%s reason=%s", address[0], type(exc).__name__)
            print(f"[CLIENT ERROR] {address[0]}: {type(exc).__name__}")


def main():
    if not 1 <= SESSION_LEASE_SECONDS <= 3600 or LOCKOUT_SECONDS <= 0:
        raise ValueError("Lease must be 1..3600; lockout must be positive")

    load_secret()  # Validate required configuration before accepting any logins.
    threading.Thread(target=expire_sessions, daemon=True).start()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen()
        server.settimeout(None)

        logger.info("SERVER_STARTED host=%s port=%s", HOST, PORT)

        print(f"Authentication server listening on {HOST}:{PORT}")
        print(f"Session lease: {SESSION_LEASE_SECONDS} seconds")
        print(f"IP lockout: {MAX_FAILED_ATTEMPTS} attempts")
        print("Press Ctrl+C to stop.")

        try:
            serve_threaded(server, handle_client, max_connections=32,
                           busy_response=b'{"ok":false,"error":"Server busy"}\n')

        except KeyboardInterrupt:
            logger.info("SERVER_STOPPED")
            print("\nShutting down authentication server.")


if __name__ == "__main__":
    main()
