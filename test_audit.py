"""Unprivileged regressions. No Mininet or live-controller claims are made."""
import logging
import socket
import threading
import time
import tempfile
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

logging.basicConfig(handlers=[logging.NullHandler()])
import auth_server as auth
import protected_service as service
import client
import performance_test as perf
from controller_client import ControllerError


class ScriptedSocket:
    def __init__(self, chunks):
        self.chunks = iter(chunks)
        self.sent = b""

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def settimeout(self, value):
        pass

    def recv(self, size):
        return next(self.chunks, b"")

    def sendall(self, value):
        self.sent += value


class AuditTests(unittest.TestCase):
    def setUp(self):
        auth.sessions.clear()
        auth.failed_attempts.clear()
        auth.locked_until.clear()
        self.allow = patch.object(auth, "send_allow", return_value="OK").start()
        self.revoke = patch.object(auth, "send_revoke", return_value="OK").start()
        self.addCleanup(patch.stopall)

    def login(self, ip="10.0.0.1"):
        return auth.handle_request({"action": "LOGIN", "username": "alice",
                                    "password": "123"}, ip)

    def logout(self, token, ip="10.0.0.1"):
        return auth.handle_request({"action": "LOGOUT", "session_id": token}, ip)

    def test_fragmented_service_command(self):
        conn = ScriptedSocket([b"GET_", b"SECRET\n"])
        service.handle_client(conn, ("10.0.0.1", 1234))
        self.assertTrue(conn.sent.startswith(b"ACCESS GRANTED"))

    def test_logout_failure_is_visible_and_retryable(self):
        token = self.login()["session_id"]
        self.revoke.side_effect = ControllerError("switch disconnected")
        self.assertFalse(self.logout(token)["ok"])
        self.assertIn(token, auth.sessions)
        self.revoke.side_effect = None
        self.assertTrue(self.logout(token)["ok"])

    def test_logout_newest_session_restores_remaining_lease(self):
        with patch.object(auth.time, "monotonic", return_value=100):
            first = self.login()["session_id"]
        with patch.object(auth.time, "monotonic", return_value=130):
            second = self.login()["session_id"]
            self.assertTrue(self.logout(second)["ok"])
        self.assertEqual(self.allow.call_args.args[-1], 30)
        self.assertIn(first, auth.sessions)

    def test_login_failure_does_not_create_session(self):
        self.allow.side_effect = ControllerError("unavailable")
        self.assertFalse(self.login()["ok"])
        self.assertFalse(auth.sessions)

    def test_token_bound_to_client_ip_and_invalidated(self):
        token = self.login()["session_id"]
        self.assertFalse(self.logout(token, "10.0.0.2")["ok"])
        self.assertTrue(self.logout(token)["ok"])
        self.assertFalse(self.logout(token)["ok"])

    def test_lockout_and_recovery(self):
        bad = {"action": "LOGIN", "username": "alice", "password": "bad"}
        with patch.object(auth.time, "monotonic", return_value=100):
            for _ in range(3):
                self.assertFalse(auth.handle_request(bad, "10.0.0.1")["ok"])
            self.assertIn("lock", self.login()["error"].lower())
        with patch.object(auth.time, "monotonic", return_value=161):
            self.assertTrue(self.login()["ok"])

    def test_fragmented_auth_json(self):
        conn = ScriptedSocket([b'{"action":', b'"LOGIN"}\n'])
        self.assertEqual(auth.receive_line(conn), '{"action":"LOGIN"}')

    def test_request_validation(self):
        for request in [[], None, {"action": "LOGIN", "username": []},
                        {"action": "LOGOUT", "session_id": []}]:
            self.assertFalse(auth.handle_request(request, "10.0.0.1")["ok"])

    def test_expiry_retries_failed_revocation(self):
        with patch.object(auth.time, "monotonic", return_value=100):
            token = self.login()["session_id"]
        with patch.object(auth.time, "monotonic", return_value=161):
            self.revoke.side_effect = ControllerError("offline")
            auth.expire_once()
            self.assertIn(token, auth.sessions)
            self.revoke.side_effect = None
            auth.expire_once()
            self.assertNotIn(token, auth.sessions)

    def test_login_and_logout_cannot_reorder_switch_updates(self):
        old = self.login()["session_id"]
        entered, release = threading.Event(), threading.Event()
        self.allow.side_effect = lambda *args: (entered.set(), release.wait(2), "OK")[-1]
        results = []
        login_thread = threading.Thread(target=lambda: results.append(self.login()))
        logout_thread = threading.Thread(target=lambda: results.append(self.logout(old)))
        login_thread.start()
        self.assertTrue(entered.wait(1))
        logout_thread.start()
        time.sleep(0.05)
        self.assertTrue(logout_thread.is_alive())
        release.set()
        login_thread.join(3)
        logout_thread.join(3)
        self.assertFalse(login_thread.is_alive() or logout_thread.is_alive())
        self.assertTrue(all(item["ok"] for item in results))
        self.revoke.assert_not_called()

    def test_oversize_and_incomplete_requests(self):
        for chunks in [[b"x" * 4097], [b'{"action":']]:
            with self.assertRaises(ValueError):
                auth.receive_line(ScriptedSocket(chunks))

    def test_one_request_per_connection(self):
        conn = ScriptedSocket([b'{"action":"UNKNOWN"}\n{"action":"LOGIN"}\n'])
        auth.handle_client(conn, ("10.0.0.1", 1234))
        self.assertEqual(conn.sent.count(b"\n"), 1)
        self.assertFalse(auth.sessions)

    def test_demo_failure_has_nonzero_exit(self):
        with patch.object(client, "send_auth_request", return_value={"ok": False}):
            with self.assertRaises(SystemExit) as ctx:
                client.main()
            self.assertEqual(ctx.exception.code, 1)

    def test_benchmark_rejects_failed_logout(self):
        with patch.object(perf, "TRIALS", 1), \
             patch.object(perf, "auth_request", side_effect=[
                 {"ok": True, "session_id": "test"}, {"ok": False}]), \
             patch.object(perf, "service_request", return_value=1), \
             patch.object(perf, "append_result") as append:
            with self.assertRaises(RuntimeError):
                perf.run_dynamic()
            append.assert_not_called()

    def test_benchmark_duplicate_preserves_existing_file(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/"results.csv"
            with patch.object(perf, "RESULTS_FILE", path):
                perf.append_result("static", 1, None, 1.25, None)
                before = path.read_bytes()
                with self.assertRaises(ValueError):
                    perf.append_result("static", 1, None, 2, None)
                self.assertEqual(path.read_bytes(), before)

    def test_benchmark_original_output_is_rejected(self):
        with patch("sys.argv", ["performance_test.py", "dynamic", "--output",
                                str(Path(perf.__file__).with_name("performance_results.csv"))]):
            with self.assertRaises(SystemExit) as ctx:
                perf.main()
            self.assertEqual(ctx.exception.code, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
