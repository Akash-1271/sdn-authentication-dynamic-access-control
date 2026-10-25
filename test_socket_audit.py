"""Real loopback TCP application checks, with mocked SDN calls."""
import contextlib
import importlib
import logging
import socketserver
import threading
import unittest
from unittest.mock import patch

logging.basicConfig(handlers=[logging.NullHandler()])
import auth_server as auth
import protected_service as service


@contextlib.contextmanager
def listener(handler):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            handler(self.request, self.client_address)
    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True
    with Server(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.server_address[1]
        finally:
            server.shutdown()
            thread.join(2)


class SocketTests(unittest.TestCase):
    def test_existing_application_scripts_over_real_tcp(self):
        auth.sessions.clear()
        auth.failed_attempts.clear()
        auth.locked_until.clear()
        with patch.object(auth, "send_allow", return_value="OK"), \
             patch.object(auth, "send_revoke", return_value="OK"), \
             patch.object(auth, "LOCKOUT_SECONDS", 1), \
             listener(auth.handle_client) as port, \
             listener(service.handle_client) as service_port:
            for name in ["test_auth", "test_concurrency", "test_security", "test_lockout_network"]:
                auth.failed_attempts.clear()
                auth.locked_until.clear()
                module = importlib.import_module(name)
                with contextlib.ExitStack() as stack:
                    for key in ("HOST", "AUTH_HOST"):
                        if hasattr(module, key):
                            stack.enter_context(patch.object(module, key, "127.0.0.1"))
                    for key in ("PORT", "AUTH_PORT"):
                        if hasattr(module, key):
                            stack.enter_context(patch.object(module, key, port))
                    stack.enter_context(patch.dict("os.environ", {"TEST_LOCKOUT_SECONDS": "1"}))
                    module.main()
            auth.failed_attempts.clear()
            auth.locked_until.clear()
            demo = importlib.import_module("client")
            with patch.object(demo, "AUTH_HOST", "127.0.0.1"), \
                 patch.object(demo, "AUTH_PORT", port), \
                 patch.object(demo, "SERVICE_HOST", "127.0.0.1"), \
                 patch.object(demo, "SERVICE_PORT", service_port):
                demo.main()
            failure = importlib.import_module("test_controller_failure")
            with patch.object(failure, "AUTH_HOST", "127.0.0.1"), \
                 patch.object(failure, "AUTH_PORT", port), \
                 patch.object(auth, "send_allow", side_effect=ConnectionRefusedError):
                failure.main()
            expiry = importlib.import_module("test_expiry")
            with patch.object(expiry, "HOST", "127.0.0.1"), \
                 patch.object(expiry, "PORT", port), \
                 patch.object(auth, "SESSION_LEASE_SECONDS", 1):
                expiry.main()
            self.assertFalse(auth.sessions)


if __name__ == "__main__":
    unittest.main(verbosity=2)
