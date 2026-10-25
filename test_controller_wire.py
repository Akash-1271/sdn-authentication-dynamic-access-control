"""Real OS-Ken process + TCP/OpenFlow wire tests against a simulated switch.

This tests framing, handshake, FlowMods, errors and barriers, not OVS forwarding.
"""
import os
from pathlib import Path
import socket
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import controller_client as client
import control_security
from net_protocol import receive_line


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def read_exact(sock, count):
    data = bytearray()
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise EOFError()
        data.extend(part)
    return bytes(data)


class WireTests(unittest.TestCase):
    def test_controller_with_simulated_openflow13_switch(self):
        # Exercise a source-only deployment even when invoked from a checkout
        # containing a virtual environment. Dependencies belong to the active
        # interpreter, not to a bundled .venv311 directory.
        source = Path(__file__).resolve().parent
        deployment = tempfile.TemporaryDirectory(prefix="sdn-wire-source-")
        self.addCleanup(deployment.cleanup)
        root = Path(deployment.name)
        for name in ("controller.py", "control_security.py", "net_protocol.py"):
            shutil.copyfile(source/name, root/name)
        of_port, ctrl_port = free_port(), free_port()
        secret_dir = tempfile.TemporaryDirectory()
        self.addCleanup(secret_dir.cleanup)
        key_path = Path(secret_dir.name)/"control.key"
        control_security.generate_key(key_path)
        env = dict(os.environ, SDN_CONTROL_HOST="127.0.0.1", SDN_CONTROL_PORT=str(ctrl_port),
                   SDN_CONTROL_ALLOWED_PEER="127.0.0.1", SDN_CONTROL_SECRET_FILE=str(key_path))
        self.enterContext(patch.dict(os.environ, {"SDN_CONTROL_SECRET_FILE": str(key_path)}))
        with tempfile.TemporaryFile(mode="w+") as log:
            proc = subprocess.Popen([sys.executable, "-m", "os_ken.cmd.manager",
                "--ofp-listen-host", "127.0.0.1", "--ofp-tcp-listen-port", str(of_port),
                str(root/"controller.py")], env=env, cwd=root, stdout=log, stderr=log)
            peer = None
            try:
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    if proc.poll() is not None:
                        log.seek(0)
                        self.fail("OS-Ken startup failed: " + log.read()[-2000:])
                    try:
                        peer = socket.create_connection(("127.0.0.1", of_port), timeout=1)
                        break
                    except OSError:
                        time.sleep(.1)
                self.assertIsNotNone(peer, "OS-Ken did not start")
                peer.settimeout(15)
                messages = []
                barriers = threading.Event()
                fail_next = threading.Event()
                thread_errors = []

                def send(kind, xid, payload=b""):
                    peer.sendall(struct.pack("!BBHI", 4, kind, 8+len(payload), xid)+payload)

                def switch():
                    try:
                        send(0, 100)
                        while True:
                            header = read_exact(peer, 8)
                            version, kind, length, xid = struct.unpack("!BBHI", header)
                            body = read_exact(peer, length-8)
                            self.assertEqual(version, 4)
                            if kind == 5:
                                send(6, xid, struct.pack("!QIBB2xII", 1, 256, 1, 0, 0, 0))
                            elif kind == 2:
                                send(3, xid, body)
                            elif kind == 18:
                                # Empty port-description reply completes the
                                # OpenFlow 1.3 CONFIG -> MAIN handshake.
                                send(19, xid, body[:2] + b"\x00" * 6)
                            elif kind == 14:
                                messages.append(body)
                                if fail_next.is_set():
                                    fail_next.clear()
                                    send(1, xid, struct.pack("!HH", 5, 0)+header+body[:56])
                            elif kind == 20:
                                send(21, xid)
                                barriers.set()
                    except (EOFError, OSError):
                        pass
                    except Exception as exc:
                        thread_errors.append(exc)

                worker = threading.Thread(target=switch, daemon=True)
                worker.start()
                deadline = time.monotonic()+10
                while len(messages) < 3 and time.monotonic() < deadline:
                    time.sleep(.05)
                self.assertGreaterEqual(len(messages), 3, "Initial rules absent")
                # FlowMod body: cookie(8), mask(8), table(1), command(1),
                # idle(2), hard(2), priority(2), then other fields.
                self.assertEqual(struct.unpack_from("!H", messages[1], 22)[0], 100)
                self.assertEqual(struct.unpack_from("!H", messages[2], 22)[0], 0)
                with patch.object(client, "CONTROLLER_HOST", "127.0.0.1"), \
                     patch.object(client, "CONTROLLER_PORT", ctrl_port):
                    self.assertEqual(client.send_allow("10.0.0.1", "10.0.0.4"), "OK")
                    self.assertTrue(barriers.is_set())
                    allow = messages[-1]
                    self.assertEqual(struct.unpack_from("!H", allow, 20)[0], 60)
                    self.assertEqual(struct.unpack_from("!H", allow, 22)[0], 200)
                    self.assertEqual(client.send_revoke("10.0.0.1", "10.0.0.4"), "OK")
                    self.assertEqual(messages[-1][17], 4)  # DELETE_STRICT
                    fail_next.set()
                    with self.assertRaises(client.ControllerError):
                        client.send_allow("10.0.0.1", "10.0.0.4")
                    self.assertEqual(messages[-1][17], 4, "Failed ALLOW must roll back")
                    with socket.create_connection(("127.0.0.1", ctrl_port), timeout=3) as conn:
                        import json
                        challenge = json.loads(receive_line(conn, 512, 3))
                        envelope = control_security.sign_request(
                            "REVOKE 10.0.0.1 10.0.0.4 8080", challenge, control_security.load_secret())
                        frame = json.dumps(envelope).encode() + b"\n"
                        for part in [frame[:3], frame[3:31], frame[31:]]:
                            conn.sendall(part)
                        self.assertEqual(conn.recv(1024), b"OK\n")
                    # Requests from an allowed peer still require a valid HMAC.
                    with socket.create_connection(("127.0.0.1", ctrl_port), timeout=3) as conn:
                        receive_line(conn, 512, 3)
                        conn.sendall(b"ALLOW 10.0.0.1 10.0.0.4 8080 60\n")
                        self.assertEqual(receive_line(conn, 512, 3), "ERR authentication failed")
                    # The second frame on a single connection is never executed.
                    with socket.create_connection(("127.0.0.1", ctrl_port), timeout=3) as conn:
                        challenge = json.loads(receive_line(conn, 512, 3))
                        signed = control_security.sign_request("REVOKE 10.0.0.1 10.0.0.4 8080", challenge, control_security.load_secret())
                        frame = json.dumps(signed).encode()+b"\n"
                        before = len(messages)
                        conn.sendall(frame+frame)
                        self.assertEqual(receive_line(conn,512,3), "OK")
                        time.sleep(.05)
                        self.assertEqual(len(messages)-before, 1)
                self.assertFalse(thread_errors)
                peer.shutdown(socket.SHUT_RDWR)
                peer.close()
                peer = None
                worker.join(2)
                with patch.object(client, "CONTROLLER_HOST", "127.0.0.1"), \
                     patch.object(client, "CONTROLLER_PORT", ctrl_port):
                    deadline = time.monotonic()+3
                    while True:
                        try:
                            client.send_allow("10.0.0.1", "10.0.0.4")
                        except client.ControllerError as exc:
                            if "no switch" in str(exc):
                                break
                        if time.monotonic() > deadline:
                            self.fail("Disconnected switch was not removed")
                        time.sleep(.1)
            finally:
                if peer is not None:
                    peer.close()
                proc.terminate()
                try:
                    proc.wait(5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
