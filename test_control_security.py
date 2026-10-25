"""Isolated crypto/framing limits plus explicit Mininet control-security probes."""
import contextlib
import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
import secrets
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from control_security import (canonical, generate_key, load_secret, new_challenge,
                              sign_request, verify_request)
from net_protocol import receive_line, serve_threaded
import controller_client


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.key = secrets.token_bytes(32)
        self.challenge = new_challenge()
        self.command = "ALLOW 10.0.0.1 10.0.0.4 8080 60"

    def test_valid_signature_and_revoke(self):
        for command in [self.command, "REVOKE 10.0.0.1 10.0.0.4 8080"]:
            self.assertEqual(verify_request(sign_request(command,self.challenge,self.key),self.challenge,self.key),command)

    def test_plain_forged_modified_and_wrong_key_rejected(self):
        signed=sign_request(self.command,self.challenge,self.key)
        for value in [self.command, {}, dict(signed,mac="0"*64),
                      dict(signed,command="REVOKE 10.0.0.1 10.0.0.4 8080"),
                      dict(signed,nonce="é"*64),dict(signed,ts=True),dict(signed,ts=10**300)]:
            self.assertIsNone(verify_request(value,self.challenge,self.key))
        self.assertIsNone(verify_request(signed,self.challenge,secrets.token_bytes(32)))

    def test_replay_different_connection_or_restart(self):
        value=sign_request(self.command,self.challenge,self.key)
        for _ in range(3):
            self.assertIsNone(verify_request(value,new_challenge(),self.key))

    def test_expired_future_and_boundary_challenges(self):
        value=sign_request(self.command,self.challenge,self.key)
        now=self.challenge['ts']
        with patch('control_security.time.time',return_value=now+30):
            self.assertEqual(verify_request(value,self.challenge,self.key),self.command)
        for clock in [now+30.001,now-30.001]:
            with patch('control_security.time.time',return_value=clock):
                self.assertIsNone(verify_request(value,self.challenge,self.key))

    def test_secret_missing_malformed_permissions_symlink_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ,{},clear=True):
            with self.assertRaises(ValueError):load_secret()
            path=Path(folder)/'control.key'
            os.environ['SDN_CONTROL_SECRET_FILE']=str(path)
            for raw in ['short','00'*32,'non-hex'*10]:
                path.write_text(raw);path.chmod(0o600)
                with self.assertRaises(ValueError):load_secret()
            path.unlink();generate_key(path)
            self.assertEqual(len(load_secret()),32)
            before=path.read_bytes()
            with self.assertRaises(FileExistsError):generate_key(path)
            self.assertEqual(path.read_bytes(),before)
            path.chmod(0o644)
            with self.assertRaises(ValueError):load_secret()
            path.chmod(0o600)
            fifo=Path(folder)/'fifo';os.mkfifo(fifo,0o600)
            os.environ['SDN_CONTROL_SECRET_FILE']=str(fifo)
            with self.assertRaises(ValueError):load_secret()
            link=Path(folder)/'link';link.symlink_to(path)
            os.environ['SDN_CONTROL_SECRET_FILE']=str(link)
            with self.assertRaises(OSError):load_secret()

    def test_no_secret_client_never_connects(self):
        with patch.dict(os.environ,{},clear=True),patch('controller_client.socket.create_connection') as connect:
            with self.assertRaises(ValueError):controller_client.send_allow('10.0.0.1','10.0.0.4')
            connect.assert_not_called()

    def test_server_startup_without_secret_fails_closed(self):
        import subprocess
        root = Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory() as folder:
            bad = Path(folder)/"bad.key"
            bad.write_text("not-a-key");bad.chmod(0o600)
            for value in [None, str(bad)]:
                env=dict(os.environ,AUTH_LOG_FILE=str(Path(folder)/"auth.log"),PYTHONDONTWRITEBYTECODE="1")
                env.pop("SDN_CONTROL_SECRET_FILE",None)
                if value is not None:env["SDN_CONTROL_SECRET_FILE"]=value
                for argv in [[sys.executable,str(root/"auth_server.py")],
                             [sys.executable,"-c",
                              "from controller import AuthAccessController; AuthAccessController()"]]:
                    process=subprocess.run(argv,cwd=root,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
                    self.assertNotEqual(process.returncode,0)
                    self.assertNotIn(b"not-a-key",process.stdout+process.stderr)

    def test_slow_trickle_absolute_deadline(self):
        # A deterministic clock proves that each byte consumes the same budget;
        # wall-clock scheduler delays in a loaded VM are not protocol defects.
        clock=[100.0]
        timeouts=[]
        class TrickleSocket:
            reads=0
            def settimeout(self,seconds):timeouts.append(seconds)
            def recv(self,size):
                self.reads+=1
                clock[0]+=.03
                return b" "
        conn=TrickleSocket()
        with patch("net_protocol.time.monotonic",side_effect=lambda:clock[0]):
            with self.assertRaises(TimeoutError):receive_line(conn,1024,.2)
        self.assertLessEqual(conn.reads,7)
        self.assertGreater(timeouts[0],timeouts[-1])
        self.assertLess(timeouts[-1],.03)

    def test_fragmented_oversized_disconnect_and_coalesced_frame(self):
        for payload,expected in [(b'GET_SECRET\n','GET_SECRET'),(b'first\nsecond\n','first'),(b'','empty')]:
            a,b=socket.socketpair()
            try:
                b.sendall(payload);b.shutdown(socket.SHUT_WR)
                self.assertEqual(receive_line(a,20,.2),None if expected=='empty' else expected)
            finally:a.close();b.close()
        for payload in [b'x'*22,b'incomplete']:
            a,b=socket.socketpair()
            try:
                b.sendall(payload);b.shutdown(socket.SHUT_WR)
                with self.assertRaises(ValueError):receive_line(a,20,.2)
            finally:a.close();b.close()

    def test_threaded_server_capacity_and_recovery(self):
        stop=threading.Event();release=threading.Event();entered=threading.Event();count=[0]
        def handler(conn,address):
            count[0]+=1
            if count[0]>=2:entered.set()
            release.wait(2)
            conn.sendall(b'OK\n')
        with socket.socket() as server:
            server.bind(('127.0.0.1',0));server.listen()
            thread=threading.Thread(target=serve_threaded,args=(server,handler),kwargs={'max_connections':2,'stop_event':stop})
            thread.start();connections=[]
            try:
                for _ in range(2):connections.append(socket.create_connection(server.getsockname(),timeout=1))
                self.assertTrue(entered.wait(1))
                with socket.create_connection(server.getsockname(),timeout=1) as extra:
                    self.assertEqual(extra.recv(100),b'ERR busy\n')
                release.set()
                for conn in connections:self.assertEqual(conn.recv(100),b'OK\n');conn.close()
                time.sleep(.05)
                with socket.create_connection(server.getsockname(),timeout=1) as recovered:
                    self.assertEqual(recovered.recv(100),b'OK\n')
            finally:
                release.set();stop.set()
                for conn in connections:conn.close()
                thread.join(3)
            self.assertFalse(thread.is_alive())


def live_control_tests():
    key=load_secret();host=controller_client.CONTROLLER_HOST;port=controller_client.CONTROLLER_PORT
    command='ALLOW 10.0.0.1 10.0.0.4 8080 5'
    saved=None
    def request(mode):
        nonlocal saved
        with socket.create_connection((host,port),timeout=3) as conn:
            challenge=json.loads(receive_line(conn,512,3))
            if mode=='plain_allow':frame=command.encode()
            elif mode=='plain_revoke':frame=b'REVOKE 10.0.0.1 10.0.0.4 8080'
            else:
                signed=sign_request(command,challenge,key)
                if mode=='forged':signed['mac']='0'*64
                elif mode=='modified':signed['command']='ALLOW 10.0.0.2 10.0.0.4 8080 5'
                elif mode=='expired':
                    signed['ts']-=31;payload={k:signed[k] for k in ['v','ts','nonce','command']}
                    signed['mac']=hmac.new(key,canonical(payload),hashlib.sha256).hexdigest()
                elif mode=='replay':signed=saved
                elif mode=='valid':saved=signed
                frame=json.dumps(signed).encode()
            conn.sendall(frame+b'\n')
            return receive_line(conn,512,8)
    try:
        for mode in ['plain_allow','plain_revoke','forged','modified','expired']:
            assert request(mode)=='ERR authentication failed',mode
            print('[PASS]',mode)
        assert request('valid')=='OK'
        print('[PASS] signed ALLOW')
        assert controller_client.send_revoke('10.0.0.1','10.0.0.4')=='OK'
        print('[PASS] signed REVOKE')
        assert request('replay')=='ERR authentication failed'
        print('[PASS] replay from previous connection rejected')
    finally:
        controller_client.send_revoke('10.0.0.1','10.0.0.4')
        controller_client.send_revoke('10.0.0.2','10.0.0.4')


def live_attacker_tests():
    for command in ['ALLOW 10.0.0.2 10.0.0.4 8080 5','REVOKE 10.0.0.1 10.0.0.4 8080']:
        with socket.create_connection(('10.0.0.254',9999),timeout=3) as conn:
            conn.sendall(command.encode()+b'\n')
            response=receive_line(conn,512,3)
            assert response=='ERR unauthorized peer'
        print('[PASS] h2 unauthorized peer rejected')


if __name__=='__main__':
    if os.environ.get('CONTROL_SECURITY_LIVE')=='1':live_control_tests()
    elif os.environ.get('CONTROL_SECURITY_ATTACK')=='1':live_attacker_tests()
    else:unittest.main(verbosity=2)
