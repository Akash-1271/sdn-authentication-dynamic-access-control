"""Focused master-verification invariants; no system network changes."""
import contextlib
import io
import json
import logging
import os
from pathlib import Path
import random
import secrets
import socket
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch, Mock

logging.basicConfig(handlers=[logging.NullHandler()])
import auth_server as auth
import client
import control_security as control
from net_protocol import receive_line
from test_audit import ScriptedSocket


class MasterTests(unittest.TestCase):
    def setUp(self):
        auth.sessions.clear();auth.failed_attempts.clear();auth.locked_until.clear()
        self.allow=self.enterContext(patch.object(auth,'send_allow',return_value='OK'))
        self.revoke=self.enterContext(patch.object(auth,'send_revoke',return_value='OK'))
        self.login_request=dict(action='LOGIN',username='alice',password='123')

    def login(self,ip='10.0.0.1'):
        return auth.handle_request(self.login_request,ip)

    def logout(self,token,ip='10.0.0.1'):
        return auth.handle_request(dict(action='LOGOUT',session_id=token),ip)

    def test_duplicate_json_cannot_create_session(self):
        frame=b'{"action":"UNKNOWN","action":"LOGIN","username":"alice","password":"123"}\n'
        conn=ScriptedSocket([frame])
        auth.handle_client(conn,('10.0.0.1',1234))
        self.assertEqual(len(auth.sessions),0)
        self.allow.assert_not_called()

    def test_username_cannot_inject_log_records(self):
        output=io.StringIO();handler=logging.StreamHandler(output)
        handler.setFormatter(logging.Formatter('%(message)s'))
        auth.logger.addHandler(handler)
        try:
            auth.handle_request(dict(action='LOGIN',username='attacker\nFORGED_EVENT',password='bad'),'10.0.0.2')
        finally:auth.logger.removeHandler(handler)
        self.assertEqual(len(output.getvalue().splitlines()),1)

    def test_key_file_trailing_data_is_not_ignored(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'control.key';control.generate_key(path)
            with path.open('ab') as target:target.write(b' '*100+b'not-key-data')
            with patch.dict(os.environ,{'SDN_CONTROL_SECRET_FILE':str(path)}):
                with self.assertRaises(ValueError):control.load_secret()

    def test_strict_json_escaped_duplicate_keys_and_constants(self):
        from net_protocol import decode_json
        for frame in [r'{"v":1,"\u0076":1}', '{"number":NaN}', '{"number":Infinity}',
                      '{"number":-Infinity}', '{"action":"LOGIN","action":"UNKNOWN"}']:
            with self.assertRaises(ValueError):decode_json(frame)
        self.assertEqual(decode_json('{"v":1,"name":"alice"}'),{'v':1,'name':'alice'})

    def test_expiry_logout_race_cleans_once(self):
        with patch.object(auth.time,'monotonic',return_value=100):token=self.login()['session_id']
        with patch.object(auth.time,'monotonic',return_value=161):
            with ThreadPoolExecutor(max_workers=2) as pool:
                jobs=[pool.submit(self.logout,token),pool.submit(auth.expire_once)]
                for job in jobs:job.result(timeout=2)
        self.assertEqual(len(auth.sessions),0)
        self.assertEqual(self.revoke.call_count,1)

    def test_port_preflight_rejects_listener_and_accepts_after_close(self):
        from audit_live import check_port_available
        listener=socket.socket();listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        listener.bind(('127.0.0.1',0));port=listener.getsockname()[1];listener.listen()
        peer=socket.create_connection(('127.0.0.1',port),timeout=1)
        accepted,_=listener.accept()
        try:
            with self.assertRaises(OSError):check_port_available(port)
            accepted.close();peer.recv(1);peer.close();listener.close()
            check_port_available(port)
        finally:
            accepted.close();peer.close();listener.close()

    def test_benchmark_original_hardlink_alias_is_rejected(self):
        import performance_test as benchmark
        with tempfile.TemporaryDirectory() as folder:
            original=Path(folder)/'performance_results.csv';original.write_text('original preserved\n')
            alias=Path(folder)/'alias.csv';alias.hardlink_to(original)
            with patch.object(benchmark,'__file__',str(Path(folder)/'performance_test.py')), \
                 patch('sys.argv',['performance_test.py','dynamic','--output',str(alias)]), \
                 patch.object(benchmark,'run_dynamic') as run:
                with self.assertRaises(SystemExit) as exited:benchmark.main()
                self.assertEqual(exited.exception.code,2)
                run.assert_not_called()
            self.assertEqual(original.read_text(),'original preserved\n')

    def test_validation_and_ip_independence(self):
        requests=[None,[],{},dict(action='LOGIN'),dict(action='LOGIN',username='',password=''),
                  dict(action='LOGIN',username=[],password='bad'),dict(action='LOGOUT',session_id=[])]
        for request in requests:self.assertFalse(auth.handle_request(request,'10.0.0.2')['ok'])
        self.assertTrue(self.login()['ok'])
        self.assertTrue(self.login('10.0.0.2')['ok'])

    def test_lockout_exact_threshold_boundary_and_success_reset(self):
        bad=dict(action='LOGIN',username='alice',password='bad')
        with patch.object(auth.time,'monotonic',return_value=100):
            for count in (1,2):
                self.assertEqual(auth.handle_request(bad,'10.0.0.1')['error'],'Invalid credentials')
            self.assertTrue(self.login()['ok'])
            for count in (1,2):self.assertFalse(auth.handle_request(bad,'10.0.0.1')['ok'])
            self.assertIn('locked',auth.handle_request(bad,'10.0.0.1')['error'].lower())
        with patch.object(auth.time,'monotonic',return_value=159.999):self.assertFalse(self.login()['ok'])
        with patch.object(auth.time,'monotonic',return_value=160):self.assertTrue(self.login()['ok'])

    def test_same_ip_and_different_ip_concurrent_sessions(self):
        addresses=['10.0.0.1','10.0.0.1','10.0.0.2','10.0.0.2','10.0.0.5','10.0.0.6']
        with ThreadPoolExecutor(max_workers=6) as pool:results=list(pool.map(self.login,addresses))
        tokens=[result['session_id'] for result in results]
        self.assertEqual(len(set(tokens)),6)
        with ThreadPoolExecutor(max_workers=6) as pool:
            results=list(pool.map(lambda item:self.logout(*item),zip(tokens,addresses)))
        self.assertTrue(all(result['ok'] for result in results));self.assertEqual(len(auth.sessions),0)

    def test_logout_failure_retries_after_recovery(self):
        token=self.login()['session_id'];self.revoke.side_effect=OSError('offline')
        self.assertFalse(self.logout(token)['ok']);self.assertIn(token,auth.sessions)
        self.revoke.side_effect=None;self.assertTrue(self.logout(token)['ok'])
        self.assertFalse(self.logout(token)['ok'])

    def test_client_failures_have_nonzero_status_and_cleanup(self):
        for fault in ['auth_unavailable','rejected','service_unavailable','wrong_service','logout_rejected','logout_unavailable']:
            with self.subTest(fault=fault),contextlib.ExitStack() as stack:
                request=stack.enter_context(patch.object(client,'send_auth_request'))
                service=stack.enter_context(patch.object(client,'access_protected_service',return_value='ACCESS GRANTED: Demo protected data'))
                if fault=='auth_unavailable':request.side_effect=ConnectionRefusedError
                elif fault=='rejected':request.return_value={'ok':False}
                else:
                    request.side_effect=[{'ok':True,'session_id':'test-only-token'},
                                         {'ok':False} if fault=='logout_rejected' else
                                         ConnectionRefusedError() if fault=='logout_unavailable' else {'ok':True}]
                    if fault=='service_unavailable':service.side_effect=ConnectionRefusedError
                    if fault=='wrong_service':service.return_value='ERROR'
                with contextlib.redirect_stdout(io.StringIO()),self.assertRaises(SystemExit) as exited:client.main()
                self.assertEqual(exited.exception.code,1)
                if fault not in ['auth_unavailable','rejected']:self.assertEqual(request.call_count,2)

    def test_all_signed_command_fields_are_bound(self):
        key=secrets.token_bytes(32);challenge=control.new_challenge()
        value=control.sign_request('ALLOW 10.0.0.1 10.0.0.4 8080 60',challenge,key)
        for command in ['ALLOW 10.0.0.2 10.0.0.4 8080 60','ALLOW 10.0.0.1 10.0.0.5 8080 60',
                        'ALLOW 10.0.0.1 10.0.0.4 8081 60','ALLOW 10.0.0.1 10.0.0.4 8080 61',
                        'REVOKE 10.0.0.1 10.0.0.4 8080']:
            self.assertIsNone(control.verify_request(dict(value,command=command),challenge,key))

    def test_crypto_bounded_deterministic_mutations(self):
        rng=random.Random(2432026);key=secrets.token_bytes(32);challenge=control.new_challenge()
        value=control.sign_request('ALLOW 10.0.0.1 10.0.0.4 8080 60',challenge,key)
        wrong=[None,[],False,0,1.2,'',{},'é','\ud800',2**200]
        for index in range(128):
            mutation=dict(value);field=rng.choice(list(value));mutation[field]=rng.choice(wrong)
            try:result=control.verify_request(mutation,challenge,key)
            except (ValueError,UnicodeError,TypeError,OverflowError):result=None
            self.assertIsNone(result)

    def test_frame_exact_boundary_overflow_coalescing_and_eof(self):
        for limit in [1024,2048,4096]:
            for delta in [-1,0,1]:
                left,right=socket.socketpair()
                try:
                    right.sendall(b'x'*(limit+delta)+b'\n');right.shutdown(socket.SHUT_WR)
                    if delta<=0:self.assertEqual(len(receive_line(left,limit,.5)),limit+delta)
                    else:
                        with self.assertRaises(ValueError):receive_line(left,limit,.5)
                finally:left.close();right.close()
        for frame,expected in [(b'\n',''),(b'first\nsecond\n','first'),(b'',None)]:
            self.assertEqual(receive_line(ScriptedSocket([frame]),20,.5),expected)

    def test_missing_key_file_and_directory_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            for path in [Path(folder)/'missing',Path(folder)]:
                with patch.dict(os.environ,{'SDN_CONTROL_SECRET_FILE':str(path)}):
                    with self.assertRaises((OSError,ValueError)):control.load_secret()

    def test_topology_preflight_refuses_existing_resources(self):
        # System Python supplies Mininet; no privileged invocation occurs here.
        import subprocess,sys
        code='''import topology
from unittest.mock import patch,Mock
with patch.object(topology.subprocess,"run",return_value=Mock(returncode=0)), patch.object(topology,"Mininet") as net:
 try:topology.run()
 except RuntimeError:pass
 else:raise AssertionError("existing bridge was accepted")
 net.assert_not_called()
'''
        p=subprocess.run(['/usr/bin/python3','-c',code],cwd=Path(__file__).parent,capture_output=True,timeout=10)
        self.assertEqual(p.returncode,0)



class ControllerMasterTests(unittest.TestCase):
    def setUp(self):
        import controller
        from test_controller_audit import Datapath
        self.module=controller;self.dp=Datapath()
        self.app=controller.AuthAccessController.__new__(controller.AuthAccessController)
        self.app.logger=logging.getLogger('master-controller')
        self.app.datapaths={1:self.dp};self.app.pending_operations={}

    def test_missing_barrier_times_out_and_cleans_pending(self):
        operation=self.app._begin_operation(self.dp)
        with patch.object(self.module,'BARRIER_TIMEOUT_SECONDS',.02):
            self.assertEqual(self.app._finish_operation(self.dp,operation),'ERR switch confirmation timed out')
        self.assertFalse(self.app.pending_operations)

    def test_flow_errors_correlate_only_known_xids(self):
        from types import SimpleNamespace
        op=self.app._begin_operation(self.dp);op['flow_xids']={12}
        for xid in [11,12]:
            msg=SimpleNamespace(datapath=self.dp,xid=xid,type=5,code=0)
            self.app.error_msg_handler(SimpleNamespace(msg=msg))
        self.assertEqual(len(op['errors']),1)

    def test_switch_disconnect_wakes_pending_waiter(self):
        from types import SimpleNamespace
        op=self.app._begin_operation(self.dp);op['event']=Mock()
        self.app.switch_state_handler(SimpleNamespace(datapath=self.dp,state=self.module.DEAD_DISPATCHER))
        self.assertNotIn(1,self.app.datapaths);op['event'].set.assert_called_once()
        self.assertTrue(op['errors'])

    def test_reconnect_clears_owned_grants_and_orders_deny_first(self):
        from types import SimpleNamespace
        self.app.switch_features_handler(SimpleNamespace(msg=SimpleNamespace(datapath=self.dp)))
        delete,deny,normal=self.dp.messages
        self.assertEqual(delete.cookie,self.module.ALLOW_COOKIE)
        self.assertEqual(delete.cookie_mask,self.module.COOKIE_MASK)
        self.assertEqual(delete.command,self.dp.ofproto.OFPFC_DELETE)
        self.assertEqual(deny.priority,100);self.assertEqual(normal.priority,0)

    def test_wildcard_binding_rejected_and_key_cli_wrong_cwd(self):
        import subprocess,sys
        root=Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory() as folder:
            key=Path(folder)/'control.key'
            generated=subprocess.run([sys.executable,str(root/'control_security.py'),'--generate-key',str(key)],cwd=folder,capture_output=True,timeout=10)
            self.assertEqual(generated.returncode,0);self.assertEqual(key.stat().st_mode&0o777,0o600)
            env=dict(os.environ,SDN_CONTROL_SECRET_FILE=str(key),SDN_CONTROL_HOST='0.0.0.0',PYTHONDONTWRITEBYTECODE='1')
            result=subprocess.run([sys.executable,'-c',f'import sys;sys.path.insert(0,{str(root)!r});from controller import AuthAccessController;AuthAccessController()'],cwd=folder,env=env,capture_output=True,timeout=20)
            self.assertNotEqual(result.returncode,0)


class ControlHandlerMasterTests(unittest.TestCase):
    def setUp(self):
        import controller
        self.module=controller
        self.app=controller.AuthAccessController.__new__(controller.AuthAccessController)
        self.app.control_key=secrets.token_bytes(32)
        self.app.control_slots=threading.BoundedSemaphore(32)
        self.app.command_lock=threading.Lock()
        self.app.process_command=Mock(return_value='OK')
        self.app.logger=logging.getLogger('master-handler')

    def exchange(self,build,peer='10.0.0.3'):
        left,right=socket.socketpair()
        worker=threading.Thread(target=self.app.handle_control_client,args=(right,(peer,1234)))
        worker.start()
        try:
            greeting=receive_line(left,512,1)
            if greeting.startswith('ERR '):return greeting
            frame=build(json.loads(greeting))
            left.sendall(frame+b'\n')
            return receive_line(left,1024,2)
        finally:
            left.close();worker.join(3)
            self.assertFalse(worker.is_alive())

    def test_real_handler_rejects_duplicate_and_unknown_envelopes(self):
        command='ALLOW 10.0.0.1 10.0.0.4 8080 60'
        def duplicate(challenge):
            value=control.sign_request(command,challenge,self.app.control_key)
            return json.dumps(value).encode()[:-1]+b',"v":1}'
        self.assertEqual(self.exchange(duplicate),'ERR authentication failed')
        self.app.process_command.assert_not_called()
        self.assertEqual(self.exchange(lambda c:b'{}'),'ERR authentication failed')
        self.app.process_command.assert_not_called()

    def test_valid_then_cross_connection_and_concurrent_replay(self):
        capture=[]
        def signed(challenge):
            frame=json.dumps(control.sign_request('ALLOW 10.0.0.1 10.0.0.4 8080 60',challenge,self.app.control_key)).encode()
            capture.append(frame);return frame
        self.assertEqual(self.exchange(signed),'OK')
        self.app.process_command.assert_called_once()
        self.app.process_command.reset_mock()
        with ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(lambda _:self.exchange(lambda c:capture[0]),range(2)))
        self.assertEqual(results,['ERR authentication failed']*2)
        self.app.process_command.assert_not_called()

    def test_peer_and_capacity_gate_before_dispatch(self):
        self.assertEqual(self.exchange(lambda c:b'{}',peer='10.0.0.2'),'ERR unauthorized peer')
        self.app.control_slots=threading.BoundedSemaphore(0)
        self.assertEqual(self.exchange(lambda c:b'{}'),'ERR busy')
        self.app.process_command.assert_not_called()

    def test_sensitive_material_not_logged_on_rejection(self):
        target=io.StringIO();handler=logging.StreamHandler(target);self.app.logger.addHandler(handler)
        signatures=[]
        def bad(challenge):
            value=control.sign_request('ALLOW 10.0.0.1 10.0.0.4 8080 60',challenge,self.app.control_key)
            signatures.append(value['mac']);value['command']='changed'
            return json.dumps(value).encode()
        try:self.assertEqual(self.exchange(bad),'ERR authentication failed')
        finally:self.app.logger.removeHandler(handler)
        self.assertFalse(self.app.control_key.hex() in target.getvalue())
        self.assertFalse(signatures[0] in target.getvalue())


if __name__=='__main__':unittest.main(verbosity=2)
