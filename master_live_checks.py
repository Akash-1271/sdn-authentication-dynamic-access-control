"""Additional master checks within audit_live's already owned Mininet network."""
import json,os,socket,subprocess,sys,tempfile,time
from pathlib import Path
from control_security import generate_key


def run(net,out,record,host_command,flows,start_controller,start_auth,start_service,stop,controller,auth,service):
    root=Path(__file__).resolve().parent
    def probe(host,mode,*extra):
        argv=[sys.executable,'-u',str(root/'master_live_probe.py'),mode,*extra]
        code,text=host_command(net[host],argv,timeout=25)
        record('master-'+host+'-'+mode+('-'+extra[-1] if extra else ''),text,code)
        return json.loads(text)
    def table(label):
        text=flows();(out/(label+'-flows.txt')).write_text(text)
        return text
    def service_probe(host):
        code,text=host_command(net[host],[sys.executable,str(root/'security_probe.py'),'service'],timeout=6)
        if code:raise RuntimeError('Service probe failed')
        return json.loads(text)
    def health():
        code,text=host_command(net['h1'],[sys.executable,str(root/'security_probe.py'),'health'],timeout=15)
        record('master-legitimate-recovery',text,code)
        if not json.loads(text)['healthy']:raise RuntimeError('Health failed')
    def blocked(host,label):
        remote=service_probe(host);local=service_probe('h_srv');text=table(label)
        good=(remote['result']=='timeout' and local.get('response','').startswith('ACCESS GRANTED')
              and f'nw_src={net[host].IP()}' not in '\n'.join(line for line in text.splitlines() if 'priority=200' in line))
        record(label,json.dumps(dict(client=remote,service_self=local)),0 if good else 1)
    def connected():
        if not net.waitConnected(timeout=15):raise RuntimeError('Switch reconnect failed')
        time.sleep(.3)
    # Capture the actual socket binding while the lab is running.
    result=subprocess.run(['ss','-ltnp'],text=True,capture_output=True)
    (out/'master-listeners.txt').write_text(result.stdout)
    record('master-listener-binding',result.stdout,0 if '10.0.0.254:9999' in result.stdout and '0.0.0.0:9999' not in result.stdout else 1)
    probe('h_auth','allow')
    before=table('master-signed-allow')
    if 'hard_timeout=60' not in before or 'nw_src=10.0.0.1' not in before:raise RuntimeError('Missing grant')
    if not service_probe('h1').get('response','').startswith('ACCESS GRANTED'):raise RuntimeError('ALLOW did not enable service')
    blocked('h2','master-specific-client-only')
    probe('h_auth','matrix');probe('h2','attacker')
    if not service_probe('h1').get('response','').startswith('ACCESS GRANTED'):raise RuntimeError('Rejected command removed grant')
    probe('h_auth','revoke');blocked('h1','master-revoke-deny')
    # A harmless test-owned UDP drop must survive application REVOKE.
    cookie='0x4d41535445520001'
    argv=['ovs-ofctl','-O','OpenFlow13','add-flow','s1',f'cookie={cookie},priority=177,udp,nw_dst=10.0.0.4,tp_dst=4567,actions=drop']
    result=subprocess.run(argv,capture_output=True,text=True)
    record('master-unrelated-rule-add',result.stdout,result.returncode)
    try:
        probe('h_auth','allow');probe('h_auth','revoke')
        text=table('master-unrelated-rule-retained')
        if cookie not in text:raise RuntimeError('REVOKE removed unrelated rule')
    finally:
        result=subprocess.run(['ovs-ofctl','-O','OpenFlow13','del-flows','s1',f'cookie={cookie}/-1'],capture_output=True,text=True)
        record('master-unrelated-rule-remove',result.stdout,result.returncode)
    for host in ['h1','h2']:probe(host,'fragmented_auth')
    # Purely silent clients, separate from partial/slow input covered by baseline runner.
    jobs=[]
    for target,host in [('auth','h2'),('control','h_auth'),('service','h_srv')]:
        argv=[sys.executable,str(root/'master_live_probe.py'),'silent','--target',target]
        jobs.append((target,net[host].popen(argv,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)))
    try:
        for target,p in jobs:
            try:output,_=p.communicate(timeout=15)
            except Exception:p.kill();p.communicate();raise
            record('master-silent-'+target,output,p.returncode)
    finally:
        for _,p in jobs:
            if p.poll() is None:p.terminate();p.wait(5)
    health()
    original_key=os.environ['SDN_CONTROL_SECRET_FILE']
    with tempfile.TemporaryDirectory(prefix='sdn-master-private-') as private:
        folder=Path(private);token=folder/'session.private';envelope=folder/'capture.private'
        probe('h1','token_capture','--private',str(token))
        rejected=probe('h2','token_logout','--private',str(token))
        if rejected.get('ok'):raise RuntimeError('Foreign-IP token accepted')
        # Controller failure during REVOKE, then retry after recovery.
        probe('h_auth','capture','--private',str(envelope))
        # Capture used an overlapping direct grant. Restore application's source grant.
        probe('h_auth','allow')
        stopped_at=time.monotonic();stop(controller)
        failed=probe('h1','token_logout','--private',str(token))
        if failed.get('ok') or 'unconfirmed' not in failed.get('error',''):raise RuntimeError('Failed revoke hidden')
        if not service_probe('h1').get('response','').startswith('ACCESS GRANTED'):raise RuntimeError('Existing grant missing')
        controller=start_controller();connected()
        replay=probe('h_auth','replay','--private',str(envelope))
        if not replay['response'].startswith('ERR '):raise RuntimeError('Restart replay accepted')
        record('master-restart-replay-window',f'Replay rejected {time.monotonic()-stopped_at:.3f}s after stopping controller')
        probe('h_auth','concurrent_replay','--private',str(envelope))
        retry=probe('h1','token_logout','--private',str(token))
        if not retry.get('ok'):raise RuntimeError('REVOKE retry failed')
        token.unlink()
        blocked('h1','master-after-revoke-retry')
        # Auth restart loses token state; retain/revoke only the finite owned test flow.
        probe('h1','token_capture','--private',str(token));stop(auth)
        code,text=host_command(net['h1'],[sys.executable,str(root/'client.py')],timeout=10)
        record('master-auth-unavailable-client',text,0 if code!=0 else 1,observed_exit_code=code)
        table('master-auth-down-finite-grant')
        auth=start_auth()
        stale=probe('h1','token_logout','--private',str(token))
        if stale.get('ok'):raise RuntimeError('Restart retained undocumented token state')
        probe('h_auth','revoke');token.unlink();blocked('h1','master-auth-restarted-deny');health()
        # Protected-service outage must be an application failure, not a policy PASS.
        stop(service)
        code,text=host_command(net['h1'],[sys.executable,str(root/'client.py')],timeout=15)
        record('master-service-unavailable-client',text,0 if code!=0 and '[PASS] Protected service access succeeded' not in text else 1,observed_exit_code=code)
        service=start_service();health()
        # Mismatched key fails closed, then rotate both sides and restore original.
        rotated=folder/'rotated.key';generate_key(rotated)
        stop(auth)
        os.environ['SDN_CONTROL_SECRET_FILE']=str(rotated)
        try:
            auth=start_auth()
            code,text=host_command(net['h1'],[sys.executable,str(root/'security_probe.py'),'login'],timeout=15)
            result=json.loads(text)
            record('master-mismatched-control-key',json.dumps(result),0 if code==0 and not result.get('ok') else 1)
            if 'priority=200' in table('master-mismatched-key-deny'):raise RuntimeError('Wrong key granted flow')
            stop(controller);controller=start_controller();connected()
            health()
            replay=probe('h_auth','replay','--private',str(envelope))
            if not replay['response'].startswith('ERR '):raise RuntimeError('Old-key envelope accepted')
            record('master-key-rotation', 'Both rotated components completed legitimate login/service/logout')
        finally:
            stop(auth);stop(controller)
            os.environ['SDN_CONTROL_SECRET_FILE']=original_key
            controller=start_controller();connected();auth=start_auth()
    health();blocked('h1','master-final-deny');blocked('h2','master-final-h2-deny')
    return controller,auth,service
