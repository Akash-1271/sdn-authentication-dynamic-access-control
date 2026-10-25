"""Additional owned-network checks invoked by audit_live; no broad cleanup."""
import json
from pathlib import Path
import sys
import time


def run(net,out,record,host_command,flows,start_controller,stop,controller):
    root=Path(__file__).resolve().parent
    def probe(host,mode,*extra):
        code,text=host_command(net[host],[sys.executable,'-u',str(root/'security_probe.py'),mode,*extra],timeout=20)
        record(f'{host}-{mode}-'+('-'.join(extra) or 'request'),text,code)
        return json.loads(text)
    def table(label):
        text=flows();(out/(label+'-flows.txt')).write_text(text)
        return text
    def deny(label):
        remote=probe('h1','service');local=probe('h_srv','service');text=table(label)
        record(label,json.dumps(dict(client=remote,service_self=local)),
               0 if remote['result']=='timeout' and local.get('response','').startswith('ACCESS GRANTED')
               and 'priority=200' not in text and 'priority=100' in text else 1)
    def health(label):
        result=probe('h1','health');text=table(label)
        if not result['healthy'] or 'priority=200' in text:raise RuntimeError('Recovery failed')
    login=probe('h1','login')
    if not login.get('ok') or login['lease_seconds']!=60:raise RuntimeError('Expected normal 60-second lease')
    code,output=host_command(net['h2'],['env','CONTROL_SECURITY_ATTACK=1',sys.executable,
                                      str(root/'test_control_security.py')],timeout=15)
    record('h2-cannot-revoke-active-h1',output,code)
    if not probe('h1','service').get('response','').startswith('ACCESS GRANTED'):raise RuntimeError('Initial service failure')
    table('outage-before-stop');stop(controller);start=time.monotonic()
    # Stop new-auth attempts first to distinguish token denial from existing access.
    for host in ['h1','h2']:
        result=probe(host,'login')
        if result.get('ok') or 'Controller unavailable' not in result.get('error',''):raise RuntimeError('Unexpected outage login')
    for offset in [0,20,50]:
        time.sleep(max(0,start+offset-time.monotonic()))
        result=probe('h1','service');text=table(f'outage-{offset}s')
        record(f'existing-access-outage-{offset}s',json.dumps(result),
               0 if result.get('response','').startswith('ACCESS GRANTED') and 'hard_timeout=60' in text else 1)
    while 'priority=200' in table('outage-expiry'):
        if time.monotonic()-start>72:raise RuntimeError('Grant did not expire')
        time.sleep(1)
    record('outage-hard-timeout',f'First no-grant observation {time.monotonic()-start:.3f}s after stop')
    deny('outage-expired-deny')
    controller=start_controller()
    if not net.waitConnected(timeout=15):raise RuntimeError('Switch recovery failed')
    time.sleep(.3);deny('outage-restored-deny');health('outage-restored-health')
    for case in ['invalid_json','invalid_utf8','incomplete','oversized','disconnect','idle','slow']:
        jobs=[]
        for target,host in [('auth','h2'),('control','h_auth'),('service','h_srv')]:
            argv=[sys.executable,'-u',str(root/'security_probe.py'),'malformed','--target',target,'--case',case]
            proc=net[host].popen(argv,stdout=-1,stderr=-2,text=True)
            jobs.append((proc,target))
        try:
            if case=='slow':time.sleep(1);health('during-slow-input')
            for proc,target in jobs:
                try:output,_=proc.communicate(timeout=17)
                except Exception:
                    proc.kill();proc.communicate();raise
                record(f'malformed-{target}-{case}',output,proc.returncode)
                result=json.loads(output)
                if result['result']=='still_open':raise RuntimeError('Absolute deadline not enforced')
                if case=='slow' and result['elapsed_s']>({'auth':10,'control':5,'service':5}[target]+1.5):
                    raise RuntimeError('Slow input exceeded absolute deadline tolerance')
        finally:
            for proc,_ in jobs:
                if proc.poll() is None:proc.terminate();proc.wait(5)
        health('after-'+case)
    for target,host in [('auth','h2'),('control','h_auth'),('service','h_srv')]:
        result=probe(host,'capacity','--target',target)
        if result['result']!='busy':raise RuntimeError('Capacity was not bounded')
        time.sleep(.15);health('after-capacity-'+target)
    deny('after-security-robustness')
    return controller
