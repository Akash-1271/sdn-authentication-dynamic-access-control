"""Bounded master-verification clients. Sensitive envelopes/tokens stay private."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib,hmac,json,os,secrets,socket,time
from pathlib import Path
import control_security as control
import controller_client
from net_protocol import receive_line,decode_json
from security_probe import service,safe,login as normal_login,auth_request

COMMAND='ALLOW 10.0.0.1 10.0.0.4 8080 60'


def control_request(case,private=None):
    with socket.create_connection(('10.0.0.254',9999),timeout=3) as conn:
        greeting=receive_line(conn,512,3)
        if greeting.startswith('ERR '):return {'response':greeting}
        challenge=decode_json(greeting);key=control.load_secret()
        value=control.sign_request(COMMAND,challenge,key)
        if case=='plain':frame=COMMAND.encode()
        elif case=='empty':frame=b''
        elif case=='invalid_json':frame=b'{bad}'
        elif case=='invalid_utf8':frame=b'\xff'
        elif case=='oversized':frame=b'x'*2049
        elif case=='replay':frame=Path(private).read_bytes()
        else:
            if case=='missing_mac':value.pop('mac')
            elif case=='invalid_mac':value['mac']='0'*64
            elif case=='wrong_key':value=control.sign_request(COMMAND,challenge,secrets.token_bytes(32))
            elif case.startswith('modified_'):
                parts=COMMAND.split();index={'source':1,'destination':2,'port':3,'lease':4}[case[9:]]
                parts[index]={'source':'10.0.0.2','destination':'10.0.0.5','port':'8081','lease':'61'}[case[9:]]
                value['command']=' '.join(parts)
            elif case=='cross_command':value['command']='REVOKE 10.0.0.1 10.0.0.4 8080'
            elif case in ['expired','future','nonce','version']:
                if case=='expired':value['ts']-=31
                elif case=='future':value['ts']+=100
                elif case=='nonce':value['nonce']=secrets.token_hex(32)
                else:value['v']=2
                payload={k:value[k] for k in ['v','ts','nonce','command']}
                value['mac']=hmac.new(key,control.canonical(payload),hashlib.sha256).hexdigest()
            elif case=='missing_field':value.pop('ts')
            elif case=='extra_field':value['extra']=True
            elif case=='wrong_type':value['command']=[]
            frame=json.dumps(value,separators=(',',':')).encode()
            if case=='duplicate':frame=frame[:-1]+b',"v":1}'
            if case=='capture':
                # Captured replay material is an exclusive private temp file,
                # never placed in evidence or emitted to stdout.
                fd=os.open(private,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
                with os.fdopen(fd,'wb') as output:output.write(frame)
        if case=='truncated':
            conn.sendall(frame[:len(frame)//2]);conn.shutdown(socket.SHUT_WR)
        else:conn.sendall(frame+b'\n')
        try:response=receive_line(conn,1024,8)
        except (OSError,ValueError):response='closed'
        return {'response':response or 'closed'}


def matrix(attacker=False):
    cases=['plain','missing_mac','invalid_mac','wrong_key','modified_source','modified_destination',
           'modified_port','modified_lease','cross_command','expired','future','nonce','version',
           'missing_field','extra_field','wrong_type','duplicate','empty','truncated',
           'invalid_json','invalid_utf8','oversized']
    for case in cases:
        if attacker:
            # Source filtering should reject before any challenge/key handling.
            with socket.create_connection(('10.0.0.254',9999),timeout=3) as conn:
                try:
                    value=control.sign_request(COMMAND,control.new_challenge(),secrets.token_bytes(32))
                    if case=='missing_mac':value.pop('mac')
                    elif case=='missing_field':value.pop('nonce')
                    elif case=='extra_field':value['extra']=True
                    elif case=='wrong_type':value['command']=[]
                    elif case=='version':value['v']=2
                    elif case=='expired':value['ts']-=31
                    elif case=='future':value['ts']+=100
                    elif case=='nonce':value['nonce']='0'*64
                    elif case.startswith('modified_'):value['command']='ALLOW 10.0.0.2 10.0.0.5 8081 61'
                    elif case=='cross_command':value['command']='REVOKE 10.0.0.1 10.0.0.4 8080'
                    frame=json.dumps(value).encode()
                    if case=='plain':frame=COMMAND.encode()
                    elif case=='empty':frame=b''
                    elif case=='invalid_json':frame=b'{bad}'
                    elif case=='invalid_utf8':frame=b'\xff'
                    elif case=='oversized':frame=b'x'*2049
                    elif case=='truncated':frame=frame[:len(frame)//2]
                    elif case=='duplicate':frame=frame[:-1]+b',"v":1}'
                    conn.sendall(frame+b'\n')
                    response=receive_line(conn,512,3)
                except (OSError,ValueError):response='closed'
            assert response in ['ERR unauthorized peer','closed'],case
        else:
            response=control_request(case)['response']
            assert response=='closed' or response.startswith('ERR '),case
    return {'cases':len(cases),'rejected':len(cases),'peer':'unauthorized' if attacker else 'permitted'}


def fragmented_auth(request):
    with socket.create_connection(('10.0.0.3',9000),timeout=5) as conn:
        frame=json.dumps(request).encode()+b'\n'
        for index in range(0,len(frame),3):
            conn.sendall(frame[index:index+3]);time.sleep(.002)
        return decode_json(receive_line(conn,4096,8))


def main():
    p=argparse.ArgumentParser();p.add_argument('mode');p.add_argument('--private');p.add_argument('--case');p.add_argument('--target');args=p.parse_args()
    if args.mode=='matrix':result=matrix()
    elif args.mode=='attacker':result=matrix(True)
    elif args.mode=='allow':result={'response':controller_client.send_allow('10.0.0.1','10.0.0.4')}
    elif args.mode=='revoke':result={'response':controller_client.send_revoke('10.0.0.1','10.0.0.4')}
    elif args.mode=='capture':
        result=control_request('capture',args.private)
        controller_client.send_revoke('10.0.0.1','10.0.0.4')
    elif args.mode=='replay':result=control_request('replay',args.private)
    elif args.mode=='concurrent_replay':
        with ThreadPoolExecutor(max_workers=2) as pool:responses=list(pool.map(lambda _:control_request('replay',args.private),range(2)))
        assert all(r['response'].startswith('ERR ') for r in responses)
        result={'attempts':2,'rejected':2}
    elif args.mode=='token_capture':
        result=normal_login()
        if not result.get('ok'):raise RuntimeError('Capture login failed')
        fd=os.open(args.private,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as output:json.dump(result,output)
        result=safe(result)
    elif args.mode=='token_logout':
        token=json.loads(Path(args.private).read_text())['session_id']
        result=safe(auth_request(dict(action='LOGOUT',session_id=token)))
    elif args.mode=='fragmented_auth':
        # Obtain only documented demo credentials from the existing AST helper.
        import ast
        tree=ast.parse(Path(__file__).with_name('auth_server.py').read_text())
        users=next(ast.literal_eval(node.value) for node in tree.body if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='DEMO_USERS' for t in node.targets))
        username,password=next(iter(users.items()))
        logged=fragmented_auth(dict(action='LOGIN',username=username,password=password));result={'login_ok':logged.get('ok',False)}
        if logged.get('ok'):
            try:result['service']=service()
            finally:result['logout_ok']=fragmented_auth(dict(action='LOGOUT',session_id=logged['session_id'])).get('ok',False)
        assert result['login_ok'] and result.get('logout_ok') and result.get('service',{}).get('response','').startswith('ACCESS GRANTED')
    elif args.mode=='silent':
        host,port,budget={'auth':('10.0.0.3',9000,10),'control':('10.0.0.254',9999,5),'service':('10.0.0.4',8080,5)}[args.target]
        start=time.monotonic()
        with socket.create_connection((host,port),timeout=3) as conn:
            if args.target=='control':receive_line(conn,512,3)
            conn.settimeout(budget+3)
            data=conn.recv(1024)
        assert not data
        result={'target':args.target,'result':'silent_closed','elapsed_s':round(time.monotonic()-start,3)}
    else:raise ValueError('Unknown probe mode')
    print(json.dumps(result),flush=True)


if __name__=='__main__':main()
