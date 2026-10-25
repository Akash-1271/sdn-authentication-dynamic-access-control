"""Bounded Mininet security probes; never print keys, MACs or session tokens."""
import argparse
import ast
import json
from pathlib import Path
import select
import socket
import time
import controller_client
from net_protocol import receive_line


def auth_request(request):
    with socket.create_connection(('10.0.0.3',9000),timeout=12) as conn:
        conn.sendall(json.dumps(request).encode()+b'\n')
        return json.loads(receive_line(conn,4096,12))


def login():
    tree=ast.parse(Path(__file__).with_name('auth_server.py').read_text())
    for node in tree.body:
        if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='DEMO_USERS' for t in node.targets):
            username,password=next(iter(ast.literal_eval(node.value).items()))
            return auth_request(dict(action='LOGIN',username=username,password=password))
    raise ValueError('Demo account unavailable')


def safe(response):
    return {key:('[redacted]' if key=='session_id' else value) for key,value in response.items()}


def service():
    try:
        with socket.create_connection(('10.0.0.4',8080),timeout=2) as conn:
            conn.sendall(b'GET_SECRET\n');response=receive_line(conn,4096,3)
            return dict(result='accessible',response=response)
    except socket.timeout:return dict(result='timeout')


def target_address(target):
    return {'auth':('10.0.0.3',9000,4096,10),
            'control':('10.0.0.254',9999,2048,5),
            'service':('10.0.0.4',8080,1024,5)}[target]


def connect_target(target):
    host,port,_,_=target_address(target)
    conn=socket.create_connection((host,port),timeout=3)
    if target=='control':
        greeting=receive_line(conn,512,3)
        if not greeting or greeting.startswith('ERR'):
            conn.close();raise ValueError('Probe requires the permitted control source')
    return conn


def malformed(target,case):
    _,_,limit,seconds=target_address(target);start=time.monotonic()
    with connect_target(target) as conn:
        if case=='disconnect':return dict(result='client_closed',elapsed_s=0)
        if case=='slow':
            while time.monotonic()-start < seconds+3:
                readable,_,_=select.select([conn],[],[],.1)
                if readable:
                    data=conn.recv(1024)
                    if not data:return dict(result='deadline_closed',elapsed_s=round(time.monotonic()-start,3))
                    return dict(result='response',elapsed_s=round(time.monotonic()-start,3))
                try:conn.sendall(b' ')
                except OSError:return dict(result='deadline_closed',elapsed_s=round(time.monotonic()-start,3))
                time.sleep(.2)
            return dict(result='still_open',elapsed_s=round(time.monotonic()-start,3))
        if case=='invalid_json':payload=b'{bad json}\n'
        elif case=='invalid_utf8':payload=b'\xff\n'
        elif case=='oversized':payload=b'x'*(limit+1)+b'\n'
        elif case in {'incomplete','idle'}:payload=b'{' if target=='auth' else b'PARTIAL'
        else:raise ValueError(case)
        conn.sendall(payload)
        if case=='incomplete':conn.shutdown(socket.SHUT_WR)
        conn.settimeout(seconds+3)
        data=bytearray()
        try:
            while b'\n' not in data:
                part=conn.recv(1024)
                if not part:break
                data.extend(part)
                if len(data)>4096:raise ValueError('Probe response too large')
            result='response' if data else 'eof'
        except ConnectionResetError:result='reset'
        return dict(result=result,response=data.decode('utf8','replace').strip(),elapsed_s=round(time.monotonic()-start,3))


def capacity(target):
    peers=[]
    try:
        for _ in range(32):
            conn=connect_target(target);peers.append(conn)
            if target!='control':conn.sendall(b' ')
        # Let accepted workers acquire their slots before opening the 33rd.
        time.sleep(.15)
        host,port,_,_=target_address(target)
        with socket.create_connection((host,port),timeout=3) as extra:
            response=receive_line(extra,1024,3)
        return dict(result='busy' if response and 'busy' in response.lower() else 'unexpected',connections=32)
    finally:
        for conn in peers:conn.close()


def main():
    parser=argparse.ArgumentParser();parser.add_argument('mode',choices=['login','health','service','malformed','capacity'])
    parser.add_argument('--target',choices=['auth','control','service']);parser.add_argument('--case')
    args=parser.parse_args()
    if args.mode=='login':result=safe(login())
    elif args.mode=='service':result=service()
    elif args.mode=='malformed':result=malformed(args.target,args.case)
    elif args.mode=='capacity':result=capacity(args.target)
    else:
        response=login();result={'login':safe(response)}
        if response.get('ok'):
            try:result['service']=service()
            finally:result['logout']=safe(auth_request(dict(action='LOGOUT',session_id=response['session_id'])))
        result['healthy']=bool(response.get('ok') and result.get('service',{}).get('response','').startswith('ACCESS GRANTED') and result.get('logout',{}).get('ok'))
    print(json.dumps(result),flush=True)
    if args.mode=='health' and not result['healthy']:raise SystemExit(1)


if __name__=='__main__':main()
