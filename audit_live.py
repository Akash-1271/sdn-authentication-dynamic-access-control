"""Explicitly invoked privileged integration runner. Never runs mn -c.

Use only with permission to create a temporary Mininet topology. The optional
stale-s1 removal requires separate user authorization; it is never automatic.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import tempfile
from control_security import generate_key, load_secret

ROOT = Path(__file__).resolve().parent


def check_port_available(port):
    """Reject live conflicts while permitting normal TCP TIME_WAIT reuse."""
    with socket.socket() as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind(("0.0.0.0", port))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--remove-stale-s1", action="store_true")
    parser.add_argument("--master", action="store_true", help="Run additional bounded master-verification checks")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Run through sudo/pkexec after reviewing and authorizing this script")
    # Exclusive directory creation prevents overwriting previous evidence.
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=False)
    results = []
    processes = []
    key_dir = tempfile.TemporaryDirectory(prefix="sdn-control-")
    key_path = Path(key_dir.name)/"control.key"
    generate_key(key_path)
    os.environ["SDN_CONTROL_SECRET_FILE"] = str(key_path)
    os.environ["SDN_CONTROL_HOST"] = "10.0.0.254"
    os.environ["SDN_CONTROL_ALLOWED_PEER"] = "10.0.0.3"
    os.environ["AUTH_LOG_FILE"] = str(out/"security.log")
    load_secret()
    net = None
    link_created = False

    command_events = []
    process_events = []

    def command(argv, **kwargs):
        result = subprocess.run(argv, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=kwargs.pop("timeout", 30), **kwargs)
        command_events.append({"argv": argv, "exit_code": result.returncode, "output": result.stdout})
        return result

    def flows():
        result = command(["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", "s1"])
        if result.returncode:
            raise RuntimeError(result.stdout)
        return result.stdout

    def record(name, output, code=0, observed_exit_code=None):
        results.append({"name": name, "exit_code": code, "output": output,
                        "observed_exit_code": code if observed_exit_code is None else observed_exit_code})
        (out/"results.json").write_text(json.dumps(results, indent=2))
        print(f"{name}: exit={code}", flush=True)
        if code:
            raise RuntimeError(f"{name} failed: {output}")

    def host_command(host, argv, timeout=30):
        proc = host.popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          text=True, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
        try:
            output, _ = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            raise
        command_events.append({"host": host.name, "argv": argv,
                               "exit_code": proc.returncode, "output": output})
        return proc.returncode, output

    def script(host, name, extra_env=None, allowed=(0,), timeout=30):
        argv = ["env"] + [f"{k}={v}" for k,v in (extra_env or {}).items()]
        argv += [sys.executable, "-u", str(ROOT/name)]
        code, output = host_command(host, argv, timeout)
        record(name, output, 0 if code in allowed else code, observed_exit_code=code)
        return code, output

    probe = '''import socket,sys
try:
 s=socket.create_connection(("10.0.0.4",8080),timeout=2)
 with s:
  s.settimeout(2);s.sendall(b"GET_SECRET\\n");data=s.recv(1024)
  print(data.decode().strip())
  sys.exit(0 if data.startswith(b"ACCESS GRANTED") else 12)
except socket.timeout: sys.exit(10)
except OSError as e: print(type(e).__name__);sys.exit(11)
'''

    def blocked(host, label):
        code, output = host_command(host, [sys.executable, "-c", probe])
        local_code, local_output = host_command(net["h_srv"], [sys.executable, "-c", probe])
        table = flows()
        (out/(label+"-flows.txt")).write_text(table)
        grants = [line for line in table.splitlines() if "priority=200" in line
                  and f"nw_src={host.IP()}" in line]
        deny = any("priority=100" in line and "tp_dst=8080" in line and "actions=drop" in line
                   for line in table.splitlines())
        record(label, f"client_exit={code}; service_self_exit={local_code}; deny={deny}; grants={len(grants)}",
               0 if code==10 and local_code==0 and deny and not grants else 1)

    def start_controller():
        handle = (out/f"controller-{len(processes)}.log").open("w")
        proc = subprocess.Popen([str(ROOT/".venv311/bin/osken-manager"),
            "--ofp-listen-host", "127.0.0.1", "--ofp-tcp-listen-port", "6653", str(ROOT/"controller.py")],
            cwd=ROOT, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"),
            stdout=handle, stderr=subprocess.STDOUT)
        handle.close()
        processes.append(proc)
        process_events.append({"event":"start-controller","pid":proc.pid,"argv":proc.args})
        deadline = time.monotonic()+30
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError("OS-Ken exited; inspect controller log")
            try:
                with socket.create_connection(("10.0.0.254", 9999), timeout=.5):
                    pass
                # TCP readiness and OVS's cached is_connected bit can precede
                # registration in this new OS-Ken process. Require a signed,
                # barrier-confirmed no-op for an unused source in our lab.
                readiness = (
                    f"import sys; sys.path.insert(0, {str(ROOT)!r}); from controller_client import send_revoke\n"
                    "try: send_revoke('10.0.0.253','10.0.0.4',8080)\n"
                    "except Exception: sys.exit(1)\n"
                )
                code, _ = host_command(net["h_auth"],
                                       [sys.executable, "-c", readiness], timeout=10)
                if code == 0:
                    return proc
            except OSError:
                time.sleep(.1)
        raise RuntimeError("Controller did not start")

    def stop(proc):
        if proc.poll() is None:
            process_events.append({"event":"stop-owned","pid":proc.pid,"signal":"SIGTERM"})
            proc.terminate()
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(5)
        process_events.append({"event":"owned-exit","pid":proc.pid,"returncode":proc.returncode})

    def start_service():
        handle = (out/f"service-{len(processes)}.log").open("w")
        proc = net["h_srv"].popen([sys.executable,"-u",str(ROOT/"protected_service.py")],
                                  env=dict(os.environ,PYTHONDONTWRITEBYTECODE="1"),
                                  stdout=handle,stderr=subprocess.STDOUT)
        handle.close()
        processes.append(proc)
        process_events.append({"event":"start-service","pid":proc.pid,"argv":proc.args})
        time.sleep(.25)
        return proc

    def start_auth(short=False):
        handle = (out/f"auth-{len(processes)}.log").open("w")
        env = dict(os.environ, AUTH_LOG_FILE=str(out/"security.log"), PYTHONDONTWRITEBYTECODE="1")
        env.pop("AUTH_LEASE_SECONDS", None)
        env.pop("AUTH_LOCKOUT_SECONDS", None)
        if short:
            env.update(AUTH_LEASE_SECONDS="5", AUTH_LOCKOUT_SECONDS="5")
        proc = net["h_auth"].popen([sys.executable,"-u",str(ROOT/"auth_server.py")],
                                  env=env, stdout=handle, stderr=subprocess.STDOUT)
        handle.close()
        processes.append(proc)
        process_events.append({"event":"start-auth","pid":proc.pid,"argv":proc.args,
                               "lease_seconds":5 if short else 60})
        deadline = time.monotonic()+5
        while time.monotonic() < deadline:
            code, _ = host_command(net["h1"], [sys.executable,"-c",
                'import socket;socket.create_connection(("10.0.0.3",9000),timeout=.5).close()'])
            if code == 0:
                return proc
            if proc.poll() is not None:
                raise RuntimeError("Authentication server exited")
            time.sleep(.1)
        raise RuntimeError("Authentication server did not become ready")

    try:
        for port in (6653,9999,9000,8080):
            check_port_available(port)
        before = command(["ovs-vsctl","show"])
        (out/"ovs-before.txt").write_text(before.stdout)
        if before.returncode:
            raise RuntimeError(before.stdout)
        for name in ("ctrlroot0","ctrlovs0","s1-eth1","s1-eth2","s1-eth3","s1-eth4"):
            if command(["ip","link","show",name]).returncode==0:
                raise RuntimeError(f"Existing interface {name}; refusing to alter it")
        has_bridge = command(["ovs-vsctl","br-exists","s1"]).returncode
        if has_bridge == 0:
            if not args.remove_stale_s1:
                raise RuntimeError("Existing s1 bridge; separate approval needed for removal")
            ports = command(["ovs-vsctl","list-ports","s1"])
            if not set(ports.stdout.split()).issubset({"s1-eth1","s1-eth2","s1-eth3","s1-eth4","ctrlovs0"}):
                raise RuntimeError("Unexpected s1 ports; refusing stale cleanup")
            removal = command(["ovs-vsctl","del-br","s1"])
            record("approved-stale-s1-removal", removal.stdout, removal.returncode)
        elif has_bridge != 2:
            raise RuntimeError("OVS bridge query failed")
        import topology
        from mininet.net import Mininet
        from mininet.node import OVSSwitch, RemoteController
        net = Mininet(topo=topology.AuthenticationTopology(), controller=None,
                      switch=OVSSwitch, autoSetMacs=True, build=False)
        net.addController("c0",controller=RemoteController,ip="127.0.0.1",port=6653)
        net.build()
        net.start()
        topology.setup_controller_link()
        link_created = True
        controller = start_controller()
        if not net.waitConnected(timeout=15):
            raise RuntimeError("Switch did not connect")
        loss = net.pingAll()
        record("pingall", str(loss), 0 if loss==0 else 1)
        service = start_service()
        auth = start_auth()
        blocked(net["h1"], "unauthenticated-h1")
        blocked(net["h2"], "unauthenticated-h2")
        script(net["h1"], "test_auth.py")
        script(net["h1"], "test_concurrency.py")
        script(net["h_auth"], "test_controller_client.py")
        script(net["h_auth"], "test_control_security.py", {"CONTROL_SECURITY_LIVE":"1"})
        script(net["h2"], "test_control_security.py", {"CONTROL_SECURITY_ATTACK":"1"})
        blocked(net["h1"], "after-control-security-tests")
        script(net["h1"], "client.py")
        blocked(net["h1"], "after-logout")
        from security_live_checks import run as security_checks
        controller = security_checks(net, out, record, host_command, flows,
                                     start_controller, stop, controller)
        if args.master:
            from master_live_checks import run as master_checks
            controller, auth, service = master_checks(
                net, out, record, host_command, flows, start_controller,
                start_auth, start_service, stop, controller, auth, service)
        stop(auth)
        auth = start_auth(short=True)
        script(net["h1"], "test_security.py", {"TEST_LOCKOUT_SECONDS":"5"})
        script(net["h2"], "test_lockout_network.py")
        script(net["h1"], "test_expiry.py")
        # Standalone timeout is intentionally inconclusive. Qualify it below
        # using service liveness plus the actual switch flow table.
        code, output = script(net["h1"], "test_real_expiry.py", allowed=(2,))
        if code != 2 or "Timed out after expiry" not in output:
            raise RuntimeError("Unexpected expiry result")
        blocked(net["h1"], "after-real-expiry")
        stop(controller)
        script(net["h1"], "test_controller_failure.py")
        controller = start_controller()
        if not net.waitConnected(timeout=15):
            raise RuntimeError("Switch did not reconnect")
        time.sleep(.5)
        blocked(net["h1"], "after-controller-restart")
        stop(auth)
        auth = start_auth()
        benchmark = out/"fresh-performance.csv"
        result = command([sys.executable,str(ROOT/"performance_test.py"),"dynamic","--output",str(benchmark)],timeout=120)
        record("dynamic-performance-20",result.stdout,result.returncode)
        static_cookie = "0x53444e42454e4348"
        rule = f"cookie={static_cookie},priority=200,hard_timeout=60,tcp,nw_src=10.0.0.254,nw_dst=10.0.0.4,tp_dst=8080,actions=NORMAL"
        try:
            result = command(["ovs-ofctl","-O","OpenFlow13","add-flow","s1",rule])
            record("static-rule-install", result.stdout,result.returncode)
            result = command([sys.executable,str(ROOT/"performance_test.py"),"static","--output",str(benchmark)],timeout=120)
            record("static-performance-20",result.stdout,result.returncode)
        finally:
            result = command(["ovs-ofctl","-O","OpenFlow13","--strict","del-flows","s1",
                f"cookie={static_cookie}/-1,priority=200,tcp,nw_src=10.0.0.254,nw_dst=10.0.0.4,tp_dst=8080"])
            if result.returncode:
                raise RuntimeError("Static-rule removal failed: "+result.stdout)
        table = flows()
        (out/"final-flows.txt").write_text(table)
        record("benchmark-rule-cleanup",table,0 if "priority=200" not in table and "priority=100" in table else 1)
        blocked(net["h1"], "final-h1-blocked")
    finally:
        for proc in reversed(processes):
            stop(proc)
        if net is not None:
            net.stop()
        if link_created:
            command(["ip","link","delete","ctrlroot0"])
        (out/"ovs-after.txt").write_text(command(["ovs-vsctl","show"]).stdout)
        (out/"results.json").write_text(json.dumps(results,indent=2))
        (out/"commands.json").write_text(json.dumps(command_events,indent=2))
        (out/"processes.json").write_text(json.dumps(process_events,indent=2))
        key_dir.cleanup()


if __name__ == "__main__":
    main()
