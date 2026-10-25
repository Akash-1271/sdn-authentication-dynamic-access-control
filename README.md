# SDN-Based Authentication and Dynamic Access Control

Team 1, Project 2: Authentication and Network Access Control. This student project combines Python TCP sockets, OS-Ken 3.1.1, OpenFlow 1.3, Mininet and Open vSwitch. It demonstrates application login controlling temporary access to a protected TCP service.

This revision was reconciled and validated in the original Ubuntu VM on 25 October 2026. All **75 isolated methods passed**, the current normal Mininet run and a clean CLI/private-log demo passed, and one fresh 20-dynamic/20-static batch was measured. See [validation](docs/VALIDATION.md), [assessment evidence](docs/ASSESSMENT_EVIDENCE.md), [current results](docs/CURRENT_PERFORMANCE.md), [performance method](docs/PERFORMANCE_EVALUATION.md) and [demo/viva guide](docs/DEMO_AND_VIVA.md). Individual viva/rehearsal and later repository sharing remain human actions.

## Architecture

| Component | Address | Purpose |
|---|---|---|
| h1 | 10.0.0.1 | Authorized-client demo |
| h2 | 10.0.0.2 | Unauthorized and lockout tests |
| h_auth | 10.0.0.3:9000 | Authentication server |
| h_srv | 10.0.0.4:8080 | Protected GET_SECRET service |
| Ubuntu management veth | 10.0.0.254:9999 | Authenticated custom control listener |
| OS-Ken OpenFlow endpoint | 127.0.0.1:6653 | Switch/controller connection |

The four hosts connect to one OVS switch, s1. `ctrlroot0`/`ctrlovs0` connect the Ubuntu root namespace to the emulated LAN. TCP port 9999 is a custom application protocol, distinct from OpenFlow on 6653. REST is not used.

Table 0 uses priority 200 for source-specific TCP grants to 10.0.0.4:8080, priority 100 for the default protected-service drop, and priority 0 for OVS NORMAL forwarding. ARP, ICMP and other traffic can pass. Grant cookie `0x53444e4155544801` scopes strict deletion to this application's rules. An OpenFlow barrier plus correlated errors confirms switch processing; actual service access needs a separate probe.

Default user-session lease and failed-login lockout are **60 seconds**, with a **three-attempt threshold**. Tokens use `secrets.token_urlsafe(32)` and are bound to the observed client IP. Concurrent sessions from the same IP share one switch rule. Login/logout/expiry transitions are serialized; the remaining session lifetime is restored when one overlapping session ends. Failed revocations remain retryable. The expiry sweep runs every second.

## Required environment

Run the commands below from your clone root, for example `cd /path/to/cn-project-fallback`. Open every demo terminal in that same directory. This VM's previously tested checkout is `/home/akash/cn-project-fallback`; source paths are derived from their own files. A new machine must already have a trusted Python 3.11 interpreter, system-Python Mininet, Open vSwitch with its service running, and the `ip`, `ovs-vsctl` and `ovs-ofctl` tools. Then create the controller environment in the clone:

```bash
python3.11 -m venv .venv311
.venv311/bin/python -m pip install -r requirements.txt
.venv311/bin/python -m pip check
```

These provisioning commands are for a new machine; do not recreate the working VM environment during a demo. Full transitive dependency/system-package reproducibility is not established by the single OS-Ken pin.

The existing controller environment is `.venv311` (Python 3.11.13, OS-Ken 3.1.1); the Mininet topology/applications use system Python. `requirements.txt` pins OS-Ken, but does not lock all transitive/system packages. No new dependency is needed for the security code: HMAC, SHA-256, sockets, threading and secrets are Python standard-library modules.

Do not recreate an already working environment. On a new installation, provision Mininet, OVS and a Python 3.11 virtual environment using the approved installation guide, then install `requirements.txt`. Package/system installation is a separate administrator action. Eventlet emits a deprecation warning; this project retains the working OS-Ken framework.

## Control-key configuration

**A control key is mandatory. There is no insecure fallback.** The controller and authentication server must load the same private key file through `SDN_CONTROL_SECRET_FILE`. This is separate from demo-user passwords and session tokens.

Generate a random 256-bit key in a private runtime directory outside the repository. For this Ubuntu desktop account, for example:

```bash
export SDN_CONTROL_SECRET_FILE="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/sdn-control.key"
python3 control_security.py --generate-key "$SDN_CONTROL_SECRET_FILE"
```

The generator creates a new mode-0600 file and refuses to overwrite an existing file. If your key already exists, reuse it; do not run generation again over it. The file contains 64 hex characters. Missing, malformed, obviously weak, symlinked or group/world-readable key files are rejected. Never print the contents, pass the key value as a command argument, add it to Git, or include it in an archive. `*.key`, `*.secret` and `.env*` are ignored as defense in depth. The environment contains only the path.

Use the same private key path in both components. The Mininet example below uses `/run/user/1000`; replace `1000` with the result of `id -u` in your desktop terminal, and match any different runtime path selected above. A terminal export does not automatically configure an already running Mininet host. Runtime directories may be cleared on logout/reboot; generate/reconfigure a key for the next demo if absent. Rotation requires configuring and restarting both components with the new key. The controller loads its key at startup; the control client validates/reads it for each command.

## Clean startup and demo

Inspect current listeners, interfaces and `ovs-vsctl show` first. Do not terminate unrelated processes or run broad `mn -c`. The topology refuses pre-existing s1/control-interface names. Resolve inspected stale state only with explicit approval.

**Start the topology before the controller.** This order creates 10.0.0.254 before the listener tries to bind to it. A temporary warning that the remote controller is not yet running is expected.

Terminal A:

```bash
sudo /usr/bin/python3 topology.py
```

Leave Mininet open. Terminal B, after creating/reusing the private key:

```bash
export SDN_CONTROL_SECRET_FILE="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/sdn-control.key"
.venv311/bin/osken-manager --ofp-listen-host 127.0.0.1 --ofp-tcp-listen-port 6653 controller.py
```

Default custom-listener bind is **10.0.0.254:9999**, and the only permitted source is **10.0.0.3** (h_auth). `SDN_CONTROL_HOST` and `SDN_CONTROL_ALLOWED_PEER` can select a specific IPv4 address for controlled isolated tests; wildcard bind 0.0.0.0 is rejected. Binding alone is not authentication: the HMAC check remains mandatory. h2 can establish a TCP connection to the shared management LAN address but receives `ERR unauthorized peer` and cannot execute commands.

At Mininet, verify `h1 pwd` shows the clone root (host shells inherit the topology working directory), then start the service and authentication server once. Substitute your desktop UID/runtime key path as described above:

Choose a new evidence directory outside the clone for each demonstration. Replace
`UNIQUE` consistently below; continue only if the exclusive `mkdir` succeeds.
The service access log and authentication logs will then remain available for the
examiner without entering the source package.

```text
sh mkdir -m 700 /tmp/sdn-demo-UNIQUE
h_srv python3 -u ./protected_service.py > /tmp/sdn-demo-UNIQUE/service.log 2>&1 &
h_auth env AUTH_LOG_FILE=/tmp/sdn-demo-UNIQUE/authentication.log SDN_CONTROL_SECRET_FILE=/run/user/1000/sdn-control.key python3 -u ./auth_server.py > /tmp/sdn-demo-UNIQUE/auth-console.log 2>&1 &
```

The root authentication process can read the private file owned by your desktop account. Capture only logs/output, not the key. `AUTH_LOG_FILE` can select a separate authentication log; default is local ignored security.log. Record the PID printed for each background job; `h_srv echo $!` and `h_auth echo $!` immediately afterward also show those job PIDs.

Demo commands:

```text
pingall
h1 python3 ./test_auth.py
h1 python3 ./test_concurrency.py
h_auth env SDN_CONTROL_SECRET_FILE=/run/user/1000/sdn-control.key python3 ./test_controller_client.py
h1 python3 ./client.py
h2 python3 ./test_lockout_network.py
```

The client logs in, requests protected data and logs out. Verify blocked access before/after with independent h_srv self-access and actual switch flows. A timeout by itself is inconclusive. `test_network.py` and `test_real_expiry.py` therefore return exit 2 on a standalone timeout.

For a denial/expiry demonstration, run these from Mininet while the services are healthy:

```text
h_srv python3 -c 'from client import access_protected_service; print(access_protected_service())'
h2 python3 ./test_network.py
h1 python3 ./client.py
h1 python3 ./test_network.py
h1 python3 ./test_real_expiry.py
h_srv python3 -c 'from client import access_protected_service; print(access_protected_service())'
sh ovs-ofctl -O OpenFlow13 dump-flows s1
```

`client.py` demonstrates grant, protected access and confirmed logout. The expiry script first proves access, then waits the advertised lease plus two seconds (normally 62 seconds). Its timeout exits 2, intentionally **inconclusive alone**. Qualify both denial timeouts using successful service self-access and a priority-100 protected-service drop with no source-specific priority-200 grant. During the expiry script's wait, a separate terminal can inspect the temporary priority-200 `hard_timeout=60` rule with `sudo ovs-ofctl -O OpenFlow13 dump-flows s1`. After expiry/logout, inspect that it is gone. The owned live runner automates these combined checks.

For shutdown, verify the recorded background PIDs still identify your auth/service commands (`h_auth ps -p <auth-pid> -o pid,args` and the equivalent for h_srv), then send `h_auth kill -TERM <auth-pid>` and `h_srv kill -TERM <service-pid>`. Stop your foreground controller with Ctrl+C, then type `exit` at Mininet. The topology removes its own control link and switch. Inspect listeners/interfaces afterward; do not use broad `pkill`, `killall` or `mn -c`.

## Authenticated control protocol

Each connection processes exactly one request. Plaintext bare ALLOW/REVOKE requests are no longer accepted.

1. After checking the permitted peer and connection capacity, the controller sends a bounded newline-framed JSON challenge with version, timestamp and a fresh 256-bit random nonce.
2. `controller_client.py` includes that challenge and the ALLOW/REVOKE command in a canonical JSON payload, prefixed by a protocol domain string, and computes HMAC-SHA-256 with the shared key.
3. The controller checks field types/limits, the exact connection's nonce and timestamp, the 30-second freshness window, and the MAC with `hmac.compare_digest`. Only then does it call the existing rule-operation code.
4. The response remains `OK` or `ERR <reason>`, terminated by newline. A valid MAC does not bypass command/IP/port/lease validation.

Authenticated command semantics remain:

```text
ALLOW <client_ip> 10.0.0.4 8080 <lease_seconds>
REVOKE <client_ip> 10.0.0.4 8080
```

A captured signed request cannot be reused against a different connection's challenge, including after restart. The second frame on the same connection is not executed. This avoids a growing global nonce cache and nonce-retention/restart holes: only a single challenge is retained per active handler. At most 32 control handlers are admitted. Clock checks bound freshness, while monotonic message deadlines work independently of wall-clock adjustments.

Keys, MACs, tokens and complete control payloads are not logged. Error messages do not echo the received signed envelope. There is no TLS or confidentiality; HMAC authenticates the control request, not the entire transport. Acknowledgements are not signed. Deployments requiring resistance to an on-path attacker should use authenticated encrypted transport rather than treating this classroom channel as production security.

## Message and resource limits

| Listener/client | Maximum frame content | Absolute receive budget | Concurrent handlers |
|---|---:|---:|---:|
| Authentication | 4096 bytes | 10 seconds | 32 |
| Control envelope | 2048 bytes; command at most 1024 | 5 seconds including challenge exchange | 32 |
| Protected service | 1024 bytes | 5 seconds | 32 |
| Controller client | 512-byte challenge, 1024-byte acknowledgement | One 8-second operation budget | One connection per command |
| Demo client response | 4096 bytes | Auth 5 seconds; service 3 seconds, including connection time | One connection per request |
| Benchmark response | 4096 bytes | 5 seconds, including connection time | Sequential trials |

Deadlines use monotonic time and shrink each recv timeout to the remaining budget. A trickle of bytes does not restart the deadline. New connections above capacity get a brief busy response and close; no additional application worker is started. The OS TCP backlog remains separate. Incomplete, oversized, invalid or disconnected peers are closed and their slots released. Some malformed input gets a closed connection rather than a structured response. One newline-delimited frame is handled; pipelined extra frames are ignored on close.

## Controller outage behavior

New logins are denied when the controller is unavailable. **Existing switch grants can remain usable until their installed hard timeout.** Stopping OS-Ken does not immediately delete OVS rules. The previous targeted run observed an existing 60-second rule disappear about 59.3 seconds after controller stop because it had already aged before the stop.

The live regression repeats this distinction using the normal 60-second lease, observes successful transactions while the rule remains, verifies expiry with service/flow evidence, restarts OS-Ken and checks recovery/default deny. Cookie-owned grants are cleared on reconnect; a client may need to log in again. Legacy cookie-zero rules from older versions are not covered by the new cookie filter and need explicit inspection before an upgrade demo.

The existing maximum accepted lease is 3600 seconds; normal login still requests 60. Shorter leases/periodic renewal could reduce the outage exposure window, at the cost of more control traffic/barriers and earlier loss of valid access during outages. No default lease, watchdog or major outage-policy change has been implemented. Instantaneous offline revocation is not claimed.

## Repeatable verification

Unprivileged isolated regressions (75 test methods in this candidate), including a real OS-Ken process with a simulated OpenFlow switch. The new total is 60 existing methods plus 8 response-reader and 7 offline performance-validation methods; the full 75-test Ubuntu run passed (see docs/VALIDATION.md). The child uses the active interpreter; no virtual environment is bundled in the source package:

```bash
.venv311/bin/python -m unittest discover -v
```

A deliberately privileged, owned-network run, only after reviewing and authorizing the temporary network changes:

```bash
sudo /usr/bin/python3 ./audit_live.py --output-dir /tmp/sdn-secure-audit-UNIQUE
```

Use a new output directory each run. The runner generates a private temporary key outside the repository/evidence, sets the same path for the controller/auth server, creates the management link before starting OS-Ken, and destroys its key after shutting down the test processes. It refuses existing state and never calls mn -c. The optional stale-bridge removal flag is solely for separately inspected/approved stale s1 cleanup.

The runner checks signed ALLOW/REVOKE, bare commands, forged/modified/expired/replayed requests from the permitted peer, h2 rejection, normal login/service/logout, concurrency, 60-second controller-outage expiry/recovery, malformed/slow input and capacity across all three listeners, plus temporary five-second session/lockout scenarios. Short test settings affect only dedicated processes; defaults remain 60 seconds. `test_security.py` uses `TEST_LOCKOUT_SECONDS=5` with that five-second server. Expiry tests derive their wait from the advertised lease.

`security_probe.py` and `security_live_checks.py` support those recorded lab checks; run them through the runner. `test_control_security.py` also has explicit live/attacker modes selected by environment variables, invoked from h_auth/h2 by the runner. Test-generated messages and session IDs are sanitized in evidence. It captures commands/exit codes, process records, logs and flow snapshots, verifies final default deny/no priority-200 grants, then stops only its own resources.

## Performance and preserved historical data

`performance_results.csv` remains the original 40 rows (20 dynamic, 20 static). The historical values below predate control-channel authentication and **do not measure the HMAC implementation**:

| Metric | Historical mean | Historical median |
|---|---:|---:|
| Dynamic login/control | 11.412 ms | 6.996 ms |
| Dynamic service transaction | 54.657 ms | 1.223 ms |
| Dynamic login-to-access | 66.081 ms | 8.440 ms |
| Static service transaction | 4.360 ms | 2.306 ms |

The original dynamic trial-13 service outlier is 1060.678 ms; static trial 11 is 33.418 ms. Keep outliers. Means are sensitive to them; medians describe typical observations in these batches. Service RTT in the CSV includes TCP connection setup, application handling and response, not raw propagation latency. Only service transaction time is directly comparable across dynamic and static modes. Results from one VM/ordered batch do not establish a general speed ranking.

The live runner creates a separate fresh CSV for any new 20+20-trial benchmark and removes its dedicated static rule in finally. The standalone benchmark requires a separate output path and protects the original CSV:

```bash
python3 performance_test.py dynamic --output /tmp/sdn-performance-UNIQUE.csv
python3 performance_test.py static --output /tmp/sdn-performance-UNIQUE.csv
```

It does not install static rules itself; use the live runner to manage those safely. Duplicate mode/trial IDs and malformed headers are rejected. The old exploratory 21.4 Gbit/s iperf3 story has no retained command/output and remains unverified historical context, not a reproducible result.

Validate and summarize an existing complete batch without editing its data:

```bash
python3 summarize_performance.py performance_results.csv --label 'Historical pre-HMAC batch'
python3 summarize_performance.py /path/to/fresh-performance.csv --label 'Current Ubuntu candidate; attach source manifest' --output /tmp/sdn-performance-summary-UNIQUE.md
```

The second command requires an actual measured CSV. The reporter rejects missing
or duplicate trials, unknown modes, invalid/nonfinite/negative values and nonblank
static login/total fields. It retains all observations, reports mean/median/range
in milliseconds, and refuses to overwrite an existing report or input alias.
Labels are supplied by the caller and must be backed by the measured-source
manifest. The reviewed current Ubuntu CSV is data/performance_results_current.csv; its generated report is docs/CURRENT_PERFORMANCE.md. The original historical CSV remains separate and unchanged.

## Files and submission

Core files: controller.py, controller_client.py, control_security.py, net_protocol.py, auth_server.py, protected_service.py, client.py and topology.py. Test/demo support: audit_live.py, security_live_checks.py, security_probe.py, master_live_checks.py, master_live_probe.py and all test_*.py scripts (including test_master_verification.py and test_response_protocol.py). performance_test.py handles measurements; summarize_performance.py validates/reports existing CSVs, with test_performance_summary.py covering its data-integrity behavior. The docs/ directory contains course evidence, performance methodology and viva guidance. `alice`/`123` and `bob`/`456` are intentional demo-only credentials; never reuse real account passwords. README, requirements, .gitignore and source/test files belong in a reviewed submission; virtual environments, keys, logs and old audit backups do not.

The allocation/rubric require documented architecture, TCP implementation, Mininet/SDN integration, challenging scenarios, performance comparison, a final demo and individual viva understanding. GitHub publishing is a separate manual step; these tests do not commit, push or upload. Numerical marks are not guaranteed.

## Remaining educational limitations

Hardcoded demo-user passwords and login traffic remain plaintext. Dataplane access is source-IP based, so users sharing an IP share a grant; no ingress-port/IP/ARP anti-spoofing policy is added. Default OpenFlow in this trusted lab is not TLS-authenticated. HMAC key holders can issue supported control commands; protect the key and peer configuration. Mininet hosts share the VM filesystem/kernel and often run as root: a hostile root process in a namespace can read files or bypass these assumptions. These tests model network clients, not a compromised VM administrator.

Bounded handlers/deadlines reduce resource retention; they do not prove resistance to all floods, backlog attacks or malicious payloads. The authentication state dictionaries are not a production distributed/session store. Switch rule bootstrap error recovery is not a transactional policy installer. Dependency versions are not fully locked. Retained leases during controller outages are intentional observed behavior, not immediate revocation. Use this as a verified classroom demonstration with stated limits.


## Final master verification

The optional extended lab checks are run with a fresh output directory:

```bash
sudo /usr/bin/python3 ./audit_live.py --master --output-dir /tmp/sdn-master-UNIQUE
.venv311/bin/python -m unittest discover -v
```

The normal runner remains available without `--master`. The extended mode adds bounded control-message mutations, listener-binding evidence, an unrelated-flow preservation check, fragmented requests, silent peers, controller-restart replay, foreign-IP/stale token tests, owned auth/service outages, and mismatched-key/rotation/recovery tests. Private captured envelopes/session tokens are held only in a private temporary directory outside evidence and removed afterward. It does not change normal leases, lockout defaults, addressing or protocol version.

JSON parsers reject duplicate field names and nonstandard numeric constants. Key loading rejects oversized files instead of accepting only a valid-looking prefix. Failed-login usernames are escaped and truncated in logs to prevent forged multiline records. These checks supplement the existing HMAC, deadlines and handler limits; they do not establish exhaustive fuzz or production isolation coverage.
