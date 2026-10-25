# Current Ubuntu validation — 25 October 2026

This records executed checks of the applied reader corrections, not a production security guarantee or a student viva result.

## Source identity and environment

Baseline release ZIP: `15ced75227c1bda2c6a9a4ef1b895062c6ada5111215ad421572f3ea774d57b8`.
Transferred candidate ZIP: `dd8ce0a5fa8f67a0f7e4fef6d1a06a27e52bf443be1b9f25454225096df3ca59`.
The current project matched the 33-file baseline before reconciliation. Only client.py, performance_test.py and README differed in existing files; six new candidate files were added. Later updates are evidence/docs/current data, not runtime behavior changes. Exact Python/requirements hashes are in RUNTIME_SOURCE_MANIFEST.json; the returned final ZIP manifest also hashes documentation/data.

Tested on Ubuntu 26.04 LTS in VirtualBox, kernel 7.0.0-38-generic; system Python 3.14.4, controller Python 3.11.13 and OS-Ken 3.1.1; Mininet 2.3.0, Open vSwitch 3.7.1 (DB schema 8.8.0). OVS was active. No package installation, environment reset, VM reconfiguration or dependency upgrade was performed. Existing packages were used; a newly provisioned machine was not tested.

## Executed checks

```bash
.venv311/bin/python -m unittest -v test_response_protocol test_performance_summary
.venv311/bin/python -m unittest discover -v
.venv311/bin/python -m pip check
sudo /usr/bin/python3 ./audit_live.py --output-dir <new-private-live-directory>
```

The first subset passed 15 methods. Full discovery passed 75 methods in 9.989 seconds, exit 0; all 32 Python files compiled with system Python, all non-topology modules imported with the controller interpreter, and topology imported with system Mininet. CLI help and read-only historical summarization passed. Per-file hashes link the tests to this candidate. The old readers failed the new eight-method suite in a disposable pre-change fixture; the new readers pass, with bounded strict responses and one absolute budget including connect/send/receive.

The successful normal live runner returned exit 0 with 80 checkpoint verdicts passing, including pingall 12/12, healthy-service/default deny before login, signed authorization, protected access, logout/revocation, real network expiry, h2 rejection, five-client concurrency, invalid/slow/capacity checks and controller outage/recovery. One standalone expiry script observed exit 2; its timeout was qualified using independent service liveness and actual switch rules. Existing grants survived the controller outage while installed: First no-grant observation 60.189s after stop. Immediate offline revocation is not claimed.

A separate short clean topology.py CLI demo verified private `mkdir -m 700` evidence capture, authentication and service log retention, healthy login/access/logout and h2 denial. Runtime keys were private temporary files outside source/evidence and removed; existing keys were untouched. Raw new logs remain private, with selected sanitized outputs returned separately.

Only one complete fresh 20+20 benchmark was made for this code. Current CSV/schema/statistics are verified, all observations retained; the dedicated finite static rule was removed and final deny/no-grant confirmed. Final test bridges/control/host interfaces, project services/listeners and owned processes were cleaned; the global OVS service/infrastructure was retained. No broad cleanup command was used.

An earlier normal attempt was accidentally interrupted during authentication handover before benchmarking. Its partial evidence is retained and not called a pass. Its own residual bridge/control link were removed against the empty initial snapshot, then the separate successful retry ran. No repeated extended --master audit/key-rotation matrix was needed. Earlier extensive policy/security evidence remains historical and is linked by unchanged core source hashes.

## Interpretation, omissions and remaining actions

See the external VM_COMPLETION_REPORT.md and final manifest for the independently executed ZIP/hash/extraction checks and their exact outcomes. The final package does not contain raw logs, secrets, captured tokens/envelopes, environments, caches, old backups or administrative files.

Limits remain: plaintext demo credentials/tokens; no TLS or signed ACKs; trusted VM root/HMAC holders; source-IP grants/spoofing assumptions; same-IP sessions share permission; finite grants survive outages until timeout; nonpersistent sessions; nontransactional bootstrap/lost-ACK uncertainty; bounded rather than exhaustive stress/fuzz tests; incomplete transitive/system dependency lock. Eventlet deprecation/RLock warnings are retained. No fresh throughput/iperf claim or guaranteed marks is made.

Individual student rehearsal/demo/viva and GitHub sharing remain human actions. No files were staged/committed, no remote changed, and nothing was pushed or published. Use the course-facing guides and final evidence, then decide publication separately.
