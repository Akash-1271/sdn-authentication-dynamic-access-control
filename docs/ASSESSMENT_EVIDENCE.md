# Assessment evidence — current Ubuntu completion

The candidate was applied to the original Ubuntu project on 25 October 2026 after checksum/manifest verification and comparison with the 33-file release. No newer Ubuntu source differed from that baseline. This is actual current VM evidence, not the earlier Windows-only result.

The official supplied rubric totals **D1 15 + D2 25 = 40 marks**. Its PDF was read again during this task. The following maps evidence to criteria, not awarded marks. Test methods, subcases and live checkpoints are different counts.

|Deliverable|Official criterion|Marks|Source/tests|Exact evidence or observation|Status|
|---|---|---:|---|---|---|
|D1|Problem Understanding & Architecture|2|README architecture; topology.py; controller.py|Current documented four-host/one-switch topology; pingall and actual flow/listener evidence.|Executable evidence verified|
|D1|TCP/UDP Socket Implementation|4|auth_server.py; client.py; protected_service.py; net_protocol.py; test_response_protocol.py; test_socket_audit.py|75-method suite; fragmented/strict/oversized/deadline response tests; real low-level TCP demo.|Executable evidence verified|
|D1|Mininet + SDN Implementation|4|topology.py; controller.py|normal_live_runner_verified.log: pingall 12/12; live flow snapshots show OpenFlow 1.3 policy and finite grant.|Executable evidence verified|
|D1|Socket–SDN Integration|3|auth_server.py; controller_client.py; controller.py|Live signed ALLOW/REVOKE, client login/service/logout and after-logout deny; barrier-ACK unit/wire tests.|Executable evidence verified|
|D1|Initial Testing & Demo|2|client.py; test_auth.py; test_concurrency.py|Current client script and clean_log_demo.log exit 0, healthy service and h2 denial, private retained logs.|Executable evidence verified|
|D2|Complete Application Functionality|4|auth_server.py; test_audit.py; test_master_verification.py|Current 75 tests and live login/logout, five clients, lockout, expiry and recovery; private auth/access logs.|Executable evidence verified|
|D2|Dynamic SDN Functionality|6|controller.py; auth_server.py|Scoped priority-200 finite grants; priority-100 default deny; logout and real expiry remove access. Unrelated-flow preservation is unchanged-policy historical master evidence.|Executable evidence verified|
|D2|Challenging Scenario / Robustness|4|test_control_security.py; test_response_protocol.py; security_live_checks.py|Current unauthorized h2, invalid control, malformed/slow/capacity checks and controller outage/recovery; old source-linked extended key-rotation/mutation cases remain historical.|Executable evidence verified|
|D2|Performance Evaluation & Comparison|5|performance_test.py; summarize_performance.py; data/performance_results_current.csv; docs/CURRENT_PERFORMANCE.md|Exactly one current full 20-dynamic/20-static batch; all rows retained, schema/statistics checked, finite static rule cleaned.|Executable evidence verified|
|D2|Documentation, Final Demo & Viva|6|README; docs/VALIDATION.md; docs/DEMO_AND_VIVA.md; docs/PERFORMANCE_EVALUATION.md|Current machine demo and documentation verified; individual student demonstration/viva and separately authorized GitHub sharing still require human action.|Human actions remain|

## Current evidence set

- Full isolated discovery: 75 methods in 9.989 seconds, exit 0 (`full_isolated_75.log`). New response/reporter subset: 15 methods, exit 0 (`new_candidate_tests.log`). No methods were dropped.
- Normal owned Mininet runner: exit 0; 80 successful checkpoint verdicts. One underlying standalone expiry timeout intentionally has observed exit 2 and is qualified by healthy-service/default-deny/no-grant evidence.
- Clean CLI/private-log demo: exit 0; `clean_log_demo.log`, `clean-log-demo/commands.json`, sanitized auth/service excerpts and final flow table. Raw logs stay private.
- Current measurements: `data/performance_results_current.csv` and `docs/CURRENT_PERFORMANCE.md`; source hashes in `docs/RUNTIME_SOURCE_MANIFEST.json`.
- Source/package identity, extraction validation and actual commands are returned in the VM completion report, final manifest and separate sanitized evidence archive.

Key current flow stages: `live-verified/unauthenticated-h1-flows.txt`, `unauthenticated-h2-flows.txt`, `outage-before-stop-flows.txt` (active finite h1 grant), `after-logout-flows.txt`, `after-real-expiry-flows.txt` and `final-flows.txt`. These are paired with service self-probes and client observations in results/commands. A timeout alone is never an enforcement pass.

An initial run was interrupted during authentication handover before any benchmark. Its partial outputs are retained privately and labeled interrupted, not passed. Only its own bridge/control link needed explicit cleanup against the saved empty initial OVS snapshot. The separate successful retry made the sole current complete benchmark. No extended --master rerun was performed.

Earlier extended master evidence is source-linked because controller.py, auth_server.py, control_security.py, controller_client.py, net_protocol.py and topology.py remained byte-identical. Historical unrelated-rule/replay/key-rotation results are not presented as newly rerun. Earlier performance rows are not measurements of the changed reader.

## Remaining human assessment and hand-in

Each student must rehearse and personally demonstrate/explain the system; `DEMO_AND_VIVA.md` is preparation, not proof of competence. The rubric requires final source/documentation sharing in GitHub, but staging, committing, remote changes and publication were not authorized or performed. Review the final package and choose publication separately. No numerical marks, oral pass or production security certification is claimed. The rubric does not mandate a specific slide/report template.
