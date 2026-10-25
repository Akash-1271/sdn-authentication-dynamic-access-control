# Performance evaluation

Batch label: Ubuntu 2026-10-25; applied Windows reader fixes; source identity docs/RUNTIME_SOURCE_MANIFEST.json

Input SHA-256: `34d7243ca1716fd1f554a658685a091fd24a2257327bcfb241410952f1fc83be`

Validated rows: 40. All observations retained.

| Mode | Metric (ms) | Trials | Mean | Median | Minimum | Maximum |
|---|---|---:|---:|---:|---:|---:|
| dynamic | login_ms | 20 | 5.7369 | 4.9280 | 2.9160 | 16.4240 |
| dynamic | service_rtt_ms | 20 | 309.6386 | 1.4515 | 0.4070 | 1052.8410 |
| dynamic | login_to_access_ms | 20 | 315.4083 | 8.9445 | 5.2400 | 1055.7660 |
| static | service_rtt_ms | 20 | 1.2762 | 1.1660 | 0.6970 | 2.9470 |

Service transaction time includes TCP connection setup and application response.
Compare service_rtt_ms across modes. Static login/total fields are not applicable.
Login/control and login-to-access measure additional dynamic authorization work.
A mean or median from one ordered VM batch does not establish a general speed advantage.
The caller-provided batch label is not proof of the tested source version; retain its manifest.

## Observations over 100 ms (retained, not discarded)

- dynamic, trial 4, service_rtt_ms: 1043.752 ms
- dynamic, trial 4, login_to_access_ms: 1047.959 ms
- dynamic, trial 7, service_rtt_ms: 1052.841 ms
- dynamic, trial 7, login_to_access_ms: 1055.766 ms
- dynamic, trial 9, service_rtt_ms: 1052.374 ms
- dynamic, trial 9, login_to_access_ms: 1055.379 ms
- dynamic, trial 10, service_rtt_ms: 1013.743 ms
- dynamic, trial 10, login_to_access_ms: 1018.001 ms
- dynamic, trial 16, service_rtt_ms: 1006.127 ms
- dynamic, trial 16, login_to_access_ms: 1010.341 ms
- dynamic, trial 18, service_rtt_ms: 1007.268 ms
- dynamic, trial 18, login_to_access_ms: 1010.402 ms
