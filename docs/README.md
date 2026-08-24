# docs/

Project documentation beyond the four root files (`README.md`, `SPEC.md`, `CHANGELOG.md`,
`CONTRIBUTING.md`). Organized 2026-08-24; file moves preserve git history.

| Path | What lives here |
|---|---|
| **`DECISION-LOG.md`** | The numbered rulings (D-\*): every decision that changed the protocol, the code, or a gate, with its date and reasoning. The institutional memory |
| **`LANGUAGE.md`** | The language ruling: why Zig, the four obligations that choice activates, and what would reopen it. Also defines the metrics vocabulary (O1 conformance recording, §4 cost model) |
| **`THREAT-MODEL.md`** | Assets, adversaries (including *the model itself*), falsifiable security goals, accepted risks named rather than hidden |
| **`INTEGRATION.md`** | Operator/integrator guide: booting a node by env, CA CLI workflow, and the local control-plane API (`openapi.yaml` at root of `examples/`; stdlib Python client included) |
| **`G3-SOAK-RUNBOOK.md`** | D-092 gate G3 execution runbook: owner-run 24h adversarial soak kit (`tools/g3-soak.sh`) on dedicated hardware, co-tenancy journal, lastro receipt option, artifact list that returns for the gate receipt |
| `audits/M1-AUDIT.md` | What has been measured in M1 and how: marker-by-marker keying audit, mutation rounds, attack-surface budget, correcting addenda |
| `audits/KEYING-AUDIT.md` | Keying audit record |
| `audits/CRYPTO-REVIEW-BRIEF.md` | The 2026-08-20 crypto review brief + findings register (F1-F14) and dispositions. Per D-092 G1 this is the pre-audit baseline for the future independent composition review, not the review itself |
| `audits/INCIDENTS.md` | Empirical incident records feeding the threat model |
| `audits/RED-TEAM-08.md`, `audits/RED-TEAM-09.md` | Red-team round reports and their rulings |
| `planning/*-ESTIMATE.md` | Closed phase estimates: declared ahead of code, closed when measured. Kept as the prediction-vs-reality paper trail (CHANNEL, DAEMON, LEDGER, MESH, NOISE-SESSION, PHASE-B/C/D, POSTAUTH, RELAY, SCOPE, SYNC, TRANSPORT) |

Documents refer to each other by filename (house style), not relative path; search any name.
