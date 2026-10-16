# Decision Ledger — Intended vs Recovered Design

**Implementation evidence:** `751c13e39cf8679628d4c1806a785d3f83840a79`  
**Compared:** 2026-10-17

This comparison checks the hand-written V0.1 design against the code-derived implementation described in `generated/EDD.md`.

| Design claim | Recovered implementation | Result |
|---|---|---|
| one reusable job: portable tamper-evident decision history | one CLI + one `internal/ledger` package; no application workflow/projection layer | **MATCH** |
| Go 1.26 baseline | `go.mod` declares 1.26 | **MATCH** |
| standard-library only | no third-party modules/imports | **MATCH** |
| append-only JSONL representation | append writes one JSON object plus newline; no update/delete API exists | **MATCH** |
| human signs decision before chain position | `RecordDigest` excludes signatures, sequence and previous hash | **MATCH** |
| Ed25519 human provenance | maker/confirmer signatures verified over record digest | **MATCH** |
| sequence + previous hash bind history | `chainCore` and verifier enforce monotonic sequence/linkage | **MATCH** |
| server signs chain-bound entry | server Ed25519 signature covers computed entry hash | **MATCH** |
| configured server public/private key must match | explicit byte comparison before append | **MATCH** |
| verify complete history before append | `verifiedTail` calls full `Verify` before reading tail | **MATCH** |
| maker/confirmer and explicit self-approval rules | enforced by `validateRecord` | **MATCH** |
| unconfirmed records cannot carry misleading confirmation metadata | confirmer/signature/self-approval fields rejected unless confirmed | **MATCH** |
| live/exercise separation | incident and item modes must match | **MATCH** |
| explicit time trust label | only `trusted|drifting|untrusted` accepted | **MATCH** |
| 4 MiB format limit | append refuses oversize before file open; verifier scanner uses same bound plus headroom | **MATCH** |
| deterministic refusal distinct from operational error | `ErrRefused`/`IsRefusal`; CLI maps refusal 1 vs operational 3 | **MATCH** |
| standalone verification | `Verify(io.Reader, Keyring)` requires public keys only | **MATCH** |
| no hidden database/network dependency | none exists in module | **MATCH** |
| fsync after append | `File.Sync()` follows write | **MATCH** |
| single-writer operation | no lock/CAS around verify-tail + append | **MATCH — DELIBERATE LIMIT** |
| forensic chain of custody / trusted timestamp / HSM | absent | **NOT IMPLEMENTED — DELIBERATE LIMIT** |
| constrained-hardware runtime benchmark | ARM64 build is proven; runtime performance is unmeasured | **UNKNOWN / FUTURE BENCHMARK** |
| external key governance/revocation | keyring is supplied; custody/policy is external | **UNKNOWN / EXTERNAL** |

## Result

The V0.1 implementation matches the intended design and makes the critical cryptographic boundary concrete: humans sign the decision content, while the server binds that signed decision to its final chain position.

No material design mismatch was found. The important residual risks are explicit rather than hidden: one writer per file, external key governance, external time trust and no claim of forensic chain-of-custody status.
