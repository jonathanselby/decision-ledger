# Decision Ledger — Generated Engineering Design Document

**Evidence commit:** `751c13e39cf8679628d4c1806a785d3f83840a79`  
**Method:** code-derived review using the `codebase-to-edd` evidence discipline  
**Generated:** 2026-10-17

This document describes the implementation at the evidence commit. `PRD.md`, `EDD.md` and `FORMAT.md` are design inputs for later comparison, not evidence for the findings below.

## 1. Executive system description

**KNOWN** — `decision-ledger` is a Go command-line component with one executable at `cmd/decision-ledger/main.go` and one material reusable package at `internal/ledger`.

**KNOWN** — the component appends one JSON object per line to a ledger file and can independently verify the resulting JSONL stream using public keys only.

**KNOWN** — the runtime implementation contains no database, network client, service discovery, background worker or application-specific projection layer.

## 2. Evidence basis

Evidence inspected at the pinned commit:

- `cmd/decision-ledger/main.go` — command parsing, environment/private-key input and exit codes;
- `internal/ledger/ledger.go` — record contract, signing domains, append algorithm and verifier;
- `internal/ledger/ledger_test.go` — executable corruption, key, mode and chain evidence;
- `.github/workflows/test.yml` — continuous-integration contract;
- `examples/bafflewick/README.md` — acceptance procedure;
- `go.mod` and `VERSION` — language/dependency/version boundary.

## 3. Runtime map

```text
record JSON + public keyring + server private key
                       |
                       v
              cmd/decision-ledger
                 |          |
              append      verify
                 |          |
                 v          v
              internal/ledger
                 |          |
                 v          v
              JSONL       VerifyResult
```

**KNOWN** — the CLI is thin. Ledger format and validation logic live in `internal/ledger`.

## 4. Material data model

**KNOWN** — `Record` contains timestamp/trust state, incident/item identity and mode, item type, status, maker/confirmer identity, explicit self-approval fields, opaque JSON `Data`, and human signature objects.

**KNOWN** — `Entry` adds chain fields `Seq`, `PrevHash`, `Hash`, `ServerKeyID` and `ServerSignature` around the record.

**KNOWN** — `Keyring` is a map of key ID to base64 Ed25519 public key. No private key is stored in the keyring type.

## 5. Human signing domain

**KNOWN** — `RecordDigest` marshals `unsignedRecord(r)` and returns SHA-256 of those bytes.

**KNOWN** — `unsignedRecord` maps a `Record` to `recordCore`, which excludes maker/confirmer signature objects and excludes chain position fields.

**KNOWN** — therefore human signatures are independent of eventual `Seq` and `PrevHash` values.

**KNOWN** — `SignRecord` signs the 32-byte `RecordDigest` with Ed25519.

## 6. Human provenance validation

**KNOWN** — `verifyUserSignature` accepts either a signature value or an explicit `MissingReason`; both together are rejected and neither is rejected.

**KNOWN** — signature verification loads the public key by `KeyID`, base64-decodes the signature and performs Ed25519 verification over the record digest.

**KNOWN** — `Append` verifies maker provenance for every record and confirmer provenance when `Status == "confirmed"` before reading/extending ledger history.

## 7. Record invariants

**KNOWN** — `validateRecord` requires a timestamp, incident ID, item ID, item type and maker.

**KNOWN** — time status is restricted to `trusted`, `drifting` or `untrusted`.

**KNOWN** — incident and item modes are each restricted to `live` or `exercise`, and they must match.

**KNOWN** — status is restricted to `proposed`, `confirmed` or `comment`.

**KNOWN** — confirmed records require a confirmer. Same-person confirmation requires `SelfApproval` plus a non-empty reason. Different maker/confirmer identities reject self-approval fields.

**KNOWN** — non-confirmed records reject confirmer, confirmer-signature and self-approval fields so they cannot carry confirmation-like metadata.

## 8. Existing-ledger gate

**KNOWN** — `verifiedTail` opens the existing file when present and first calls `Verify` over the complete ledger.

**KNOWN** — if full verification fails, `verifiedTail` returns a refusal and `Append` does not extend the file.

**KNOWN** — after successful verification, `verifiedTail` re-reads the file to obtain only the final entry's sequence and hash. A missing ledger is treated as an empty chain.

## 9. Chain construction

**KNOWN** — append increments the verified tail sequence and uses the verified tail hash as `PrevHash`.

**KNOWN** — `entryHash` hashes JSON containing `chainCore` plus the maker and confirmer signature objects.

**KNOWN** — `chainCore` contains sequence, previous hash and the unsigned `recordCore`.

**KNOWN** — the server signs the 32-byte entry hash using Ed25519; the stored entry contains both the hexadecimal hash and base64 server signature.

## 10. Server-key relationship

**KNOWN** — before append, the configured public key identified by `serverKeyID` is decoded and compared byte-for-byte with `priv.Public()`.

**KNOWN** — a mismatch is a deterministic refusal before file mutation.

## 11. Append I/O behaviour

**KNOWN** — the completed entry is JSON-marshalled before the file is opened for append.

**KNOWN** — the implementation refuses a serialised entry larger than `MaxEntryBytes`, defined as 4 MiB, before opening/creating the ledger file.

**KNOWN** — a valid entry is written as one JSON line to a file opened with `O_CREATE|O_WRONLY|O_APPEND` and mode `0600`, followed by `Sync()`.

**UNKNOWN** — filesystem atomicity/durability beyond the guarantees of the host OS/filesystem is not established by this repository.

## 12. Standalone verification

**KNOWN** — `Verify` accepts only an `io.Reader` plus public keyring.

**KNOWN** — verification checks JSON decoding, sequence continuity, previous-hash linkage, record invariants, maker/confirmer provenance, recomputed entry hash, server public key and server signature.

**KNOWN** — verification accumulates errors and returns `Valid=false`; there is no repair, skip or rewrite path.

**KNOWN** — scanner capacity is bounded at `MaxEntryBytes + 1024`.

## 13. Failure classes and CLI mapping

**KNOWN** — `ErrRefused` identifies deterministic ledger-contract refusal; `IsRefusal` exposes that classification.

**KNOWN** — record/signature/key relationship failures, corrupt-existing-ledger refusal and oversize-entry refusal are wrapped as `ErrRefused`.

**KNOWN** — filesystem open/write/sync failures are returned as operational errors rather than converted into refusals.

**KNOWN** — CLI append maps refusals to exit `1`, usage errors to `2`, malformed input/environment/operational errors to `3`, and success to `0`.

**KNOWN** — CLI verification emits `VerifyResult` and exits `1` when the readable ledger is invalid.

## 14. Concurrency and state boundary

**KNOWN** — there is no process/file lock, compare-and-swap primitive or database transaction around `verifiedTail` plus append.

**INFERRED** — safe V0.1 operation therefore requires a single writer for each ledger file. Two independent appenders could verify the same tail before either writes.

**KNOWN** — no runtime state exists outside the ledger file, process environment and supplied keyring.

## 15. Build and test evidence

**KNOWN** — `go.mod` declares Go 1.26 and no third-party module dependencies.

**KNOWN** — CI runs formatting, `go vet`, race tests, native build, exact version assertion, `linux/arm64` cross-build and a targeted Bafflewick integrity suite.

Named behavioural tests include:

- `TestVerifyAndTamper`;
- `TestAppendRejectsInvalidHumanSignature`;
- `TestAppendRefusesCorruptExistingLedger`;
- `TestSelfApprovalRule`;
- `TestExerciseLiveMismatch`;
- `TestPreviousHashBreakDetected`;
- `TestServerSignatureCorruptionDetected`;
- `TestHumanSignatureIndependentOfChainPosition`;
- `TestServerKeyMismatchRefused`;
- `TestOversizedEntryRefusedBeforeWrite`;
- `TestUnconfirmedRecordCannotLookConfirmed`.

## 16. Known / inferred / unknown

| Classification | Finding |
|---|---|
| KNOWN | append-only JSONL writer plus standalone verifier |
| KNOWN | human signatures bind decision content but not chain position |
| KNOWN | server signature binds human-signed decision to sequence and previous hash |
| KNOWN | existing history must verify before append |
| KNOWN | server public/private key relationship is checked before append |
| KNOWN | 4 MiB serialised-entry limit is enforced before file creation/write |
| KNOWN | no database, network dependency or third-party Go module |
| INFERRED | single-writer ownership is required because append has no inter-process lock |
| UNKNOWN | quality/custody/revocation of externally managed signing keys |
| UNKNOWN | truthfulness/trustworthiness of the supplied timestamp and time-status label |
| UNKNOWN | production latency, throughput and storage growth on constrained hardware |
| UNKNOWN | forensic admissibility or chain-of-custody guarantees outside this format |

## 17. Evidence trace

| Property recovered from code | Primary source | Executable evidence |
|---|---|---|
| decision-content human digest | `RecordDigest`, `unsignedRecord` | `TestHumanSignatureIndependentOfChainPosition` |
| human signature verification | `verifyUserSignature` | `TestAppendRejectsInvalidHumanSignature` |
| record invariants/self-approval | `validateRecord` | `TestSelfApprovalRule`, `TestUnconfirmedRecordCannotLookConfirmed` |
| live/exercise separation | `validateRecord` | `TestExerciseLiveMismatch` |
| existing ledger verified before append | `verifiedTail` | `TestAppendRefusesCorruptExistingLedger` |
| previous-hash chain | `makeChainCore`, `Verify` | `TestPreviousHashBreakDetected` |
| server signature binds entry hash | `entryHash`, Ed25519 sign/verify | `TestServerSignatureCorruptionDetected` |
| server keypair consistency | `Append` public/private comparison | `TestServerKeyMismatchRefused` |
| size bound before file mutation | `MaxEntryBytes`, pre-open length check | `TestOversizedEntryRefusedBeforeWrite` |
| deterministic refusal classification | `ErrRefused`, `IsRefusal` | refusal assertions in key/oversize tests |
| Go/race/ARM64/integrity suite | CI workflow | `.github/workflows/test.yml` |

The code proves a compact tamper-evident decision ledger. It does not prove key governance, trusted time, forensic custody, multi-writer safety or the correctness of the decisions being recorded.
