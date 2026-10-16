# Decision Ledger — Product Requirements Document

**Version:** 0.1

## 1. Problem

Incident and governance applications need a decision history that remains trustworthy when the application database, network or user interface is unavailable. A copied database table is not sufficient: alteration of history must be detectable and the provenance of each decision must be independently checkable.

## 2. Product objective

Provide a small Go command-line component that appends and independently verifies a tamper-evident, signed sequence of decision records.

> **History is append-only. Verification must work without the application, database or network.**

The V0.1 product question is: can a small portable file format provide independently verifiable provenance for human decisions without becoming a forensic evidence platform?

## 3. Users

Primary users are applications and operators that need an exportable decision history separate from application projections.

## 4. In scope

- append-only UTF-8 JSON Lines ledger;
- 4 MiB maximum serialised entry size;
- SHA-256 record and chain hashing;
- Ed25519 human and server signatures;
- explicit reason when a human signature is absent;
- human signing before ledger sequence/previous hash are assigned;
- maker/confirmer and explicit self-approval rules;
- live/exercise separation;
- time trust-status label;
- complete existing-ledger verification before append;
- standalone verification using only ledger export and public-key file;
- server public/private key consistency check;
- fsync after append;
- stable CLI/exit-code contract;
- Go 1.26 and `linux/arm64` build proof.

## 5. Out of scope

Forensic chain of custody, database projection management, key generation/private-key custody, HSM integration, trusted timestamp authority, multi-process append locking, remote transparency/notary service, and record edit/delete/correction in place.

A single writer must own a ledger file in V0.1.

## 6. Functional requirements

### FR1 — Human signing domain
Human signatures cover decision content but do not include eventual ledger sequence or previous hash.

### FR2 — Chain binding
Append assigns a monotonic sequence and previous hash, computes a chain hash and signs that hash with the configured server private key.

### FR3 — Full verification before append
The complete existing ledger must verify before a new entry can be written.

### FR4 — Standalone verification
Verification must require no application database, network service or private key.

### FR5 — Confirmation integrity
A confirmed record requires a confirmer. Maker and confirmer must differ unless self-approval is explicitly flagged with a non-empty reason. Unconfirmed records may not carry confirmer/self-approval fields that make them appear confirmed.

### FR6 — Mode separation
Incident mode and item mode must both be `live` or both be `exercise`.

### FR7 — Key relationship
Append must prove the configured server public key corresponds to the supplied private key before writing.

### FR8 — Format bounds
Append must refuse an entry larger than the supported verifier limit before creating/writing the ledger file.

### FR9 — Failure classification
CLI exit status must distinguish deterministic ledger refusal from usage and operational/input failure.

## 7. Acceptance criteria

V0.1 is accepted when executable evidence demonstrates:

1. altered signed content is detected;
2. broken previous-hash linkage is explicitly detected;
3. corrupted server signature is explicitly detected;
4. invalid human signature is rejected;
5. append refuses to extend a corrupt existing ledger;
6. server public/private key mismatch is refused;
7. same maker/confirmer fails unless self-approval and reason are present;
8. unconfirmed records cannot carry confirmer/self-approval fields;
9. exercise/live mismatch is refused;
10. the same pre-chain human signatures can be bound at different sequence positions;
11. oversize entries are refused before a ledger file is created;
12. standalone verification operates over only reader + public keyring;
13. `go vet`, race tests, native build and `linux/arm64` build pass;
14. CLI version and exit-code contracts are stable.

## 8. Definition of done

V0.1 is complete when the file/signing format is reproducible from repository documentation, every acceptance criterion has named executable evidence, CI proves the Go 1.26 build, the known single-writer limitation is explicit, and the generated EDD independently recovers the implementation from the release-candidate source commit.
