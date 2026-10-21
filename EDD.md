# Decision Ledger — Engineering Design Document

**Version:** 0.1

## 1. Purpose

Decision Ledger implements one reusable job: append and independently verify a tamper-evident sequence of human decisions.

> **History is append-only. Verification must work without the application, database or network.**

The design separates two signing moments: humans sign the decision content before chain position exists; the server later signs the chain-bound entry.

## 2. Non-goals

V0.1 does not provide forensic evidence custody, key generation/custody, HSM integration, trusted timestamping, database projections, multi-process writer coordination, remote transparency logs, or edit/delete operations.

A single writer must own a ledger file.

## 3. Component model

```text
record JSON + public keys + server private key
                  |
                  v
+--------------------------------+
| cmd/decision-ledger            |
| append / verify CLI            |
+---------------+----------------+
                |
                v
+--------------------------------+
| internal/ledger                |
| format + signatures + chain    |
+---------------+----------------+
                |
                v
          ledger.jsonl
```

The CLI handles files, environment and exit codes. `internal/ledger` owns the portable ledger contract.

## 4. Core data model

`Record` contains timestamp/trust status, incident and item modes, item identity/type, status, maker/confirmer, optional explicit self-approval, opaque JSON data and human signatures.

`Entry` adds:

```text
seq
prev_hash
hash
server_key_id
server_signature
```

`Keyring` maps key IDs to base64 Ed25519 public keys.

`VerifyResult` reports validity, number of entries inspected and explicit errors.

## 5. Human signing domain

`RecordDigest` SHA-256 hashes JSON encoding of `recordCore`, which contains decision fields but excludes both signatures and all chain-position fields.

That means a maker/confirmer can sign before append knows the eventual `seq` or `prev_hash`.

The exact field domain is normative in `FORMAT.md`.

## 6. Human signature rules

`verifyUserSignature` accepts either:

- a base64 Ed25519 signature plus `key_id`; or
- an explicit `missing_reason` when no signature exists.

A signature and missing reason cannot both be present. A missing signature carries no key ID.

For an actual signature, `key_id` must equal the named maker/confirmer identity for that role before the key is looked up and the Ed25519 signature is checked. This prevents a valid key for one identity from asserting another identity's provenance.

Maker signature/absence is checked for every record. Confirmer signature/absence is checked for confirmed records.

## 7. Record invariants

`validateRecord` requires:

- non-zero timestamp;
- incident ID, item ID, item type and maker;
- `time_status` in `trusted|drifting|untrusted`;
- incident/item modes each in `live|exercise` and equal to one another;
- status in `proposed|confirmed|comment`.

For confirmed records:

- confirmer is required;
- maker and confirmer may be equal only with `self_approval=true` and non-empty reason;
- self-approval fields are rejected when maker and confirmer differ.

For non-confirmed records, confirmer/signature/self-approval fields are rejected so an unconfirmed record cannot carry misleading confirmation metadata.

## 8. Chain construction

Before append, the full existing ledger is verified.

The next entry uses:

```text
seq = previous seq + 1
prev_hash = previous stored hash
```

The chain hash is SHA-256 over JSON containing `chainCore` plus the maker/confirmer signature objects. The server signs that 32-byte hash with Ed25519.

The first entry uses sequence 1 and an empty previous hash.

## 9. Append algorithm

`Append` executes this order:

1. validate server private key/key ID;
2. validate record invariants;
3. load server public key and prove it matches the private key;
4. compute human record digest;
5. verify maker and, where required, confirmer provenance, including signer/key identity binding;
6. verify complete existing ledger and recover its tail;
7. assign chain position;
8. compute hash and server signature;
9. marshal entry and enforce `MaxEntryBytes` = 4 MiB;
10. open with append semantics, write one JSONL line and `fsync`.

An oversized entry is refused before the ledger file is opened for append.

## 10. Standalone verification

`Verify(io.Reader, Keyring)` requires no filesystem path, database, network or private key.

For each readable line it checks:

- JSON parse;
- sequence continuity;
- previous-hash linkage;
- record invariants;
- maker/confirmer identity binding and human signatures/absence reasons;
- recomputed entry hash;
- server public key and signature.

Any error sets `Valid=false`; verification does not repair or skip history. A malformed JSON line terminates verification immediately because continuing would require guessing the missing chain state and would only generate secondary errors.

The scanner accepts up to the documented entry limit plus small delimiter/headroom.

## 11. Failure classification

Append failures fall into two classes.

### Deterministic refusal

`ErrRefused` wraps invalid record/signature/key relationship, corrupt existing history and oversize-entry conditions. The CLI maps this class to exit `1`.

### Operational/input failure

File read/write/open/sync and malformed external input failures are operational. The CLI maps these to exit `3`.

CLI usage errors exit `2`; success exits `0`.

Verification of an invalid but readable ledger returns a structured result and exit `1`.

## 12. File and concurrency behaviour

The format is UTF-8 JSON Lines with one complete entry per line. Files are created with mode `0600` by `Append`.

Append uses `O_APPEND`, one write and `fsync`, but V0.1 does **not** lock across processes. Two writers can both verify the same tail before either appends, so multi-writer operation is outside the contract.

## 13. Key boundary

Private-key generation and custody are external.

The append CLI receives the server private key via `DECISION_LEDGER_SERVER_KEY` and public keys via JSON keyring. The verifier needs public keys only.

The repository does not store private keys or provide a keystore.

## 14. Build and dependency boundary

The module targets Go 1.26 and uses the standard library only.

CI runs formatting, vet, race tests, native build, version contract, `linux/arm64` build and a targeted Bafflewick integrity suite.

## 15. Operational limits

Known limits:

- one writer per ledger file;
- maximum 4 MiB serialised entry;
- no trusted timestamp source—only a `time_status` label supplied with the record;
- no key revocation/rotation policy beyond key IDs in the exported keyring;
- no external notarisation or transparency log;
- no runtime performance benchmark on constrained hardware in V0.1.

## 16. Security reasoning

The design makes several different changes observable:

- changing decision content invalidates human signatures and chain hash;
- changing a named maker/confirmer without the matching identity key invalidates provenance;
- changing human signature metadata changes the chain hash;
- changing sequence or previous hash changes the chain hash;
- changing the chain hash invalidates the server signature;
- changing the server signature is detected directly;
- changing historical content causes full verification failure and therefore blocks append.

This is tamper evidence, not proof that the original decision was correct or that a signing key was well governed.

## 17. Acceptance-to-evidence map

| PRD criterion | Executable evidence |
|---|---|
| altered signed content detected | `TestVerifyAndTamper` |
| previous-hash break detected | `TestPreviousHashBreakDetected` |
| server-signature corruption detected | `TestServerSignatureCorruptionDetected` |
| invalid human signature refused | `TestAppendRejectsInvalidHumanSignature` |
| signer identity bound to key ID | `TestSignerIdentityMustMatchKeyID` |
| corrupt ledger cannot be extended | `TestAppendRefusesCorruptExistingLedger` |
| server key mismatch refused | `TestServerKeyMismatchRefused` |
| explicit self-approval rule | `TestSelfApprovalRule` |
| explicit missing-signature reason remains supported | `TestMissingSignatureReasonRemainsSupported` |
| unconfirmed record cannot look confirmed | `TestUnconfirmedRecordCannotLookConfirmed` |
| live/exercise separation | `TestExerciseLiveMismatch` |
| human signature independent of chain position | `TestHumanSignatureIndependentOfChainPosition` |
| malformed history stops verification | `TestMalformedEntryStopsVerification` |
| oversize entry refused before file creation | `TestOversizedEntryRefusedBeforeWrite` |
| standalone verification | `Verify(io.Reader, Keyring)` exercised throughout verifier tests |
| Go/race/build/ARM64/Bafflewick | `.github/workflows/test.yml` |

`generated/EDD.md` is separately recovered from code at the evidence commit and is not a copy of this intended design.
