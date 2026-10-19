# Decision Ledger

[![test](https://github.com/jonathanselby/decision-ledger/actions/workflows/test.yml/badge.svg)](https://github.com/jonathanselby/decision-ledger/actions/workflows/test.yml)

**History is append-only. Verification must work without the application, database or network.**

`decision-ledger` is a small Go component for appending and independently verifying a tamper-evident sequence of human decisions. It is designed for systems that need a portable audit history that can survive loss of the application database or network.

## What V0.1 proves

V0.1 demonstrates a deliberately narrow provenance model:

- human signatures cover the decision before chain position is assigned;
- SHA-256 links each entry to the previous entry;
- an Ed25519 server signature binds the signed decision to its final sequence and previous hash;
- the entire existing ledger is verified before it can be extended;
- verification requires only the JSONL export and public-key file;
- corrupt history, signatures and chain linkage are visible rather than repaired.

See [`FORMAT.md`](FORMAT.md) for the exact signing and verification contract.

## Install

Requires Go 1.26+.

```bash
go install github.com/jonathanselby/decision-ledger/cmd/decision-ledger@main
```

`decision-ledger -version` must print `decision-ledger 0.1.0`.

## CLI

Verify an export:

```bash
decision-ledger verify -ledger ledger.jsonl -keys public-keys.json
```

Append a pre-signed decision record:

```bash
export DECISION_LEDGER_SERVER_KEY='<base64 Ed25519 private key>'
decision-ledger append -ledger ledger.jsonl -request decision.json -keys public-keys.json -server-key-id server
```

The component deliberately does not generate or custody private keys.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | append/verification succeeded |
| `1` | deterministic refusal: invalid ledger/record/signature/key relationship |
| `2` | invalid CLI usage |
| `3` | malformed input file, file I/O or execution failure |

Append distinguishes a ledger-contract refusal from an operational failure; a filesystem error is not reported as a governance decision.

## Security properties demonstrated

The automated suite proves that V0.1 detects or refuses altered signed content, broken previous-hash linkage, corrupted server signatures, invalid human signatures, extension of corrupt history, server key mismatch, invalid self-approval, live/exercise mismatch, misleading confirmation fields and entries larger than the supported 4 MiB format limit.

It also proves that the same human signature remains valid at a different chain position because humans do not sign `seq` or `prev_hash`.

## Operational boundary

V0.1 intentionally does not provide forensic evidence custody, private-key storage/HSM integration, trusted timestamping, database projections, multi-process append locking, remote notarisation or edit/delete operations.

A single writer must own each ledger file. Verification is safe to run independently against an exported copy.

## Repository map

```text
decision-ledger/
├── .github/workflows/test.yml
├── PRD.md
├── EDD.md
├── FORMAT.md
├── README.md
├── SKILL.md
├── RELEASE.md
├── VERSION
├── CHANGELOG.md
├── LICENSE
├── architecture.txt
├── go.mod
├── cmd/decision-ledger/main.go
├── internal/ledger/
├── examples/bafflewick/
└── generated/
    ├── EDD.md
    └── COMPARISON.md
```

## Engineering evidence

- [`PRD.md`](PRD.md) — product boundary and acceptance criteria;
- [`EDD.md`](EDD.md) — intended engineering design;
- [`FORMAT.md`](FORMAT.md) — independently reproducible signing/chain contract;
- [`architecture.txt`](architecture.txt) — compact runtime view;
- [`internal/ledger`](internal/ledger) — implementation and behavioural tests;
- [`examples/bafflewick`](examples/bafflewick) — fictional acceptance case;
- [`generated/EDD.md`](generated/EDD.md) — code-derived design evidence pinned to a source commit;
- [`generated/COMPARISON.md`](generated/COMPARISON.md) — intended design versus recovered implementation;
- [`RELEASE.md`](RELEASE.md) — release gate.

## Design rule

> **History is append-only. Verification must work without the application, database or network.**

## Licence

MIT. See [`LICENSE`](LICENSE).
