# Changelog

## 0.1.0 — 2026-10-17

- initial append-only JSONL decision-ledger format;
- SHA-256 record/chain hashing and Ed25519 human/server signatures;
- human signing domain independent of final chain position;
- complete existing-ledger verification before append;
- server public/private key consistency check;
- maker/confirmer, self-approval and live/exercise rules;
- explicit unconfirmed-record integrity rule;
- 4 MiB serialised-entry limit shared by append and verifier;
- deterministic refusal versus operational CLI failure classification;
- standalone verification with public keys only;
- corruption, previous-hash, server-signature and key-mismatch tests;
- Go 1.26 baseline with race tests and `linux/arm64` cross-build;
- PRD, EDD, FORMAT, architecture, Bafflewick example and code-derived design evidence.
