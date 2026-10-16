# Decision Ledger — Skill

## Use this when

Use `decision-ledger` when an application needs a portable append-only decision history that can be verified independently of its database and network.

## Core rule

> **History is append-only. Verification must work without the application, database or network.**

## Read order

1. `PRD.md` — product boundary and acceptance criteria.
2. `FORMAT.md` — exact human/server signing domains and verifier algorithm.
3. `EDD.md` — intended runtime, failure and operational design.
4. `architecture.txt` — compact flow.
5. `examples/bafflewick/` — executable acceptance evidence.

## Change discipline

1. Run `go vet ./...` and `go test -race -count=1 ./...` before and after change.
2. Do not add edit/delete/correction-in-place operations.
3. Human signing must remain independent of eventual `seq` and `prev_hash`.
4. Verify the complete existing chain before append.
5. Never silently repair or skip invalid entries.
6. Preserve deterministic refusal (exit 1) versus operational/input failure (exit 3).
7. Keep the documented format limit consistent with verifier and append code.
8. Treat any signing-domain/hash change as a format/version change.
9. Regenerate code-derived evidence after code change.
10. Do not tag until `RELEASE.md` is satisfied.

## Do not use this repo for

Forensic chain of custody, key generation/custody, HSM integration, trusted timestamping, concurrent multi-writer coordination, database projections, or remote transparency/notary services.
