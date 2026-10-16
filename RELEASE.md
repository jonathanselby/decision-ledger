# Release checklist

A release is ready only when all of the following are true.

## Source and format

- [ ] `VERSION`, CLI version and tag agree.
- [ ] `go.mod` uses the Garage Go baseline.
- [ ] any signing/hash-domain change is reflected in `FORMAT.md` and versioning.
- [ ] `CHANGELOG.md` records the release.

## Engineering gate

- [ ] `gofmt` produces no changes.
- [ ] `go vet ./...` passes.
- [ ] `go test -race -count=1 ./...` passes.
- [ ] native build passes.
- [ ] `GOOS=linux GOARCH=arm64 go build ./cmd/...` passes.
- [ ] Bafflewick corruption/chain/signature acceptance tests pass.

## Requirements traceability

- [ ] every PRD acceptance criterion maps to a named test or explicit acceptance check.
- [ ] deterministic refusal and operational failure remain distinguishable.
- [ ] the single-writer limitation remains explicit unless code actually changes it.

## Design evidence

- [ ] `EDD.md` describes the release candidate.
- [ ] `generated/EDD.md` is recovered from the source commit.
- [ ] `generated/COMPARISON.md` explains all matches, deliberate limits and unknowns.
- [ ] generated evidence contains the exact source commit SHA.

Tag format: `v0.1.0`, `v0.2.0`, and so on.
