# Bafflewick acceptance example

Bafflewick is fictional. The ledger deliberately does not generate or custody signing keys, so the acceptance case uses ephemeral Ed25519 keys created inside the test process.

Run the full ledger acceptance suite:

```bash
go test ./internal/ledger -run 'TestVerifyAndTamper|TestPreviousHashBreakDetected|TestServerSignatureCorruptionDetected|TestAppendRefusesCorruptExistingLedger|TestHumanSignatureIndependentOfChainPosition|TestServerKeyMismatchRefused|TestOversizedEntryRefusedBeforeWrite' -count=1 -v
```

The tests demonstrate: human signs decision content -> ledger verifies human provenance -> ledger verifies all existing history -> ledger assigns sequence/previous hash -> server signs chain-bound entry -> standalone verifier replays all checks.

A content change, previous-hash change or server-signature change makes verification fail. A corrupt existing ledger cannot be extended.

`TestHumanSignatureIndependentOfChainPosition` proves the same pre-chain signatures remain valid when a record is assigned different chain positions.

See [`../../FORMAT.md`](../../FORMAT.md) for the exact signing and verification domains.
