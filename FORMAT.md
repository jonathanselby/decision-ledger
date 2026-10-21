# Decision Ledger — File and Signing Format

**Format version:** 0.1  
**Reviewed:** 2026-10-22

This file defines the portable verification contract. A verifier should be able to implement these rules without the originating application or database.

## Ledger representation

The ledger is UTF-8 JSON Lines. Each line is one complete `Entry` object. V0.1 accepts at most 4 MiB of serialised JSON per entry.

The file is append-only. V0.1 has no edit, delete or correction-in-place operation.

## Decision record

The human-signing domain is the canonical Go JSON encoding of these fields, in this order:

```text
timestamp
time_status
incident_id
incident_mode
item_mode
item_type
item_id
status
maker
confirmer
self_approval
self_approval_reason
data
```

The human digest is `SHA-256(JSON(recordCore))`.

`maker_signature` and `confirmer_signature` are deliberately excluded from that digest. So are `seq` and `prev_hash`. This lets a human sign the decision before its final position in the ledger is known.

## Human signatures

Human signatures use Ed25519 over the 32-byte record digest. A `Signature` contains either a `key_id` plus base64 Ed25519 `value`, or an explicit `missing_reason`. `value` and `missing_reason` are mutually exclusive.

When a signature value is present, `key_id` must equal the named `maker` or `confirmer` whose provenance is being asserted. A different valid key may not sign on behalf of that named identity. When a signature is absent, `missing_reason` records that absence and `key_id` must be empty; this is explicit absence, not cryptographic provenance.

A confirmed record requires a confirmer. If maker and confirmer are the same person, `self_approval` must be true and `self_approval_reason` non-empty. A non-confirmed record may not carry confirmer or self-approval fields that could make it appear confirmed.

## Chain binding

After human signatures are verified, append assigns `seq` and `prev_hash`. The chain core is `seq`, `prev_hash`, and `recordCore`.

The entry hash is SHA-256 over JSON containing the chain core plus maker and confirmer signature objects. `prev_hash` is empty for the first entry and must equal the preceding entry's stored `hash` thereafter.

## Server signature

The server signs the 32-byte entry hash with Ed25519 and stores `hash`, `server_key_id`, and `server_signature`. The configured public key for `server_key_id` must match the supplied private key before append proceeds.

The server signature therefore binds the already human-signed decision to its ledger sequence and previous-hash position.

## Verification algorithm

A standalone verifier processes the JSONL file from first line to last and checks: valid JSON/record contract; monotonically increasing sequence beginning at 1; previous-hash linkage; maker provenance; confirmer provenance when confirmed; recomputed entry hash; and server signature.

Any failure makes the ledger invalid. A malformed JSON line terminates verification because later chain position cannot be reconstructed without guessing past unreadable history. Verification does not repair, skip or rewrite history.

## Append algorithm

Append performs: record validation; server public/private key match; human signature verification; complete existing-ledger verification; sequence/hash assignment; server signature; serialised-entry size check; one append write and `fsync`.

The component refuses to extend an invalid existing ledger.

## Deliberate limits

V0.1 is not a forensic chain-of-custody standard. It does not provide a trusted timestamp authority, HSM custody, multi-process append locking, Merkle trees, remote transparency logs or notarisation.

A single writer must own a ledger file. Concurrent appenders can race between verification and append and are outside the V0.1 contract.
