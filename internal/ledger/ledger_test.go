package ledger

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func keyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func keyring(maker, confirmer, server ed25519.PublicKey) Keyring {
	return Keyring{
		"m":      base64.StdEncoding.EncodeToString(maker),
		"c":      base64.StdEncoding.EncodeToString(confirmer),
		"server": base64.StdEncoding.EncodeToString(server),
	}
}

func signedRecord(t *testing.T, mk, ck ed25519.PrivateKey) Record {
	t.Helper()
	r := Record{
		Timestamp:    time.Date(2026, 10, 17, 1, 2, 3, 0, time.UTC),
		TimeStatus:   "trusted",
		IncidentID:   "INC-1",
		IncidentMode: "live",
		ItemMode:     "live",
		ItemType:     "fact",
		ItemID:       "fact-1",
		Status:       "confirmed",
		Maker:        "m",
		Confirmer:    "c",
		Data:         json.RawMessage(`{"severity":"major"}`),
	}
	ms, err := SignRecord(r, mk)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := SignRecord(r, ck)
	if err != nil {
		t.Fatal(err)
	}
	r.MakerSignature = Signature{KeyID: "m", Value: ms}
	r.ConfirmerSignature = Signature{KeyID: "c", Value: cs}
	return r
}

func TestVerifyAndTamper(t *testing.T) {
	mp, mk := keyPair(t)
	cp, ck := keyPair(t)
	sp, sk := keyPair(t)
	keys := keyring(mp, cp, sp)
	path := t.TempDir() + "/ledger.jsonl"

	if _, err := Append(path, signedRecord(t, mk, ck), "server", sk, keys); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	res := Verify(f, keys)
	f.Close()
	if !res.Valid || res.Entries != 1 {
		t.Fatalf("verification failed: %+v", res)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b = []byte(strings.Replace(string(b), "major", "minor", 1))
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	f, _ = os.Open(path)
	res = Verify(f, keys)
	f.Close()
	if res.Valid {
		t.Fatal("tampered ledger verified")
	}
}

func TestAppendRejectsInvalidHumanSignature(t *testing.T) {
	mp, mk := keyPair(t)
	cp, ck := keyPair(t)
	sp, sk := keyPair(t)
	keys := keyring(mp, cp, sp)
	r := signedRecord(t, mk, ck)
	r.Data = json.RawMessage(`{"severity":"changed-after-signing"}`)
	if _, err := Append(t.TempDir()+"/ledger.jsonl", r, "server", sk, keys); err == nil {
		t.Fatal("append accepted a record changed after human signature")
	}
}

func TestAppendRefusesCorruptExistingLedger(t *testing.T) {
	mp, mk := keyPair(t)
	cp, ck := keyPair(t)
	sp, sk := keyPair(t)
	keys := keyring(mp, cp, sp)
	path := t.TempDir() + "/ledger.jsonl"
	if _, err := Append(path, signedRecord(t, mk, ck), "server", sk, keys); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	b = []byte(strings.Replace(string(b), "major", "minor", 1))
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Append(path, signedRecord(t, mk, ck), "server", sk, keys); err == nil {
		t.Fatal("append extended a corrupt ledger")
	}
}

func TestSelfApprovalRule(t *testing.T) {
	_, mk := keyPair(t)
	sp, sk := keyPair(t)
	keys := Keyring{
		"m":      base64.StdEncoding.EncodeToString(mk.Public().(ed25519.PublicKey)),
		"server": base64.StdEncoding.EncodeToString(sp),
	}
	r := Record{
		Timestamp:    time.Now().UTC(),
		TimeStatus:   "trusted",
		IncidentID:   "I",
		IncidentMode: "live",
		ItemMode:     "live",
		ItemType:     "fact",
		ItemID:       "1",
		Status:       "confirmed",
		Maker:        "m",
		Confirmer:    "m",
		Data:         json.RawMessage(`{}`),
	}
	sig, _ := SignRecord(r, mk)
	r.MakerSignature = Signature{KeyID: "m", Value: sig}
	r.ConfirmerSignature = Signature{KeyID: "m", Value: sig}
	if _, err := Append(t.TempDir()+"/x", r, "server", sk, keys); err == nil {
		t.Fatal("self approval without flag accepted")
	}
	r.SelfApproval = true
	r.SelfApprovalReason = "single-person window"
	sig, _ = SignRecord(r, mk)
	r.MakerSignature.Value = sig
	r.ConfirmerSignature.Value = sig
	if _, err := Append(t.TempDir()+"/y", r, "server", sk, keys); err != nil {
		t.Fatal(err)
	}
}

func TestExerciseLiveMismatch(t *testing.T) {
	mp, mk := keyPair(t)
	cp, ck := keyPair(t)
	sp, sk := keyPair(t)
	keys := keyring(mp, cp, sp)
	r := signedRecord(t, mk, ck)
	r.ItemMode = "exercise"
	if _, err := Append(t.TempDir()+"/ledger.jsonl", r, "server", sk, keys); err == nil {
		t.Fatal("exercise item accepted into live incident")
	}
}

func TestPreviousHashBreakDetected(t *testing.T) {
	mp, mk := keyPair(t)
	cp, ck := keyPair(t)
	sp, sk := keyPair(t)
	keys := keyring(mp, cp, sp)
	path := t.TempDir() + "/ledger.jsonl"
	if _, err := Append(path, signedRecord(t, mk, ck), "server", sk, keys); err != nil {
		t.Fatal(err)
	}
	if _, err := Append(path, signedRecord(t, mk, ck), "server", sk, keys); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	var second Entry
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatal(err)
	}
	second.PrevHash = strings.Repeat("0", 64)
	changed, _ := json.Marshal(second)
	lines[1] = string(changed)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	f, _ := os.Open(path)
	res := Verify(f, keys)
	f.Close()
	if res.Valid || !containsError(res.Errors, "previous hash mismatch") {
		t.Fatalf("broken previous hash was not identified: %+v", res)
	}
}

func TestServerSignatureCorruptionDetected(t *testing.T) {
	mp, mk := keyPair(t)
	cp, ck := keyPair(t)
	sp, sk := keyPair(t)
	keys := keyring(mp, cp, sp)
	path := t.TempDir() + "/ledger.jsonl"
	if _, err := Append(path, signedRecord(t, mk, ck), "server", sk, keys); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	var e Entry
	if err := json.Unmarshal(bytes.TrimSpace(b), &e); err != nil {
		t.Fatal(err)
	}
	e.ServerSignature = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	changed, _ := json.Marshal(e)
	f := strings.NewReader(string(changed) + "\n")
	res := Verify(f, keys)
	if res.Valid || !containsError(res.Errors, "server signature invalid") {
		t.Fatalf("server signature corruption was not identified: %+v", res)
	}
}

func TestHumanSignatureIndependentOfChainPosition(t *testing.T) {
	mp, mk := keyPair(t)
	cp, ck := keyPair(t)
	sp, sk := keyPair(t)
	keys := keyring(mp, cp, sp)
	path := t.TempDir() + "/ledger.jsonl"
	r := signedRecord(t, mk, ck)
	first, err := Append(path, r, "server", sk, keys)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Append(path, r, "server", sk, keys)
	if err != nil {
		t.Fatalf("same pre-chain human signatures failed at a new chain position: %v", err)
	}
	if first.Seq != 1 || second.Seq != 2 || first.PrevHash != "" || second.PrevHash != first.Hash {
		t.Fatalf("unexpected chain positions: first=%+v second=%+v", first, second)
	}
	if r.MakerSignature.Value != first.Record.MakerSignature.Value || r.MakerSignature.Value != second.Record.MakerSignature.Value {
		t.Fatal("ledger changed the human signature when assigning chain position")
	}
}

func TestServerKeyMismatchRefused(t *testing.T) {
	mp, mk := keyPair(t)
	cp, ck := keyPair(t)
	sp, _ := keyPair(t)
	_, wrong := keyPair(t)
	keys := keyring(mp, cp, sp)
	if _, err := Append(t.TempDir()+"/ledger.jsonl", signedRecord(t, mk, ck), "server", wrong, keys); err == nil || !IsRefusal(err) {
		t.Fatalf("server key mismatch was not a governed refusal: %v", err)
	}
}

func TestOversizedEntryRefusedBeforeWrite(t *testing.T) {
	mp, mk := keyPair(t)
	cp, ck := keyPair(t)
	sp, sk := keyPair(t)
	keys := keyring(mp, cp, sp)
	r := signedRecord(t, mk, ck)
	r.Data = json.RawMessage(`{"payload":"` + strings.Repeat("x", MaxEntryBytes) + `"}`)
	ms, err := SignRecord(r, mk)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := SignRecord(r, ck)
	if err != nil {
		t.Fatal(err)
	}
	r.MakerSignature.Value = ms
	r.ConfirmerSignature.Value = cs
	path := t.TempDir() + "/ledger.jsonl"
	if _, err := Append(path, r, "server", sk, keys); err == nil || !IsRefusal(err) {
		t.Fatalf("oversized entry accepted: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("oversized entry created a ledger file: %v", err)
	}
}

func TestUnconfirmedRecordCannotLookConfirmed(t *testing.T) {
	_, mk := keyPair(t)
	sp, sk := keyPair(t)
	keys := Keyring{
		"m":      base64.StdEncoding.EncodeToString(mk.Public().(ed25519.PublicKey)),
		"server": base64.StdEncoding.EncodeToString(sp),
	}
	r := Record{
		Timestamp:    time.Now().UTC(),
		TimeStatus:   "trusted",
		IncidentID:   "I",
		IncidentMode: "live",
		ItemMode:     "live",
		ItemType:     "fact",
		ItemID:       "1",
		Status:       "proposed",
		Maker:        "m",
		Confirmer:    "someone",
		Data:         json.RawMessage(`{}`),
	}
	sig, _ := SignRecord(r, mk)
	r.MakerSignature = Signature{KeyID: "m", Value: sig}
	if _, err := Append(t.TempDir()+"/ledger.jsonl", r, "server", sk, keys); err == nil || !IsRefusal(err) {
		t.Fatalf("unconfirmed record carried confirmer fields: %v", err)
	}
}

func containsError(xs []string, part string) bool {
	for _, x := range xs {
		if strings.Contains(x, part) {
			return true
		}
	}
	return false
}
