package ledger

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

type Signature struct {
	KeyID         string `json:"key_id,omitempty"`
	Value         string `json:"value,omitempty"`
	MissingReason string `json:"missing_reason,omitempty"`
}

type Record struct {
	Timestamp          time.Time       `json:"timestamp"`
	TimeStatus         string          `json:"time_status"`
	IncidentID         string          `json:"incident_id"`
	IncidentMode       string          `json:"incident_mode"`
	ItemMode           string          `json:"item_mode"`
	ItemType           string          `json:"item_type"`
	ItemID             string          `json:"item_id"`
	Status             string          `json:"status"`
	Maker              string          `json:"maker"`
	Confirmer          string          `json:"confirmer,omitempty"`
	SelfApproval       bool            `json:"self_approval,omitempty"`
	SelfApprovalReason string          `json:"self_approval_reason,omitempty"`
	Data               json.RawMessage `json:"data"`
	MakerSignature     Signature       `json:"maker_signature"`
	ConfirmerSignature Signature       `json:"confirmer_signature,omitempty"`
}

type recordCore struct {
	Timestamp          time.Time       `json:"timestamp"`
	TimeStatus         string          `json:"time_status"`
	IncidentID         string          `json:"incident_id"`
	IncidentMode       string          `json:"incident_mode"`
	ItemMode           string          `json:"item_mode"`
	ItemType           string          `json:"item_type"`
	ItemID             string          `json:"item_id"`
	Status             string          `json:"status"`
	Maker              string          `json:"maker"`
	Confirmer          string          `json:"confirmer,omitempty"`
	SelfApproval       bool            `json:"self_approval,omitempty"`
	SelfApprovalReason string          `json:"self_approval_reason,omitempty"`
	Data               json.RawMessage `json:"data"`
}

type chainCore struct {
	Seq      uint64     `json:"seq"`
	PrevHash string     `json:"prev_hash"`
	Record   recordCore `json:"record"`
}

type Entry struct {
	Seq             uint64 `json:"seq"`
	PrevHash        string `json:"prev_hash"`
	Record          Record `json:"record"`
	Hash            string `json:"hash"`
	ServerKeyID     string `json:"server_key_id"`
	ServerSignature string `json:"server_signature"`
}

type Keyring map[string]string

const MaxEntryBytes = 4 << 20

var ErrRefused = errors.New("ledger append refused")

func IsRefusal(err error) bool { return errors.Is(err, ErrRefused) }

func refusal(err error) error {
	if err == nil {
		return ErrRefused
	}
	return fmt.Errorf("%w: %v", ErrRefused, err)
}

type VerifyResult struct {
	Valid   bool     `json:"valid"`
	Entries int      `json:"entries"`
	Errors  []string `json:"errors,omitempty"`
}

// Append validates the record, its human signatures, the configured server key,
// and the complete existing ledger before extending the chain.
func Append(path string, r Record, serverKeyID string, priv ed25519.PrivateKey, keys Keyring) (Entry, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return Entry{}, refusal(errors.New("invalid server private key"))
	}
	if serverKeyID == "" {
		return Entry{}, refusal(errors.New("server key id required"))
	}
	if err := validateRecord(r); err != nil {
		return Entry{}, refusal(err)
	}
	serverPub, err := publicKey(keys, serverKeyID)
	if err != nil {
		return Entry{}, refusal(fmt.Errorf("server public key: %w", err))
	}
	actualServerPub := priv.Public().(ed25519.PublicKey)
	if !bytes.Equal(serverPub, actualServerPub) {
		return Entry{}, refusal(errors.New("server public key does not match private key"))
	}

	digest, err := RecordDigest(r)
	if err != nil {
		return Entry{}, refusal(err)
	}
	if err = verifyUserSignature(r.MakerSignature, r.Maker, digest, keys); err != nil {
		return Entry{}, refusal(fmt.Errorf("maker signature: %w", err))
	}
	if r.Status == "confirmed" {
		if err = verifyUserSignature(r.ConfirmerSignature, r.Confirmer, digest, keys); err != nil {
			return Entry{}, refusal(fmt.Errorf("confirmer signature: %w", err))
		}
	}

	seq, prev, err := verifiedTail(path, keys)
	if err != nil {
		return Entry{}, err
	}
	seq++
	cc := makeChainCore(seq, prev, r)
	h := entryHash(cc, r.MakerSignature, r.ConfirmerSignature)
	sig := ed25519.Sign(priv, h[:])
	e := Entry{
		Seq:             seq,
		PrevHash:        prev,
		Record:          r,
		Hash:            hex.EncodeToString(h[:]),
		ServerKeyID:     serverKeyID,
		ServerSignature: base64.StdEncoding.EncodeToString(sig),
	}

	b, err := json.Marshal(e)
	if err != nil {
		return Entry{}, refusal(err)
	}
	if len(b) > MaxEntryBytes {
		return Entry{}, refusal(fmt.Errorf("serialized entry exceeds %d bytes", MaxEntryBytes))
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return Entry{}, err
	}
	defer f.Close()
	if _, err = f.Write(append(b, '\n')); err != nil {
		return Entry{}, err
	}
	if err = f.Sync(); err != nil {
		return Entry{}, err
	}
	return e, nil
}

func Verify(r io.Reader, keys Keyring) VerifyResult {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), MaxEntryBytes+1024)
	res := VerifyResult{Valid: true}
	var prev string
	var seq uint64
	for sc.Scan() {
		res.Entries++
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			res.add(fmt.Sprintf("entry %d malformed: %v", res.Entries, err))
			return res
		}
		seq++
		if e.Seq != seq {
			res.add(fmt.Sprintf("entry %d sequence mismatch", res.Entries))
		}
		if e.PrevHash != prev {
			res.add(fmt.Sprintf("entry %d previous hash mismatch", res.Entries))
		}
		if err := validateRecord(e.Record); err != nil {
			res.add(fmt.Sprintf("entry %d record: %v", res.Entries, err))
		}

		digest, err := RecordDigest(e.Record)
		if err != nil {
			res.add(fmt.Sprintf("entry %d record digest: %v", res.Entries, err))
		} else {
			if err := verifyUserSignature(e.Record.MakerSignature, e.Record.Maker, digest, keys); err != nil {
				res.add(fmt.Sprintf("entry %d maker signature: %v", res.Entries, err))
			}
			if e.Record.Status == "confirmed" {
				if err := verifyUserSignature(e.Record.ConfirmerSignature, e.Record.Confirmer, digest, keys); err != nil {
					res.add(fmt.Sprintf("entry %d confirmer signature: %v", res.Entries, err))
				}
			}
		}

		cc := makeChainCore(e.Seq, e.PrevHash, e.Record)
		h := entryHash(cc, e.Record.MakerSignature, e.Record.ConfirmerSignature)
		if e.Hash != hex.EncodeToString(h[:]) {
			res.add(fmt.Sprintf("entry %d hash mismatch", res.Entries))
		}
		pub, err := publicKey(keys, e.ServerKeyID)
		sig, sigErr := base64.StdEncoding.DecodeString(e.ServerSignature)
		if err != nil || sigErr != nil || !ed25519.Verify(pub, h[:], sig) {
			res.add(fmt.Sprintf("entry %d server signature invalid", res.Entries))
		}
		prev = e.Hash
	}
	if err := sc.Err(); err != nil {
		res.add(err.Error())
	}
	return res
}

func (r *VerifyResult) add(s string) {
	r.Valid = false
	r.Errors = append(r.Errors, s)
}

func validateRecord(r Record) error {
	if r.Timestamp.IsZero() || r.IncidentID == "" || r.ItemID == "" || r.Maker == "" {
		return errors.New("timestamp, incident_id, item_id and maker are required")
	}
	if r.TimeStatus != "trusted" && r.TimeStatus != "drifting" && r.TimeStatus != "untrusted" {
		return errors.New("invalid time_status")
	}
	if (r.IncidentMode != "live" && r.IncidentMode != "exercise") || (r.ItemMode != "live" && r.ItemMode != "exercise") {
		return errors.New("invalid incident/item mode")
	}
	if r.IncidentMode != r.ItemMode {
		return errors.New("exercise/live mode mismatch")
	}
	if r.Status != "proposed" && r.Status != "confirmed" && r.Status != "comment" {
		return errors.New("invalid status")
	}
	if r.ItemType == "" {
		return errors.New("item_type is required")
	}
	if r.Status == "confirmed" {
		if r.Confirmer == "" {
			return errors.New("confirmed record requires confirmer")
		}
		if r.Maker == r.Confirmer {
			if !r.SelfApproval || r.SelfApprovalReason == "" {
				return errors.New("self-confirmation requires self_approval flag and reason")
			}
		} else if r.SelfApproval || r.SelfApprovalReason != "" {
			return errors.New("self approval fields only valid when maker equals confirmer")
		}
	} else if r.Confirmer != "" || r.ConfirmerSignature.Value != "" || r.ConfirmerSignature.MissingReason != "" || r.ConfirmerSignature.KeyID != "" || r.SelfApproval || r.SelfApprovalReason != "" {
		return errors.New("unconfirmed record cannot carry confirmer or self-approval fields")
	}
	return nil
}

func unsignedRecord(r Record) recordCore {
	return recordCore{
		Timestamp:          r.Timestamp,
		TimeStatus:         r.TimeStatus,
		IncidentID:         r.IncidentID,
		IncidentMode:       r.IncidentMode,
		ItemMode:           r.ItemMode,
		ItemType:           r.ItemType,
		ItemID:             r.ItemID,
		Status:             r.Status,
		Maker:              r.Maker,
		Confirmer:          r.Confirmer,
		SelfApproval:       r.SelfApproval,
		SelfApprovalReason: r.SelfApprovalReason,
		Data:               r.Data,
	}
}

func makeChainCore(seq uint64, prev string, r Record) chainCore {
	return chainCore{Seq: seq, PrevHash: prev, Record: unsignedRecord(r)}
}

// RecordDigest is the content that humans sign. It deliberately excludes chain
// sequence/previous hash, so a human can sign the decision before the ledger assigns
// its final append position.
func RecordDigest(r Record) ([32]byte, error) {
	b, err := json.Marshal(unsignedRecord(r))
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

func entryHash(c chainCore, maker, confirmer Signature) [32]byte {
	b, _ := json.Marshal(struct {
		Core      chainCore `json:"core"`
		Maker     Signature `json:"maker_signature"`
		Confirmer Signature `json:"confirmer_signature"`
	}{c, maker, confirmer})
	return sha256.Sum256(b)
}

func publicKey(k Keyring, id string) (ed25519.PublicKey, error) {
	s, ok := k[id]
	if !ok {
		return nil, errors.New("key not found: " + id)
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("invalid public key")
	}
	return ed25519.PublicKey(b), nil
}

func verifyUserSignature(s Signature, signerID string, d [32]byte, k Keyring) error {
	if s.Value == "" {
		if s.MissingReason == "" {
			return errors.New("signature or missing_reason required")
		}
		if s.KeyID != "" {
			return errors.New("missing signature cannot carry key_id")
		}
		return nil
	}
	if s.MissingReason != "" {
		return errors.New("signature and missing_reason are mutually exclusive")
	}
	if s.KeyID == "" {
		return errors.New("key_id required")
	}
	if s.KeyID != signerID {
		return fmt.Errorf("key_id %q does not match signer %q", s.KeyID, signerID)
	}
	pub, err := publicKey(k, s.KeyID)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(s.Value)
	if err != nil || !ed25519.Verify(pub, d[:], sig) {
		return errors.New("invalid signature")
	}
	return nil
}

func verifiedTail(path string, keys Keyring) (uint64, string, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return 0, "", nil
	}
	if err != nil {
		return 0, "", err
	}
	defer f.Close()

	res := Verify(f, keys)
	if !res.Valid {
		return 0, "", refusal(fmt.Errorf("existing ledger verification failed: %s", stringsJoin(res.Errors)))
	}
	if res.Entries == 0 {
		return 0, "", nil
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, "", err
	}
	sc := bufio.NewScanner(f)
	var last Entry
	for sc.Scan() {
		if err := json.Unmarshal(sc.Bytes(), &last); err != nil {
			return 0, "", err
		}
	}
	if err := sc.Err(); err != nil {
		return 0, "", err
	}
	return last.Seq, last.Hash, nil
}

func stringsJoin(xs []string) string {
	if len(xs) == 0 {
		return "unknown verification error"
	}
	out := xs[0]
	for _, x := range xs[1:] {
		out += "; " + x
	}
	return out
}

func SignRecord(r Record, priv ed25519.PrivateKey) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", errors.New("invalid private key")
	}
	d, err := RecordDigest(r)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, d[:])), nil
}
