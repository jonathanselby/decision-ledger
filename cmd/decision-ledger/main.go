package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/jonathanselby/decision-ledger/internal/ledger"
	"os"
)

const version = "0.1.0"

func main() {
	var v bool
	flag.BoolVar(&v, "version", false, "print version")
	flag.Parse()
	if v {
		fmt.Println("decision-ledger " + version)
		return
	}
	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}
	switch args[0] {
	case "verify":
		verify(args[1:])
	case "append":
		appendEntry(args[1:])
	default:
		usage()
		os.Exit(2)
	}
}
func verify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	p := fs.String("ledger", "", "ledger JSONL")
	k := fs.String("keys", "", "public keyring JSON")
	if fs.Parse(args) != nil || *p == "" || *k == "" {
		os.Exit(2)
	}
	var kr ledger.Keyring
	if e := read(*k, &kr); e != nil {
		fail3(e)
	}
	f, e := os.Open(*p)
	if e != nil {
		fail3(e)
	}
	defer f.Close()
	r := ledger.Verify(f, kr)
	json.NewEncoder(os.Stdout).Encode(r)
	if !r.Valid {
		os.Exit(1)
	}
}
func appendEntry(args []string) {
	fs := flag.NewFlagSet("append", flag.ContinueOnError)
	p := fs.String("ledger", "", "ledger JSONL")
	req := fs.String("request", "", "record JSON")
	kid := fs.String("server-key-id", "server", "server key id")
	keysPath := fs.String("keys", "", "public keyring JSON")
	if fs.Parse(args) != nil || *p == "" || *req == "" || *keysPath == "" {
		os.Exit(2)
	}
	var r ledger.Record
	if e := read(*req, &r); e != nil {
		fail3(e)
	}
	var kr ledger.Keyring
	if e := read(*keysPath, &kr); e != nil {
		fail3(e)
	}
	raw := os.Getenv("DECISION_LEDGER_SERVER_KEY")
	b, e := base64.StdEncoding.DecodeString(raw)
	if e != nil || len(b) != ed25519.PrivateKeySize {
		fail3(fmt.Errorf("DECISION_LEDGER_SERVER_KEY must be base64 Ed25519 private key"))
	}
	out, e := ledger.Append(*p, r, *kid, ed25519.PrivateKey(b), kr)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		if ledger.IsRefusal(e) {
			os.Exit(1)
		}
		os.Exit(3)
	}
	json.NewEncoder(os.Stdout).Encode(out)
}
func read(p string, v any) error {
	b, e := os.ReadFile(p)
	if e != nil {
		return e
	}
	return json.Unmarshal(b, v)
}
func fail3(e error) { fmt.Fprintln(os.Stderr, e); os.Exit(3) }
func usage()        { fmt.Fprintln(os.Stderr, "decision-ledger append|verify ...") }
