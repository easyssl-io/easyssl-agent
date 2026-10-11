package csr

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/easyssl-io/easyssl-contract/wire"

	"github.com/easyssl-io/easyssl-agent/internal/keystore"
	"github.com/easyssl-io/easyssl-agent/internal/serverapi"
)

const certificateID = "3f2b9c44-1a77-4ce0-8d21-0d5e8f6a4b72"

// fakeAPI stands in for the Server wrapper. Only Generate and Load are replaced
// (they require root and a filesystem), by an in-memory keystore keyed by
// fingerprint so what the Server named is observable.
type fakeAPI struct {
	work      wire.CSRWork
	workErr   error
	submitErr error
	submitted []string // PEM CSRs received, in order
}

func (f *fakeAPI) CSRWork(_ context.Context, _, _ string) (wire.CSRWork, error) {
	return f.work, f.workErr
}

func (f *fakeAPI) SubmitCSR(_ context.Context, _, _, csrPEM string) error {
	f.submitted = append(f.submitted, csrPEM)
	return f.submitErr
}

// memoryKeystore stands in for the keystore: Generate mints a key and files it
// under its fingerprint, Load returns what is filed there or ErrNoKey.
func memoryKeystore(t *testing.T) {
	t.Helper()
	keys := map[string]crypto.Signer{}
	origGenerate, origLoad := generateKey, loadKey
	generateKey = func(keyType string) (string, crypto.Signer, error) {
		var k crypto.Signer
		var err error
		if keyType == wire.KeyTypeRSA2048 {
			k, err = rsa.GenerateKey(rand.Reader, 2048)
		} else {
			k, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		}
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKIXPublicKey(k.Public())
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(der)
		fp := hex.EncodeToString(sum[:])
		keys[fp] = k
		return fp, k, nil
	}
	loadKey = func(fp string) (crypto.Signer, error) {
		if k, ok := keys[fp]; ok {
			return k, nil
		}
		return nil, keystore.ErrNoKey
	}
	t.Cleanup(func() { generateKey, loadKey = origGenerate, origLoad })
}

func newHandler(t *testing.T, api *fakeAPI) func(context.Context, wire.Command) error {
	t.Helper()
	memoryKeystore(t)
	return New(api, "esat_test", slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// keyOf is the SPKI fingerprint of the key a PEM CSR was built from.
func keyOf(t *testing.T, p string) string {
	t.Helper()
	block, _ := pem.Decode([]byte(p))
	req, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(req.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func work(domains ...string) wire.CSRWork {
	return wire.CSRWork{CertificateID: certificateID, Domains: domains, KeyType: wire.KeyTypeECP256}
}

func command() wire.Command {
	return wire.Command{ID: "cmd-1", Type: wire.CommandRequestCSR, RefID: certificateID}
}

func TestBuildsAndSubmitsAVerifiableCSR(t *testing.T) {
	api := &fakeAPI{work: work("app.example.test", "*.svc.example.test")}
	h := newHandler(t, api)

	if err := h(context.Background(), command()); err != nil {
		t.Fatalf("handler = %v, want nil", err)
	}
	if len(api.submitted) != 1 {
		t.Fatalf("submitted %d CSRs, want 1", len(api.submitted))
	}

	block, rest := pem.Decode([]byte(api.submitted[0]))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(rest) != 0 {
		t.Fatalf("submission is not exactly one CERTIFICATE REQUEST block")
	}
	req, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if err := req.CheckSignature(); err != nil {
		t.Fatalf("CSR self-signature: %v", err)
	}
	wantSANs := []string{"app.example.test", "*.svc.example.test"}
	gotSANs := slices.Clone(req.DNSNames)
	slices.Sort(gotSANs)
	slices.Sort(wantSANs)
	if !slices.Equal(gotSANs, wantSANs) {
		t.Fatalf("CSR SANs = %v, want %v", req.DNSNames, wantSANs)
	}
	if req.Subject.CommonName != "" {
		t.Fatalf("CSR carries a Common Name %q, want none", req.Subject.CommonName)
	}
	pub, ok := req.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		t.Fatalf("CSR key = %T, want ECDSA P-256", req.PublicKey)
	}
}

// A re-run after a crash gets the same command, and the work now names the
// stored CSR's key: the build must use that key, not a fresh one, so it matches
// the CSR the Server stored from the first run.
func TestReRunUsesTheNamedKey(t *testing.T) {
	api := &fakeAPI{work: work("app.example.test")}
	h := newHandler(t, api)

	if err := h(context.Background(), command()); err != nil {
		t.Fatal(err)
	}
	api.work.KeyFingerprint = keyOf(t, api.submitted[0])
	api.submitErr = &serverapi.APIError{Status: 409, Code: wire.CodeCSRAlreadySubmitted}
	if err := h(context.Background(), command()); err != nil {
		t.Fatalf("re-run = %v, want nil (already submitted is success)", err)
	}
	if len(api.submitted) != 2 {
		t.Fatalf("submitted %d CSRs, want 2", len(api.submitted))
	}
	if keyOf(t, api.submitted[0]) != keyOf(t, api.submitted[1]) {
		t.Fatal("re-run built a CSR from a different key")
	}
}

// Work naming no key gets a fresh one each run: the keystore knows no
// certificate, so two runs of the same command are two keys. Nothing is
// signed with the first, so it is an orphan the inventory lists, not a bug.
func TestUnnamedKeyIsFreshEachRun(t *testing.T) {
	api := &fakeAPI{work: work("app.example.test")}
	h := newHandler(t, api)
	for range 2 {
		if err := h(context.Background(), command()); err != nil {
			t.Fatal(err)
		}
	}
	if keyOf(t, api.submitted[0]) == keyOf(t, api.submitted[1]) {
		t.Fatal("two runs with no key named reused one key")
	}
}

// A named key this host does not hold is never replaced: no CSR is built, and
// the command stays pending so its expiry fails the certificate naming this
// Agent rather than the Server receiving a CSR from a key it did not ask for.
func TestNamedKeyAbsentBuildsNothing(t *testing.T) {
	api := &fakeAPI{work: work("app.example.test")}
	api.work.KeyFingerprint = strings.Repeat("0", 64)
	h := newHandler(t, api)
	if err := h(context.Background(), command()); !errors.Is(err, keystore.ErrNoKey) {
		t.Fatalf("handler = %v, want ErrNoKey (left pending)", err)
	}
	if len(api.submitted) != 0 {
		t.Fatal("a CSR was submitted from a key the Server did not name")
	}
}

func TestTerminalRefusalsAreAcked(t *testing.T) {
	for _, code := range []string{wire.CodeNotAwaitingCSR, wire.CodeCSRMismatch} {
		api := &fakeAPI{work: work("app.example.test"), submitErr: &serverapi.APIError{Status: 409, Code: code}}
		h := newHandler(t, api)
		if err := h(context.Background(), command()); err != nil {
			t.Fatalf("%s: handler = %v, want nil (terminal, acked)", code, err)
		}
	}
}

func TestUnknownWorkIsDiscarded(t *testing.T) {
	api := &fakeAPI{workErr: &serverapi.APIError{Status: 404, Code: "not_found"}}
	h := newHandler(t, api)
	if err := h(context.Background(), command()); err != nil {
		t.Fatalf("handler = %v, want nil (stale instruction)", err)
	}
	if len(api.submitted) != 0 {
		t.Fatal("submitted a CSR for work that does not exist")
	}
}

func TestTransportTroubleLeavesTheCommandPending(t *testing.T) {
	fetch := &fakeAPI{workErr: errors.New("connection refused")}
	if err := newHandler(t, fetch)(context.Background(), command()); err == nil {
		t.Fatal("fetch transport error: handler = nil, want error (retry later)")
	}
	submit := &fakeAPI{work: work("app.example.test"), submitErr: errors.New("connection reset")}
	if err := newHandler(t, submit)(context.Background(), command()); err == nil {
		t.Fatal("submit transport error: handler = nil, want error (retry later)")
	}
}

// Work this Agent cannot perform is acked, not retried: nothing changes on a
// retry, and the command's expiry is what reports the certificate stuck.
func TestUnperformableWorkIsAckedWithoutSubmitting(t *testing.T) {
	cases := map[string]wire.CSRWork{
		"unknown key type": {CertificateID: certificateID, Domains: []string{"a.example.test"}, KeyType: "ml-dsa-44"},
		"no domains":       {CertificateID: certificateID, Domains: nil, KeyType: wire.KeyTypeECP256},
	}
	for name, w := range cases {
		api := &fakeAPI{work: w}
		if err := newHandler(t, api)(context.Background(), command()); err != nil {
			t.Fatalf("%s: handler = %v, want nil", name, err)
		}
		if len(api.submitted) != 0 {
			t.Fatalf("%s: submitted a CSR, want none", name)
		}
	}
}

func TestKeystoreTroubleLeavesTheCommandPending(t *testing.T) {
	api := &fakeAPI{work: work("app.example.test")}
	orig := generateKey
	generateKey = func(string) (string, crypto.Signer, error) { return "", nil, errors.New("disk full") }
	t.Cleanup(func() { generateKey = orig })
	h := New(api, "esat_test", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := h(context.Background(), command()); err == nil {
		t.Fatal("keystore failure: handler = nil, want error (retry until the command expires)")
	}
}

func TestRSAWorkBuildsAnRSACSR(t *testing.T) {
	w := work("app.example.test")
	w.KeyType = wire.KeyTypeRSA2048
	api := &fakeAPI{work: w}
	if err := newHandler(t, api)(context.Background(), command()); err != nil {
		t.Fatal(err)
	}
	if len(api.submitted) != 1 {
		t.Fatalf("submitted %d CSRs, want 1", len(api.submitted))
	}
	block, _ := pem.Decode([]byte(api.submitted[0]))
	req, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if got := wire.KeyTypeOf(req.PublicKey); got != wire.KeyTypeRSA2048 {
		t.Fatalf("CSR key is %s, want rsa_2048", got)
	}
}
