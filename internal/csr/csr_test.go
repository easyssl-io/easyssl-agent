package csr

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"slices"
	"testing"

	"github.com/easyssl-io/easyssl-contract/wire"

	"github.com/easyssl-io/easyssl-agent/internal/serverapi"
)

const certID = "3f2b9c44-1a77-4ce0-8d21-0d5e8f6a4b72"

// fakeAPI stands in for the Server wrapper. Keys still come from real keystore
// code paths where possible: only Ensure is replaced (it requires root and a
// filesystem), and with a per-certificate memoized key so idempotence is
// observable.
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

func memoizedEnsure(t *testing.T) func(string) (*ecdsa.PrivateKey, error) {
	t.Helper()
	keys := map[string]*ecdsa.PrivateKey{}
	return func(id string) (*ecdsa.PrivateKey, error) {
		if k, ok := keys[id]; ok {
			return k, nil
		}
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[id] = k
		return k, nil
	}
}

func newHandler(t *testing.T, api *fakeAPI) func(context.Context, wire.Command) error {
	t.Helper()
	orig := ensureKey
	ensureKey = memoizedEnsure(t)
	t.Cleanup(func() { ensureKey = orig })
	return New(api, "esct_test", slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func work(domains ...string) wire.CSRWork {
	return wire.CSRWork{CertificateID: certID, Domains: domains, KeyType: wire.KeyTypeECP256}
}

func command() wire.Command {
	return wire.Command{ID: "cmd-1", Type: wire.CommandRequestCSR, RefID: certID}
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

// A re-run after a crash is handed the same command again; the key must be the
// one already generated, so the Server's stored CSR (from run one) matches what
// run two would have sent.
func TestReRunUsesTheSameKey(t *testing.T) {
	api := &fakeAPI{work: work("app.example.test")}
	h := newHandler(t, api)

	if err := h(context.Background(), command()); err != nil {
		t.Fatal(err)
	}
	api.submitErr = &serverapi.APIError{Status: 409, Code: wire.CodeCSRAlreadySubmitted}
	if err := h(context.Background(), command()); err != nil {
		t.Fatalf("re-run = %v, want nil (already submitted is success)", err)
	}
	if len(api.submitted) != 2 {
		t.Fatalf("submitted %d CSRs, want 2", len(api.submitted))
	}
	key := func(p string) any {
		block, _ := pem.Decode([]byte(p))
		req, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKIXPublicKey(req.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		return string(der)
	}
	if key(api.submitted[0]) != key(api.submitted[1]) {
		t.Fatal("re-run built a CSR from a different key")
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
		"unknown key type": {CertificateID: certID, Domains: []string{"a.example.test"}, KeyType: "ml-dsa-44"},
		"no domains":       {CertificateID: certID, Domains: nil, KeyType: wire.KeyTypeECP256},
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
	orig := ensureKey
	ensureKey = func(string) (*ecdsa.PrivateKey, error) { return nil, errors.New("disk full") }
	t.Cleanup(func() { ensureKey = orig })
	h := New(api, "esct_test", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := h(context.Background(), command()); err == nil {
		t.Fatal("keystore failure: handler = nil, want error (retry until the command expires)")
	}
}
