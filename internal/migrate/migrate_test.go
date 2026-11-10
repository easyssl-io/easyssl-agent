package migrate

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/easyssl-io/easyssl-agent/internal/acmeclients"
	"github.com/easyssl-io/easyssl-agent/internal/msg"
	"github.com/easyssl-io/easyssl-agent/internal/pluginmgr"
	"github.com/easyssl-io/easyssl-contract/l10n"
	"github.com/easyssl-io/easyssl-contract/plugincontract"
)

const keyPEM = "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n"

type host struct {
	t    *testing.T
	root string
}

func (h host) write(p, content string, mode os.FileMode) {
	h.t.Helper()
	full := filepath.Join(h.root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), mode); err != nil {
		h.t.Fatal(err)
	}
	if err := os.Chmod(full, mode); err != nil {
		h.t.Fatal(err)
	}
}

func (h host) read(p string) string {
	h.t.Helper()
	b, err := os.ReadFile(filepath.Join(h.root, p))
	if err != nil {
		h.t.Fatal(err)
	}
	return string(b)
}

func (h host) link(p, target string) {
	h.t.Helper()
	full := filepath.Join(h.root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.Symlink(target, full); err != nil {
		h.t.Fatal(err)
	}
}

// cert is a self-signed certificate with the given common name and names.
func cert(t *testing.T, cn string, dns []string, ips []net.IP) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		DNSNames: dns, IPAddresses: ips, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), hex.EncodeToString(sum[:])
}

// lineage lays out a certbot lineage under /etc/letsencrypt and returns its
// current certificate and that certificate's digest.
func (h host) lineage(name string) (string, string) {
	c, sum := cert(h.t, name, []string{name}, nil)
	dir := "/etc/letsencrypt"
	h.write(dir+"/archive/"+name+"/cert1.pem", c, 0o644)
	h.write(dir+"/archive/"+name+"/fullchain1.pem", c, 0o644)
	h.write(dir+"/archive/"+name+"/privkey1.pem", keyPEM, 0o600)
	for _, f := range []string{"cert", "fullchain", "privkey"} {
		h.link(dir+"/live/"+name+"/"+f+".pem", "../../archive/"+name+"/"+f+"1.pem")
	}
	h.write(dir+"/renewal/"+name+".conf", "archive_dir = "+dir+"/archive/"+name+"\ncert = "+dir+"/live/"+name+"/cert.pem\n", 0o644)
	return c, sum
}

func declared(contract string) plugincontract.DescribeResponse {
	return plugincontract.DescribeResponse{
		ContractVersion: contract, Version: "0.2.0",
		Declarations: []plugincontract.SettingDeclaration{
			{Key: "ssl_certificate", Label: l10n.Text{"en": "c"}, Type: plugincontract.SettingTypePath, Identity: true, Summary: true},
			{Key: "ssl_certificate_key", Label: l10n.Text{"en": "k"}, Type: plugincontract.SettingTypePath},
			{Key: "reload", Label: l10n.Text{"en": "r"}, Type: plugincontract.SettingTypeCommand},
		},
	}
}

func target(certPath, keyPath, sum string, domains []string, refs ...plugincontract.Reference) plugincontract.DiscoveredTarget {
	return plugincontract.DiscoveredTarget{
		Settings:    map[string]string{"ssl_certificate": certPath, "ssl_certificate_key": keyPath, "reload": "nginx -s reload"},
		ExtraData:   []plugincontract.ExtraDatum{},
		Certificate: &plugincontract.DiscoveredCertificate{Domains: domains, SHA256: sum},
		References:  refs, Warnings: []l10n.Text{},
	}
}

func ref(setting, file string, line int, value string) plugincontract.Reference {
	return plugincontract.Reference{Setting: setting, File: file, Line: line, Value: value}
}

// observer answers each Observe with the next answer in its list, the last
// one repeated.
type observer struct {
	answers [][]pluginmgr.Observation
	calls   int
}

func (o *observer) Observe(context.Context) ([]pluginmgr.Observation, error) {
	a := o.answers[min(o.calls, len(o.answers)-1)]
	o.calls++
	return a, nil
}

func nginx(contract string, targets ...plugincontract.DiscoveredTarget) pluginmgr.Observation {
	return pluginmgr.Observation{
		Installed: pluginmgr.Installed{ID: "nginx", Path: "/var/lib/easyssl/plugins/nginx"},
		Describe:  declared(contract),
		Discover:  plugincontract.DiscoverResponse{ContractVersion: contract, DiscoveredTargets: targets, Warnings: []l10n.Text{}},
	}
}

type chown struct {
	name     string
	uid, gid int
}

type run struct {
	out       bytes.Buffer
	relocated []plugincontract.RelocateRequest
	chowns    []chown
	reported  bool
}

func (h host) options(r *run, obs *observer, input string) Options {
	return Options{
		In: strings.NewReader(input), Out: &r.out,
		Host:    acmeclients.Host{Root: h.root},
		Plugins: obs,
		Relocate: func(_ context.Context, p pluginmgr.Installed, req plugincontract.RelocateRequest) (string, int, error) {
			r.relocated = append(r.relocated, req)
			return "changed 2 lines\n", 0, nil
		},
		HasACL: func(string) bool { return false },
		Chown: func(name string, uid, gid int) error {
			rel, _ := filepath.Rel(h.root, name)
			if strings.Contains(rel, ".tmp-") {
				rel = filepath.Dir(rel) + "/<tmp>"
			}
			r.chowns = append(r.chowns, chown{"/" + rel, uid, gid})
			return nil
		},
		Report: func(context.Context) (string, error) { r.reported = true; return "https://easyssl.example", nil },
	}
}

func TestMigrateMovesACertbotCertificate(t *testing.T) {
	h := host{t: t, root: t.TempDir()}
	certText, sum := h.lineage("example.com")
	_, otherSum := h.lineage("other.example")
	h.write("/etc/nginx/ssl/copy.pem", certText, 0o644)
	h.write("/etc/nginx/ssl/copy.key", keyPEM, 0o600)
	h.write("/etc/ssl/plain.pem", certText, 0o644)

	site := "/etc/nginx/sites-enabled/example"
	moved := target("/etc/letsencrypt/archive/example.com/fullchain1.pem", "/etc/letsencrypt/archive/example.com/privkey1.pem", sum,
		[]string{"example.com"},
		ref("ssl_certificate", site, 3, "/etc/letsencrypt/live/example.com/fullchain.pem"),
		ref("ssl_certificate_key", site, 4, "/etc/letsencrypt/live/example.com/privkey.pem"))
	fixFirst := target("/etc/letsencrypt/archive/other.example/fullchain1.pem", "/etc/letsencrypt/archive/other.example/privkey1.pem", otherSum,
		[]string{"other.example"}, ref("ssl_certificate", "/etc/apache2/a.conf", 9, "/etc/letsencrypt/live/other.example/fullchain.pem"))
	fixFirst.Warnings = []l10n.Text{{"en": "It is also named by `SSLCertificateChainFile`."}}
	hookCopy := target("/etc/nginx/ssl/copy.pem", "/etc/nginx/ssl/copy.key", sum, []string{"example.com"},
		ref("ssl_certificate", "/etc/nginx/sites-enabled/copy", 2, "/etc/nginx/ssl/copy.pem"))
	before := nginx("0.2.0", moved, fixFirst, hookCopy)

	after := moved
	after.Settings = map[string]string{"ssl_certificate": "/etc/ssl/easyssl/example.com/certificate.pem", "ssl_certificate_key": "/etc/ssl/easyssl/example.com/key.pem"}
	after.References = []plugincontract.Reference{
		ref("ssl_certificate", site, 3, "/etc/ssl/easyssl/example.com/certificate.pem"),
		ref("ssl_certificate_key", site, 4, "/etc/ssl/easyssl/example.com/key.pem"),
	}
	obs := &observer{answers: [][]pluginmgr.Observation{{before}, {nginx("0.2.0", after, fixFirst, hookCopy)}}}

	r := &run{}
	if err := Run(context.Background(), h.options(r, obs, "1\ny\n")); err != nil {
		t.Fatalf("migrate: %v\n%s", err, r.out.String())
	}
	out := r.out.String()
	for _, want := range []string{
		"certbot directory /etc/letsencrypt, with 2 certificates, checked because:\n    it is certbot's default directory\n\n",
		"  certbot certificate example.com in /etc/letsencrypt:\n    1. nginx  /etc/letsencrypt/archive/example.com/fullchain1.pem  example.com",
		"Fix first, since its Plugin reports more than certbot's directory:\n    nginx  /etc/letsencrypt/archive/other.example/fullchain1.pem  other.example\n        - It is also named by `SSLCertificateChainFile`.",
		"Cannot be moved by this command:\n    nginx  /etc/nginx/ssl/copy.pem  example.com\n        - It is identical to certbot's current certificate `example.com`",
		"  /etc/letsencrypt/archive/example.com/fullchain1.pem -> /etc/ssl/easyssl/example.com/certificate.pem\n" +
			"  /etc/letsencrypt/archive/example.com/privkey1.pem -> /etc/ssl/easyssl/example.com/key.pem\n",
		"  " + site + ":3  /etc/letsencrypt/live/example.com/fullchain.pem -> /etc/ssl/easyssl/example.com/certificate.pem\n",
		"✓ Copied 2 files under /etc/ssl/easyssl.",
		"changed 2 lines\n✓ The nginx Plugin changed its configuration.",
		"Nothing the Plugins read uses certbot's certificate example.com any more.",
		"check that nothing else uses /etc/letsencrypt/live/example.com/ before",
		"    certbot delete --cert-name example.com\n",
		"✓ Reported the new inventory to https://easyssl.example.",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output lacks %q:\n%s", want, out)
		}
	}
	// The unmanaged certificate is not mentioned at all.
	if strings.Contains(out, "/etc/ssl/plain.pem") {
		t.Fatalf("an unmanaged certificate was listed:\n%s", out)
	}

	if got := h.read("/etc/ssl/easyssl/example.com/certificate.pem"); got != certText {
		t.Fatal("the certificate copy differs from its source")
	}
	if got := h.read("/etc/ssl/easyssl/example.com/key.pem"); got != keyPEM {
		t.Fatal("the key copy differs from its source")
	}
	fi, err := os.Stat(filepath.Join(h.root, "etc/ssl/easyssl/example.com/key.pem"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key copy mode = %v, %v", fi.Mode(), err)
	}
	if entries, _ := os.ReadDir(filepath.Join(h.root, "etc/ssl/easyssl/example.com")); len(entries) != 2 {
		t.Fatalf("leftovers beside the copies: %v", entries)
	}
	uid, gid := os.Getuid(), os.Getgid()
	wantChowns := []chown{
		{"/etc/ssl/easyssl", 0, 0},
		{"/etc/ssl/easyssl/example.com", uid, gid},
		{"/etc/ssl/easyssl/example.com/<tmp>", uid, gid},
		{"/etc/ssl/easyssl/example.com/<tmp>", uid, gid},
	}
	if !reflect.DeepEqual(r.chowns, wantChowns) {
		t.Fatalf("chowns = %+v\nwant %+v", r.chowns, wantChowns)
	}

	wantReq := []plugincontract.RelocateRequest{{
		Moves: []plugincontract.Move{
			{From: "/etc/letsencrypt/live/example.com/fullchain.pem", To: "/etc/ssl/easyssl/example.com/certificate.pem"},
			{From: "/etc/letsencrypt/live/example.com/privkey.pem", To: "/etc/ssl/easyssl/example.com/key.pem"},
		},
		References: moved.References,
	}}
	if !reflect.DeepEqual(r.relocated, wantReq) {
		t.Fatalf("relocate = %+v\nwant %+v", r.relocated, wantReq)
	}
	if !r.reported {
		t.Fatal("the inventory was not reported")
	}
}

func TestALineageStillUsedIsListedInsteadOfDeleted(t *testing.T) {
	h := host{t: t, root: t.TempDir()}
	_, sum := h.lineage("example.com")
	a := target("/etc/letsencrypt/archive/example.com/fullchain1.pem", "/etc/letsencrypt/archive/example.com/privkey1.pem", sum, nil,
		ref("ssl_certificate", "/etc/nginx/a", 1, "/etc/letsencrypt/live/example.com/fullchain.pem"))
	// The Plugin's configuration still names the lineage after the move, as it
	// would had another server block been added meanwhile.
	obs := &observer{answers: [][]pluginmgr.Observation{{nginx("0.2.0", a)}}}
	r := &run{}
	if err := Run(context.Background(), h.options(r, obs, "all\ny\n")); err != nil {
		t.Fatal(err)
	}
	out := r.out.String()
	if !strings.Contains(out, "certbot's certificate example.com is still used by:\n    /etc/nginx/a:1  /etc/letsencrypt/live/example.com/fullchain.pem") ||
		strings.Contains(out, "certbot delete") {
		t.Fatalf("output:\n%s", out)
	}
}

func TestCancelingChangesNothing(t *testing.T) {
	for name, input := range map[string]string{"no choice": "\n", "closed input": "", "declined": "1\nn\n", "invalid then cancel": "7\nx\n\n"} {
		t.Run(name, func(t *testing.T) {
			h := host{t: t, root: t.TempDir()}
			_, sum := h.lineage("example.com")
			a := target("/etc/letsencrypt/archive/example.com/fullchain1.pem", "/etc/letsencrypt/archive/example.com/privkey1.pem", sum, nil,
				ref("ssl_certificate", "/etc/nginx/a", 1, "/etc/letsencrypt/live/example.com/fullchain.pem"))
			r := &run{}
			err := Run(context.Background(), h.options(r, &observer{answers: [][]pluginmgr.Observation{{nginx("0.2.0", a)}}}, input))
			if !errors.Is(err, ErrNothingChanged) {
				t.Fatalf("err = %v", err)
			}
			if _, err := os.Stat(filepath.Join(h.root, DestDir)); err == nil || len(r.relocated) > 0 || r.reported {
				t.Fatal("something was changed")
			}
		})
	}
}

func TestWhatTheCommandCannotMove(t *testing.T) {
	h := host{t: t, root: t.TempDir()}
	_, sum := h.lineage("example.com")
	h.write("/var/lib/acme/x/cert.pem", "", 0o644)
	a := target("/etc/letsencrypt/archive/example.com/fullchain1.pem", "/etc/letsencrypt/archive/example.com/privkey1.pem", sum, nil,
		ref("ssl_certificate", "/etc/nginx/a", 1, "/etc/letsencrypt/live/example.com/fullchain.pem"))
	lego := target("/var/lib/acme/x/cert.pem", "/var/lib/acme/x/key.pem", "", nil)
	for name, tc := range map[string]struct {
		obs  pluginmgr.Observation
		acl  bool
		want string
	}{
		"an older Plugin": {nginx("0.1.0", a), false, "Its nginx Plugin 0.2.0 cannot change its configuration."},
		"an ACL":          {nginx("0.2.0", a), true, "/etc/letsencrypt/archive/example.com/fullchain1.pem carries a POSIX ACL"},
		"no references":   {nginx("0.2.0", target(a.Settings["ssl_certificate"], a.Settings["ssl_certificate_key"], sum, nil)), false, "reports no configuration line naming it"},
		"another client":  {nginx("0.2.0", lego), false, "It is under `/var/lib/acme`, which lego manages"},
	} {
		t.Run(name, func(t *testing.T) {
			r := &run{}
			opts := h.options(r, &observer{answers: [][]pluginmgr.Observation{{tc.obs}}}, "")
			opts.HasACL = func(string) bool { return tc.acl }
			if err := Run(context.Background(), opts); err != nil {
				t.Fatal(err)
			}
			out := r.out.String()
			if !strings.Contains(out, "Cannot be moved by this command:") || !strings.Contains(out, tc.want) ||
				!strings.Contains(out, "None of them can be moved by this command.") {
				t.Fatalf("output:\n%s", out)
			}
		})
	}
}

func TestALineSharedWithACertificateNotChosenRefuses(t *testing.T) {
	h := host{t: t, root: t.TempDir()}
	_, sum := h.lineage("example.com")
	_, sum2 := h.lineage("b.example")
	// Two Targets whose configuration spells a path the same way: a relative
	// path in two included files, say.
	a := target("/etc/letsencrypt/archive/example.com/fullchain1.pem", "/etc/letsencrypt/archive/example.com/privkey1.pem", sum, nil,
		ref("ssl_certificate", "/etc/nginx/a", 1, "fullchain.pem"))
	b := target("/etc/letsencrypt/archive/b.example/fullchain1.pem", "/etc/letsencrypt/archive/b.example/privkey1.pem", sum2, nil,
		ref("ssl_certificate", "/etc/nginx/b", 1, "fullchain.pem"))
	r := &run{}
	err := Run(context.Background(), h.options(r, &observer{answers: [][]pluginmgr.Observation{{nginx("0.2.0", a, b)}}}, "1\n"))
	if err == nil || !strings.Contains(err.Error(), "for a certificate not chosen") {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(h.root, DestDir)); err == nil {
		t.Fatal("copies were made")
	}
}

func TestCopiesAreNamedAndNeverOverwritten(t *testing.T) {
	h := host{t: t, root: t.TempDir()}
	certText, sum := cert(t, "Ignored.example", []string{"*.Example.org"}, nil)
	h.write("/etc/certbot-like/fullchain.pem", certText, 0o644)
	h.write("/etc/certbot-like/privkey.pem", keyPEM, 0o640)
	// An earlier run left another certificate under the same name, and the
	// same key, with the source's mode.
	h.write("/etc/ssl/easyssl/_.example.org/certificate.pem", "earlier", 0o644)
	h.write("/etc/ssl/easyssl/_.example.org/key.pem", keyPEM, 0o640)

	s := &session{opts: Options{Host: acmeclients.Host{Root: h.root}}}
	it := &item{obs: &pluginmgr.Observation{Describe: declared("0.2.0")}, target: target("/etc/certbot-like/fullchain.pem", "/etc/certbot-like/privkey.pem", sum, []string{"*.Example.org"},
		ref("ssl_certificate", "/etc/nginx/a", 1, "/etc/certbot-like/fullchain.pem"),
		ref("ssl_certificate_key", "/etc/nginx/a", 2, "/etc/certbot-like/privkey.pem"))}
	m, err := s.plan([]*item{it}, []*item{it})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, c := range m.copies {
		got[c.dest] = c.reuse
	}
	want := map[string]bool{"/etc/ssl/easyssl/_.example.org/certificate-2.pem": false, "/etc/ssl/easyssl/_.example.org/key.pem": true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("copies = %v", got)
	}
}

// A file left by an earlier run is reused only when it is exactly the copy:
// a symlink or another mode is someone else's file under that name, and a
// directory that is no longer safe refuses the plan, reused copies included.
func TestReusedCopiesAreCheckedLikeNewOnes(t *testing.T) {
	plan := func(t *testing.T, prepare func(h host)) (map[string]bool, error) {
		h := host{t: t, root: t.TempDir()}
		certText, sum := cert(t, "a.example", []string{"a.example"}, nil)
		h.write("/etc/certbot-like/fullchain.pem", certText, 0o644)
		h.write("/etc/certbot-like/privkey.pem", keyPEM, 0o600)
		h.write("/etc/ssl/easyssl/a.example/certificate.pem", certText, 0o644)
		h.write("/etc/ssl/easyssl/a.example/key.pem", keyPEM, 0o600)
		for _, d := range []string{"/etc/ssl/easyssl", "/etc/ssl/easyssl/a.example"} {
			if err := os.Chmod(filepath.Join(h.root, d), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		prepare(h)
		s := &session{opts: Options{Host: acmeclients.Host{Root: h.root}}}
		it := &item{obs: &pluginmgr.Observation{Describe: declared("0.2.0")}, target: target("/etc/certbot-like/fullchain.pem", "/etc/certbot-like/privkey.pem", sum, []string{"a.example"},
			ref("ssl_certificate", "/etc/nginx/a", 1, "/etc/certbot-like/fullchain.pem"),
			ref("ssl_certificate_key", "/etc/nginx/a", 2, "/etc/certbot-like/privkey.pem"))}
		m, err := s.plan([]*item{it}, []*item{it})
		if err != nil {
			return nil, err
		}
		got := map[string]bool{}
		for _, c := range m.copies {
			got[c.dest] = c.reuse
		}
		return got, nil
	}
	got, err := plan(t, func(host) {})
	if want := map[string]bool{"/etc/ssl/easyssl/a.example/certificate.pem": true, "/etc/ssl/easyssl/a.example/key.pem": true}; err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("exact copies: %v, %v", got, err)
	}
	got, err = plan(t, func(h host) {
		key := filepath.Join(h.root, "/etc/ssl/easyssl/a.example/key.pem")
		os.Remove(key)
		h.write("/elsewhere/key.pem", keyPEM, 0o600)
		if err := os.Symlink(filepath.Join(h.root, "/elsewhere/key.pem"), key); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(h.root, "/etc/ssl/easyssl/a.example/certificate.pem"), 0o664); err != nil {
			t.Fatal(err)
		}
	})
	if want := map[string]bool{"/etc/ssl/easyssl/a.example/certificate-2.pem": false, "/etc/ssl/easyssl/a.example/key-2.pem": false}; err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("a symlink and another mode: %v, %v", got, err)
	}
	_, err = plan(t, func(h host) {
		if err := os.Chmod(filepath.Join(h.root, "/etc/ssl/easyssl/a.example"), 0o777); err != nil {
			t.Fatal(err)
		}
	})
	if err == nil || !strings.Contains(err.Error(), "can be written by users other than its owner") {
		t.Fatalf("a writable directory holding reused copies: err = %v", err)
	}
}

// A destination whose parent cannot be a directory fails every name the same
// way, so planning stops and says why instead of trying names forever.
func TestADestinationThatCannotHoldCopiesStopsPlanning(t *testing.T) {
	h := host{t: t, root: t.TempDir()}
	certText, sum := cert(t, "a.example", []string{"a.example"}, nil)
	h.write("/etc/certbot-like/fullchain.pem", certText, 0o644)
	h.write("/etc/ssl/easyssl", "a file where the directory goes", 0o644)

	s := &session{opts: Options{Host: acmeclients.Host{Root: h.root}}}
	it := &item{obs: &pluginmgr.Observation{Describe: declared("0.2.0")}, target: target("/etc/certbot-like/fullchain.pem", "", sum, []string{"a.example"},
		ref("ssl_certificate", "/etc/nginx/a", 1, "/etc/certbot-like/fullchain.pem"))}
	done := make(chan error, 1)
	go func() {
		_, err := s.plan([]*item{it}, []*item{it})
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "cannot hold a copy") {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("planning did not return")
	}
}

func TestNames(t *testing.T) {
	h := host{t: t, root: t.TempDir()}
	cnOnly, _ := cert(t, "Only.CN.example", nil, nil)
	h.write("/c/cn.pem", cnOnly, 0o644)
	none, _ := cert(t, "", nil, nil)
	h.write("/c/none.pem", none, 0o644)
	s := &session{opts: Options{Host: acmeclients.Host{Root: h.root}}}
	obs := &pluginmgr.Observation{Describe: declared("0.2.0")}
	for want, it := range map[string]*item{
		"example.com":     {obs: obs, lineage: &acmeclients.Lineage{Name: "example.com"}, target: target("/x", "/y", "", []string{"other.example"})},
		"_.example.org":   {obs: obs, target: target("/x", "/y", "", []string{"*.EXAMPLE.org", "example.org"})},
		"2001-db8---1":    {obs: obs, target: target("/x", "/y", "", []string{"2001:db8:::1"})},
		"only.cn.example": {obs: obs, target: target("/c/cn.pem", "/y", "", nil)},
		"certificate":     {obs: obs, target: target("/c/none.pem", "/y", "", nil)},
		"a_b":             {obs: obs, lineage: &acmeclients.Lineage{Name: "a/b"}, target: target("/x", "/y", "", nil)},
	} {
		if got := s.name(it); got != want {
			t.Errorf("name = %q, want %q", got, want)
		}
	}
}

func TestParseChoice(t *testing.T) {
	for in, want := range map[string][]int{"1": {1}, "3, 1": {3, 1}, "1,1 2": {1, 2}, "all": {1, 2, 3}, "ALL": {1, 2, 3}} {
		if got, ok := parseChoice(in, 3); !ok || !reflect.DeepEqual(got, want) {
			t.Errorf("parseChoice(%q) = %v, %v", in, got, ok)
		}
	}
	for _, in := range []string{"0", "4", "1-2", "x", ","} {
		if _, ok := parseChoice(in, 3); ok {
			t.Errorf("parseChoice(%q) accepted", in)
		}
	}
}

func TestAFailedRelocateIsReported(t *testing.T) {
	h := host{t: t, root: t.TempDir()}
	_, sum := h.lineage("example.com")
	a := target("/etc/letsencrypt/archive/example.com/fullchain1.pem", "/etc/letsencrypt/archive/example.com/privkey1.pem", sum, nil,
		ref("ssl_certificate", "/etc/nginx/a", 1, "/etc/letsencrypt/live/example.com/fullchain.pem"))
	r := &run{}
	opts := h.options(r, &observer{answers: [][]pluginmgr.Observation{{nginx("0.2.0", a)}}}, "1\ny\n")
	opts.Relocate = func(context.Context, pluginmgr.Installed, plugincontract.RelocateRequest) (string, int, error) {
		return "nginx -t failed; the original configuration is back\n", 1, errors.New("its output says why")
	}
	err := Run(context.Background(), opts)
	if err == nil || err.Error() != "1 Plugin could not change its configuration; its output above says why." {
		t.Fatalf("err = %v", err)
	}
	out := r.out.String()
	if !strings.Contains(out, "nginx -t failed; the original configuration is back\n✗ The nginx Plugin did not change its configuration (exit status 1): its output says why") ||
		!strings.Contains(out, "certbot's certificate example.com is still used by:") {
		t.Fatalf("output:\n%s", out)
	}
}

func TestRunRelocate(t *testing.T) {
	dir := t.TempDir()
	plugin := filepath.Join(dir, "nginx")
	script := "#!/bin/sh\n[ \"$1\" = relocate ] || exit 9\ncat > " + filepath.Join(dir, "req.json") + "\necho 'changed 1 line'\necho diagnostics >&2\nexit ${EXIT:-0}\n"
	if err := os.WriteFile(plugin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	req := plugincontract.RelocateRequest{Moves: []plugincontract.Move{{From: "/a", To: "/b"}}, References: []plugincontract.Reference{ref("ssl_certificate", "/etc/nginx/a", 1, "/a")}}
	out, status, err := runRelocate(context.Background(), plugin, req, nil)
	if err != nil || status != 0 || out != "changed 1 line\n" {
		t.Fatalf("relocate = %q, %d, %v", out, status, err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "req.json")); string(got) != `{"moves":[{"from":"/a","to":"/b"}],"references":[{"setting":"ssl_certificate","file":"/etc/nginx/a","line":1,"value":"/a"}]}` {
		t.Fatalf("request = %s", got)
	}
	t.Setenv("EXIT", "1")
	out, status, err = runRelocate(context.Background(), plugin, req, nil)
	if err == nil || status != 1 || out != "changed 1 line\ndiagnostics" {
		t.Fatalf("relocate = %q, %d, %v", out, status, err)
	}
}

// The Plugin answers in the language this run speaks, whatever EASYSSL_LANG the
// caller's environment held (`sudo` drops it).
func TestRunRelocatePassesTheLanguage(t *testing.T) {
	dir := t.TempDir()
	plugin := filepath.Join(dir, "nginx")
	if err := os.WriteFile(plugin, []byte("#!/bin/sh\necho \"$EASYSSL_LANG\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EASYSSL_LANG", "en")
	msg.SetLanguage("es")
	t.Cleanup(func() { msg.SetLanguage("en") })
	out, _, err := runRelocate(context.Background(), plugin, plugincontract.RelocateRequest{}, nil)
	if err != nil || out != "es\n" {
		t.Fatalf("relocate saw EASYSSL_LANG=%q, %v", out, err)
	}
}

// A Plugin built before 0.2.0 reports certbot's certificates only as warnings,
// so the command says why it offers none of them and how to change that.
func TestAPluginTooOldToRelocateIsNamed(t *testing.T) {
	h := host{t: t, root: t.TempDir()}
	h.lineage("example.com")
	obs := &observer{answers: [][]pluginmgr.Observation{{nginx("0.1.0")}}}
	r := &run{}
	if err := Run(context.Background(), h.options(r, obs, "\n")); err != nil {
		t.Fatal(err)
	}
	if out := r.out.String(); !strings.Contains(out, "The nginx Plugin was built against contract 0.1.0, older than 0.2.0") ||
		!strings.Contains(out, "`easyssl-agent plugin install nginx`") {
		t.Fatalf("output:\n%s", out)
	}
}

// A destination directory someone could have prepared is refused before any
// key is written: a symlink, or one others can write.
func TestUnsafeDestinationDirectoriesAreRefused(t *testing.T) {
	for name, prepare := range map[string]func(t *testing.T, root string) string{
		"easySSL's directory is a symlink": func(t *testing.T, root string) string {
			elsewhere := t.TempDir()
			mustMkdir(t, filepath.Join(root, "etc/ssl"), 0o755)
			if err := os.Symlink(elsewhere, filepath.Join(root, DestDir)); err != nil {
				t.Fatal(err)
			}
			return elsewhere
		},
		"the certificate's directory is group-writable": func(t *testing.T, root string) string {
			dir := filepath.Join(root, DestDir, "example.com")
			mustMkdir(t, dir, 0o775)
			if err := os.Chmod(dir, 0o775); err != nil {
				t.Fatal(err)
			}
			return dir
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := host{t: t, root: t.TempDir()}
			_, sum := h.lineage("example.com")
			a := target("/etc/letsencrypt/archive/example.com/fullchain1.pem", "/etc/letsencrypt/archive/example.com/privkey1.pem", sum, nil,
				ref("ssl_certificate", "/etc/nginx/a", 1, "/etc/letsencrypt/live/example.com/fullchain.pem"))
			watched := prepare(t, h.root)
			relocated := false
			opts := h.options(&run{}, &observer{answers: [][]pluginmgr.Observation{{nginx("0.2.0", a)}}}, "1\ny\n")
			opts.Relocate = func(context.Context, pluginmgr.Installed, plugincontract.RelocateRequest) (string, int, error) {
				relocated = true
				return "", 0, nil
			}
			if err := Run(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "so no key is written there") {
				t.Fatalf("err = %v", err)
			}
			if entries, _ := os.ReadDir(watched); len(entries) != 0 || relocated {
				t.Fatalf("wrote %d entries, relocated %v", len(entries), relocated)
			}
		})
	}
}

func mustMkdir(t *testing.T, dir string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(dir, mode); err != nil {
		t.Fatal(err)
	}
}
