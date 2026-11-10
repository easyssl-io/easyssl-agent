package acmeclients

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/easyssl-io/easyssl-contract/l10n"
	"github.com/easyssl-io/easyssl-contract/plugincontract"
)

// fixture is a host under a temporary root.
type fixture struct {
	t    *testing.T
	root string
}

func newFixture(t *testing.T) *fixture { return &fixture{t: t, root: t.TempDir()} }

func (f *fixture) host() Host { return Host{Root: f.root, PATH: "/usr/local/bin:/usr/bin"} }

func (f *fixture) write(p, content string) {
	f.t.Helper()
	full := filepath.Join(f.root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) link(p, target string) {
	f.t.Helper()
	full := filepath.Join(f.root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Symlink(target, full); err != nil {
		f.t.Fatal(err)
	}
}

// certPEM is a fresh self-signed certificate for name, and its leaf SHA-256.
func certPEM(t *testing.T, name string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), hex.EncodeToString(sum[:])
}

// lineage lays out a certbot lineage the way certbot does: versioned files in
// archive/, relative links in live/, and its renewal configuration. It returns
// the leaf SHA-256 of its current certificate.
func (f *fixture) lineage(dir, name string) string {
	f.t.Helper()
	cert, sum := certPEM(f.t, name)
	f.write(dir+"/archive/"+name+"/cert1.pem", cert)
	f.write(dir+"/archive/"+name+"/fullchain1.pem", cert)
	f.write(dir+"/archive/"+name+"/privkey1.pem", "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n")
	for _, file := range []string{"cert", "fullchain", "privkey"} {
		f.link(dir+"/live/"+name+"/"+file+".pem", "../../archive/"+name+"/"+file+"1.pem")
	}
	f.write(dir+"/renewal/"+name+".conf", strings.Join([]string{
		"# renew_before_expiry = 30 days",
		"version = 2.11.0",
		"archive_dir = " + dir + "/archive/" + name,
		"cert = " + dir + "/live/" + name + "/cert.pem",
		"privkey = " + dir + "/live/" + name + "/privkey.pem",
		"fullchain = " + dir + "/live/" + name + "/fullchain.pem",
		"",
		"[renewalparams]",
		"archive_dir = /elsewhere",
		"authenticator = nginx",
	}, "\n"))
	return sum
}

func TestTheDefaultDirectoryAndItsLineages(t *testing.T) {
	f := newFixture(t)
	sum := f.lineage(DefaultCertbotDir, "example.com")
	r := f.host().Scan(nil)
	dirs := r.CertbotDirs()
	if len(dirs) != 1 || dirs[0].Path != DefaultCertbotDir || !reflect.DeepEqual(dirs[0].Sources, []Source{{Kind: FromDefault}}) {
		t.Fatalf("certbot dirs = %+v", dirs)
	}
	ls := dirs[0].Lineages
	if len(ls) != 1 || ls[0].Name != "example.com" || ls[0].ArchiveDir != "/etc/letsencrypt/archive/example.com" ||
		ls[0].LiveDir != "/etc/letsencrypt/live/example.com" || ls[0].CertSHA256 != sum {
		t.Fatalf("lineages = %+v (want sha %s)", ls, sum)
	}

	for _, p := range []string{
		"/etc/letsencrypt/archive/example.com/fullchain1.pem",
		"/etc/letsencrypt/live/example.com/privkey.pem",
	} {
		fs := r.Check(Target{Paths: []string{p}})
		if len(fs) != 1 || fs[0].Kind != Certbot || fs[0].Dir != DefaultCertbotDir || fs[0].Lineage == nil || fs[0].Lineage.Name != "example.com" {
			t.Fatalf("%s: findings = %+v", p, fs)
		}
	}
	// The certificate and the key in the same directory are one finding.
	fs := r.Check(Target{Paths: []string{
		"/etc/letsencrypt/live/example.com/fullchain.pem", "/etc/letsencrypt/live/example.com/privkey.pem",
	}})
	if len(fs) != 1 {
		t.Fatalf("findings = %+v, want one", fs)
	}
	// Outside it, nothing; and a sibling whose name only starts the same.
	for _, p := range []string{"/etc/ssl/example.pem", "/etc/letsencrypt-old/live/example.com/fullchain.pem"} {
		if fs := r.Check(Target{Paths: []string{p}}); len(fs) != 0 {
			t.Fatalf("%s: findings = %+v", p, fs)
		}
	}
}

func TestALinkIntoCertbotsDirectoryIsManaged(t *testing.T) {
	f := newFixture(t)
	f.lineage(DefaultCertbotDir, "example.com")
	f.link("/etc/nginx/ssl/example.pem", "/etc/letsencrypt/live/example.com/fullchain.pem")
	r := f.host().Scan(nil)
	fs := r.Check(Target{Paths: []string{"/etc/nginx/ssl/example.pem"}})
	if len(fs) != 1 || fs[0].Kind != Certbot || fs[0].Path != "/etc/nginx/ssl/example.pem" || fs[0].Lineage.Name != "example.com" {
		t.Fatalf("findings = %+v", fs)
	}
	if real, err := f.host().Resolve("/etc/nginx/ssl/example.pem"); err != nil || real != "/etc/letsencrypt/archive/example.com/fullchain1.pem" {
		t.Fatalf("resolved = %q, %v", real, err)
	}
}

func TestDirectoriesNamedBySystemdCronAndCLIIni(t *testing.T) {
	f := newFixture(t)
	f.lineage("/srv/le", "a.example")
	f.lineage("/opt/certs", "b.example")
	f.lineage("/var/ini", "c.example")
	f.write("/etc/systemd/system/renew.service", "[Service]\nType=oneshot\nExecStart=-/usr/bin/certbot -q renew --config-dir /srv/le --deploy-hook 'systemctl reload nginx'\n")
	f.write("/etc/cron.d/certbot", "SHELL=/bin/sh\n# certbot --config-dir /commented\n0 */12 * * * root test -x /usr/bin/certbot && certbot -q renew --config-dir=\"/opt/certs\"\n")
	f.write("/etc/letsencrypt/cli.ini", "# comment\nconfig-dir = /var/ini\nemail: a@example.com\n")
	// A unit that names a directory that does not exist, and one that is not certbot's.
	f.write("/lib/systemd/system/other.service", "[Service]\nExecStart=/usr/bin/certbot renew --config-dir /missing\n")
	f.write("/lib/systemd/system/backup.service", "[Service]\nExecStart=/usr/bin/rsync --config-dir /srv/le\n")

	got := map[string][]Source{}
	for _, d := range f.host().Scan(nil).CertbotDirs() {
		got[d.Path] = d.Sources
	}
	want := map[string][]Source{
		"/srv/le":          {{Kind: FromSystemd, File: "/etc/systemd/system/renew.service"}},
		"/opt/certs":       {{Kind: FromCron, File: "/etc/cron.d/certbot"}},
		"/var/ini":         {{Kind: FromCLIIni, File: "/etc/letsencrypt/cli.ini"}},
		"/etc/letsencrypt": {{Kind: FromDefault}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("dirs = %+v\nwant %+v", got, want)
	}
}

func TestADirectoryShownByStructure(t *testing.T) {
	f := newFixture(t)
	f.lineage("/data/store", "x.example")
	// Same layout, but its renewal configuration names another archive.
	f.lineage("/data/fake", "y.example")
	f.write("/data/fake/renewal/y.example.conf", "archive_dir = /data/fake/archive/z\n")

	p := "/data/store/live/x.example/fullchain.pem"
	r := f.host().Scan([]string{p, "/data/fake/archive/y.example/cert1.pem"})
	dirs := r.CertbotDirs()
	if len(dirs) != 1 || dirs[0].Path != "/data/store" || !reflect.DeepEqual(dirs[0].Sources, []Source{{Kind: FromStructure, File: p}}) {
		t.Fatalf("dirs = %+v", dirs)
	}
	if fs := r.Check(Target{Paths: []string{p}}); len(fs) != 1 || fs[0].Kind != Certbot || fs[0].Dir != "/data/store" {
		t.Fatalf("findings = %+v", fs)
	}
}

func TestAHookCopy(t *testing.T) {
	f := newFixture(t)
	sum := f.lineage(DefaultCertbotDir, "example.com")
	r := f.host().Scan(nil)
	copyTarget := Target{Paths: []string{"/etc/nginx/ssl/example.key", "/etc/nginx/ssl/example.pem"}, CertSHA256: sum, CertPath: "/etc/nginx/ssl/example.pem"}

	fs := r.Assess([]Target{copyTarget})
	if len(fs[0]) != 1 || fs[0][0].Kind != HookCopy || fs[0][0].Lineage.Name != "example.com" || fs[0][0].Path != "/etc/nginx/ssl/example.pem" || fs[0][0].LineageInUse {
		t.Fatalf("findings = %+v", fs)
	}
	// While another Target still serves the lineage's own files, deleting it is
	// not the advice.
	fs = r.Assess([]Target{copyTarget, {Paths: []string{"/etc/letsencrypt/live/example.com/fullchain.pem"}, CertSHA256: sum}})
	if len(fs[0]) != 1 || !fs[0][0].LineageInUse {
		t.Fatalf("findings = %+v", fs)
	}
	// The lineage's own files are certbot findings, never hook copies.
	if len(fs[1]) != 1 || fs[1][0].Kind != Certbot {
		t.Fatalf("findings = %+v", fs[1])
	}
	// Another certificate is not a copy.
	_, other := certPEM(t, "other.example")
	if fs := r.Check(Target{Paths: []string{"/etc/nginx/ssl/o.pem"}, CertSHA256: other}); len(fs) != 0 {
		t.Fatalf("findings = %+v", fs)
	}
}

func TestOtherClientsByPathAlone(t *testing.T) {
	r := newFixture(t).host().Scan(nil)
	for p, want := range map[string]Finding{
		"/root/.acme.sh/example.com/fullchain.cer":   {Kind: OtherClient, Client: "acme.sh", Dir: "/root/.acme.sh"},
		"/home/web/.acme.sh/example.com_ecc/a.key":   {Kind: OtherClient, Client: "acme.sh", Dir: "/home/web/.acme.sh"},
		"/etc/dehydrated/certs/example.com/cert.pem": {Kind: OtherClient, Client: "dehydrated", Dir: "/etc/dehydrated"},
		"/var/lib/dehydrated/certs/x/privkey.pem":    {Kind: OtherClient, Client: "dehydrated", Dir: "/var/lib/dehydrated"},
		"/var/lib/acme/example.com/cert.pem":         {Kind: OtherClient, Client: "lego", Dir: "/var/lib/acme"},
	} {
		fs := r.Check(Target{Paths: []string{p}})
		want.Path = p
		if len(fs) != 1 || !reflect.DeepEqual(fs[0], want) {
			t.Fatalf("%s: findings = %+v", p, fs)
		}
	}
	for _, p := range []string{"/var/lib/acmefoo/x.pem", "/srv/acme.sh/x.pem", "relative/.acme.sh/x"} {
		if fs := r.Check(Target{Paths: []string{p}}); len(fs) != 0 {
			t.Fatalf("%s: findings = %+v", p, fs)
		}
	}
}

func TestDetectOthers(t *testing.T) {
	f := newFixture(t)
	if got := f.host().DetectOthers(); len(got) != 0 {
		t.Fatalf("nothing installed, got %+v", got)
	}
	f.write("/root/.acme.sh/acme.sh", "#!/bin/sh\n")
	f.write("/var/lib/dehydrated/accounts/x", "")
	f.write("/usr/bin/lego", "#!/bin/sh\n")
	if err := os.Chmod(filepath.Join(f.root, "usr/bin/lego"), 0o755); err != nil {
		t.Fatal(err)
	}
	got := f.host().DetectOthers()
	want := []Other{
		{Client: "acme.sh", Evidence: "/root/.acme.sh/acme.sh"},
		{Client: "dehydrated", Evidence: "/var/lib/dehydrated"},
		{Client: "lego", Evidence: "/usr/bin/lego"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("detected = %+v", got)
	}
}

func TestShellWords(t *testing.T) {
	got := shellWords(`test -x /usr/bin/certbot -a \! -d /run/systemd/system && perl -e 'sleep int(rand(43200))' && certbot -q renew --config-dir="/a b"`)
	if !runsCertbot(got) || !reflect.DeepEqual(configDirs(got), []string{"/a b"}) {
		t.Fatalf("words = %q", got)
	}
}

func TestPathValuesReadOnlyPathSettings(t *testing.T) {
	decls := []plugincontract.SettingDeclaration{
		{Key: "reload", Type: plugincontract.SettingTypeCommand},
		{Key: "z_key", Type: plugincontract.SettingTypePath},
		{Key: "a_cert", Type: plugincontract.SettingTypePath},
		{Key: "empty", Type: plugincontract.SettingTypePath},
	}
	got := PathValues(decls, map[string]string{"reload": "/usr/sbin/nginx", "z_key": "/k", "a_cert": "/c"})
	if !reflect.DeepEqual(got, []string{"/c", "/k"}) {
		t.Fatalf("paths = %q", got)
	}
}

func TestWarningsNeverNameTheTargetsPath(t *testing.T) {
	l := &Lineage{Name: "example.com", Dir: "/srv/le"}
	for _, f := range []Finding{
		{Kind: Certbot, Path: "/srv/le/live/example.com/fullchain.pem", Dir: "/srv/le", Lineage: l},
		{Kind: HookCopy, Path: "/etc/nginx/ssl/example.pem", Dir: "/srv/le", Lineage: l},
		{Kind: HookCopy, Path: "/etc/nginx/ssl/example.pem", Dir: "/srv/le", Lineage: l, LineageInUse: true},
		{Kind: OtherClient, Path: "/var/lib/acme/x/cert.pem", Dir: "/var/lib/acme", Client: "lego"},
	} {
		w := f.Warning()
		if err := w.Validate(); err != nil {
			t.Fatal(err)
		}
		for _, lang := range l10n.Supported() {
			if w[lang] == "" || strings.Contains(w[lang], f.Path) {
				t.Fatalf("%s warning = %q", lang, w[lang])
			}
		}
	}
	hook := Finding{Kind: HookCopy, Lineage: l}.Warning()[l10n.English]
	if !strings.Contains(hook, "`certbot delete --config-dir /srv/le --cert-name example.com`") {
		t.Fatalf("hook copy warning = %q", hook)
	}
}
