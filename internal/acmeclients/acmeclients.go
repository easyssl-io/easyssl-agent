// Package acmeclients is the Agent's rule for files another ACME client
// manages: certbot's directories and the certificates it keeps current, and
// the default directories of acme.sh, dehydrated and lego. A file under one of
// them is rewritten by that client on its own schedule, so easySSL never
// deploys there: the check-in marks such a discovered Target, a Deployment to
// one is refused before its Plugin runs, and `easyssl-agent migrate` moves
// what it can out of certbot's directories. The three callers share this one
// rule so that what is marked, refused and offered cannot disagree.
//
// Plugins know nothing of ACME clients; they report the files their
// configuration names, and this package decides.
package acmeclients

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/easyssl-io/easyssl-contract/plugincontract"
)

// DefaultCertbotDir is where certbot keeps everything when nothing says
// otherwise.
const DefaultCertbotDir = "/etc/letsencrypt"

// Host is the machine the rule reads: its filesystem under Root and the PATH
// searched for client executables. Root is "/" on a real host and a
// temporary directory in a test; every path the rule reports is the host's,
// without Root.
type Host struct {
	Root string
	PATH string
}

// System is the host this process runs on.
func System() Host { return Host{Root: "/", PATH: os.Getenv("PATH")} }

// File is where the host path p is read from on this machine.
func (h Host) File(p string) string {
	if h.Root == "" || h.Root == "/" {
		return p
	}
	return filepath.Join(h.Root, p)
}

// SourceKind says how a certbot directory was found.
type SourceKind int

const (
	// FromSystemd: `--config-dir` on a certbot command in a systemd unit.
	FromSystemd SourceKind = iota + 1
	// FromCron: `--config-dir` on a certbot command in a cron entry.
	FromCron
	// FromCLIIni: `config-dir` in a certbot cli.ini.
	FromCLIIni
	// FromDefault: DefaultCertbotDir exists.
	FromDefault
	// FromStructure: a checked path lies in `<dir>/live/<lineage>/` or
	// `<dir>/archive/<lineage>/` and `<dir>/renewal/<lineage>.conf` names
	// that archive directory, whatever the directory is called. Given only
	// for a directory nothing else named.
	FromStructure
)

// Source is one reason a directory is taken as certbot's, with the file that
// gave it: the unit, crontab or cli.ini, or the path that showed it. Empty for
// FromDefault.
type Source struct {
	Kind SourceKind
	File string
}

// CertbotDir is one certbot configuration directory and its lineages.
type CertbotDir struct {
	Path     string
	Sources  []Source
	Lineages []Lineage
}

// Lineage is one certificate certbot keeps renewing, as its
// `renewal/<name>.conf` describes it.
type Lineage struct {
	Name string
	// Dir is the certbot directory it belongs to.
	Dir        string
	ArchiveDir string
	// LiveDir is the directory of the lineage's `cert` link.
	LiveDir string
	// CertSHA256 is the lowercase hex SHA-256 of the DER of the certificate
	// its `cert` link resolves to now, the one a deploy hook copies; empty
	// when that cannot be read.
	CertSHA256 string
}

// DeleteCommand is the certbot command that stops renewing the lineage,
// naming the directory when it is not certbot's default.
func (l Lineage) DeleteCommand() string {
	if l.Dir == DefaultCertbotDir {
		return "certbot delete --cert-name " + l.Name
	}
	return "certbot delete --config-dir " + l.Dir + " --cert-name " + l.Name
}

// contains reports whether p lies in one of the lineage's own directories.
func (l Lineage) contains(p string) bool {
	return within(p, l.ArchiveDir) || (l.LiveDir != "" && within(p, l.LiveDir))
}

// Other is an ACME client this Agent detects but does not process, with what
// showed it.
type Other struct {
	Client   string
	Evidence string
}

// Kind is what makes a path managed.
type Kind int

const (
	// Certbot: the path lies in a certbot directory.
	Certbot Kind = iota + 1
	// HookCopy: the Target's certificate is the current certificate of a
	// certbot lineage while the path lies outside every certbot directory,
	// which is what a deploy hook copying it there leaves. No hook is parsed;
	// a one-off copy stops matching at the lineage's next renewal.
	HookCopy
	// OtherClient: the path lies in acme.sh's, dehydrated's or lego's default
	// directory, managed by path alone whether that client is detected or
	// not.
	OtherClient
)

// Finding is one reason a Target's path is managed.
type Finding struct {
	Kind Kind
	// Path is the checked path the finding is about, as the Target gives it.
	Path string
	// Dir is the certbot directory (Certbot, HookCopy) or the other client's
	// directory (OtherClient).
	Dir string
	// Lineage is the certbot lineage: always for HookCopy, for Certbot when
	// the path lies in one.
	Lineage *Lineage
	// Client names the other ACME client.
	Client string
	// LineageInUse is set by Assess on a HookCopy whose lineage's own files
	// some Target still names, which a `certbot delete` would break.
	LineageInUse bool
}

// Target is what the rule reads from a discovered Target or a Deployment:
// the values of its path settings and the leaf SHA-256 of its certificate,
// when known.
type Target struct {
	Paths      []string
	CertSHA256 string
	// CertPath is the path holding the certificate, which a HookCopy names;
	// the first path when empty.
	CertPath string
}

// PathValues are the non-empty values of every setting decls declares as a
// path, ordered by key so the same Target always reads the same way.
func PathValues(decls []plugincontract.SettingDeclaration, settings map[string]string) []string {
	var keys []string
	for _, d := range decls {
		if d.Type == plugincontract.SettingTypePath && settings[d.Key] != "" {
			keys = append(keys, d.Key)
		}
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, settings[k])
	}
	return out
}

// Rule is the rule as read from one host at one moment.
type Rule struct {
	host    Host
	certbot []CertbotDir
}

// Scan reads where certbot keeps its files on h and the lineages in each.
// paths are the paths about to be checked, so a certbot directory under any
// name is found from their structure. Nothing here fails: a file that cannot
// be read is a source that says nothing, since the rule runs on every
// check-in and must not stop reporting a host.
func (h Host) Scan(paths []string) *Rule {
	found := map[string][]Source{}
	order := []string{}
	add := func(dir string, s Source) {
		dir = path.Clean(dir)
		if !path.IsAbs(dir) || !h.isDir(dir) {
			return
		}
		if _, ok := found[dir]; !ok {
			order = append(order, dir)
		}
		for _, have := range found[dir] {
			if have == s {
				return
			}
		}
		found[dir] = append(found[dir], s)
	}
	for _, inv := range h.certbotInvocations() {
		for _, dir := range inv.dirs {
			add(dir, Source{Kind: inv.kind, File: inv.file})
		}
	}
	// Every invocation without `--config-dir` uses cli.ini's or the default,
	// and some never show up as a unit or a crontab line (a snap's timer, a
	// wrapper script), so both are always checked.
	for _, ini := range []string{DefaultCertbotDir + "/cli.ini", "/root/.config/letsencrypt/cli.ini"} {
		if dir := h.cliIniConfigDir(ini); dir != "" {
			add(dir, Source{Kind: FromCLIIni, File: ini})
		}
	}
	add(DefaultCertbotDir, Source{Kind: FromDefault})
	// Structure only finds what nothing else named, and says so once, by the
	// first path that showed it.
	for _, p := range paths {
		for _, q := range h.forms(p) {
			if dir, ok := h.structureDir(q); ok && found[dir] == nil {
				add(dir, Source{Kind: FromStructure, File: p})
			}
		}
	}
	r := &Rule{host: h}
	for _, dir := range order {
		r.certbot = append(r.certbot, CertbotDir{Path: dir, Sources: found[dir], Lineages: h.lineages(dir)})
	}
	return r
}

// CertbotDirs are the certbot directories found, in the order found.
func (r *Rule) CertbotDirs() []CertbotDir { return r.certbot }

// Check applies the rule to one Target. Its findings name each certbot or
// other-client directory once, so a Target whose certificate and key share one
// gets one finding.
func (r *Rule) Check(t Target) []Finding {
	var out []Finding
	seen := map[string]bool{}
	note := func(f Finding) {
		key := f.Dir + "\x00" + f.Client
		if f.Lineage != nil {
			key += "\x00" + f.Lineage.Name
		}
		if !seen[key] {
			seen[key] = true
			out = append(out, f)
		}
	}
	inCertbot := false
	for _, p := range t.Paths {
		for _, q := range r.host.forms(p) {
			if d, ok := r.certbotDirOf(q); ok {
				inCertbot = true
				f := Finding{Kind: Certbot, Path: p, Dir: d.Path}
				if l, ok := lineageOf(d, q); ok {
					f.Lineage = &l
				}
				note(f)
			}
			if client, dir, ok := otherClientDir(q); ok {
				note(Finding{Kind: OtherClient, Path: p, Dir: dir, Client: client})
			}
		}
	}
	if !inCertbot && t.CertSHA256 != "" && len(t.Paths) > 0 {
		for _, d := range r.certbot {
			for _, l := range d.Lineages {
				if l.CertSHA256 != "" && l.CertSHA256 == t.CertSHA256 {
					p := t.CertPath
					if p == "" {
						p = t.Paths[0]
					}
					note(Finding{Kind: HookCopy, Path: p, Dir: d.Path, Lineage: &l})
				}
			}
		}
	}
	return out
}

// Assess applies the rule to every Target one host reports at once, which a
// hook copy's advice depends on: deleting its lineage is advised only while no
// Target still names that lineage's own files.
func (r *Rule) Assess(targets []Target) [][]Finding {
	out := make([][]Finding, len(targets))
	for i, t := range targets {
		out[i] = r.Check(t)
	}
	for i := range out {
		for j := range out[i] {
			f := &out[i][j]
			if f.Kind != HookCopy {
				continue
			}
			for _, t := range targets {
				if r.Uses(t.Paths, *f.Lineage) {
					f.LineageInUse = true
					break
				}
			}
		}
	}
	return out
}

// Uses reports whether any of paths lies in the lineage's own directories,
// as written or with symlinks followed.
func (r *Rule) Uses(paths []string, l Lineage) bool {
	for _, p := range paths {
		for _, q := range r.host.forms(p) {
			if l.contains(q) {
				return true
			}
		}
	}
	return false
}

// LineageOf is the certbot lineage whose own directories hold p, as written or
// with symlinks followed.
func (r *Rule) LineageOf(p string) (Lineage, bool) {
	for _, q := range r.host.forms(p) {
		if d, ok := r.certbotDirOf(q); ok {
			if l, ok := lineageOf(d, q); ok {
				return l, true
			}
		}
	}
	return Lineage{}, false
}

func (r *Rule) certbotDirOf(p string) (CertbotDir, bool) {
	for _, d := range r.certbot {
		if within(p, d.Path) {
			return d, true
		}
	}
	return CertbotDir{}, false
}

func lineageOf(d CertbotDir, p string) (Lineage, bool) {
	for _, l := range d.Lineages {
		if l.contains(p) {
			return l, true
		}
	}
	return Lineage{}, false
}

// otherClients are the default directories of the clients this Agent does not
// process. acme.sh keeps its directory in its user's home, so any `.acme.sh`
// component counts, whoever's home it is in.
var otherClients = []struct{ client, dir string }{
	{"dehydrated", "/etc/dehydrated"},
	{"dehydrated", "/var/lib/dehydrated"},
	{"lego", "/var/lib/acme"},
}

func otherClientDir(p string) (client, dir string, ok bool) {
	if i := strings.Index(p+"/", "/.acme.sh/"); i >= 0 {
		return "acme.sh", p[:i] + "/.acme.sh", true
	}
	for _, c := range otherClients {
		if within(p, c.dir) {
			return c.client, c.dir, true
		}
	}
	return "", "", false
}

// DetectOthers reports acme.sh, dehydrated and lego when their executable or
// default directory is on the host. Detection only: their files are managed by
// path whether or not this finds them.
func (h Host) DetectOthers() []Other {
	var out []Other
	detect := func(client string, dirs []string, exe string) {
		for _, d := range dirs {
			if h.exists(d) {
				out = append(out, Other{Client: client, Evidence: d})
				return
			}
		}
		if p, ok := h.lookPath(exe); ok {
			out = append(out, Other{Client: client, Evidence: p})
		}
	}
	detect("acme.sh", []string{"/root/.acme.sh/acme.sh"}, "acme.sh")
	detect("dehydrated", []string{"/etc/dehydrated", "/var/lib/dehydrated"}, "dehydrated")
	detect("lego", []string{"/var/lib/acme"}, "lego")
	return out
}

func (h Host) lookPath(name string) (string, bool) {
	for _, dir := range filepath.SplitList(h.PATH) {
		if !path.IsAbs(dir) {
			continue
		}
		p := path.Join(dir, name)
		if fi, err := os.Stat(h.File(p)); err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0 {
			return p, true
		}
	}
	return "", false
}

// structureDir recognizes `<D>/live/<L>/…` and `<D>/archive/<L>/…` whose
// `<D>/renewal/<L>.conf` names `<D>/archive/<L>` as its archive directory.
func (h Host) structureDir(p string) (string, bool) {
	parts := strings.Split(strings.TrimPrefix(path.Clean(p), "/"), "/")
	for i := len(parts) - 3; i >= 0; i-- {
		if parts[i] != "live" && parts[i] != "archive" {
			continue
		}
		dir := "/" + path.Join(parts[:i]...)
		name := parts[i+1]
		conf, err := h.readConf(path.Join(dir, "renewal", name+".conf"))
		if err == nil && path.Clean(conf["archive_dir"]) == path.Join(dir, "archive", name) {
			return dir, true
		}
	}
	return "", false
}

// lineages reads every `renewal/*.conf` of a certbot directory.
func (h Host) lineages(dir string) []Lineage {
	entries, err := os.ReadDir(h.File(path.Join(dir, "renewal")))
	if err != nil {
		return nil
	}
	var out []Lineage
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".conf")
		if !ok || name == "" || e.IsDir() {
			continue
		}
		conf, err := h.readConf(path.Join(dir, "renewal", e.Name()))
		if err != nil {
			continue
		}
		l := Lineage{Name: name, Dir: dir, ArchiveDir: path.Join(dir, "archive", name)}
		if a := conf["archive_dir"]; path.IsAbs(a) {
			l.ArchiveDir = path.Clean(a)
		}
		if c := conf["cert"]; path.IsAbs(c) {
			l.LiveDir = path.Dir(path.Clean(c))
			l.CertSHA256 = h.CertSHA256(c)
		}
		out = append(out, l)
	}
	return out
}

// readConf reads the top-level `key = value` lines of a certbot renewal
// configuration, before its first section.
func (h Host) readConf(p string) (map[string]string, error) {
	f, err := os.Open(h.File(p))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") {
			break
		}
		if k, v, ok := strings.Cut(line, "="); ok && !strings.HasPrefix(line, "#") {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out, sc.Err()
}

// cliIniConfigDir is the `config-dir` a certbot cli.ini sets, which certbot
// reads as `key = value`, `key: value` or `key value`.
func (h Host) cliIniConfigDir(p string) string {
	f, err := os.Open(h.File(p))
	if err != nil {
		return ""
	}
	defer f.Close()
	dir := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		key, value := line, ""
		if i := strings.IndexAny(line, "=: \t"); i >= 0 {
			key, value = line[:i], strings.TrimLeft(line[i:], "=: \t")
		}
		if strings.TrimSpace(key) == "config-dir" {
			dir = strings.Trim(strings.TrimSpace(value), `"'`)
		}
	}
	return dir
}

// CertSHA256 is the leaf SHA-256 of the first certificate in the PEM file at
// the host path p, symlinks followed; empty when there is none.
func (h Host) CertSHA256(p string) string {
	real, err := h.Resolve(p)
	if err != nil {
		return ""
	}
	return LeafSHA256(h.File(real))
}

// LeafSHA256 is the lowercase hex SHA-256 of the DER of the first certificate
// in the PEM file at name, read as it is on this machine; empty when it holds
// none or cannot be read.
func LeafSHA256(name string) string {
	data, err := os.ReadFile(name)
	if err != nil {
		return ""
	}
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			return ""
		}
		if b.Type == "CERTIFICATE" {
			sum := sha256.Sum256(b.Bytes)
			return hex.EncodeToString(sum[:])
		}
	}
}

// forms are the ways a path is checked: as given, and with every symlink
// followed, since a link outside a managed directory can point into one.
func (h Host) forms(p string) []string {
	if !path.IsAbs(p) {
		return nil
	}
	p = path.Clean(p)
	if real, err := h.Resolve(p); err == nil && real != p {
		return []string{p, real}
	}
	return []string{p}
}

var errTooManyLinks = errors.New("too many levels of symbolic links")

// Resolve follows every symlink in the host path p, reading each link under
// Root, so an absolute link target stays on the host being read rather than
// the machine running the test.
func (h Host) Resolve(p string) (string, error) {
	links := 0
	rest := strings.Split(path.Clean(p), "/")
	resolved := "/"
	for len(rest) > 0 {
		c := rest[0]
		rest = rest[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			resolved = path.Dir(resolved)
			continue
		}
		next := path.Join(resolved, c)
		fi, err := os.Lstat(h.File(next))
		if err != nil {
			return "", err
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			resolved = next
			continue
		}
		if links++; links > 40 {
			return "", errTooManyLinks
		}
		target, err := os.Readlink(h.File(next))
		if err != nil {
			return "", err
		}
		if path.IsAbs(target) {
			resolved = "/"
		}
		rest = append(strings.Split(target, "/"), rest...)
	}
	return resolved, nil
}

func (h Host) exists(p string) bool {
	_, err := os.Stat(h.File(p))
	return err == nil
}

func (h Host) isDir(p string) bool {
	fi, err := os.Stat(h.File(p))
	return err == nil && fi.IsDir()
}

// within reports whether p is dir or lies under it.
func within(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, strings.TrimSuffix(dir, "/")+"/")
}
