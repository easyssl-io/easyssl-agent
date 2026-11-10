package migrate

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/easyssl-io/easyssl-agent/internal/acmeclients"
	"github.com/easyssl-io/easyssl-agent/internal/msg"
	"github.com/easyssl-io/easyssl-agent/internal/pluginmgr"
	"github.com/easyssl-io/easyssl-contract/plugincontract"
)

// copyStep is one file to copy, or one already copied that is reused.
type copyStep struct {
	src, dest string // host paths; src is the real file
	reuse     bool
	data      []byte
	mode      os.FileMode
	uid, gid  int
	// The source's directory, whose owner, group and mode a new destination
	// directory takes.
	dirMode        os.FileMode
	dirUID, dirGID int
}

// pluginStep is one Plugin's `relocate` request.
type pluginStep struct {
	obs *pluginmgr.Observation
	req plugincontract.RelocateRequest
}

type migration struct {
	copies  []*copyStep
	plugins []*pluginStep
}

// plan decides every copy and every configuration change before anything is
// written, so the confirmation shows exactly what will happen.
func (s *session) plan(chosen, items []*item) (*migration, error) {
	m := &migration{}
	bySource := map[string]*copyStep{}
	byDest := map[string]*copyStep{}
	byPlugin := map[*pluginmgr.Observation]*pluginStep{}
	picked := map[*pluginmgr.Observation]map[int]bool{}

	for _, it := range chosen {
		name := s.name(it)
		dest := map[string]string{} // setting key -> copy
		for _, d := range it.obs.Describe.Declarations {
			value := it.target.Settings[d.Key]
			if d.Type != plugincontract.SettingTypePath || value == "" {
				continue
			}
			step, err := s.copyFor(value, name, bySource, byDest)
			if err != nil {
				return nil, err
			}
			if _, ok := byDest[step.dest]; !ok {
				byDest[step.dest] = step
				m.copies = append(m.copies, step)
			}
			dest[d.Key] = step.dest
		}

		ps := byPlugin[it.obs]
		if ps == nil {
			ps = &pluginStep{obs: it.obs, req: plugincontract.RelocateRequest{Moves: []plugincontract.Move{}, References: []plugincontract.Reference{}}}
			byPlugin[it.obs] = ps
			m.plugins = append(m.plugins, ps)
			picked[it.obs] = map[int]bool{}
		}
		picked[it.obs][it.index] = true
		for _, r := range it.target.References {
			to, ok := dest[r.Setting]
			if !ok {
				return nil, msg.Err.T("migrate.plan.unknown_setting",
					"The {plugin} Plugin names {file}:{line} for its setting {setting}, which holds no file of this certificate, so nothing was changed.",
					"plugin", it.obs.ID, "file", r.File, "line", r.Line, "setting", r.Setting)
			}
			if err := ps.add(r, to); err != nil {
				return nil, err
			}
		}
	}

	// The Plugin changes every line whose path is a move's, so a line of a
	// certificate not chosen that spells a path the same way would change too.
	for _, ps := range m.plugins {
		from := map[string]bool{}
		for _, mv := range ps.req.Moves {
			from[mv.From] = true
		}
		for j, t := range ps.obs.Discover.DiscoveredTargets {
			if picked[ps.obs][j] {
				continue
			}
			for _, r := range t.References {
				if from[r.Value] {
					return nil, msg.Err.T("migrate.plan.shared_line",
						"{file}:{line} also names {value}, for a certificate not chosen, so nothing was changed. Choose them together.",
						"file", r.File, "line", r.Line, "value", r.Value)
				}
			}
		}
	}
	if err := s.checkDests(m); err != nil {
		return nil, err
	}
	return m, nil
}

// checkDests refuses a plan whose copies would be read from a directory a key
// must not be in (safeDir), checking every one that exists, including those
// holding reused copies, which writeCopy never sees; and a reused copy that is
// no longer the file it was taken for. Run before the confirmation and again
// before any configuration is changed, since time passes between them.
func (s *session) checkDests(m *migration) error {
	dirs := map[string]bool{DestDir: true}
	for _, c := range m.copies {
		dirs[path.Dir(c.dest)] = true
	}
	for dir := range dirs {
		if _, err := os.Lstat(s.opts.Host.File(dir)); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err := safeDir(s.opts.Host.File(dir)); err != nil {
			return err
		}
	}
	for _, c := range m.copies {
		if c.reuse && !s.isCopy(c.dest, c) {
			return msg.Err.T("migrate.plan.reused_changed", "{file} changed since it was taken as a copy, so no configuration was changed; run this command again.", "file", c.dest)
		}
	}
	return nil
}

// isCopy reports whether the host file dest is exactly what writeCopy would
// have written for c: a regular file, not a symlink, with its content, owner,
// group and mode.
func (s *session) isCopy(dest string, c *copyStep) bool {
	file := s.opts.Host.File(dest)
	fi, err := os.Lstat(file)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != c.mode {
		return false
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && (int(st.Uid) != c.uid || int(st.Gid) != c.gid) {
		return false
	}
	existing, err := os.ReadFile(file)
	return err == nil && bytes.Equal(existing, c.data)
}

// add records a reference and its move, refusing one spelling of a path that
// would have to move to two places.
func (ps *pluginStep) add(r plugincontract.Reference, to string) error {
	for _, mv := range ps.req.Moves {
		if mv.From == r.Value && mv.To != to {
			return msg.Err.T("migrate.plan.conflict",
				"{value} would have to point at both {a} and {b}, so nothing was changed.", "value", r.Value, "a", mv.To, "b", to)
		}
	}
	if !containsMove(ps.req.Moves, r.Value) {
		ps.req.Moves = append(ps.req.Moves, plugincontract.Move{From: r.Value, To: to})
	}
	for _, have := range ps.req.References {
		if have == r {
			return nil
		}
	}
	ps.req.References = append(ps.req.References, r)
	return nil
}

func containsMove(moves []plugincontract.Move, from string) bool {
	for _, mv := range moves {
		if mv.From == from {
			return true
		}
	}
	return false
}

// copyFor is the copy of the file a setting names: one already planned for
// the same file or the same content, else the next free name of its kind under
// the certificate's directory, reusing an identical file already there.
func (s *session) copyFor(value, name string, bySource, byDest map[string]*copyStep) (*copyStep, error) {
	real, err := s.opts.Host.Resolve(value)
	if err != nil {
		return nil, msg.Err.T("migrate.plan.unreadable", "{file} cannot be read, so nothing was changed: {err}", "file", value, "err", err)
	}
	if step := bySource[real]; step != nil {
		return step, nil
	}
	file := s.opts.Host.File(real)
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, msg.Err.T("migrate.plan.unreadable", "{file} cannot be read, so nothing was changed: {err}", "file", real, "err", err)
	}
	step := &copyStep{src: real, data: data}
	if err := ownership(file, &step.mode, &step.uid, &step.gid); err != nil {
		return nil, err
	}
	if err := ownership(filepath.Dir(file), &step.dirMode, &step.dirUID, &step.dirGID); err != nil {
		return nil, err
	}
	kind := "certificate"
	if holdsPrivateKey(data) {
		kind = "key"
	}
	for n := 1; ; n++ {
		base := kind + ".pem"
		if n > 1 {
			base = fmt.Sprintf("%s-%d.pem", kind, n)
		}
		dest := path.Join(DestDir, name, base)
		if planned := byDest[dest]; planned != nil {
			if bytes.Equal(planned.data, data) {
				bySource[real] = planned
				return planned, nil
			}
			continue
		}
		existing, err := os.ReadFile(s.opts.Host.File(dest))
		switch {
		case err == nil && bytes.Equal(existing, data) && s.isCopy(dest, step):
			step.dest, step.reuse = dest, true
		case errors.Is(err, fs.ErrNotExist):
			step.dest = dest
		default:
			// Something else has the name, so the next one is tried. An
			// error that is not about the name, such as a parent that is
			// a file or a symlink loop, fails every name the same way.
			if _, lerr := os.Lstat(s.opts.Host.File(dest)); lerr == nil {
				continue
			}
			return nil, msg.Err.T("migrate.plan.dest_unusable", "{file} cannot hold a copy, so nothing was changed: {err}", "file", dest, "err", err)
		}
		bySource[real] = step
		return step, nil
	}
}

func ownership(name string, mode *os.FileMode, uid, gid *int) error {
	fi, err := os.Stat(name)
	if err != nil {
		return err
	}
	*mode = fi.Mode().Perm()
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		*uid, *gid = int(st.Uid), int(st.Gid)
	}
	return nil
}

func holdsPrivateKey(data []byte) bool {
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			return false
		}
		if strings.HasSuffix(b.Type, "PRIVATE KEY") {
			return true
		}
	}
}

// name is the directory a certificate's copies go in: its certbot lineage,
// else its first name with a wildcard's `*` written `_` and an IPv6 address's
// `:` written `-`, else its subject's common name, else `certificate`.
func (s *session) name(it *item) string {
	if it.lineage != nil {
		if n := safeName(it.lineage.Name); n != "" {
			return n
		}
	}
	if c := it.target.Certificate; c != nil && len(c.Domains) > 0 {
		if n := safeName(domainName(c.Domains[0])); n != "" {
			return n
		}
	}
	for _, p := range acmeclients.PathValues(it.obs.Describe.Declarations, it.target.Settings) {
		real, err := s.opts.Host.Resolve(p)
		if err != nil {
			continue
		}
		if cn := commonName(s.opts.Host.File(real)); cn != "" {
			if n := safeName(domainName(cn)); n != "" {
				return n
			}
		}
	}
	return "certificate"
}

func domainName(d string) string {
	d = strings.ToLower(d)
	if rest, ok := strings.CutPrefix(d, "*."); ok {
		d = "_." + rest
	}
	return strings.ReplaceAll(d, ":", "-")
}

// safeName keeps a name to one path component of ordinary characters, empty
// when nothing usable is left.
func safeName(n string) string {
	n = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			return r
		}
		return '_'
	}, n)
	if strings.Trim(n, ".") == "" {
		return ""
	}
	return n
}

func commonName(file string) string {
	data, err := os.ReadFile(file)
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
			c, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				return ""
			}
			return c.Subject.CommonName
		}
	}
}

func (s *session) printPlan(m *migration) {
	s.say("")
	s.say(msg.T("migrate.plan.copies", "These files will be copied, each keeping its owner, group and mode:"))
	for _, c := range m.copies {
		if c.reuse {
			s.say("  " + msg.T("migrate.plan.reuse", "{from} -> {to} (already there, reused)", "from", c.src, "to", c.dest))
		} else {
			s.say("  " + msg.T("migrate.plan.copy", "{from} -> {to}", "from", c.src, "to", c.dest))
		}
	}
	s.say(msg.T("migrate.plan.lines", "These configuration lines will change:"))
	for _, ps := range m.plugins {
		to := map[string]string{}
		for _, mv := range ps.req.Moves {
			to[mv.From] = mv.To
		}
		for _, r := range ps.req.References {
			s.say(fmt.Sprintf("  %s:%d  %s -> %s", r.File, r.Line, r.Value, to[r.Value]))
		}
	}
	s.say("")
}

// copyAll writes every copy, never over an existing file.
func (s *session) copyAll(m *migration) error {
	if err := s.ensureDestDir(); err != nil {
		return err
	}
	n := 0
	for _, c := range m.copies {
		if c.reuse {
			continue
		}
		if err := s.writeCopy(c); err != nil {
			return msg.Err.T("migrate.copy_failed",
				"copying {from} to {to}: {err}. No configuration was changed; any copies already made stay under {dir}.",
				"from", c.src, "to", c.dest, "err", err, "dir", DestDir)
		}
		n++
	}
	s.say(msg.N("migrate.copied", n, "✓ Copied {n} file under {dir}.", "✓ Copied {n} files under {dir}.", "dir", DestDir))
	return nil
}

// ensureDestDir creates DestDir as root's, 0755, when it is missing; one that
// exists is left as it is.
func (s *session) ensureDestDir() error {
	dir := s.opts.Host.File(DestDir)
	if _, err := os.Lstat(dir); err == nil {
		return safeDir(dir)
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0o755); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		return err
	}
	return s.opts.Chown(dir, 0, 0)
}

// safeDir refuses a directory a key must not be written into as root: a
// symlink, which could lead anywhere, one that is not a directory, one that
// group or others can write, where another user could swap files, and, when
// this runs as root, one root does not own. Only root can create these
// directories on a normal host, so a refusal means something to look at.
func safeDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	switch {
	case fi.Mode()&fs.ModeSymlink != 0:
		return msg.Err.T("migrate.unsafe_dir.symlink", "{dir} is a symlink, so no key is written there", "dir", dir)
	case !fi.IsDir():
		return msg.Err.T("migrate.unsafe_dir.not_dir", "{dir} is not a directory", "dir", dir)
	case fi.Mode().Perm()&0o022 != 0:
		return msg.Err.T("migrate.unsafe_dir.writable", "{dir} can be written by users other than its owner, so no key is written there", "dir", dir)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && os.Geteuid() == 0 && st.Uid != 0 {
		return msg.Err.T("migrate.unsafe_dir.owner", "{dir} is not owned by root, so no key is written there", "dir", dir)
	}
	return nil
}

// writeCopy writes one copy under a temporary name, sets its owner, group and
// mode, then links it into place, which fails rather than replace a file that
// appeared meanwhile; an identical one is taken as the copy.
func (s *session) writeCopy(c *copyStep) error {
	dir := s.opts.Host.File(path.Dir(c.dest))
	if _, err := os.Lstat(dir); err == nil {
		if err := safeDir(dir); err != nil {
			return err
		}
	} else if errors.Is(err, fs.ErrNotExist) {
		if err := os.Mkdir(dir, c.dirMode); err != nil {
			return err
		}
		if err := os.Chmod(dir, c.dirMode); err != nil {
			return err
		}
		if err := s.opts.Chown(dir, c.dirUID, c.dirGID); err != nil {
			return err
		}
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	tmp := filepath.Join(dir, ".tmp-"+hex.EncodeToString(suffix))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	if _, err := f.Write(c.data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// Owner before mode: changing the owner can clear mode bits.
	if err := s.opts.Chown(tmp, c.uid, c.gid); err != nil {
		return err
	}
	if err := os.Chmod(tmp, c.mode); err != nil {
		return err
	}
	dest := s.opts.Host.File(c.dest)
	if err := os.Link(tmp, dest); err != nil {
		if existing, rerr := os.ReadFile(dest); rerr == nil && bytes.Equal(existing, c.data) {
			return nil
		}
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// relocateAll asks each Plugin to point its configuration at the copies and
// returns how many could not.
func (s *session) relocateAll(ctx context.Context, m *migration) int {
	failed := 0
	for _, ps := range m.plugins {
		s.say(msg.T("migrate.relocate.start", "Changing the configuration the {plugin} Plugin reads...", "plugin", ps.obs.ID))
		out, status, err := s.opts.Relocate(ctx, ps.obs.Installed, ps.req)
		if out = strings.TrimRight(out, "\n"); out != "" {
			s.say(out)
		}
		if err != nil {
			failed++
			s.say(msg.T("migrate.relocate.failed", "✗ The {plugin} Plugin did not change its configuration (exit status {status}): {err}",
				"plugin", ps.obs.ID, "status", status, "err", err))
			continue
		}
		s.say(msg.T("migrate.relocate.done", "✓ The {plugin} Plugin changed its configuration.", "plugin", ps.obs.ID))
	}
	s.say("")
	return failed
}

// advise reads the host again and, for each certbot lineage a chosen
// certificate came from, prints how to stop certbot renewing it once nothing
// the Plugins read uses it, or what still does.
func (s *session) advise(ctx context.Context, chosen []*item) {
	var lineages []acmeclients.Lineage
	seen := map[string]bool{}
	for _, it := range chosen {
		if l := it.lineage; l != nil && !seen[l.Dir+"\x00"+l.Name] {
			seen[l.Dir+"\x00"+l.Name] = true
			lineages = append(lineages, *l)
		}
	}
	if len(lineages) == 0 {
		return
	}
	obs, err := s.opts.Plugins.Observe(ctx)
	if err != nil {
		s.say(msg.T("migrate.advise.unchecked", "What still uses certbot's certificates could not be checked: {err}", "err", err))
		return
	}
	rule := s.opts.Host.Scan(nil)
	for _, l := range lineages {
		var still []string
		for _, o := range obs {
			if o.Err != nil {
				continue
			}
			for _, t := range o.Discover.DiscoveredTargets {
				paths := acmeclients.PathValues(o.Describe.Declarations, t.Settings)
				if !rule.Uses(paths, l) {
					continue
				}
				for _, r := range t.References {
					still = append(still, fmt.Sprintf("%s:%d  %s", r.File, r.Line, r.Value))
				}
				if len(t.References) == 0 {
					still = append(still, o.ID+"  "+strings.Join(paths, "  "))
				}
			}
		}
		if len(still) > 0 {
			s.say(msg.T("migrate.advise.still_used", "certbot's certificate {lineage} is still used by:", "lineage", l.Name))
			for _, line := range still {
				s.say("    " + line)
			}
			continue
		}
		s.say(msg.T("migrate.advise.delete",
			"Nothing the Plugins read uses certbot's certificate {lineage} any more. easySSL sees only what its Plugins read, so check that nothing else uses {live} before you stop certbot renewing it with:",
			"lineage", l.Name, "live", l.LiveDir+"/"))
		s.say("    " + l.DeleteCommand())
	}
	s.say("")
}

// report sends the new inventory, so the web console shows the moved
// certificates now rather than at the service's next check-in.
func (s *session) report(ctx context.Context) {
	if s.opts.Report == nil {
		return
	}
	server, err := s.opts.Report(ctx)
	if err != nil {
		s.say(msg.T("migrate.report.failed", "The new inventory was not reported yet ({err}); the Agent service reports it on its next check-in.", "err", err))
		return
	}
	s.say(msg.T("migrate.report.done", "✓ Reported the new inventory to {server}.", "server", server))
}
