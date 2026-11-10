// Package migrate is `easyssl-agent migrate`: an interactive command that
// moves the certificates a web server serves out of certbot's directories, so
// easySSL can manage them. It copies each file a chosen certificate's
// configuration names to `/etc/ssl/easyssl/<name>/`, asks each Plugin to point
// its configuration at the copies (the contract's `relocate`), and reports the
// new inventory. certbot itself is left alone: what else uses its lineages is
// not something the Agent can see, so it only prints the command that stops
// one renewing once nothing its Plugins read still uses it.
//
// Which certificates are offered is decided by the same rule that marks them
// on a check-in and refuses a Deployment to them (internal/acmeclients).
package migrate

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/easyssl-io/easyssl-agent/internal/acmeclients"
	"github.com/easyssl-io/easyssl-agent/internal/msg"
	"github.com/easyssl-io/easyssl-agent/internal/pluginmgr"
	"github.com/easyssl-io/easyssl-contract/plugincontract"
)

// DestDir is where the copies go, one directory per certificate.
const DestDir = acmeclients.OwnDir

// Observer runs every installed Plugin's describe and discover.
type Observer interface {
	Observe(ctx context.Context) ([]pluginmgr.Observation, error)
}

var _ Observer = (*pluginmgr.Manager)(nil)

// RelocateFunc runs one Plugin's `relocate` and returns what it printed for a
// person, its exit status, and an error when it could not be run or did not
// exit 0.
type RelocateFunc func(ctx context.Context, p pluginmgr.Installed, req plugincontract.RelocateRequest) (output string, status int, err error)

// Options are the command's dependencies, each replaceable in a test.
type Options struct {
	In  io.Reader
	Out io.Writer
	// Host is read for certbot's directories and written for the copies.
	Host     acmeclients.Host
	Plugins  Observer
	Relocate RelocateFunc
	// HasACL reports whether the host file carries a POSIX access ACL, which
	// a copy would not keep.
	HasACL func(name string) bool
	// Chown sets a file's owner and group.
	Chown func(name string, uid, gid int) error
	// Report sends the host inventory to the Server, so the web console shows
	// the moved certificates without waiting for the service's next check-in.
	// It returns the Server it reported to.
	Report func(ctx context.Context) (server string, err error)
	Logger *slog.Logger
}

// System is the command as it runs on this host.
func System(plugins *pluginmgr.Manager, logger *slog.Logger, report func(context.Context) (string, error)) Options {
	return Options{
		In: os.Stdin, Out: os.Stdout,
		Host:    acmeclients.System(),
		Plugins: plugins,
		Relocate: func(ctx context.Context, p pluginmgr.Installed, req plugincontract.RelocateRequest) (string, int, error) {
			return runRelocate(ctx, p.Path, req, logger)
		},
		HasACL: hasACL,
		Chown:  os.Lchown,
		Report: report,
		Logger: logger,
	}
}

// ErrNothingChanged is a cancel at either prompt: an error, so a script that
// reached a prompt does not read it as success.
var ErrNothingChanged = msg.Err.T("migrate.nothing_changed", "Nothing was changed.")

// group is which list a certificate on a managed path falls in.
type group int

const (
	offered group = iota + 1
	fixFirst
	cannotMove
)

// item is one discovered Target with a managed path.
type item struct {
	obs *pluginmgr.Observation
	// index is the Target's place in its Plugin's discover answer.
	index    int
	target   plugincontract.DiscoveredTarget
	findings []acmeclients.Finding
	group    group
	// notes are the Plugin's warnings (fixFirst) or why the command cannot
	// move it (cannotMove), in this host's language.
	notes   []string
	lineage *acmeclients.Lineage
	// dir is the certbot directory of an offered item.
	dir string
}

type session struct {
	opts Options
	out  io.Writer
	in   *bufio.Reader
}

// Run is the whole command.
func Run(ctx context.Context, opts Options) error {
	s := &session{opts: opts, out: opts.Out, in: bufio.NewReader(opts.In)}
	if s.opts.Logger == nil {
		s.opts.Logger = slog.New(slog.DiscardHandler)
	}

	obs, err := opts.Plugins.Observe(ctx)
	if err != nil {
		return err
	}
	rule, findings := pluginmgr.AssessOn(opts.Host, obs)
	if rule == nil {
		rule = opts.Host.Scan(nil)
	}
	s.printClients(rule)
	for _, o := range obs {
		if o.Err != nil {
			s.say(msg.T("migrate.plugin_unobserved", "The {plugin} Plugin did not answer `{op}`, so what it uses was not checked: {err}",
				"plugin", o.ID, "op", o.FailedOp, "err", o.Err))
		}
	}

	items := s.classify(obs, findings, rule)
	if len(items) == 0 {
		s.say(msg.T("migrate.none_managed", "No certificate the installed Plugins use is in another ACME client's directory, so there is nothing to move."))
		return nil
	}
	choices := s.printGroups(items)
	if len(choices) == 0 {
		s.say(msg.T("migrate.none_offered", "None of them can be moved by this command."))
		return nil
	}

	chosen, ok := s.choose(choices)
	if !ok {
		return ErrNothingChanged
	}
	p, err := s.plan(chosen, items)
	if err != nil {
		return err
	}
	s.printPlan(p)
	if !msg.Yes(s.prompt(msg.T("migrate.confirm", "Copy the files and change these lines? [y/N] "))) {
		return ErrNothingChanged
	}
	if err := s.copyAll(p); err != nil {
		return err
	}
	failed := s.relocateAll(ctx, p)
	s.advise(ctx, chosen)
	s.report(ctx)
	if failed > 0 {
		return errors.New(msg.N("migrate.relocate_failed", failed,
			"{n} Plugin could not change its configuration; its output above says why.",
			"{n} Plugins could not change their configuration; their output above says why."))
	}
	return nil
}

func (s *session) say(line string) { fmt.Fprintln(s.out, line) }

// prompt writes the label and reads one line; ok is false once nothing more
// can be read, which an empty answer is not.
func (s *session) ask(label string) (string, bool) {
	fmt.Fprint(s.out, label)
	line, err := s.in.ReadString('\n')
	if err != nil && line == "" {
		return "", false
	}
	return strings.TrimSpace(line), true
}

func (s *session) prompt(label string) string {
	answer, _ := s.ask(label)
	return answer
}

// printClients names every certbot directory checked and why, and the
// clients found that this command does not process.
func (s *session) printClients(rule *acmeclients.Rule) {
	dirs := rule.CertbotDirs()
	if len(dirs) == 0 {
		s.say(msg.T("migrate.clients.no_certbot", "No certbot directory was found."))
	}
	for _, d := range dirs {
		s.say(msg.N("migrate.clients.certbot_dir", len(d.Lineages),
			"certbot directory {dir}, with {n} certificate, checked because:",
			"certbot directory {dir}, with {n} certificates, checked because:", "dir", d.Path))
		for _, src := range d.Sources {
			s.say("    " + sourceText(src))
		}
	}
	for _, o := range s.opts.Host.DetectOthers() {
		s.say(msg.T("migrate.clients.other", "{client} found ({evidence}), not supported: its certificates were not checked.",
			"client", o.Client, "evidence", o.Evidence))
	}
	s.say("")
}

func sourceText(src acmeclients.Source) string {
	switch src.Kind {
	case acmeclients.FromSystemd:
		return msg.T("migrate.source.systemd", "`--config-dir` in the systemd unit {file}", "file", src.File)
	case acmeclients.FromCron:
		return msg.T("migrate.source.cron", "`--config-dir` in the cron entries of {file}", "file", src.File)
	case acmeclients.FromCLIIni:
		return msg.T("migrate.source.cli_ini", "`config-dir` in {file}", "file", src.File)
	case acmeclients.FromStructure:
		return msg.T("migrate.source.structure", "a certbot lineage holds {file}", "file", src.File)
	default:
		return msg.T("migrate.source.default", "it is certbot's default directory")
	}
}

// classify keeps the discovered Targets that carry one of the Agent's findings
// and sorts them into the three lists.
func (s *session) classify(obs []pluginmgr.Observation, findings [][][]acmeclients.Finding, rule *acmeclients.Rule) []*item {
	var out []*item
	for i := range obs {
		o := &obs[i]
		if o.Err != nil {
			continue
		}
		for j, t := range o.Discover.DiscoveredTargets {
			fs := findings[i][j]
			if len(fs) == 0 {
				continue
			}
			it := &item{obs: o, index: j, target: t, findings: fs}
			it.group, it.notes = s.decide(it)
			if it.group == offered {
				it.dir = fs[0].Dir
				for _, f := range fs {
					if f.Lineage != nil {
						it.lineage = f.Lineage
						it.dir = f.Dir
						break
					}
				}
			}
			out = append(out, it)
		}
	}
	return out
}

func (s *session) decide(it *item) (group, []string) {
	var notes []string
	for _, f := range it.findings {
		if f.Kind != acmeclients.Certbot {
			notes = append(notes, f.Reason().Error())
		}
	}
	if len(notes) > 0 {
		return cannotMove, notes
	}
	if len(it.target.Warnings) > 0 {
		for _, w := range it.target.Warnings {
			notes = append(notes, w.In(msg.Language()))
		}
		return fixFirst, notes
	}
	desc := it.obs.Describe
	if !plugincontract.AtLeast(desc.ContractVersion, plugincontract.RelocateSince) {
		return cannotMove, []string{msg.T("migrate.cannot.old_plugin",
			"Its {plugin} Plugin {version} cannot change its configuration. Install the current one with `sudo easyssl-agent plugin install {plugin}` and run this command again.",
			"plugin", it.obs.ID, "version", desc.Version)}
	}
	if len(it.target.References) == 0 {
		return cannotMove, []string{msg.T("migrate.cannot.no_references",
			"The {plugin} Plugin reports no configuration line naming it, so there is nothing to change.", "plugin", it.obs.ID)}
	}
	for _, p := range acmeclients.PathValues(desc.Declarations, it.target.Settings) {
		real, err := s.opts.Host.Resolve(p)
		if err != nil {
			return cannotMove, []string{msg.T("migrate.cannot.unreadable", "{file} cannot be read: {err}", "file", p, "err", err)}
		}
		if s.opts.HasACL != nil && s.opts.HasACL(s.opts.Host.File(real)) {
			return cannotMove, []string{msg.T("migrate.cannot.acl",
				"{file} carries a POSIX ACL, which a copy would not keep. Copy it yourself, keeping the ACL, and point the configuration at the copy.", "file", real)}
		}
	}
	return offered, nil
}

// printGroups lists the three groups and returns the offered items in the
// order they are numbered.
func (s *session) printGroups(items []*item) []*item {
	var choices []*item
	for _, it := range items {
		if it.group == offered {
			choices = append(choices, it)
		}
	}
	// Grouped by lineage, then by directory for files in no lineage.
	sort.SliceStable(choices, func(i, j int) bool { return groupKey(choices[i]) < groupKey(choices[j]) })
	if len(choices) > 0 {
		s.say(msg.T("migrate.group.offered", "Can be moved out of certbot's directories:"))
		last := ""
		for n, it := range choices {
			if k := groupKey(it); k != last {
				last = k
				if it.lineage != nil {
					s.say("  " + msg.T("migrate.group.lineage", "certbot certificate {lineage} in {dir}:", "lineage", it.lineage.Name, "dir", it.dir))
				} else {
					s.say("  " + msg.T("migrate.group.no_lineage", "in certbot's directory {dir}, in no lineage:", "dir", it.dir))
				}
			}
			s.say(fmt.Sprintf("    %d. %s", n+1, describe(it)))
		}
		s.say("")
	}
	s.printNoted(items, fixFirst, msg.T("migrate.group.fix_first", "Fix first, since its Plugin reports more than certbot's directory:"))
	s.printNoted(items, cannotMove, msg.T("migrate.group.cannot", "Cannot be moved by this command:"))
	return choices
}

func (s *session) printNoted(items []*item, g group, heading string) {
	printed := false
	for _, it := range items {
		if it.group != g {
			continue
		}
		if !printed {
			s.say(heading)
			printed = true
		}
		s.say("    " + describe(it))
		for _, n := range it.notes {
			s.say("        - " + n)
		}
	}
	if printed {
		s.say("")
	}
}

func groupKey(it *item) string {
	if it.lineage != nil {
		return it.dir + "\x00" + it.lineage.Name
	}
	return it.dir + "\x00\x00"
}

// describe is one line naming a certificate: its Plugin, the value it is known
// by and the names it holds.
func describe(it *item) string {
	shown := it.target.Settings[plugincontract.SummarySetting(it.obs.Describe.Declarations)]
	if shown == "" {
		if ps := acmeclients.PathValues(it.obs.Describe.Declarations, it.target.Settings); len(ps) > 0 {
			shown = ps[0]
		}
	}
	line := it.obs.ID + "  " + shown
	if it.target.Certificate != nil && len(it.target.Certificate.Domains) > 0 {
		line += "  " + strings.Join(it.target.Certificate.Domains, ", ")
	}
	return line
}

// choose asks which offered certificates to move; ok is false on a cancel.
func (s *session) choose(choices []*item) ([]*item, bool) {
	for {
		answer, ok := s.ask(msg.T("migrate.choose", "Certificates to move (numbers such as 1,3, or all; Enter cancels): "))
		if !ok || answer == "" {
			return nil, false
		}
		if picked, ok := parseChoice(answer, len(choices)); ok {
			out := make([]*item, 0, len(picked))
			for _, n := range picked {
				out = append(out, choices[n-1])
			}
			return out, true
		}
		s.say(msg.T("migrate.choose.invalid", "\"{answer}\" is not a list of the numbers above.", "answer", answer))
	}
}

// parseChoice reads `all`, or numbers from 1 to n separated by commas or
// blanks, each at most once, in the order given.
func parseChoice(answer string, n int) ([]int, bool) {
	a := strings.ToLower(strings.TrimSpace(answer))
	for _, word := range append([]string{"all"}, strings.Fields(msg.T("migrate.choose.all_words", "all"))...) {
		if a == word {
			out := make([]int, n)
			for i := range out {
				out[i] = i + 1
			}
			return out, true
		}
	}
	seen := map[int]bool{}
	var out []int
	for _, f := range strings.FieldsFunc(a, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		k, err := strconv.Atoi(f)
		if err != nil || k < 1 || k > n {
			return nil, false
		}
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	return out, len(out) > 0
}
