package acmeclients

import (
	"bufio"
	"os"
	"path"
	"strings"
)

// systemdDirs are where unit files live, in the order systemd reads them.
var systemdDirs = []string{
	"/etc/systemd/system",
	"/run/systemd/system",
	"/usr/local/lib/systemd/system",
	"/usr/lib/systemd/system",
	"/lib/systemd/system",
}

// cronFiles and cronDirs are where cron entries live across distributions:
// the system crontab, its drop-in directory, the periodic script directories
// and each user's crontab (Debian's spool, then Red Hat's).
var (
	cronFiles = []string{"/etc/crontab"}
	cronDirs  = []string{
		"/etc/cron.d",
		"/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly",
		"/var/spool/cron/crontabs",
		"/var/spool/cron",
	}
)

// invocation is a line that runs certbot and the configuration directories it
// names with `--config-dir`; none when it uses cli.ini's or the default.
type invocation struct {
	kind SourceKind
	file string
	dirs []string
}

// certbotInvocations reads every systemd unit and cron entry that runs certbot
// and names a `--config-dir`. A unit's `Exec*=` lines and every line of a cron
// file count; a script they call is not followed.
func (h Host) certbotInvocations() []invocation {
	var out []invocation
	for _, dir := range systemdDirs {
		for _, f := range h.listFiles(dir, true) {
			if strings.HasSuffix(f, ".service") || (strings.HasSuffix(f, ".conf") && strings.HasSuffix(path.Dir(f), ".service.d")) {
				out = append(out, h.scanFile(f, FromSystemd, systemdExec)...)
			}
		}
	}
	files := append([]string{}, cronFiles...)
	for _, dir := range cronDirs {
		files = append(files, h.listFiles(dir, false)...)
	}
	for _, f := range files {
		out = append(out, h.scanFile(f, FromCron, func(line string) (string, bool) { return line, true })...)
	}
	return out
}

// systemdExec is the command of a unit's `Exec*=` line.
func systemdExec(line string) (string, bool) {
	key, value, ok := strings.Cut(line, "=")
	if !ok || !strings.HasPrefix(strings.TrimSpace(key), "Exec") {
		return "", false
	}
	return value, true
}

func (h Host) scanFile(p string, kind SourceKind, command func(string) (string, bool)) []invocation {
	f, err := os.Open(h.file(p))
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []invocation
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		cmd, ok := command(line)
		if !ok {
			continue
		}
		words := shellWords(cmd)
		if !runsCertbot(words) {
			continue
		}
		if dirs := configDirs(words); len(dirs) > 0 {
			out = append(out, invocation{kind: kind, file: p, dirs: dirs})
		}
	}
	return out
}

// runsCertbot reports whether a word names certbot's executable: `certbot`,
// `certbot-auto`, or a path ending in either.
func runsCertbot(words []string) bool {
	for _, w := range words {
		switch path.Base(w) {
		case "certbot", "certbot-auto":
			return true
		}
	}
	return false
}

func configDirs(words []string) []string {
	var out []string
	for i, w := range words {
		if v, ok := strings.CutPrefix(w, "--config-dir="); ok && v != "" {
			out = append(out, v)
		} else if w == "--config-dir" && i+1 < len(words) {
			out = append(out, words[i+1])
		}
	}
	return out
}

// shellWords splits a command line roughly as a shell would: on blanks and on
// `;`, `&` and `|`, with single and double quotes grouping. Good enough to
// find a program name and its flags; nothing here is executed.
func shellWords(s string) []string {
	var out []string
	var cur strings.Builder
	have := false
	var quote rune
	flush := func() {
		if have {
			out = append(out, cur.String())
		}
		cur.Reset()
		have = false
	}
	for _, c := range s {
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				cur.WriteRune(c)
			}
		case c == '\'' || c == '"':
			quote = c
			have = true
		case c == ' ' || c == '\t' || c == ';' || c == '&' || c == '|' || c == '(' || c == ')':
			flush()
		default:
			cur.WriteRune(c)
			have = true
		}
	}
	flush()
	return out
}

// listFiles lists the regular files of a directory, and with dropIns the
// files of its `*.d` subdirectories too.
func (h Host) listFiles(dir string, dropIns bool) []string {
	entries, err := os.ReadDir(h.file(dir))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		p := path.Join(dir, e.Name())
		fi, err := os.Stat(h.file(p))
		if err != nil {
			continue
		}
		switch {
		case fi.Mode().IsRegular():
			out = append(out, p)
		case fi.IsDir() && dropIns && strings.HasSuffix(e.Name(), ".d"):
			out = append(out, h.listFiles(p, false)...)
		}
	}
	return out
}
