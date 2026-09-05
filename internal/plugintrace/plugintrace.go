// Package plugintrace makes one Plugin invocation legible: what the Agent sent,
// what the Plugin said back, how it exited and how long it took.
//
// None of it is on by default. There are two switches and they are separate on
// purpose, because they differ in exactly one respect that matters.
//
//   - EASYSSL_LOG_LEVEL=debug logs every exchange with the private key removed.
//     Safe to leave on, safe on somebody else's host, safe to paste into an
//     issue.
//   - EASYSSL_PLUGIN_TRACE=<path> writes the literal bytes, key included, to
//     that file and nowhere else.
//
// A single switch that did both is the one that gets left on. An install
// request carries privateKeyPem (plugincontract.InstallRequest), so logging the
// exchange verbatim into the journal would put usable private keys somewhere
// that persists, that anyone in `systemd-journal` can read, and that log
// shipping copies off the host. Enabling that has to be a decision of its own,
// and naming a file for the keys to go into is what makes it one.
package plugintrace

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// TraceEnv is the variable naming the file the literal bytes go to. Empty, or
// unset, and nothing is written.
const TraceEnv = "EASYSSL_PLUGIN_TRACE"

// LevelEnv sets the Agent's log level: debug, info, warn or error. Anything
// else, or nothing, leaves it at info.
const LevelEnv = "EASYSSL_LOG_LEVEL"

// FormatEnv chooses between the Agent's two log formats. `json` gives the same
// shape the Server writes, which is what makes a debug session one `jq` call
// rather than a parser for Go's quoting; anything else keeps the text handler,
// which is what a person reading `journalctl` without a pipeline wants.
const FormatEnv = "EASYSSL_LOG_FORMAT"

// Handler builds the Agent's log handler from the two variables. Everything the
// Agent logs goes through it, so the service and the subcommands cannot end up
// configured differently.
func Handler(w io.Writer, level, format string) slog.Handler {
	opts := &slog.HandlerOptions{Level: Level(level)}
	if strings.EqualFold(strings.TrimSpace(format), "json") {
		return slog.NewJSONHandler(w, opts)
	}
	return slog.NewTextHandler(w, opts)
}

// Level reads LevelEnv. Unset or unrecognized is info, deliberately rather than
// an error: a typo in a unit file must not stop an Agent from running.
func Level(v string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// Exchange is one run of one Plugin, whole. Every field is optional except Op
// and Path: describe sends no request, and a Plugin that could not be started
// produced no output.
type Exchange struct {
	Op       string
	Path     string
	Args     []string
	Stdin    []byte
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Duration time.Duration
	Err      error
	// Attrs names what this run was for — the Deployment, the Plugin and its
	// version — in the caller's own terms, since this package knows none of it.
	Attrs []any
}

// Record logs the exchange at debug and, when tracing is on, writes its literal
// bytes to the trace file. Cheap when neither is enabled: the level check comes
// first, and redaction only runs if something will read the result.
func Record(logger *slog.Logger, ex Exchange) {
	writeTrace(logger, ex)
	if logger == nil || !logger.Enabled(context.Background(), slog.LevelDebug) {
		return
	}
	attrs := []any{
		"op", ex.Op,
		"path", ex.Path,
		"args", strings.Join(ex.Args, " "),
		"exit", ex.ExitCode,
		"duration", ex.Duration.Round(time.Millisecond).String(),
		"stdin_bytes", len(ex.Stdin),
		"stdout_bytes", len(ex.Stdout),
	}
	attrs = append(attrs, ex.Attrs...)
	if len(ex.Stdin) > 0 {
		attrs = append(attrs, "stdin", RedactPrivateKeys(string(ex.Stdin)))
	}
	if len(ex.Stdout) > 0 {
		attrs = append(attrs, "stdout", RedactPrivateKeys(string(ex.Stdout)))
	}
	// Verbatim rather than through the Server's funnel: stderr is the Plugin's
	// own diagnostics and never leaves this host, and truncating it here is
	// what would hide the line explaining the failure.
	if len(ex.Stderr) > 0 {
		attrs = append(attrs, "stderr", RedactPrivateKeys(string(ex.Stderr)))
	}
	if ex.Err != nil {
		attrs = append(attrs, "err", ex.Err)
	}
	logger.Debug("plugin exchange", attrs...)
}

var (
	traceMu   sync.Mutex
	traceFile *os.File
	traceOnce sync.Once
	traceOff  bool
)

// writeTrace appends the literal exchange to the trace file, opening it on
// first use. A failure to open disables tracing rather than the Agent: this is
// a debugging aid, and a bad path in a unit file must not stop a host working.
func writeTrace(logger *slog.Logger, ex Exchange) {
	path := strings.TrimSpace(os.Getenv(TraceEnv))
	if path == "" {
		return
	}
	traceOnce.Do(func() {
		// 0600 and O_APPEND: this file holds private keys, and a run that
		// truncated the previous one would lose the exchange somebody is
		// comparing against.
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			if logger != nil {
				logger.Error("plugin trace could not be opened; continuing without it", "path", path, "err", err)
			}
			traceOff = true
			return
		}
		traceFile = f
		fmt.Fprintf(f, "\n=== easySSL Agent plugin trace, opened %s ===\n"+
			"WARNING: this file contains private keys, verbatim, as they were handed to each\n"+
			"Plugin. It exists because %s is set. Delete it when you are finished.\n\n",
			time.Now().Format(time.RFC3339), TraceEnv)
		if logger != nil {
			logger.Warn("plugin tracing is on; this writes private keys to a file",
				"path", path, "disable_by", "unsetting "+TraceEnv)
		}
	})
	if traceOff || traceFile == nil {
		return
	}
	traceMu.Lock()
	defer traceMu.Unlock()
	fmt.Fprintf(traceFile, "--- %s  %s %s  exit=%d  %s\n",
		time.Now().Format(time.RFC3339), ex.Path, ex.Op, ex.ExitCode,
		ex.Duration.Round(time.Millisecond))
	for name, b := range map[string][]byte{"stdin": ex.Stdin, "stdout": ex.Stdout, "stderr": ex.Stderr} {
		if len(b) > 0 {
			fmt.Fprintf(traceFile, "%s:\n%s\n", name, b)
		}
	}
	if ex.Err != nil {
		fmt.Fprintf(traceFile, "err: %v\n", ex.Err)
	}
}

// privateKeyBlock matches a PEM private key however it is framed. The body is
// `[\s\S]` rather than `.` so it spans real newlines, and the same match
// covers a key echoed inside JSON, where the newlines are two-character `\n`
// escapes and the whole block is one line.
var privateKeyBlock = regexp.MustCompile(
	`(-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----)([\s\S]*?)(-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----)`)

// keyBegin and keyEnd locate the markers on their own, for the case below where
// a key has no end marker left.
var (
	keyBegin = regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----`)
	keyEnd   = regexp.MustCompile(`-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----`)
)

// KeyPlaceholder stands in for what was removed, and says who removed it so a
// reader does not go looking for a truncated file.
//
// It carries no newline of its own, and that is load-bearing rather than
// cosmetic. Most of what passes through here is a JSON document with the key
// inside a string value, and a real newline there makes the document
// unparseable: the debug log stops being something `jq` can read, for a
// prettier rendering of the one part that has been removed. The markers on
// either side already show where the key was.
const KeyPlaceholder = " ****** private key redacted by the easySSL Agent ****** "

// RedactPrivateKeys masks the body of any PEM private key in text.
//
// It guards two different exposures with one rule, which is why it lives here
// rather than beside either of them. A Plugin is arbitrary code and receives
// the key on its stdin, so one that echoes its request — or simply prints the
// file it was handed — puts the key in its output; reporting that verbatim
// would store a usable private key in the Server's database and show it in the
// web console, which is worse than the exposure the whole design avoids by
// never sending a key over the wire. And the debug log above passes the request
// itself through here, where the key is not an accident but the payload.
//
// The markers are kept so the redaction is visible rather than looking like a
// Plugin that said nothing.
func RedactPrivateKeys(s string) string {
	s = privateKeyBlock.ReplaceAllString(s, "${1}"+KeyPlaceholder+"${3}")
	// Whatever survives the pass above is a key with no end marker, which is
	// what a bounded or interrupted echo leaves. Only the last begin marker can
	// be unclosed — every earlier one was closed, or it would have swallowed
	// the rest — so the tail from it is dropped. Done by index rather than by a
	// second pattern: a pattern anchored to the end would also match the begin
	// marker the pass above deliberately kept, and take the whole output after
	// a redacted key with it.
	last := keyBegin.FindAllStringIndex(s, -1)
	if len(last) == 0 {
		return s
	}
	start := last[len(last)-1]
	if keyEnd.FindStringIndex(s[start[1]:]) != nil {
		return s // closed, and already redacted above
	}
	return s[:start[1]] + KeyPlaceholder
}
