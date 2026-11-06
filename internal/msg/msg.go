// Package msg is everything the Agent says to a person, in that person's
// language. A message is an explicit ID naming where it appears, with its
// English text beside it at the call site:
//
//	fmt.Println(msg.T("uninstall.aborted", "Aborted; nothing was changed."))
//
// The translations are `locales/<lang>.json`, embedded in the binary; the call
// sites are the English catalog, and TestCatalog fails when the two disagree.
//
// What is not for a person does not come through here and does not change with
// the language: the running service's logs, what is sent to the Server and
// what is written to the host.
package msg

import (
	"embed"
	"strings"
	"sync/atomic"

	"github.com/easyssl-io/easyssl-contract/l10n"
)

//go:embed locales/*.json
var locales embed.FS

var catalog = l10n.MustLoad(locales, "locales")

// active is the language every message is rendered in. English until main
// settles the host's language, which is also what a test gets.
var active atomic.Pointer[l10n.Printer]

func init() { SetLanguage(l10n.English) }

// SetLanguage makes lang the language of every later message. A language that
// is not supported reads as English.
func SetLanguage(lang string) {
	p := catalog.In(lang)
	active.Store(&p)
}

func Language() string { return active.Load().Language() }

// T renders the message id in the active language. english is its English
// text; args are name, value pairs filling its `{name}` placeholders.
func T(id, english string, args ...any) string {
	return active.Load().T(id, english, args...)
}

// N renders a message whose wording depends on the count n, which also fills
// the `{n}` placeholder.
func N(id string, n int, one, other string, args ...any) string {
	return active.Load().N(id, n, one, other, args...)
}

// Text renders the message id in every supported language, for a text that is
// sent to the Server: whoever reads it there may read another language than
// this host's, so every language travels and the reader's side chooses.
func Text(id, english string, args ...any) l10n.Text {
	t := l10n.Text{}
	for _, lang := range l10n.Supported() {
		t[lang] = catalog.In(lang).T(id, english, in(lang, args)...)
	}
	return t
}

// Error is an error whose text is a message. It is rendered when it is read,
// not when it is made, so a package-level sentinel declared before the
// language is known still speaks the host's language, and one error can be
// read in several.
type Error struct {
	id, english string
	args        []any
}

// Err makes errors out of messages: `msg.Err.T(id, english, args...)`. It is a
// value with a method named T, rather than a function with a name of its own,
// so the catalog check reads the call as the message it is.
var Err errs

type errs struct{}

// T returns the message id as an error. An argument that is itself an error
// is wrapped, so errors.Is and errors.As see through the message as they see
// through `%w`.
func (errs) T(id, english string, args ...any) error {
	return &Error{id: id, english: english, args: args}
}

func (e *Error) Error() string { return e.In(Language()) }

func (e *Error) In(lang string) string {
	return catalog.In(lang).T(e.id, e.english, in(lang, e.args)...)
}

// Text renders the error in every supported language, for one that is sent to
// the Server instead of shown on this host. An argument that is itself a
// message reads in each language; any other value, an operating system's error
// included, stays as produced in all of them.
func (e *Error) Text() l10n.Text {
	t := l10n.Text{}
	for _, lang := range l10n.Supported() {
		t[lang] = e.In(lang)
	}
	return t
}

// TextOf is err as a text to send to the Server: every language of an error
// that is one of the Agent's messages, and English alone of any other.
func TextOf(err error) l10n.Text {
	if e, ok := err.(*Error); ok && e != nil {
		return e.Text()
	}
	return l10n.Text{l10n.English: err.Error()}
}

func (e *Error) Unwrap() []error {
	var wrapped []error
	for i := 1; i < len(e.args); i += 2 {
		if err, ok := e.args[i].(error); ok && err != nil {
			wrapped = append(wrapped, err)
		}
	}
	return wrapped
}

// in renders the values that are messages themselves in lang, so a message
// holding an error reads in one language throughout.
func in(lang string, args []any) []any {
	out := make([]any, len(args))
	copy(out, args)
	for i := 1; i < len(out); i += 2 {
		if e, ok := out[i].(*Error); ok && e != nil {
			out[i] = e.In(lang)
		}
	}
	return out
}

// Yes reports whether answer accepts a yes/no prompt: the active language's
// own affirmative, and always `y` and `yes`, so a habit from English never
// reads as a refusal. Anything else, an empty answer included, is a no.
func Yes(answer string) bool {
	answer = strings.ToLower(strings.TrimSpace(answer))
	if answer == "y" || answer == "yes" {
		return true
	}
	// The words are a message so that a language brings its own with its
	// catalog: space-separated, lowercase.
	for _, word := range strings.Fields(T("prompt.affirmative", "y yes")) {
		if answer == word {
			return true
		}
	}
	return false
}
