package msg

import (
	"strings"

	"github.com/easyssl-io/easyssl-contract/l10n"
)

// EnvVar carries a language into a run. The install command the web console
// gives sets it to the language its reader uses; on any other command it
// overrides the saved language for that one run.
const EnvVar = "EASYSSL_LANG"

// Resolve is the one order a language is chosen in.
//
// flag is `--lang`, which only the installer has. It decides: nothing is asked
// afterwards, and an unsupported code is an error naming the supported ones,
// because whoever typed it should learn it did nothing.
//
// Without it the answer is the first of these that names a supported language:
// env (EASYSSL_LANG), saved (the host's configuration), the operating system's
// locale read through getenv, and English. One that names nothing supported
// falls through instead of failing: none was typed for this purpose by whoever
// is reading, and `C` is the locale of most servers. For the installer that
// answer is only the default its language step offers, which is what decided
// reports.
func Resolve(flag, env, saved string, getenv func(string) string) (lang string, decided bool, err error) {
	if flag != "" {
		lang, err = Parse(flag)
		return lang, err == nil, err
	}
	for _, candidate := range []string{env, saved} {
		if l, ok := l10n.Base(candidate); ok {
			return l, false, nil
		}
	}
	if l, ok := l10n.FromLocale(getenv); ok {
		return l, false, nil
	}
	return l10n.English, false, nil
}

// Parse resolves a language somebody typed, or refuses it naming the
// supported ones.
func Parse(code string) (string, error) {
	if l, ok := l10n.Base(code); ok {
		return l, nil
	}
	return "", Err.T("language.unsupported", "{code} is not a supported language; the supported ones are {supported}",
		"code", code, "supported", SupportedList())
}

// Describe names a language by its code and its own name: `es (Español)`.
func Describe(lang string) string { return lang + " (" + l10n.Name(lang) + ")" }

// SupportedList is every supported language as Describe names it.
func SupportedList() string {
	langs := l10n.Supported()
	for i, l := range langs {
		langs[i] = Describe(l)
	}
	return strings.Join(langs, ", ")
}

// LanguageHeading is the word "Language" in every supported language, for the
// one prompt that is read before a language is chosen.
func LanguageHeading() string {
	words := Text("language.step.heading", "Language")
	var parts []string
	for _, l := range l10n.Supported() {
		parts = append(parts, words[l])
	}
	return strings.Join(parts, " / ")
}
