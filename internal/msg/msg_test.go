package msg

import (
	"errors"
	"io/fs"
	"strings"
	"testing"

	"github.com/easyssl-io/easyssl-contract/l10n"
	"github.com/easyssl-io/easyssl-contract/l10n/l10ncheck"
)

// Every message of the module against its translations: one with no
// translation, a translation nothing uses, one ID with two English texts and
// placeholders that differ all fail here.
func TestCatalog(t *testing.T) { l10ncheck.Check(t, "../..", "locales") }

func env(vars map[string]string) func(string) string {
	return func(name string) string { return vars[name] }
}

func TestResolve(t *testing.T) {
	spanishLocale := env(map[string]string{"LANG": "es_PE.UTF-8"})
	noLocale := env(nil)
	for _, c := range []struct {
		name             string
		flag, env, saved string
		getenv           func(string) string
		want             string
		decided          bool
	}{
		// The installer's order.
		{"the flag decides over everything", "en", "es", "es", spanishLocale, "en", true},
		{"the flag takes a regional variant", "es-PE", "", "", noLocale, "es", true},
		{"the variable is the default ahead of the saved language", "", "es", "en", noLocale, "es", false},
		{"an unsupported variable is ignored", "", "fr", "es", noLocale, "es", false},
		{"the saved language is ahead of the locale", "", "", "en", spanishLocale, "en", false},
		{"an unsupported saved language is ignored", "", "", "fr", spanishLocale, "es", false},
		{"the locale is ahead of English", "", "", "", spanishLocale, "es", false},
		{"LC_ALL outranks LANG", "", "", "", env(map[string]string{"LC_ALL": "C", "LANG": "es_PE.UTF-8"}), "en", false},
		{"English is last", "", "", "", noLocale, "en", false},
		// Every other command's order is the same one without the flag.
		{"the variable overrides the saved language for one run", "", "en", "es", spanishLocale, "en", false},
		{"a configuration with no language reads as the locale's", "", "", "", env(map[string]string{"LC_MESSAGES": "es_419"}), "es", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, decided, err := Resolve(c.flag, c.env, c.saved, c.getenv)
			if err != nil || got != c.want || decided != c.decided {
				t.Fatalf("Resolve = %q, %v, %v; want %q, %v, nil", got, decided, err, c.want, c.decided)
			}
		})
	}

	t.Run("an unsupported flag is refused naming the supported ones", func(t *testing.T) {
		_, decided, err := Resolve("fr", "es", "es", spanishLocale)
		if err == nil || decided {
			t.Fatalf("Resolve = decided %v, err %v; want an error", decided, err)
		}
		if got, want := err.Error(), "fr is not a supported language; the supported ones are en (English), es (Español)"; got != want {
			t.Fatalf("error = %q, want %q", got, want)
		}
	})
}

func inLanguage(t *testing.T, lang string) {
	t.Helper()
	SetLanguage(lang)
	t.Cleanup(func() { SetLanguage(l10n.English) })
}

func TestYes(t *testing.T) {
	for _, c := range []struct {
		lang, answer string
		want         bool
	}{
		{"en", "y", true}, {"en", "YES", true}, {"en", " y ", true},
		{"en", "", false}, {"en", "n", false}, {"en", "s", false},
		{"es", "s", true}, {"es", "Sí", true}, {"es", "si", true},
		{"es", "y", true}, {"es", "yes", true},
		{"es", "", false}, {"es", "n", false}, {"es", "no", false},
	} {
		inLanguage(t, c.lang)
		if got := Yes(c.answer); got != c.want {
			t.Errorf("Yes(%q) in %s = %v, want %v", c.answer, c.lang, got, c.want)
		}
	}
}

// An error made before the language is known speaks the language in effect
// when it is read, wraps what it holds, and reads in one language throughout.
func TestErrorIsRenderedWhenRead(t *testing.T) {
	inner := Err.T("language.unsupported", "{code} is not a supported language; the supported ones are {supported}",
		"code", "fr", "supported", "en")
	err := Err.T("language.save", "saving the language: {err}", "err", inner)
	wrapped := Err.T("language.save", "saving the language: {err}", "err", fs.ErrPermission)

	if !errors.Is(err, inner) || !errors.Is(wrapped, fs.ErrPermission) {
		t.Fatal("an error among the arguments is not wrapped")
	}
	english := err.Error()
	inLanguage(t, "es")
	spanish := err.Error()
	if english == spanish {
		t.Fatalf("the error reads %q in both languages", english)
	}
	text := Text("language.save", "saving the language: {err}", "err", inner)
	if text["en"] != english || text["es"] != spanish {
		t.Fatalf("Text = %v, want %q and %q", text, english, spanish)
	}
}

// An error sent to the Server carries every language whatever this host
// speaks, with a message it holds rendered in each and anything else left as
// produced; an error that is not the Agent's wording travels as English alone.
func TestErrorAsText(t *testing.T) {
	inner := Err.T("language.unsupported", "{code} is not a supported language; the supported ones are {supported}",
		"code", "fr", "supported", "en")
	err := Err.T("language.save", "saving the language: {err}", "err", inner)
	english := err.Error()
	inLanguage(t, "es")
	spanish := err.Error()

	text := TextOf(err)
	if text["en"] != english || text["es"] != spanish || len(text) != len(l10n.Supported()) {
		t.Fatalf("TextOf = %v, want %q and %q", text, english, spanish)
	}
	if verr := text.Validate(); verr != nil {
		t.Fatal(verr)
	}

	produced := TextOf(Err.T("language.save", "saving the language: {err}", "err", fs.ErrPermission))
	for lang, s := range produced {
		if !strings.HasSuffix(s, fs.ErrPermission.Error()) {
			t.Fatalf("%s reads %q, which rewords an error the Agent did not write", lang, s)
		}
	}

	other := TextOf(fs.ErrPermission)
	if len(other) != 1 || other["en"] != fs.ErrPermission.Error() {
		t.Fatalf("TextOf of another's error = %v, want English alone", other)
	}
}

func TestLanguageHeadingIsReadableInEveryLanguage(t *testing.T) {
	if got, want := LanguageHeading(), "Language / Idioma"; got != want {
		t.Fatalf("LanguageHeading = %q, want %q", got, want)
	}
}
