// Package version orders the versions the Agent and its Plugins report:
// semantic versions without the leading `v`, a release `0.2.1` or a build of a
// later commit `0.2.1+dev.<commit>`, whose build metadata ranks it with that
// release.
package version

import (
	"strconv"
	"strings"
)

// Older reports whether v ranks below than as semantic versions without the
// leading `v`, ignoring build metadata (`+dev.<commit>`). A value that is not
// a version is never older, so nothing is refused on a version unread.
func Older(v, than string) bool {
	a, okA := parse(v)
	b, okB := parse(than)
	if !okA || !okB {
		return false
	}
	for i := 0; i < 3; i++ {
		if a.n[i] != b.n[i] {
			return a.n[i] < b.n[i]
		}
	}
	// A pre-release ranks below its release; two pre-releases by their text,
	// which is enough for the forms this project tags.
	switch {
	case a.pre == b.pre:
		return false
	case a.pre == "":
		return false
	case b.pre == "":
		return true
	}
	return a.pre < b.pre
}

type semver struct {
	n   [3]int
	pre string
}

func parse(v string) (semver, bool) {
	v, _, _ = strings.Cut(v, "+")
	core, pre, _ := strings.Cut(v, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return semver{}, false
	}
	var s semver
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || p == "" || (len(p) > 1 && p[0] == '0') {
			return semver{}, false
		}
		s.n[i] = n
	}
	s.pre = pre
	return s, true
}
