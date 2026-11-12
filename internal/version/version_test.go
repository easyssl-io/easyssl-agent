package version

import "testing"

func TestOlder(t *testing.T) {
	for _, c := range []struct {
		v, than string
		want    bool
	}{
		{"0.2.1", "0.2.2", true},
		{"0.2.2+dev.aaaaaaaaaaaa", "0.2.2", false},
		{"0.10.0", "0.9.0", false},
		{"0.2.2-rc1", "0.2.2", true},
		{"0.0.0", "0.2.1", true},
		{"", "0.2.1", false},
		{"0.2.1", "x", false},
	} {
		if got := Older(c.v, c.than); got != c.want {
			t.Errorf("Older(%q, %q) = %v", c.v, c.than, got)
		}
	}
}
