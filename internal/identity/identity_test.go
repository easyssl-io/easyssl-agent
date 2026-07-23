package identity

import (
	"regexp"
	"testing"
)

func TestNewInstanceID(t *testing.T) {
	re := regexp.MustCompile(`^[0-9a-f]{16}$`)
	seen := map[string]bool{}
	for range 100 {
		id, err := NewInstanceID()
		if err != nil {
			t.Fatalf("NewInstanceID: %v", err)
		}
		if !re.MatchString(id) {
			t.Fatalf("instance ID %q does not match %s", id, re)
		}
		if seen[id] {
			t.Fatalf("duplicate instance ID %q", id)
		}
		seen[id] = true
	}
}

func TestServiceName(t *testing.T) {
	if got := ServiceName("a1b2c3d4e5f60718"); got != "easyssl-client@a1b2c3d4e5f60718.service" {
		t.Errorf("ServiceName = %q", got)
	}
}
