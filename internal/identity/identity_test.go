package identity

import (
	"testing"
)

func TestServiceName(t *testing.T) {
	if got := ServiceName(); got != "easyssl-client.service" {
		t.Errorf("ServiceName = %q", got)
	}
}
