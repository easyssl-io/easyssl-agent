package inventory

import (
	"testing"
	"time"

	"github.com/easyssl-io/easyssl-contract/wire"
)

func TestInventoryFingerprintIsOrderAndClockIndependent(t *testing.T) {
	at := time.Date(2026, 9, 5, 23, 45, 49, 0, time.UTC)
	a := wire.Inventory{
		Diagnostics: wire.Diagnostics{Hostname: "h", OS: "Debian 13", HostType: "vm"},
		Keys: []wire.KeyInfo{
			{SPKISHA256: "bb", KeyType: "ec_p256", CreatedAt: at},
			{SPKISHA256: "aa", KeyType: "ec_p256", CreatedAt: at.In(time.FixedZone("x", 3600)).Add(300 * time.Millisecond)},
		},
	}
	b := wire.Inventory{
		Diagnostics: a.Diagnostics,
		Keys: []wire.KeyInfo{
			{SPKISHA256: "aa", KeyType: "ec_p256", CreatedAt: at},
			{SPKISHA256: "bb", KeyType: "ec_p256", CreatedAt: at},
		},
	}
	fa, err := Fingerprint(a)
	if err != nil {
		t.Fatal(err)
	}
	fb, _ := Fingerprint(b)
	if fa != fb {
		t.Fatalf("key order and sub-second clock changed the fingerprint: %s vs %s", fa, fb)
	}
	if len(fa) != 64 {
		t.Fatalf("fingerprint = %q, want 64 hex characters", fa)
	}

	withPlugins := b
	withPlugins.Plugins = []wire.PluginInventory{{ID: "nginx", SHA256: "d1"}, {ID: "generic-cli", SHA256: "d2"}}
	reordered := b
	reordered.Plugins = []wire.PluginInventory{{ID: "generic-cli", SHA256: "d2"}, {ID: "nginx", SHA256: "d1"}}
	fp1, _ := Fingerprint(withPlugins)
	fp2, _ := Fingerprint(reordered)
	if fp1 != fp2 || fp1 == fb {
		t.Fatalf("plugin order changed the fingerprint, or plugins did not: %s %s %s", fp1, fp2, fb)
	}

	c := b
	c.Diagnostics.Hostname = "renamed"
	if fc, _ := Fingerprint(c); fc == fb {
		t.Fatal("a changed hostname did not change the fingerprint")
	}
	empty, _ := Fingerprint(wire.Inventory{Diagnostics: a.Diagnostics})
	emptySlice, _ := Fingerprint(wire.Inventory{Diagnostics: a.Diagnostics, Keys: []wire.KeyInfo{}})
	if empty != emptySlice {
		t.Fatal("nil and empty key lists hash differently")
	}
}
