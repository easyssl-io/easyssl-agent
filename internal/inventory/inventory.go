// Package inventory builds the host inventory: everything this Agent observes
// about its own host, recomputed on every check-in and kept nowhere on it. The
// Server holds the last document and its fingerprint, so nothing here can go
// stale and then be reported as fact.
package inventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"

	"github.com/easyssl-io/easyssl-agent/internal/hostinfo"
	"github.com/easyssl-io/easyssl-agent/internal/keystore"
	"github.com/easyssl-io/easyssl-agent/internal/pluginmgr"
	"github.com/easyssl-io/easyssl-contract/wire"
)

// Collect reads every contributor afresh: the diagnostics, every installed
// Plugin's describe and discover answers, and the keystore listing. A read that fails is an
// error and not an empty entry: the document replaces what the Server holds, so
// a list that could not be read must not be sent as a host with none. A Plugin
// that fails to answer is not such a failure; it is reported as present but
// unobserved (pluginmgr.Discover).
func Collect(ctx context.Context, plugins *pluginmgr.Manager) (wire.Inventory, error) {
	discovered, err := plugins.Discover(ctx)
	if err != nil {
		return wire.Inventory{}, err
	}
	keys, err := keystore.List()
	if err != nil {
		return wire.Inventory{}, err
	}
	inv := wire.Inventory{Diagnostics: hostinfo.Collect(), Plugins: discovered, Keys: keys}
	if inv.Fingerprint, err = Fingerprint(inv); err != nil {
		return wire.Inventory{}, err
	}
	return inv, nil
}

// Fingerprint is this Agent's hash of an inventory, ignoring its Fingerprint
// field. The Server stores it as sent and compares the next check-in's
// against it, so all it has to be is stable for one host: keys sorted by
// fingerprint and Plugins by id, and key times in UTC to the second, so a
// document that has not changed hashes the same on every check-in and is not
// sent again.
func Fingerprint(inv wire.Inventory) (string, error) {
	keys := make([]wire.KeyInfo, len(inv.Keys))
	copy(keys, inv.Keys)
	sort.Slice(keys, func(i, j int) bool { return keys[i].Fingerprint < keys[j].Fingerprint })
	for i := range keys {
		keys[i].CreatedAt = keys[i].CreatedAt.UTC().Truncate(time.Second)
	}
	plugins := make([]wire.PluginInventory, len(inv.Plugins))
	copy(plugins, inv.Plugins)
	sort.Slice(plugins, func(i, j int) bool { return plugins[i].ID < plugins[j].ID })
	raw, err := json.Marshal(wire.Inventory{Diagnostics: inv.Diagnostics, Plugins: plugins, Keys: keys})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
