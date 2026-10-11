// Package inventory builds the host inventory: everything this Agent observes
// about its own host, recomputed on every check-in and kept nowhere on it. The
// Server holds the last document and its fingerprint, so nothing here can go
// stale and then be reported as fact.
package inventory

import (
	"context"

	"github.com/easyssl-io/easyssl-agent/internal/hostinfo"
	"github.com/easyssl-io/easyssl-agent/internal/keystore"
	"github.com/easyssl-io/easyssl-agent/internal/pluginmgr"
	"github.com/easyssl-io/easyssl-contract/wire"
)

// Collect reads every contributor afresh: the diagnostics, every installed
// Plugin's discover answer, and the keystore listing. A read that fails is an
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
	return wire.Inventory{Diagnostics: hostinfo.Collect(), Plugins: discovered, Keys: keys}, nil
}
