// Package inventory builds the host inventory: everything this Agent observes
// about its own host, recomputed on every check-in and kept nowhere on it. The
// Server holds the last document and its fingerprint; the Agent holds only
// what it can re-derive, so nothing here can go stale and then be reported as
// fact.
package inventory

import (
	"github.com/easyssl-io/easyssl-agent/internal/hostinfo"
	"github.com/easyssl-io/easyssl-agent/internal/keystore"
	"github.com/easyssl-io/easyssl-contract/wire"
)

// Collect reads every contributor afresh. A read that fails is an error and
// not an empty entry: the document replaces what the Server holds, so a key
// list that could not be read must not be sent as a host with no keys.
func Collect() (wire.Inventory, error) {
	keys, err := keystore.List()
	if err != nil {
		return wire.Inventory{}, err
	}
	return wire.Inventory{Diagnostics: hostinfo.Collect(), Keys: keys}, nil
}
