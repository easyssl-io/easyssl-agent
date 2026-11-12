package pluginmgr

import (
	"context"
	"slices"

	"github.com/easyssl-io/easyssl-agent/internal/msg"
)

// UpdateState is what `plugin update` does with one installed Plugin.
type UpdateState string

const (
	// UpdateNeeded: the catalog's build for this platform differs from the
	// installed one.
	UpdateNeeded UpdateState = "update"
	// UpdateCurrent: the installed bytes are the catalog's.
	UpdateCurrent UpdateState = "current"
	// UpdateNotOffered: the catalog no longer offers this Plugin, so it is left
	// as it is.
	UpdateNotOffered UpdateState = "not_offered"
	// UpdateNoBuild: it does, but not for this platform.
	UpdateNoBuild UpdateState = "no_build"
)

// PluginUpdate is one installed Plugin compared with the catalog.
type PluginUpdate struct {
	ID string
	// Current is the version the installed build answers describe with, empty
	// when it does not answer.
	Current string
	Offered string // the catalog's version, when it offers the Plugin
	// OfferedContract is the contract version the catalog's build was made
	// against, empty when the catalog does not say.
	OfferedContract string
	State           UpdateState
}

// PlanUpdates compares each installed Plugin, or only those named, with the
// catalog by digest, as Install would fetch it. Naming one that is not
// installed is refused: updating installs nothing new.
func (m *Manager) PlanUpdates(ctx context.Context, ids []string, goos, goarch string) ([]PluginUpdate, error) {
	installed, err := m.List()
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		if !slices.ContainsFunc(installed, func(i Installed) bool { return i.ID == id }) {
			return nil, msg.Err.T("plugin.update.not_installed", "{plugin} is not installed on this host; install it with `easyssl-agent plugin install {plugin}`", "plugin", id)
		}
	}
	cat, err := m.catalog.Catalog(ctx)
	if err != nil {
		return nil, msg.Err.T("plugin.install.catalog_failed", "reading the Marketplace catalog: {err}", "err", err)
	}
	var out []PluginUpdate
	for _, inst := range installed {
		if len(ids) > 0 && !slices.Contains(ids, inst.ID) {
			continue
		}
		u := PluginUpdate{ID: inst.ID}
		// describeRaw decodes the answer before judging it, so a build this
		// Agent refuses still says what it is.
		if desc, _, _ := m.describeRaw(ctx, inst.Path, inst.ID); desc.Version != "" {
			u.Current = desc.Version
		}
		entry, ok := findPlugin(cat, inst.ID)
		switch {
		case !ok:
			u.State = UpdateNotOffered
		default:
			u.Offered, u.OfferedContract = entry.Version, entry.ContractVersion
			a, ok := artifactFor(entry, goos, goarch)
			switch {
			case !ok:
				u.State = UpdateNoBuild
			case a.SHA256 == inst.Digest:
				u.State = UpdateCurrent
			default:
				u.State = UpdateNeeded
			}
		}
		out = append(out, u)
	}
	return out, nil
}
