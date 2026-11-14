package selfupdate

import (
	"bytes"
	"context"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/easyssl-io/easyssl-contract/plugincontract"
)

// Accepts asks the build at path which breaking contract versions it accepts
// from a Plugin (`easyssl-agent version --contracts`). Nil when it cannot say,
// as a build from before the flag cannot: Strands then has nothing to judge by.
func Accepts(ctx context.Context, path string) []string {
	vctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// #nosec G204 -- path is the staged build, checked against the catalog's
	// digest before this runs.
	out, err := exec.CommandContext(vctx, path, "version", "--contracts").Output()
	if err != nil {
		return nil
	}
	return strings.Fields(string(bytes.TrimSpace(out)))
}

// Strands names the installed Plugins a build accepting the breaking versions
// accepts would refuse. installed maps each Plugin to the contract version it
// answered describe with; updates maps those about to be updated to the
// contract version of the build replacing them, which is the one judged, and
// a Plugin updated from a catalog that does not say is not judged. An Agent
// two breaking versions ahead of a Plugin refuses it: every check-in reports
// it as not answering and every Deployment through it fails, so `update`
// refuses to strand one.
func Strands(accepts []string, installed map[string]string, updates map[string]string) []string {
	if len(accepts) == 0 {
		return nil
	}
	var out []string
	for id, contract := range installed {
		if next, ok := updates[id]; ok {
			if next == "" {
				continue
			}
			contract = next
		}
		breaking, ok := plugincontract.BreakingVersion(contract)
		if !ok || !contains(accepts, breaking) {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
