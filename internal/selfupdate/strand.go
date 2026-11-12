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
// accepts would refuse, leaving out those about to be updated, since the
// update brings their build for it. plugins maps each Plugin to the contract
// version it answered describe with. An Agent two breaking versions ahead of a
// Plugin refuses it: every check-in reports it as not answering and every
// Deployment through it fails, so `update` refuses to strand one.
func Strands(accepts []string, plugins map[string]string, updating map[string]bool) []string {
	if len(accepts) == 0 {
		return nil
	}
	var out []string
	for id, contract := range plugins {
		if updating[id] {
			continue
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
