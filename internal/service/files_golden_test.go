package service

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/easyssl-io/easyssl-contract/contracttest"
)

// The service files the Agent writes where they do not depend on what the
// host has, systemd's unit and OpenRC's script: what an operator reads and a
// later Agent overwrites. runit's and sysvinit's depend on the directories and
// tools found, and BusyBox's is a line in /etc/inittab; their lifecycle tests
// cover them.
func TestServiceFiles(t *testing.T) {
	for _, b := range []*backend{systemd(), openrc()} {
		for _, f := range b.files {
			contracttest.GoldenFile(t, filepath.Join("testdata", strings.ToLower(b.Init), filepath.Base(f.path)), []byte(f.content))
		}
	}
}
