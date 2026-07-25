// Package hostinfo collects best-effort host diagnostics the Client reports at
// registration: machine ID, hostname, OS, host type, and the binary, config, and
// service paths. Every field is best-effort; an unavailable value is reported as
// an empty string rather than failing.
package hostinfo

import (
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/easyssl-io/easyssl-client/internal/identity"
	"github.com/easyssl-io/easyssl-contract/wire"
)

// Collect gathers the host diagnostics reported at registration.
func Collect() wire.Diagnostics {
	bin, _ := os.Executable()
	return wire.Diagnostics{
		MachineID:   machineID(),
		Hostname:    hostname(),
		OS:          osName(),
		HostType:    hostType(),
		BinaryPath:  bin,
		ConfigPath:  identity.BaseDir,
		ServiceName: identity.ServiceName(),
	}
}

// machineID reads /etc/machine-id (the systemd stable OS-install identifier).
func machineID() string {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if b, err := os.ReadFile(p); err == nil {
			if id := strings.TrimSpace(string(b)); id != "" {
				return id
			}
		}
	}
	return ""
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}

// osName returns the distribution PRETTY_NAME from /etc/os-release, falling back
// to the Go runtime OS name.
func osName() string {
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		for line := range strings.SplitSeq(string(b), "\n") {
			if v, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
				return strings.Trim(strings.TrimSpace(v), `"`)
			}
		}
	}
	return runtime.GOOS
}

// hostType classifies the host as container, vm, bare-metal, or unknown when it
// genuinely cannot tell. It asks systemd-detect-virt first: it ships with
// systemd (which this Client already requires), and it recognizes dozens of
// hypervisors and container runtimes, including ones the file heuristics below
// miss entirely. The heuristics remain only as a fallback for hosts where the
// tool is unavailable, and they never assert bare-metal on their own: guessing
// bare-metal for anything unrecognized is how a VM ends up mislabeled.
func hostType() string {
	if t, ok := detectVirt(); ok {
		return t
	}
	if fileExists("/.dockerenv") || fileExists("/run/.containerenv") {
		return "container"
	}
	if b, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		s := string(b)
		if strings.Contains(s, "docker") || strings.Contains(s, "containerd") || strings.Contains(s, "lxc") {
			return "container"
		}
	}
	// DMI vendor/product hints at a hypervisor. "virtualization" catches
	// platforms whose vendor string is a hardware maker (an Apple VM reports
	// vendor "Apple Inc." with product "Apple Virtualization Generic Platform",
	// while bare-metal Apple hardware reports a real model name).
	for _, p := range []string{"/sys/class/dmi/id/sys_vendor", "/sys/class/dmi/id/product_name"} {
		if b, err := os.ReadFile(p); err == nil {
			v := strings.ToLower(strings.TrimSpace(string(b)))
			for _, needle := range []string{"qemu", "kvm", "vmware", "virtualbox", "xen", "amazon", "microsoft", "google", "bochs", "virtualization"} {
				if strings.Contains(v, needle) {
					return "vm"
				}
			}
		}
	}
	return "unknown"
}

// detectVirt classifies the host with systemd-detect-virt, returning false when
// the tool is not available. `--quiet --container` and `--quiet --vm` each exit
// 0 only when that kind of virtualization is detected, so systemd does the
// classification and this Client needs no table of hypervisor names.
func detectVirt() (string, bool) {
	if _, err := exec.LookPath("systemd-detect-virt"); err != nil {
		return "", false
	}
	if exec.Command("systemd-detect-virt", "--quiet", "--container").Run() == nil {
		return "container", true
	}
	if exec.Command("systemd-detect-virt", "--quiet", "--vm").Run() == nil {
		return "vm", true
	}
	// The tool ran and found nothing, which is a positive answer.
	return "bare-metal", true
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
