//go:build linux

package cyberhygiene

import (
	"fmt"
	"os"
)

func discoverPlatformContext(ctx *EndpointContext) error {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return fmt.Errorf("read /etc/os-release: %w", err)
	}
	workstationEvidence := os.Getenv("XDG_CURRENT_DESKTOP") != "" || os.Getenv("DISPLAY") != ""
	for _, path := range []string{"/usr/share/xsessions", "/usr/share/wayland-sessions"} {
		if entries, readErr := os.ReadDir(path); readErr == nil && len(entries) > 0 {
			workstationEvidence = true
		}
	}
	applyLinuxRelease(ctx, string(data), workstationEvidence)
	return nil
}
