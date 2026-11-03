//go:build darwin

package cyberhygiene

import (
	"fmt"
	"os/exec"
	"strings"
)

func discoverPlatformContext(ctx *EndpointContext) error {
	cmd := exec.Command("sw_vers", "-productVersion")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("query macOS version: %w", err)
	}
	ctx.OSFamily = "darwin"
	ctx.OSProduct = "macOS"
	ctx.OSVersion = strings.TrimSpace(string(output))
	ctx.OSRole = RoleWorkstation
	ctx.RoleSource = "macos_platform"
	return nil
}
