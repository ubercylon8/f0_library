//go:build windows

package cyberhygiene

import (
	"fmt"
	"os/exec"
)

func discoverPlatformContext(ctx *EndpointContext) error {
	script := `
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
[pscustomobject]@{
  caption = $os.Caption
  version = $os.Version
  build_number = $os.BuildNumber
  ubr = $cv.UBR
  product_type = $os.ProductType
  domain_role = $cs.DomainRole
  part_of_domain = $cs.PartOfDomain
  architecture = $env:PROCESSOR_ARCHITECTURE
} | ConvertTo-Json -Compress`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("query Windows system information: %w", err)
	}
	return applyWindowsSystemInfo(ctx, output)
}
