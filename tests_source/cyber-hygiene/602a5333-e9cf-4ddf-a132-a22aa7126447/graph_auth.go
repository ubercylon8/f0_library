//go:build windows
// +build windows

package main

import (
	"fmt"
	"os"
	"strings"
)

// Required environment variables for service principal authentication
const (
	EnvTenantID     = "AZURE_TENANT_ID"
	EnvClientID     = "AZURE_CLIENT_ID"
	EnvClientSecret = "AZURE_CLIENT_SECRET"
)

// Required PowerShell modules for Graph API queries
var requiredModules = []string{
	"Microsoft.Graph.Authentication",
	"Microsoft.Graph.Identity.SignIns",
	"Microsoft.Graph.Identity.DirectoryManagement",
	"Microsoft.Graph.Identity.Governance",
}

// graphAuthPreamble is the PowerShell snippet prepended to every Graph query.
// Since each RunPowerShell() call spawns a new process, we must authenticate in each invocation.
var graphAuthPreamble string

// GraphPreFlight validates prerequisites and authenticates to Microsoft Graph.
// Returns the tenant display name on success, or an error if prerequisites are not met.
func GraphPreFlight() (string, error) {
	// 1. Check environment variables
	tenantID := os.Getenv(EnvTenantID)
	clientID := os.Getenv(EnvClientID)
	clientSecret := os.Getenv(EnvClientSecret)

	missing := []string{}
	if tenantID == "" {
		missing = append(missing, EnvTenantID)
	}
	if clientID == "" {
		missing = append(missing, EnvClientID)
	}
	if clientSecret == "" {
		missing = append(missing, EnvClientSecret)
	}

	if len(missing) > 0 {
		return "", fmt.Errorf(
			"missing required environment variables: %s\n"+
				"  Set these variables with a service principal that has read-only Graph API permissions:\n"+
				"    - Policy.Read.All\n"+
				"    - Directory.Read.All\n"+
				"    - RoleManagement.Read.All\n"+
				"    - AuditLog.Read.All\n"+
				"    - Application.Read.All",
			strings.Join(missing, ", "))
	}

	// 2. Check PowerShell is available
	_, err := RunPowerShell("$PSVersionTable.PSVersion.ToString()")
	if err != nil {
		return "", fmt.Errorf("PowerShell is not available: %v", err)
	}

	// 3. Check required Graph modules are installed
	missingModules := checkGraphModules()
	if len(missingModules) > 0 {
		return "", fmt.Errorf(
			"missing required PowerShell modules: %s\n"+
				"  Install them with:\n"+
				"    Install-Module Microsoft.Graph -Scope CurrentUser -Force",
			strings.Join(missingModules, ", "))
	}

	// 4. Build the reusable auth preamble
	graphAuthPreamble = fmt.Sprintf(
		`$ErrorActionPreference = 'Stop'`+"\n"+
			`$secureSecret = ConvertTo-SecureString '%s' -AsPlainText -Force`+"\n"+
			`$credential = New-Object System.Management.Automation.PSCredential('%s', $secureSecret)`+"\n"+
			`Connect-MgGraph -TenantId '%s' -ClientSecretCredential $credential -NoWelcome`+"\n",
		escapePS(clientSecret), escapePS(clientID), escapePS(tenantID))

	// 5. Validate authentication by querying the tenant organization
	authScript := graphAuthPreamble + `$org = Get-MgOrganization` + "\n" + `$org.DisplayName`
	tenantName, err := RunPowerShell(authScript)
	if err != nil {
		return "", fmt.Errorf("Graph authentication failed: %v\n  Verify service principal credentials and permissions", err)
	}

	tenantName = strings.TrimSpace(tenantName)
	if tenantName == "" {
		tenantName = tenantID
	}

	return tenantName, nil
}

// RunGraphCommand executes a PowerShell script with Graph authentication prepended.
func RunGraphCommand(script string) (string, error) {
	fullScript := graphAuthPreamble + script
	return RunPowerShell(fullScript)
}

// RunGraphJSON executes a PowerShell script with Graph auth and returns JSON-parsed output.
func RunGraphJSON(query string) ([]map[string]interface{}, error) {
	script := fmt.Sprintf(`%s | ConvertTo-Json -Depth 10 -Compress`, query)
	output, err := RunGraphCommand(script)
	if err != nil {
		return nil, err
	}
	return ParseGraphJSON(output)
}

// RunGraphJSONSingle executes a query and parses the result as a single JSON object.
func RunGraphJSONSingle(query string) (map[string]interface{}, error) {
	script := fmt.Sprintf(`%s | ConvertTo-Json -Depth 10 -Compress`, query)
	output, err := RunGraphCommand(script)
	if err != nil {
		return nil, err
	}
	return ParseGraphJSONSingle(output)
}

// GraphDisconnect cleanly disconnects from Microsoft Graph.
func GraphDisconnect() {
	RunGraphCommand("Disconnect-MgGraph -ErrorAction SilentlyContinue")
}

// checkGraphModules verifies that required PowerShell modules are installed.
func checkGraphModules() []string {
	missing := []string{}
	for _, mod := range requiredModules {
		script := fmt.Sprintf(`if (Get-Module -ListAvailable -Name '%s') { 'OK' } else { 'MISSING' }`, mod)
		output, err := RunPowerShell(script)
		if err != nil || strings.TrimSpace(output) != "OK" {
			missing = append(missing, mod)
		}
	}
	return missing
}

// escapePS escapes single quotes in PowerShell strings.
func escapePS(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}
