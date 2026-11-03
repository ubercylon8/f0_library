package cyberhygiene

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
)

type OSRole string

const (
	RoleWorkstation      OSRole = "workstation"
	RoleServer           OSRole = "server"
	RoleMemberServer     OSRole = "member_server"
	RoleDomainController OSRole = "domain_controller"
	RoleUnknown          OSRole = "unknown"
)

type EndpointContext struct {
	Hostname     string `json:"hostname"`
	OSFamily     string `json:"os_family"`
	OSProduct    string `json:"os_product"`
	OSVersion    string `json:"os_version"`
	OSBuild      string `json:"os_build,omitempty"`
	Architecture string `json:"architecture"`
	OSRole       OSRole `json:"os_role"`
	RoleSource   string `json:"role_source"`
	DomainJoined bool   `json:"domain_joined"`
	EntraJoined  bool   `json:"entra_joined"`
}

func DiscoverEndpointContext() (EndpointContext, error) {
	hostname, _ := os.Hostname()
	ctx := EndpointContext{
		Hostname:     hostname,
		OSFamily:     runtime.GOOS,
		Architecture: strings.ToLower(runtime.GOARCH),
		OSRole:       RoleUnknown,
		RoleSource:   "unknown",
	}
	if err := discoverPlatformContext(&ctx); err != nil {
		return ctx, err
	}
	if override := strings.TrimSpace(os.Getenv("F0_OS_ROLE")); override != "" {
		role, err := ParseOSRole(override)
		if err != nil {
			return ctx, err
		}
		ctx.OSRole = role
		ctx.RoleSource = "environment_override"
	}
	return ctx, nil
}

func ParseOSRole(value string) (OSRole, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.ReplaceAll(normalized, "-", "_")
	normalized = strings.ReplaceAll(normalized, " ", "_")
	switch normalized {
	case "workstation", "pc", "client":
		return RoleWorkstation, nil
	case "server", "standalone_server":
		return RoleServer, nil
	case "member_server":
		return RoleMemberServer, nil
	case "domain_controller", "dc":
		return RoleDomainController, nil
	default:
		return RoleUnknown, fmt.Errorf("unsupported F0_OS_ROLE %q", value)
	}
}

type windowsSystemInfo struct {
	Caption      string `json:"caption"`
	Version      string `json:"version"`
	BuildNumber  string `json:"build_number"`
	UBR          int    `json:"ubr"`
	ProductType  int    `json:"product_type"`
	DomainRole   int    `json:"domain_role"`
	PartOfDomain bool   `json:"part_of_domain"`
	EntraJoined  bool   `json:"entra_joined"`
	Architecture string `json:"architecture"`
}

func applyWindowsSystemInfo(ctx *EndpointContext, raw []byte) error {
	var info windowsSystemInfo
	if err := json.Unmarshal(raw, &info); err != nil {
		return fmt.Errorf("parse Windows system information: %w", err)
	}
	ctx.OSFamily = "windows"
	ctx.OSProduct = strings.TrimSpace(info.Caption)
	ctx.OSVersion = strings.TrimSpace(info.Version)
	ctx.OSBuild = strings.TrimSpace(info.BuildNumber)
	if info.UBR > 0 && ctx.OSBuild != "" {
		ctx.OSBuild = fmt.Sprintf("%s.%d", ctx.OSBuild, info.UBR)
	}
	ctx.DomainJoined = info.PartOfDomain
	ctx.EntraJoined = info.EntraJoined
	if info.Architecture != "" {
		ctx.Architecture = strings.ToLower(info.Architecture)
	}

	switch info.ProductType {
	case 1:
		ctx.OSRole = RoleWorkstation
	case 2:
		ctx.OSRole = RoleDomainController
	case 3:
		if info.PartOfDomain {
			ctx.OSRole = RoleMemberServer
		} else {
			ctx.OSRole = RoleServer
		}
	default:
		ctx.OSRole = RoleUnknown
	}
	ctx.RoleSource = "win32_operatingsystem"
	return nil
}

type linuxRelease struct {
	ID         string
	IDLike     string
	PrettyName string
	VersionID  string
}

func parseOSRelease(raw string) linuxRelease {
	release := linuxRelease{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), "\"")
		switch key {
		case "ID":
			release.ID = value
		case "ID_LIKE":
			release.IDLike = value
		case "PRETTY_NAME":
			release.PrettyName = value
		case "VERSION_ID":
			release.VersionID = value
		}
	}
	return release
}

func applyLinuxRelease(ctx *EndpointContext, raw string, workstationEvidence bool) {
	release := parseOSRelease(raw)
	ctx.OSFamily = "linux"
	ctx.OSProduct = release.ID
	ctx.OSVersion = release.VersionID
	if release.PrettyName != "" {
		ctx.OSProduct = release.PrettyName
	}
	ctx.DomainJoined = false
	if workstationEvidence {
		ctx.OSRole = RoleWorkstation
	} else {
		ctx.OSRole = RoleServer
	}
	ctx.RoleSource = "desktop_evidence_heuristic"
}
