package cyberhygiene

import "testing"

func TestParseOSRole(t *testing.T) {
	for input, want := range map[string]OSRole{
		"workstation":       RoleWorkstation,
		"PC":                RoleWorkstation,
		"member-server":     RoleMemberServer,
		"dc":                RoleDomainController,
		"standalone_server": RoleServer,
	} {
		got, err := ParseOSRole(input)
		if err != nil || got != want {
			t.Fatalf("ParseOSRole(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	if _, err := ParseOSRole("router"); err == nil {
		t.Fatal("expected unsupported role to fail")
	}
}

func TestApplyWindowsSystemInfo(t *testing.T) {
	ctx := EndpointContext{}
	raw := []byte(`{"caption":"Microsoft Windows Server 2025 Standard","version":"10.0.26100","build_number":"26100","ubr":1,"product_type":3,"domain_role":3,"part_of_domain":true,"architecture":"AMD64"}`)
	if err := applyWindowsSystemInfo(&ctx, raw); err != nil {
		t.Fatal(err)
	}
	if ctx.OSRole != RoleMemberServer || ctx.OSBuild != "26100.1" || ctx.Architecture != "amd64" || !ctx.DomainJoined {
		t.Fatalf("unexpected context: %+v", ctx)
	}

	raw = []byte(`{"caption":"Microsoft Windows 11 Enterprise","product_type":1,"part_of_domain":false}`)
	if err := applyWindowsSystemInfo(&ctx, raw); err != nil {
		t.Fatal(err)
	}
	if ctx.OSRole != RoleWorkstation || ctx.DomainJoined {
		t.Fatalf("unexpected workstation context: %+v", ctx)
	}
}

func TestParseOSRelease(t *testing.T) {
	release := parseOSRelease("ID=debian\nVERSION_ID=\"13\"\nPRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nID_LIKE=debian\n")
	if release.ID != "debian" || release.VersionID != "13" || release.PrettyName != "Debian GNU/Linux 13 (trixie)" {
		t.Fatalf("unexpected release: %+v", release)
	}
	ctx := EndpointContext{}
	applyLinuxRelease(&ctx, "ID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"", false)
	if ctx.OSRole != RoleServer || ctx.OSVersion != "24.04" || ctx.OSProduct != "Ubuntu 24.04 LTS" {
		t.Fatalf("unexpected Linux context: %+v", ctx)
	}
}
