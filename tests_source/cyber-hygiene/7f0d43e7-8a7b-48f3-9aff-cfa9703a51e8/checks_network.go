//go:build linux
// +build linux

package main

import (
	"fmt"
	"strings"
)

// RunNetworkChecks performs CIS Linux L1 network security checks
func RunNetworkChecks() ValidatorResult {
	checks := []CheckResult{
		checkIPForwardingDisabled(),
		checkICMPRedirectsDisabled(),
		checkSourceRoutingDisabled(),
		checkFirewallActive(),
		checkDefaultDenyFirewall(),
	}

	passed, failed := AggregateValidatorResults(checks)

	return ValidatorResult{
		Name:        "Network Security",
		Checks:      checks,
		PassedCount: passed,
		FailedCount: failed,
		TotalChecks: len(checks),
		IsCompliant: failed == 0,
	}
}

// checkIPForwardingDisabled verifies IP forwarding is disabled
// CIS 3.1.1 - Ensure IP forwarding is disabled
func checkIPForwardingDisabled() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CL1-009",
		Name:        "IP Forwarding Disabled",
		Category:    "network",
		Description: "Verify IP forwarding is disabled to prevent the system from acting as a router",
		Severity:    "high",
		Expected:    "net.ipv4.ip_forward = 0",
		Techniques:  []string{"T1557"},
		Tactics:     []string{"credential-access"},
	}

	val, err := CheckSysctl("net.ipv4.ip_forward")
	if err != nil {
		result.Passed = false
		result.Actual = "Unable to read sysctl value"
		result.Details = fmt.Sprintf("Error: %v", err)
		return result
	}

	if val == "0" {
		result.Passed = true
		result.Actual = "net.ipv4.ip_forward = 0"
		result.Details = "IP forwarding is disabled"
	} else {
		result.Passed = false
		result.Actual = fmt.Sprintf("net.ipv4.ip_forward = %s", val)
		result.Details = "IP forwarding is enabled — system can route packets between interfaces"
	}

	return result
}

// checkICMPRedirectsDisabled verifies ICMP redirects are not accepted
// CIS 3.2.2 - Ensure ICMP redirects are not accepted
func checkICMPRedirectsDisabled() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CL1-010",
		Name:        "ICMP Redirects Disabled",
		Category:    "network",
		Description: "Verify ICMP redirects are not accepted to prevent man-in-the-middle routing attacks",
		Severity:    "medium",
		Expected:    "net.ipv4.conf.all.accept_redirects = 0",
		Techniques:  []string{"T1557"},
		Tactics:     []string{"credential-access"},
	}

	val, err := CheckSysctl("net.ipv4.conf.all.accept_redirects")
	if err != nil {
		result.Passed = false
		result.Actual = "Unable to read sysctl value"
		result.Details = fmt.Sprintf("Error: %v", err)
		return result
	}

	valDefault, _ := CheckSysctl("net.ipv4.conf.default.accept_redirects")

	if val == "0" && (valDefault == "0" || valDefault == "") {
		result.Passed = true
		result.Actual = fmt.Sprintf("all=%s, default=%s", val, valDefault)
		result.Details = "ICMP redirects are disabled"
	} else {
		result.Passed = false
		result.Actual = fmt.Sprintf("all=%s, default=%s", val, valDefault)
		result.Details = "ICMP redirects are accepted — vulnerable to MITM routing attacks"
	}

	return result
}

// checkSourceRoutingDisabled verifies source-routed packets are not accepted
// CIS 3.2.1 - Ensure source routed packets are not accepted
func checkSourceRoutingDisabled() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CL1-011",
		Name:        "Source Routing Disabled",
		Category:    "network",
		Description: "Verify source-routed packets are not accepted to prevent routing manipulation",
		Severity:    "medium",
		Expected:    "net.ipv4.conf.all.accept_source_route = 0",
		Techniques:  []string{"T1557"},
		Tactics:     []string{"credential-access"},
	}

	val, err := CheckSysctl("net.ipv4.conf.all.accept_source_route")
	if err != nil {
		result.Passed = false
		result.Actual = "Unable to read sysctl value"
		result.Details = fmt.Sprintf("Error: %v", err)
		return result
	}

	valDefault, _ := CheckSysctl("net.ipv4.conf.default.accept_source_route")

	if val == "0" && (valDefault == "0" || valDefault == "") {
		result.Passed = true
		result.Actual = fmt.Sprintf("all=%s, default=%s", val, valDefault)
		result.Details = "Source routing is disabled"
	} else {
		result.Passed = false
		result.Actual = fmt.Sprintf("all=%s, default=%s", val, valDefault)
		result.Details = "Source-routed packets are accepted — routing can be manipulated"
	}

	return result
}

// checkFirewallActive verifies a host firewall is active
// CIS 3.5.1.1 - Ensure a Firewall package is installed
func checkFirewallActive() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CL1-012",
		Name:        "Firewall Active",
		Category:    "network",
		Description: "Verify a host-based firewall (firewalld, ufw, or iptables) is active",
		Severity:    "critical",
		Expected:    "At least one firewall service is active or iptables rules are configured",
		Techniques:  []string{"T1562.004"},
		Tactics:     []string{"defense-evasion"},
	}

	firewalldActive := CheckServiceActive("firewalld")
	ufwActive := CheckServiceActive("ufw")

	// Also check nftables
	nftablesActive := CheckServiceActive("nftables")

	// Check iptables rules as fallback
	iptablesRules := RunBashIgnoreError("iptables -L -n 2>/dev/null | wc -l")
	iptablesCount := ParseIntSafe(iptablesRules)
	hasIptablesRules := iptablesCount > 8 // Default empty tables have ~8 lines of headers

	activeFW := []string{}
	if firewalldActive {
		activeFW = append(activeFW, "firewalld")
	}
	if ufwActive {
		activeFW = append(activeFW, "ufw")
	}
	if nftablesActive {
		activeFW = append(activeFW, "nftables")
	}
	if hasIptablesRules {
		activeFW = append(activeFW, fmt.Sprintf("iptables (%d rules)", iptablesCount))
	}

	if len(activeFW) > 0 {
		result.Passed = true
		result.Actual = strings.Join(activeFW, ", ")
		result.Details = fmt.Sprintf("Firewall active: %s", strings.Join(activeFW, ", "))
	} else {
		result.Passed = false
		result.Actual = "No active firewall detected"
		result.Details = "Neither firewalld, ufw, nftables, nor iptables rules found"
	}

	return result
}

// checkDefaultDenyFirewall verifies default deny firewall policy
// CIS 3.5.2.1 - Ensure default deny firewall policy
func checkDefaultDenyFirewall() CheckResult {
	result := CheckResult{
		ControlID:   "CH-CL1-013",
		Name:        "Default Deny Firewall Policy",
		Category:    "network",
		Description: "Verify the firewall has a default deny (DROP/REJECT) policy for incoming traffic",
		Severity:    "critical",
		Expected:    "INPUT chain default policy is DROP or REJECT",
		Techniques:  []string{"T1562.004"},
		Tactics:     []string{"defense-evasion"},
	}

	// Check ufw default policy
	ufwStatus := RunBashIgnoreError("ufw status verbose 2>/dev/null")
	if strings.Contains(ufwStatus, "Default: deny (incoming)") ||
		strings.Contains(ufwStatus, "Default: reject (incoming)") {
		result.Passed = true
		result.Actual = "ufw default deny incoming"
		result.Details = "ufw has default deny policy for incoming traffic"
		return result
	}

	// Check iptables INPUT chain policy
	inputPolicy := RunBashIgnoreError("iptables -L INPUT -n 2>/dev/null | head -1")
	if strings.Contains(inputPolicy, "DROP") || strings.Contains(inputPolicy, "REJECT") {
		result.Passed = true
		result.Actual = fmt.Sprintf("iptables INPUT: %s", strings.TrimSpace(inputPolicy))
		result.Details = "iptables INPUT chain has default DROP/REJECT policy"
		return result
	}

	// Check nftables default policy
	nftPolicy := RunBashIgnoreError("nft list chain inet filter input 2>/dev/null | grep policy")
	if strings.Contains(nftPolicy, "drop") {
		result.Passed = true
		result.Actual = "nftables input chain policy drop"
		result.Details = "nftables has default drop policy for input"
		return result
	}

	// Check firewalld
	firewalldDefault := RunBashIgnoreError("firewall-cmd --get-default-zone 2>/dev/null")
	if firewalldDefault != "" {
		// Public and drop zones are restrictive by default
		if firewalldDefault == "drop" || firewalldDefault == "block" {
			result.Passed = true
			result.Actual = fmt.Sprintf("firewalld zone: %s", firewalldDefault)
			result.Details = fmt.Sprintf("firewalld default zone '%s' drops/rejects incoming", firewalldDefault)
			return result
		}
		// Public zone implicitly denies but allows some services
		if firewalldDefault == "public" {
			result.Passed = true
			result.Actual = fmt.Sprintf("firewalld zone: %s (implicit deny)", firewalldDefault)
			result.Details = "firewalld public zone uses implicit deny with explicit allow rules"
			return result
		}
	}

	if strings.Contains(inputPolicy, "ACCEPT") {
		result.Passed = false
		result.Actual = fmt.Sprintf("iptables INPUT: %s", strings.TrimSpace(inputPolicy))
		result.Details = "iptables INPUT chain defaults to ACCEPT — all incoming traffic is allowed"
	} else {
		result.Passed = false
		result.Actual = "No default deny policy detected"
		result.Details = "Could not confirm a default deny firewall policy on any firewall framework"
	}

	return result
}
