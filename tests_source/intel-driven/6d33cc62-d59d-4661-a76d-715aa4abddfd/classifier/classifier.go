// Package classifier holds the integrity-critical egress classification for Stage 3
// (T1567) of the PII-exfil-to-inference test. It is a separate package so the
// leak/block/ambiguous decision is unit-testable in isolation — the stage directory
// itself has multiple package-main entrypoints (one per stage + orchestrator) and so
// cannot be `go test`ed directly.
//
// CLASSIFICATION PRINCIPLE (load-bearing): key on WHO answered, not on status code.
//   - Any HTTP response over a TLS session that VALIDATES to the real vendor — including
//     a vendor 401/403 at its auth layer — means the bytes crossed the boundary: a LEAK.
//   - A block requires positive evidence *the org's* control intervened (DNS sinkhole,
//     TLS-interception cert error, or a proxy refusing/resetting a public-IP connection).
//   - Anything ambiguous is VerdictError (999) — NEVER a block code (CLAUDE.md Rule 8).
package classifier

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Per-host classification verdicts.
const (
	VerdictLeak  = "leak"
	VerdictBlock = "block"
	VerdictError = "error"
)

// Result captures the classified outcome of one exfil attempt.
type Result struct {
	Vendor   string
	Verdict  string
	Evidence string
}

// ClassifyResponse classifies an HTTP response received over a validated TLS session.
// Reaching here means the peer presented a certificate that validated for the vendor
// host against the local trust store (else the transport would have errored and been
// handled by ClassifyTransportError). It NEVER defaults to a block code.
func ClassifyResponse(vendor, host string, resp *http.Response) Result {
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	// == Ambiguous edge cases (spec §4) — ADJUDICATED: all remain inconclusive (999).
	// Each lacks affirmative evidence of either a leak or an org-control action, and
	// mapping any to a block (126) would risk a false "protected" verdict. Rationale
	// retained per case. ==

	// (g) Captive-portal / SSO redirect: a 3xx to a host outside the vendor domain.
	// Decided inconclusive: the request body may already have been forwarded before the
	// redirect, so mapping to "block" could hide a real leak.
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if loc := resp.Header.Get("Location"); loc != "" && !sameVendorDomain(loc, host) {
			return Result{vendor, VerdictError,
				fmt.Sprintf("HTTP %d redirect to non-vendor host %q — captive-portal/SSO? (ambiguous — inconclusive by design)", resp.StatusCode, redactHost(loc))}
		}
	}

	// (f) Transparent-MITM DLP/SWG returning 200 over a trusted corporate root (TLS
	// validated). Decided inconclusive: isolated tests confirmed the header allowlist
	// does not false-positive on CDN headers, but a 200 carrying a DLP signature cannot
	// reveal whether the gateway BLOCKED (inspected and dropped) or PASSED THROUGH
	// (forwarded to the vendor → still a leak). That disposition is unobservable from
	// the client, so neither leak nor block is safe.
	if sig := interceptionProxyHeader(resp.Header); sig != "" {
		return Result{vendor, VerdictError,
			fmt.Sprintf("HTTP %d carrying corporate-proxy signature %q — DLP/SWG in-path, disposition unobservable (blocked vs. forwarded); inconclusive", resp.StatusCode, sig)}
	}

	// (d) UNAMBIGUOUS LEAK: a validated response from the real vendor at ANY status,
	// including 401/403 at the vendor's auth layer. The bytes crossed the boundary.
	return Result{vendor, VerdictLeak,
		fmt.Sprintf("HTTP %d from validated vendor endpoint (%d bytes) — PII crossed the boundary", resp.StatusCode, len(body))}
}

// ClassifyTransportError maps a client.Do transport error to a verdict. It returns a
// block ONLY on positive interception evidence; ambiguous errors map to VerdictError.
func ClassifyTransportError(vendor string, err error) Result {
	msg := strings.ToLower(err.Error())

	// (b) TLS-interception: the real vendor cert is publicly trusted, so a verification
	// failure means something re-signed the connection — an inline TLS-inspection proxy.
	if strings.Contains(msg, "x509") ||
		strings.Contains(msg, "certificate signed by unknown authority") ||
		strings.Contains(msg, "certificate is valid for") ||
		strings.Contains(msg, "tls: failed to verify") {
		return Result{vendor, VerdictBlock,
			fmt.Sprintf("TLS certificate verification failed on a public vendor host (TLS-inspection proxy): %v", err)}
	}

	// (c) Inline proxy refused/reset the connection to a public vendor IP.
	if strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "reset by peer") ||
		strings.Contains(msg, "forcibly closed") {
		return Result{vendor, VerdictBlock,
			fmt.Sprintf("TCP connection refused/reset to a public vendor IP (inline egress proxy): %v", err)}
	}

	// (h) Connection timeout with no RST — silent egress-firewall drop vs. ordinary
	// vendor slowness, indistinguishable from the client. Decided inconclusive (999).
	if strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "deadline exceeded") ||
		strings.Contains(msg, "client.timeout") {
		return Result{vendor, VerdictError,
			fmt.Sprintf("connection timed out with no reset — silent drop vs. vendor slowness (ambiguous — inconclusive by design): %v", err)}
	}

	// Everything else (no route, DNS-in-dial, etc.) is ambiguous — never a block.
	return Result{vendor, VerdictError, fmt.Sprintf("unrecognized transport outcome (inconclusive): %v", err)}
}

// interceptionProxyHeader returns a non-empty signature string if the response carries
// a header characteristic of a known corporate DLP/secure-web-gateway. It deliberately
// avoids generic CDN headers (Via, X-Cache) to limit false positives on real vendors.
func interceptionProxyHeader(h http.Header) string {
	corporateSignatures := []string{
		"X-Zscaler", "X-Zscaler-Auth", "X-Bluecoat-Via", "X-Forcepoint",
		"X-Netskope-Policy", "X-Cisco-Umbrella", "X-Ns-Proxy", "X-Iboss",
		"X-Symantec-Wss", "X-Menlo-Isolation",
	}
	for _, sig := range corporateSignatures {
		if h.Get(sig) != "" {
			return sig
		}
	}
	return ""
}

// sameVendorDomain reports whether a redirect Location stays within the vendor's domain.
func sameVendorDomain(location, vendorHost string) bool {
	u, err := url.Parse(location)
	if err != nil || u.Host == "" {
		// Relative redirect (same host) — treat as same domain.
		return true
	}
	rh := strings.ToLower(u.Hostname())
	vh := strings.ToLower(vendorHost)
	if rh == vh {
		return true
	}
	// Compare registrable-ish suffix (last two labels).
	return regDomain(rh) == regDomain(vh)
}

func regDomain(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return host
	}
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

// redactHost returns only the host of a URL for logging (never log full redirect URLs).
func redactHost(location string) string {
	if u, err := url.Parse(location); err == nil && u.Host != "" {
		return u.Host
	}
	return "<unparseable>"
}
