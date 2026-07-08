package classifier

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func mkResp(status int, hdr map[string]string) *http.Response {
	h := http.Header{}
	for k, v := range hdr {
		h.Set(k, v)
	}
	return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader("{}"))}
}

// The decision-critical test: interceptionProxyHeader must fire on real corporate-DLP
// signatures and must NOT fire on benign CDN/proxy headers that real AI vendors emit
// (OpenAI/Anthropic sit behind Cloudflare/CDNs). A false positive here would misclassify
// a real LEAK as inconclusive — the reason case (f) can be trusted to stay at 999 without
// masking leaks on ordinary vendor traffic.
func TestInterceptionProxyHeader_DLPvsCDN(t *testing.T) {
	dlp := []string{
		"X-Zscaler", "X-Zscaler-Auth", "X-Bluecoat-Via", "X-Forcepoint",
		"X-Netskope-Policy", "X-Cisco-Umbrella", "X-Ns-Proxy", "X-Iboss",
		"X-Symantec-Wss", "X-Menlo-Isolation",
	}
	for _, hdr := range dlp {
		if got := interceptionProxyHeader(http.Header{hdr: {"present"}}); got == "" {
			t.Errorf("DLP header %q: expected a signature match, got none (MISS)", hdr)
		}
	}

	// Benign / CDN / vendor headers that must NOT be mistaken for a DLP proxy.
	benign := []string{
		"Via", "X-Cache", "CF-Ray", "CF-Cache-Status", "Server", "Age",
		"X-Amz-Cf-Id", "X-Amzn-Trace-Id", "X-Amzn-RequestId", "Alt-Svc",
		"X-Content-Type-Options", "X-Envoy-Upstream-Service-Time", "Set-Cookie",
		"X-Request-Id", "X-Ratelimit-Remaining", "CF-Connecting-IP", "X-Served-By",
	}
	for _, hdr := range benign {
		if got := interceptionProxyHeader(http.Header{hdr: {"present"}}); got != "" {
			t.Errorf("benign/CDN header %q: FALSE POSITIVE, matched signature %q", hdr, got)
		}
	}
}

func TestClassifyResponse(t *testing.T) {
	const vendor, host = "OpenAI", "api.openai.com"
	cases := []struct {
		name        string
		resp        *http.Response
		wantVerdict string
		wantEvid    string // substring
	}{
		{"plain 200 real vendor", mkResp(200, nil), VerdictLeak, "crossed the boundary"},
		{"401 vendor auth", mkResp(401, nil), VerdictLeak, "crossed the boundary"},
		{"403 vendor", mkResp(403, nil), VerdictLeak, "crossed the boundary"},
		{"200 + CDN Via header (must stay LEAK)", mkResp(200, map[string]string{"Via": "1.1 cloudflare"}), VerdictLeak, "crossed the boundary"},
		{"200 + CF-Ray (must stay LEAK)", mkResp(200, map[string]string{"CF-Ray": "abc-DFW"}), VerdictLeak, "crossed the boundary"},
		{"case f: 200 + X-Zscaler DLP header", mkResp(200, map[string]string{"X-Zscaler": "inspected"}), VerdictError, "disposition unobservable"},
		{"case f: 200 + X-Netskope-Policy", mkResp(200, map[string]string{"X-Netskope-Policy": "block-pii"}), VerdictError, "disposition unobservable"},
		{"case g: 302 to non-vendor host", mkResp(302, map[string]string{"Location": "https://login.corp.example/sso"}), VerdictError, "captive-portal/SSO"},
		{"302 same-vendor domain stays LEAK", mkResp(302, map[string]string{"Location": "https://api.openai.com/v1/next"}), VerdictLeak, "crossed the boundary"},
		{"302 to openai.com subdomain stays LEAK", mkResp(302, map[string]string{"Location": "https://auth.openai.com/x"}), VerdictLeak, "crossed the boundary"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ClassifyResponse(vendor, host, c.resp)
			if got.Verdict != c.wantVerdict {
				t.Errorf("verdict = %q, want %q (evidence: %s)", got.Verdict, c.wantVerdict, got.Evidence)
			}
			if !strings.Contains(got.Evidence, c.wantEvid) {
				t.Errorf("evidence %q does not contain %q", got.Evidence, c.wantEvid)
			}
			if got.Vendor != vendor {
				t.Errorf("vendor = %q, want %q", got.Vendor, vendor)
			}
		})
	}
}

func TestClassifyTransportError(t *testing.T) {
	const vendor = "OpenAI"
	cases := []struct {
		name        string
		err         error
		wantVerdict string
	}{
		{"x509 untrusted (TLS-inspection) -> BLOCK", errors.New("x509: certificate signed by unknown authority"), VerdictBlock},
		{"tls verify failure -> BLOCK", errors.New("tls: failed to verify certificate"), VerdictBlock},
		{"connection refused (inline proxy) -> BLOCK", errors.New("dial tcp 1.2.3.4:443: connect: connection refused"), VerdictBlock},
		{"connection reset -> BLOCK", errors.New("read tcp: connection reset by peer"), VerdictBlock},
		{"case h: timeout no RST -> ERROR/999", errors.New("Post \"https://api.openai.com\": context deadline exceeded (Client.Timeout exceeded)"), VerdictError},
		{"no such host (ambiguous) -> ERROR/999", errors.New("dial tcp: lookup api.openai.com: no such host"), VerdictError},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ClassifyTransportError(vendor, c.err); got.Verdict != c.wantVerdict {
				t.Errorf("verdict = %q, want %q (evidence: %s)", got.Verdict, c.wantVerdict, got.Evidence)
			}
		})
	}
}
