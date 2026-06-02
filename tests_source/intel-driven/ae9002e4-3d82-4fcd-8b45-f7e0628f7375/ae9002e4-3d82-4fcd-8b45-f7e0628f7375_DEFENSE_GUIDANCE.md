# Defense Guidance — Mini Shai-Hulud npm Supply Chain Kill Chain

**Test ID:** ae9002e4-3d82-4fcd-8b45-f7e0628f7375
**Threat:** "mini Shai-Hulud" supply-chain campaign via compromised `@redhat-cloud-services` npm packages
**Platform:** Linux developer workstations and CI runners
**Source:** Socket Research Team — https://socket.dev/blog/mini-shai-hulud-campaign-hits-red-hat-cloud-services-npm-packages

---

## 1. Threat Summary

An attacker publishes (or hijacks) npm packages under a trusted namespace. The malicious `package.json` carries a `preinstall` hook (`node index.js`) that runs automatically during `npm install` — before any application code — on developer workstations and CI runners. The loader deobfuscates a staged payload, silently downloads the Bun JS runtime, applies locale/CI/sandbox guardrails, harvests cloud/SSH/Git/npm secrets (including live `gh auth token` and cloud instance metadata), exfiltrates them over an encrypted channel with a GitHub-commit fallback, and carries a worm capability that injects itself into downstream repositories and npm packages.

The defining property is **execution at dependency-install time**, which bypasses most app-runtime controls and reaches the highest-value credential surface in an engineering org.

---

## 2. Preventive Controls (highest leverage first)

### 2.1 Disable npm install scripts by default
The single most effective control. Lifecycle scripts are the entire attack surface for this campaign.

- Set `ignore-scripts=true` in the org-wide `.npmrc` (and CI `.npmrc`).
- Where build scripts are genuinely required, allowlist specific packages via tooling that runs scripts only for vetted dependencies.
- Prefer `npm ci` with a reviewed lockfile over ad-hoc `npm install`.

### 2.2 Pin and verify dependencies
- Commit and enforce `package-lock.json`; require lockfile review in PRs.
- Use a private registry / proxy (Artifactory, Verdaccio, GitHub Packages) with an allowlist and a quarantine window for newly published versions.
- Enable npm provenance / sigstore attestation verification where publishers support it.
- Adopt a Software Composition Analysis gate that blocks installs of packages flagged by Socket/OSV.

### 2.3 Isolate CI runners and dev environments
- Run `npm install` in ephemeral, network-restricted containers; destroy after each job.
- Apply least-privilege OIDC: short-lived, narrowly-scoped tokens; no long-lived `GITHUB_TOKEN`/cloud keys in runner env.
- Block runner egress except to the registry/proxy and required build endpoints (see 2.4).

### 2.4 Egress controls
- Deny outbound from dev/CI hosts to arbitrary internet; allowlist registry, source forge, and approved CDNs.
- Block access to `169.254.169.254` from build processes (IMDSv2 hop-limit=1; deny from container network namespaces).
- Alert on `python-requests` User-Agent and unexpected POSTs from `node`/`bun`.

### 2.5 Credential hygiene
- Remove standing cloud credentials from developer `$HOME`; use short-lived SSO/OIDC brokered credentials.
- Store SSH keys in hardware/agent with confirmation; avoid plaintext `~/.ssh/id_*`.
- Never persist `gh` long-lived tokens on shared/CI hosts.

---

## 3. Detective Controls

Deploy the bundled detection rules (KQL, Sigma, Elastic EQL, YARA, LimaCharlie D&R). Priority telemetry:

1. **Install-time process tree** — `npm`/`node` -> `node index.js`/`setup.js` during install.
2. **Runtime staging** — `node`/`bun` spawning `curl`/`unzip` for `oven-sh/bun` to `/tmp/b-*`.
3. **Credential sweep** — a single `node`/`bun` process reading 3+ credential files (`~/.aws`, `~/.ssh/id*`, `~/.npmrc`, `.git-credentials`, `~/.kube/config`).
4. **`gh auth token`** spawned by `node`/`bun`/shell.
5. **IMDS access** — connections to `169.254.169.254` from `node`/`bun`.
6. **Encrypted beacon** — POST with `python-requests/2.31.0` UA from `node`/`bun`.
7. **Worm artifacts** — writes to `.github/workflows/codeql.yml`, `.github/setup.js`.
8. **Exfil marker** — commit message `IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner`.
9. **Anti-forensics** — `/tmp/p<random>.js` create-then-delete.
10. **Canary** — `tmp.0987654321.lock`.

---

## 4. Incident Response Playbook

### Phase 1 — Triage & Scope
1. Identify the package(s) and version(s) installed (search build logs / lockfiles for `@redhat-cloud-services` versions matching the IOC list).
2. Enumerate every host (workstation + CI runner) that ran `npm install`/`npm ci` in the exposure window.
3. Pull EDR process trees for `npm`/`node`/`bun` on those hosts; look for the detection hits in Section 3.

### Phase 2 — Contain
1. Isolate affected hosts/runners from the network.
2. **Revoke and rotate every credential reachable from those hosts**: GitHub tokens (`gh auth logout` + revoke PATs/OAuth), npm tokens, cloud keys (AWS/Azure/GCP), SSH keys, Kubernetes service-account tokens, Vault tokens, Docker registry creds. Assume all `process.env` secrets are compromised.
3. Suspend npm publish rights for affected maintainers; audit recently published package versions for injected loaders.
4. Freeze CI; rotate runner OIDC trust.

### Phase 3 — Eradicate
1. Remove the malicious package and any `/tmp/b-*`, `/tmp/p*.js`, `tmp.0987654321.lock` artifacts.
2. Kill any daemonized child processes (the campaign detaches on workstations).
3. Audit repos for injected `.github/workflows/codeql.yml` / `.github/setup.js` and trojanized `index.js`; revert.
4. Search the org for the GitHub-commit exfil marker string and downstream republished packages.

### Phase 4 — Recover & Harden
1. Rebuild affected hosts from known-good images.
2. Reinstall dependencies from the private registry with `ignore-scripts=true`.
3. Implement Section 2 preventive controls before reconnecting.

### Phase 5 — Lessons Learned
- Add the package IOCs to the registry blocklist.
- Add a quarantine window for new dependency versions.
- Validate egress and IMDS controls with a re-run of this test.

---

## 5. Validation

Re-run this F0RT1KA test after hardening. With `ignore-scripts` enforced at the policy layer and EDR rules deployed, expect the install-hook stage to be detected/blocked (Exit 126) rather than completing the full chain (Exit 101).
