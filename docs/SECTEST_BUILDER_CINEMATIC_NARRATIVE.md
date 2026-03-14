# The Architect: How AI Agents Build Security Tests from Threat Intelligence

## Opening — The Problem

Every day, new cyber threats emerge. A ransomware group publishes a new technique. An APT actor deploys a novel attack chain. A vulnerability is weaponized in the wild. Security teams read the report, but the critical question remains: *would our defenses actually stop this?*

Testing that question used to take weeks. A security engineer would read the threat intelligence, manually write simulation code, build detection rules, create documentation, generate hardening scripts, and deploy the test — all by hand. It was slow, error-prone, and couldn't keep pace with the threat landscape.

F0RT1KA changed that by building an AI agent architecture that transforms raw threat intelligence into a complete, deployable security test package — fully autonomous, in minutes instead of weeks.

This is the story of how that architecture works.

---

## Act I — The Orchestrator Awakens

It begins with a single command. A security engineer pastes a threat intelligence article — perhaps a report on a new ransomware variant, an APT campaign analysis, or a CVE exploitation technique — and invokes the Orchestrator.

The Orchestrator is the central intelligence. Think of it as a film director who has read the screenplay and must now coordinate an entire production crew. It doesn't build anything itself. Instead, it understands the full picture and knows exactly which specialists to call, in what order, and what each one needs to succeed.

The Orchestrator operates on a simple but powerful principle: *sequential where dependencies exist, parallel where independence allows*. This isn't just an optimization — it's an architectural philosophy that mirrors how expert security teams actually work.

---

## Act II — Phase 1: The Assembly Line (Sequential Skills)

The first phase is a tightly orchestrated assembly line. Three specialized skills execute one after another, each building precisely on the output of the previous step. They run inside the Orchestrator's own mind — sharing context, building understanding incrementally.

### Step 1: Source Analysis — Reading the Threat

The first skill is the Analyst. It reads the raw threat intelligence and extracts structured meaning: What MITRE ATT&CK techniques are involved? What platform is targeted — Windows, Linux, macOS? How severe is this threat? Should the test simulate a single technique or a full multi-stage kill chain?

The Analyst assigns a unique identifier, maps every technique to the ATT&CK framework, and makes the critical architectural decision: will this be a simple single-binary test, or a complex multi-stage operation with separate binaries for each attack phase?

This decision shapes everything that follows.

### Step 2: Implementation — Writing the Code

With the analysis complete, the second skill takes over: the Implementer. This is where threat intelligence becomes executable reality.

The Implementer writes Go source code that faithfully simulates the threat techniques — not as a real attack, but as a controlled test that measures whether endpoint defenses detect and block each step. Every binary drops its artifacts to a designated directory. Every action is logged with millisecond precision. Every result is captured in a structured schema that feeds into Elasticsearch for analysis.

For multi-stage tests — simulating a full attack chain like initial access, lateral movement, and data exfiltration — the Implementer creates separate stage binaries, each targeting a specific technique. An orchestrator binary coordinates the stages, extracting and executing each one in sequence, checking whether defenses intervened at every step.

The code follows strict rules: single-binary deployment, embedded dependencies, comprehensive logging, organization-aware execution. These aren't suggestions — they're inviolable constraints that ensure every test is production-ready from the moment it's built.

### Step 3: Build Configuration — Forging the Binary

The third skill is the Builder. It takes the source code and produces a signed, deployable binary.

For single-stage tests, this is straightforward: compile, sign with the F0RT1KA certificate, verify.

For multi-stage tests, the build process is an intricate dance: compile each stage binary separately, sign each one individually, compress them with gzip, embed the compressed stages into the orchestrator binary, then sign the final orchestrator. The result is a single executable that contains an entire attack simulation — multiple signed binaries, compressed and embedded, ready to deploy with a single file copy.

Phase 1 is complete. The raw threat intelligence has been transformed into a compiled, signed binary. But the test package is far from finished.

---

## Act III — Phase 2: The Parallel Swarm (Independent Agents)

This is where the architecture reveals its true power.

The Orchestrator now assembles a context payload — a structured summary of everything Phase 1 produced: the test UUID, the mapped techniques, the target platform, the severity assessment, the source code location. It hands this payload to four independent agents and launches them all simultaneously.

These agents run in their own isolated contexts. They don't know about each other. They don't need to. Each one reads the test source code from disk, applies its specialized expertise, and produces its own output files. They run in parallel because their work is genuinely independent — and this parallelism cuts the total build time dramatically.

### Agent 1: The Documentarian

The Documentation Agent reads the source code and threat intelligence, then produces two files: a README with an overview and test scoring, and a detailed information card with technique mappings, detection opportunities, and expected outcomes. It scores the test on a ten-point scale based on complexity, realism, and detection difficulty.

### Agent 2: The Detection Engineer

The Detection Rules Agent is a specialist in the language of security monitoring. It reads the test's techniques and behaviors, then generates detection rules in five different formats: KQL queries for Microsoft Sentinel, YARA rules for file-based detection, Sigma rules for vendor-agnostic coverage, Elastic EQL rules for behavior-based detection, and LimaCharlie D&R rules for real-time response.

Every rule targets the *technique behavior*, not the test artifact. A detection rule that catches only the test tool is useless — the goal is rules that would catch a real attacker using the same technique.

### Agent 3: The Defense Advisor

The Defense Guidance Agent produces actionable defensive materials: a consolidated defense guidance document, platform-appropriate hardening scripts, and an incident response playbook. The hardening scripts are tailored to the test's actual target platform — a Linux test gets Linux hardening scripts, not Windows PowerShell.

### Agent 4: The Cartographer (Multi-Stage Only)

For tests that simulate a full attack chain — three or more techniques in sequence — a fourth agent activates: the Kill Chain Diagram Builder. It creates an interactive visual diagram showing the attack flow: which stages execute in what order, where defenses might intervene, which MITRE techniques map to each stage, and what the expected detection points are.

This diagram becomes a visual anchor for understanding the entire attack simulation at a glance.

All four agents work simultaneously. While one writes documentation, another crafts detection rules, a third generates hardening scripts, and the fourth maps the kill chain. The Orchestrator monitors their progress, waiting for all to complete before moving forward.

---

## Act IV — Phase 3: The Quality Gate (Validation)

Every production system needs quality control. The Validation skill runs after all parallel agents finish, acting as the final inspector before the test ships.

It verifies that all expected output files exist — typically eleven or more files for a complete package. It checks that the test scores in the README and information card match. It scans detection rules for artifact contamination — references to test-specific paths or UUIDs that would make the rules useless in production. It synchronizes the test catalog with Elasticsearch so the new test appears in the security test browser.

Only when every check passes does the Orchestrator proceed.

---

## Act V — Phase 3b: The Proving Ground (Deployment)

The final act is deployment. The test binary is sent to an actual endpoint — a real machine running real security software — and executed.

The deployment skill detects the target platform from the compiled binary, verifies SSH connectivity to the target host, copies the binary, executes it with full output capture, interprets the exit codes, retrieves the logs, and cleans up the remote artifacts.

The exit codes tell the story: 101 means the attack succeeded and the endpoint is unprotected. 126 means the endpoint's defenses blocked the attack — the desired outcome. 105 means the file was quarantined before it could even execute. 999 means something went wrong with the test itself.

This is the moment of truth — where simulation meets reality.

---

## The Complete Package

When the Orchestrator finishes, it has produced a complete security test package from a single piece of threat intelligence:

Go source code implementing the threat simulation. A compiled, signed binary ready for deployment. Five formats of detection rules for different security platforms. Defense guidance with platform-specific hardening scripts. An incident response playbook. Documentation with scoring and MITRE ATT&CK mappings. And for complex attacks, an interactive kill chain diagram.

Approximately nineteen files, created autonomously, validated for quality, and tested against a real endpoint.

What once took a security team weeks now happens in a single automated pipeline — from threat intelligence to validated security test, orchestrated by AI agents working in concert.

---

## The Architecture Philosophy

The design reflects three core principles:

**Sequential where it matters.** You cannot write code without understanding the threat. You cannot build without source code. Phase 1 respects these dependencies by running skills in strict sequence, sharing context to avoid redundant work.

**Parallel where it's possible.** Documentation, detection rules, defense guidance, and kill chain diagrams are independent outputs. Running them simultaneously as separate agents — each with its own context, its own model, its own focus — maximizes throughput without sacrificing quality.

**Validated before it ships.** Every test passes through a quality gate that checks file completeness, score consistency, artifact contamination, and catalog synchronization. Nothing leaves the pipeline without passing inspection.

This is the Architect — an AI system that doesn't just assist security engineers, but operates as a complete, autonomous security test factory. From raw threat intelligence to deployed, validated security tests, orchestrated by agents that know their roles and execute with precision.

---

*F0RT1KA — Measuring what matters: whether your defenses actually work.*
