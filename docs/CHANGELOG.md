# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Agent architecture decomposition**: Monolithic sectest-builder → orchestrator + 5 skills + 7 agents with 4-phase execution model
- **Cross-platform support**: Linux and macOS test targets with platform-specific logger files (`test_logger_linux.go`, `test_logger_darwin.go`)
- **New detection rule formats**: Sigma (`_sigma_rules.yml`) and Elastic EQL (`_elastic_rules.ndjson`) alongside existing KQL, YARA, and LimaCharlie D&R
- **Defense guidance generation**: Consolidated defense docs, hardening scripts (Windows/Linux/macOS), and incident response playbooks per test
- **References/provenance tracking**: `_references.md` files linking each test to source threat intelligence with retroactive generation for all existing tests
- **Kill chain diagram builder**: Cytoscape.js-based interactive kill chain visualizations for multi-stage tests
- **Attack flow diagram builder**: Full attack flow visualizations with light/dark theme support
- **Gzip compression for multi-stage tests**: Embedded `.exe.gz` files decompressed in memory (~35% size reduction without EDR heuristic triggers)
- **Multi-binary bundle architecture**: Quarantine-resilient bundles for cyber-hygiene tests (baseline, identity-endpoint)
- **Organization UUID support**: `org_resolver.go` with registry-based UUID resolution for multi-tenant deployments
- **Dual code signing**: F0RT1KA + organization certificate signing for ASR bypass compatibility
- **Elasticsearch catalog sync**: `sync-test-catalog-to-elasticsearch.py` with enrichment pipeline for test result analytics
- **Bundle results protocol**: `bundle_results.json` for per-control granularity in cyber-hygiene and multi-stage tests
- **Pentest readiness builder**: DORA/TIBER-EU phase-aligned test suite generation
- **Test deploy agent**: SSH-based binary deployment, execution, and result capture
- **URL validation**: Automated validation and fix for broken URLs across reference files
- **CI: Gitleaks + TruffleHog** secret scanning (replacing naive grep patterns)
- **CI: Claude Code Review** workflow with domain-specific security test review prompts
- **CI: Claude Code Action** for interactive issue/PR assistance

### Changed
- **Test consolidation**: 49 tests across 4 categories → 46 tests across 3 categories (removed `phase-aligned`, consolidated redundant cyber-hygiene tests, added new intel-driven tests)
- **Schema v2.0 enforcement**: All tests migrated to `InitLogger(testID, testName, metadata, executionContext)` signature
- **CI build workflow**: Fixed shellcheck to scope only framework scripts (not auto-generated `build_all.sh`), dynamic test path detection
- **CI security workflow**: Removed disabled CodeQL job, replaced grep-based secret scanning with Gitleaks + TruffleHog
- **CI Claude workflows**: Updated to `@v1` action, fixed permissions (`pull-requests: write`), added domain-specific review prompts
- **SECURITY.md**: Moved to repository root for GitHub Security tab auto-detection

### Removed
- `phase-aligned` test category (tests consolidated into `intel-driven`)
- 11 redundant cyber-hygiene tests (capabilities merged into multi-binary bundles)
- Disabled CodeQL job from security workflow
- Naive grep-based secret detection from security workflow

## [1.0.0] - 2025-04-15

### Added
- Initial stable release of F0RT1KA security testing framework
- Schema v2.0 test results logging with Elasticsearch integration
- `gobuild` utility for cross-platform test compilation
- `codesign` utility for Windows executable signing
- LimaCharlie Infrastructure as Code (detection rules, certificate deployment)
- Sample tests and multi-stage template
- Comprehensive documentation (ARCHITECTURE.md, DEVELOPMENT.md, TEST_RESULTS_SCHEMA_GUIDE.md)
- CI/CD workflows (build, security scanning)
- CLAUDE.md for AI-assisted development

## [0.2.0] - 2024-01-15

### Added
- Registry Change Monitor utility for Windows
- PowerShell development guidelines
- Execution policy bypass to Check-DefenderProtection.ps1
- Windows Defender status checker utility

### Changed
- Updated file formatting across utilities

## [0.1.0] - 2024-01-01

### Added
- Initial release of F0RT1KA security testing framework
- Core test structure with MITRE ATT&CK mapping
- gobuild utility for cross-platform compilation
- codesign utility for Windows executable signing
- Sample tests demonstrating framework usage
- Basic documentation and README
- CLAUDE.md for AI-assisted development

[Unreleased]: https://github.com/ubercylon8/f0_library/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/ubercylon8/f0_library/compare/v0.2.0...v1.0.0
[0.2.0]: https://github.com/ubercylon8/f0_library/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ubercylon8/f0_library/releases/tag/v0.1.0
