# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- SafePay ransomware security tests based on comprehensive threat intelligence
  - SafePay UAC Bypass & Defense Evasion test (`2cf59d3e-ae82-48bb-9779-4a5ba5bd9c11`)
  - SafePay Ransomware Simulation & Data Staging test (`109266e2-2310-40ea-9f63-b97e4b7fda61`)
- Technical reports directory structure (`tech-reports/`)
- SafePay comprehensive threat intelligence report with TTPs, IOCs, and detection strategies
- Local Prelude libraries integration for improved build reliability
- Clickable reference links in test documentation with direct access to MITRE ATT&CK, research papers, and technical resources
- Windows SSH setup documentation
- MIT License file
- Contributing guidelines (CONTRIBUTING.md)
- Code of Conduct (CODE_OF_CONDUCT.md)
- Security policy (SECURITY.md)
- This CHANGELOG file

### Changed
- Improved project structure with dedicated tech-reports directory
- Enhanced build reliability with local Prelude dependencies (no external setup required)
- Updated documentation to reflect new SafePay tests and threat intelligence integration
- Enhanced repository documentation for public release preparation

### Fixed
- Shellcheck POSIX compatibility issue in Prelude nocturnal.sh script (changed shebang from `#!/bin/sh` to `#!/bin/bash`)
- All CI/CD pipeline issues resolved - full green build status

### Security
- Added security policy and responsible disclosure guidelines
- Enhanced test documentation with proper external reference validation

## [0.2.0] - 2024-01-XX

### Added
- Registry Change Monitor utility for Windows
- PowerShell development guidelines
- Execution policy bypass to Check-DefenderProtection.ps1
- Windows Defender status checker utility

### Changed
- Updated file formatting across utilities

## [0.1.0] - 2024-01-XX

### Added
- Initial release of F0RT1KA security testing framework
- Core test structure with MITRE ATT&CK mapping
- gobuild utility for cross-platform compilation
- codesign utility for Windows executable signing
- Sample tests demonstrating framework usage
- Basic documentation and README
- CLAUDE.md for AI-assisted development

[Unreleased]: https://github.com/yourusername/f0_library/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/yourusername/f0_library/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/yourusername/f0_library/releases/tag/v0.1.0