# Contributing to F0RT1KA

First off, thank you for considering contributing to F0RT1KA! It's people like you that make F0RT1KA such a great tool for security testing and evaluation.

## Code of Conduct

This project and everyone participating in it is governed by the [F0RT1KA Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Important Security Notice

F0RT1KA is a security testing framework designed for authorized testing only. Contributors must:
- Never submit malicious code intended for unauthorized use
- Ensure all contributions are for defensive security purposes
- Include appropriate warnings and documentation for any potentially dangerous functionality

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues as you might find out that you don't need to create one. When you are creating a bug report, please include as many details as possible:

* Use a clear and descriptive title
* Describe the exact steps which reproduce the problem
* Provide specific examples to demonstrate the steps
* Describe the behavior you observed after following the steps
* Explain which behavior you expected to see instead and why
* Include details about your configuration and environment

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, please include:

* Use a clear and descriptive title
* Provide a step-by-step description of the suggested enhancement
* Provide specific examples to demonstrate the steps
* Describe the current behavior and explain which behavior you expected to see instead
* Explain why this enhancement would be useful

### Pull Requests

1. Fork the repo and create your branch from `main`
2. If you've added code that should be tested, add tests
3. Ensure the test suite passes
4. Make sure your code follows the existing code style
5. Issue that pull request!

## Development Process

### Setting Up Your Environment

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/f0_library.git
   cd f0_library
   ```

2. Install Go 1.21 or later

3. Set up the Prelude libraries in `preludeorg-libraries/` directory

### Creating a New Test

1. Generate a UUID for your test:
   ```bash
   uuidgen | tr '[:upper:]' '[:lower:]'
   ```

2. Create the test directory structure:
   ```bash
   mkdir -p tests_source/<uuid>
   ```

3. Create the required files:
   - `<uuid>.go` - Main test implementation
   - `README.md` - Brief overview
   - `<uuid>_info.md` - Detailed information card
   - `go.mod` - Module file

4. Follow the test implementation pattern from `sample_tests/`

5. Build your test:
   ```bash
   ./utils/gobuild build tests_source/<uuid>/
   ```

### Code Style Guidelines

#### Go Code
- Follow standard Go formatting (use `gofmt`)
- Use meaningful variable and function names
- Add error handling for all operations
- Use `Endpoint.Say()` for logging
- Always clean up resources

#### PowerShell Scripts
- Include admin privilege checks
- Implement execution policy bypass
- Follow the patterns in existing utilities

### Testing Your Changes

1. Build your test:
   ```bash
   ./utils/gobuild build tests_source/<uuid>/
   ```

2. Sign the binary (Windows):
   ```bash
   ./utils/codesign sign build/<uuid>/<uuid>.exe
   ```

3. Test in a safe, isolated environment

### Commit Message Guidelines

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters or less
- Reference issues and pull requests liberally after the first line

Examples:
```
Add Registry Change Monitor utility for Windows
Fix execution policy bypass in PowerShell scripts
Update gobuild to support ARM64 architecture
```

## Project Structure

```
tests_source/      # New tests go here
sample_tests/      # Reference implementations
rules/             # Development guidelines
signing-certs/     # Code signing certificates
utils/             # Build and signing utilities
docs/              # Documentation
build/             # Compiled binaries (git-ignored)
```

## Review Process

All submissions require review before being merged. We use GitHub pull requests for this purpose. Consult [GitHub Help](https://help.github.com/articles/about-pull-requests/) for more information on using pull requests.

### Review Criteria

- Code quality and adherence to project standards
- Security implications and proper safeguards
- Documentation completeness
- Test coverage
- MITRE ATT&CK mapping accuracy

## Community

- Discussions: Use GitHub Discussions for questions and ideas
- Issues: Track bugs and feature requests
- Pull Requests: Submit your contributions

Thank you for contributing to F0RT1KA!