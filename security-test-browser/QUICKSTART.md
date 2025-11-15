# F0RT1KA Security Test Browser - Quick Start Guide

## What You've Built

A professional full-stack web application for browsing and exploring F0RT1KA security tests with:

- Modern React + TypeScript frontend
- Node.js + Express REST API backend
- Real-time test indexing from your `tests_source/` directory
- Advanced search and filtering capabilities
- Syntax-highlighted code viewing
- Markdown documentation rendering
- Interactive attack flow diagrams
- Dark/light theme support

## Getting Started

### Option 1: Manual Start (Recommended First Time)

**Terminal 1 - Start Backend:**
```bash
cd security-test-browser/backend
npm run dev
```

Wait for: `Server running on port 3001` and `Indexed 19 security tests`

**Terminal 2 - Start Frontend:**
```bash
cd security-test-browser/frontend
npm run dev
```

Wait for: `Local: http://localhost:5173/`

**Open Browser:**
Navigate to: http://localhost:5173

### Option 2: Automated Start (After First Time)

```bash
cd security-test-browser
./start.sh
```

This will open two terminals automatically.

## What You Can Do

### Homepage Features

1. **Browse All Tests**: See all 19 security tests in card format
2. **Search**: Type in the search bar to find tests by:
   - Test name
   - UUID
   - MITRE ATT&CK technique (e.g., "T1105")
   - Description keywords
3. **Filter**: Use dropdowns to filter by:
   - Category (e.g., "Defense Evasion", "Ransomware")
   - Severity (Critical, High, Medium, Low)
4. **View Metadata**: Each card shows:
   - Test name and score
   - Severity level
   - MITRE techniques
   - Multi-stage indicator
   - Creation date
   - Brief description

### Test Detail Page

Click any test card to view full details:

**Left Sidebar - File Browser:**
- **Documentation**: README, Info Card, SAFETY docs
- **Attack Flow**: Interactive HTML diagram (if available)
- **Source Code**: All .go and .ps1 files
- **Configuration**: Build scripts, go.mod files

**Right Panel - Content Viewer:**
- **Markdown files**: Beautifully rendered with proper formatting
- **Code files**: Syntax highlighting for Go and PowerShell
- **Attack flows**: Interactive iframe visualization
- **Copy button**: Copy code to clipboard

**Top Header:**
- Test name and UUID
- Severity badge
- Stage count (for multi-stage tests)
- Test score rating
- All MITRE ATT&CK techniques

### Theme Switching

Click the sun/moon icon in the header to toggle between light and dark modes.

## Example Workflows

### 1. Find All Ransomware Tests
1. Open http://localhost:5173
2. Click "Category" dropdown
3. Select a category containing "Ransomware"
4. Browse filtered results

### 2. Search for Specific Technique
1. Type "T1562" in search bar
2. See all tests using defense evasion techniques
3. Click a test to view details

### 3. Read Test Documentation
1. Click any test card
2. README is automatically selected
3. Read the full documentation with rendered markdown
4. Click "Info Card" to see detailed scoring and detection opportunities

### 4. Inspect Source Code
1. Open a test detail page
2. Click on a .go file in the sidebar
3. View syntax-highlighted code
4. Use copy button to copy code snippets

### 5. View Attack Flow
1. Open a test with attack flow diagram (e.g., Tailscale test)
2. Click "Attack Flow Diagram" in sidebar
3. Interact with the visualization

## Backend API Endpoints

The backend exposes these REST endpoints:

- `GET /api/tests` - List all tests
  - Query params: `?search=keyword`, `?technique=T1234`, `?category=...`, `?severity=...`
- `GET /api/tests/:uuid` - Get test details
- `GET /api/tests/:uuid/files` - List test files
- `GET /api/tests/:uuid/file/:filename` - Get file content
- `GET /api/tests/:uuid/attack-flow` - Get attack flow HTML
- `POST /api/tests/refresh` - Refresh test index
- `GET /health` - API health check

## Current Status

The backend has successfully indexed **19 security tests** from your `tests_source/` directory, including:

- Multi-stage tests (Tailscale, Ransomware Killchain)
- Defense evasion tests (EDR-Freeze, MDE Authentication Bypass)
- Credential access tests (LSASS dumping, NativeDump)
- Ransomware simulations (SafePay, Gunra)
- Process injection tests
- And more...

## Architecture

```
Backend (Port 3001)
├─ Express REST API
├─ Test indexer (scans tests_source/)
├─ Metadata extractor (parses Go files, README, info cards)
└─ File service (serves file contents)

Frontend (Port 5173)
├─ React + TypeScript
├─ React Router (navigation)
├─ Tailwind CSS (styling)
├─ Syntax highlighting (code viewer)
└─ Markdown rendering (documentation)
```

## Stopping the Servers

Press `Ctrl+C` in each terminal window to stop the servers.

## Next Steps

1. **Explore Tests**: Browse through all 19 tests
2. **Search and Filter**: Try different search queries and filters
3. **Read Documentation**: View README and info cards for each test
4. **Inspect Code**: Look at the source code with syntax highlighting
5. **View Diagrams**: Check out attack flow visualizations
6. **Switch Themes**: Toggle between dark and light modes

## Troubleshooting

**Backend won't start:**
- Check `tests_source/` path in `backend/.env`
- Ensure port 3001 is free

**Frontend won't start:**
- Make sure backend is running first
- Ensure port 5173 is free

**Tests not showing:**
- Check backend terminal for "Indexed X security tests"
- Verify `tests_source/` directory exists

**Can't view files:**
- Check browser console (F12) for errors
- Verify backend can read the files

## Performance

- Fast test browsing (all tests loaded at startup)
- Instant search and filtering (client-side)
- On-demand file loading (only when selected)
- Responsive UI with smooth transitions

Enjoy exploring your F0RT1KA security tests!
