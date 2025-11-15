# F0RT1KA Security Test Browser

A professional web application for browsing and exploring F0RT1KA security tests. Built with React + TypeScript (frontend) and Node.js + Express (backend).

## Features

- **Test Browser**: Browse all security tests with rich metadata
- **Advanced Search**: Search by name, UUID, technique, or description
- **Filters**: Filter by category, severity, and MITRE ATT&CK techniques
- **Test Details**: View comprehensive test information including:
  - MITRE ATT&CK technique mapping
  - Test scoring and breakdowns
  - Multi-stage architecture visualization
  - Creation dates and metadata
- **File Viewer**: Browse and view all test files:
  - README and documentation (rendered markdown)
  - Source code with syntax highlighting (Go, PowerShell)
  - Configuration files
  - Safety documentation
- **Attack Flow Diagrams**: Interactive HTML attack flow visualizations
- **Dark/Light Mode**: Theme switching for comfortable viewing
- **Responsive Design**: Works on desktop and tablet devices

## Architecture

```
security-test-browser/
├── backend/                 # Node.js + Express API
│   ├── src/
│   │   ├── routes/         # API endpoints
│   │   ├── services/       # Business logic
│   │   │   ├── testIndexer.ts      # Test scanning & indexing
│   │   │   ├── metadataExtractor.ts # Parse test metadata
│   │   │   └── fileService.ts      # File reading
│   │   └── types/          # TypeScript types
│   └── package.json
├── frontend/               # React + TypeScript + Vite
│   ├── src/
│   │   ├── components/    # React components
│   │   ├── services/      # API client
│   │   ├── hooks/         # React hooks (theme)
│   │   └── types/         # TypeScript types
│   └── package.json
└── README.md
```

## Prerequisites

- Node.js 18+ and npm
- F0RT1KA test repository (tests_source/ directory)

## Installation

### 1. Install Backend Dependencies

```bash
cd backend
npm install
```

### 2. Install Frontend Dependencies

```bash
cd frontend
npm install
```

## Running the Application

You need to run both the backend and frontend servers:

### Terminal 1: Start Backend Server

```bash
cd backend
npm run dev
```

The backend API will start on **http://localhost:3001**

### Terminal 2: Start Frontend Server

```bash
cd frontend
npm run dev
```

The frontend will start on **http://localhost:5173**

### Access the Application

Open your browser and navigate to: **http://localhost:5173**

## API Endpoints

The backend provides the following REST API endpoints:

- `GET /health` - Health check
- `GET /api/tests` - List all tests (supports search, filters)
- `GET /api/tests/:uuid` - Get test details
- `GET /api/tests/:uuid/files` - Get test files list
- `GET /api/tests/:uuid/file/:filename` - Get file content
- `GET /api/tests/:uuid/attack-flow` - Get attack flow diagram
- `POST /api/tests/refresh` - Refresh test index

### Query Parameters

**GET /api/tests** supports:
- `?search=keyword` - Search by name, UUID, technique
- `?technique=T1234` - Filter by technique
- `?category=defense_evasion` - Filter by category
- `?severity=high` - Filter by severity

## Configuration

Backend configuration is in `backend/.env`:

```env
PORT=3001
TESTS_SOURCE_PATH=../../tests_source
NODE_ENV=development
```

## How It Works

### Backend

1. **Test Indexing**: On startup, the backend scans `tests_source/` directory
2. **Metadata Extraction**: Parses Go files, README, and info cards to extract:
   - Test name, UUID, techniques
   - Scores and breakdowns
   - Stage information (for multi-stage tests)
   - Creation dates and descriptions
3. **File Categorization**: Organizes files into:
   - Documentation (README, info cards, SAFETY docs)
   - Source code (.go, .ps1 files)
   - Configuration (go.mod, build scripts)
   - Diagrams (attack flow HTML)
4. **API Service**: Serves test data and file contents via REST API

### Frontend

1. **Test List Page**: Displays all tests with search and filters
2. **Test Detail Page**: Two-pane layout:
   - Left sidebar: File browser with categorized files
   - Right panel: Content viewer (code, markdown, attack flow)
3. **Content Viewers**:
   - **Markdown Viewer**: Renders README and documentation
   - **Code Viewer**: Syntax highlighting for Go and PowerShell
   - **Attack Flow**: Iframe for interactive HTML diagrams
4. **Theme Support**: Dark/light mode with system preference detection

## Technology Stack

### Backend
- **Node.js** + **TypeScript** - Runtime and type safety
- **Express** - Web framework
- **File System APIs** - Test scanning and file reading

### Frontend
- **React 18** - UI framework
- **TypeScript** - Type safety
- **Vite** - Build tool and dev server
- **Tailwind CSS** - Styling
- **React Router** - Client-side routing
- **Axios** - HTTP client
- **react-markdown** - Markdown rendering
- **react-syntax-highlighter** - Code highlighting
- **Lucide React** - Icon library

## Development

### Backend Development

```bash
cd backend
npm run dev  # Runs with nodemon (auto-reload)
```

### Frontend Development

```bash
cd frontend
npm run dev  # Vite dev server with HMR
```

### Build for Production

```bash
# Backend
cd backend
npm run build
npm start

# Frontend
cd frontend
npm run build
npm run preview
```

## Features Not Included (By Design)

This browser is for **static test exploration only**. The following features are intentionally NOT included:

- Test execution
- Execution results viewing
- Historical test data
- Dashboards and analytics
- Real-time metrics

These features are planned for a separate analytics/execution platform.

## Browser Capabilities

### What You Can Do

- Browse all available security tests
- View test metadata, techniques, and scoring
- Read README and documentation
- Inspect source code with syntax highlighting
- View attack flow diagrams
- Search and filter tests
- Switch between dark/light themes

### What You Cannot Do

- Execute tests
- View test results or logs
- Generate reports
- Modify tests
- Deploy tests to endpoints

## Troubleshooting

### Backend won't start
- Check that `tests_source/` path is correct in `.env`
- Ensure port 3001 is available
- Verify Node.js version (18+)

### Frontend won't start
- Ensure backend is running first
- Check port 5173 is available
- Clear node_modules and reinstall

### Tests not showing
- Verify `tests_source/` directory exists and contains test directories
- Check backend logs for scanning errors
- Try the `/api/tests/refresh` endpoint to rescan

### File content not loading
- Check browser console for errors
- Verify file exists in test directory
- Check backend can read the file

## Future Enhancements

Potential improvements for future versions:

- Export test documentation as PDF
- Copy code snippets to clipboard (✓ implemented)
- Enhanced MITRE ATT&CK technique tooltips
- Test comparison view
- Technique coverage matrix
- Stage flow visualization for multi-stage tests
- Full-text search across all file contents

## License

Part of the F0RT1KA security testing framework.

## Support

For issues or questions, refer to the main F0RT1KA repository documentation.
