// Main Express server for F0RT1KA Security Test Browser

import express, { Request, Response } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import * as path from 'path';
import testRoutes, { initializeTestRoutes } from './routes/tests';

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;
const TESTS_SOURCE_PATH = process.env.TESTS_SOURCE_PATH || '../../tests_source';

// Middleware
app.use(cors());
app.use(express.json());

// Request logging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// Health check endpoint
app.get('/health', (req: Request, res: Response) => {
  res.json({
    status: 'ok',
    service: 'F0RT1KA Test Browser API',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
  });
});

// Initialize and mount test routes
const testsRouter = initializeTestRoutes(TESTS_SOURCE_PATH);
app.use('/api/tests', testsRouter);

// 404 handler
app.use((req: Request, res: Response) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found',
  });
});

// Error handler
app.use((err: Error, req: Request, res: Response, next: any) => {
  console.error('Server error:', err);
  res.status(500).json({
    success: false,
    error: 'Internal server error',
  });
});

// Start server
app.listen(PORT, () => {
  console.log('='.repeat(60));
  console.log('F0RT1KA SECURITY TEST BROWSER - Backend API');
  console.log('='.repeat(60));
  console.log(`Server running on port ${PORT}`);
  console.log(`Tests source path: ${path.resolve(TESTS_SOURCE_PATH)}`);
  console.log(`API endpoints:`);
  console.log(`  - GET  /health                           - Health check`);
  console.log(`  - GET  /api/tests                        - List all tests`);
  console.log(`  - GET  /api/tests/:uuid                  - Get test details`);
  console.log(`  - GET  /api/tests/:uuid/files            - Get test files`);
  console.log(`  - GET  /api/tests/:uuid/file/:filename   - Get file content`);
  console.log(`  - GET  /api/tests/:uuid/attack-flow      - Get attack flow`);
  console.log(`  - POST /api/tests/refresh                - Refresh test index`);
  console.log('='.repeat(60));
});

export default app;
