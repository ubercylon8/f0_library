import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import analyticsRoutes from './routes/analytics';

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3002;

// Middleware
app.use(cors());
app.use(express.json());

// Health check
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'achilles-backend' });
});

// API routes
app.use('/api', analyticsRoutes);

// Start server
app.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   ACHILLES Backend Server                                 ║
║   Test Results Visualizer API                             ║
║                                                           ║
║   Running on: http://localhost:${PORT}                      ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
  `);
});
