import { Router, Request, Response } from 'express';
import {
  loadSettings,
  saveSettings,
  getMaskedSettings,
  isConfigured
} from '../services/settings';
import {
  testConnection,
  resetClient,
  getDefenseScore,
  getDefenseScoreTrend,
  getDefenseScoreByTest,
  getDefenseScoreByTechnique,
  getDefenseScoreByOrg,
  getTestExecutions,
  getOrganizations,
  getUniqueHostnames,
  getUniqueTests,
  getResultsByErrorType,
  getTestCoverage,
  getTechniqueDistribution,
  getHostTestMatrix,
  getAvailableTests,
  getAvailableTechniques
} from '../services/elasticsearch';
import { AppSettings, AnalyticsQueryParams } from '../types/analytics';

const router = Router();

// Helper to parse query params
function parseQueryParams(query: any): AnalyticsQueryParams {
  return {
    org: query.org as string | undefined,
    from: query.from as string | undefined,
    to: query.to as string | undefined,
    interval: query.interval as 'hour' | 'day' | 'week' | undefined,
    limit: query.limit ? parseInt(query.limit as string, 10) : undefined
  };
}

// ============================================
// SETTINGS ENDPOINTS
// ============================================

// GET /api/settings - Get current settings (masked)
router.get('/settings', (_req: Request, res: Response) => {
  try {
    const settings = getMaskedSettings();
    const configured = isConfigured();
    res.json({ success: true, data: { ...settings, configured } });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// POST /api/settings - Save settings
router.post('/settings', (req: Request, res: Response) => {
  try {
    const settings = req.body as AppSettings;
    saveSettings(settings);
    resetClient(); // Force reconnection with new settings
    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// POST /api/settings/test - Test ES connection
router.post('/settings/test', async (_req: Request, res: Response) => {
  try {
    resetClient(); // Ensure fresh connection
    const result = await testConnection();
    res.json({ success: true, data: result });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================
// ANALYTICS ENDPOINTS
// ============================================

// GET /api/analytics/defense-score - Overall defense score
router.get('/analytics/defense-score', async (req: Request, res: Response) => {
  try {
    if (!isConfigured()) {
      return res.status(400).json({ success: false, error: 'Elasticsearch not configured' });
    }

    const params = parseQueryParams(req.query);
    const data = await getDefenseScore(params);
    res.json({ success: true, data });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET /api/analytics/defense-score/trend - Defense score over time
router.get('/analytics/defense-score/trend', async (req: Request, res: Response) => {
  try {
    if (!isConfigured()) {
      return res.status(400).json({ success: false, error: 'Elasticsearch not configured' });
    }

    const params = parseQueryParams(req.query);
    const data = await getDefenseScoreTrend(params);
    res.json({ success: true, data });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET /api/analytics/defense-score/by-test - Defense score by test
router.get('/analytics/defense-score/by-test', async (req: Request, res: Response) => {
  try {
    if (!isConfigured()) {
      return res.status(400).json({ success: false, error: 'Elasticsearch not configured' });
    }

    const params = parseQueryParams(req.query);
    const data = await getDefenseScoreByTest(params);
    res.json({ success: true, data });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET /api/analytics/defense-score/by-technique - Defense score by technique
router.get('/analytics/defense-score/by-technique', async (req: Request, res: Response) => {
  try {
    if (!isConfigured()) {
      return res.status(400).json({ success: false, error: 'Elasticsearch not configured' });
    }

    const params = parseQueryParams(req.query);
    const data = await getDefenseScoreByTechnique(params);
    res.json({ success: true, data });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET /api/analytics/defense-score/by-org - Defense score by organization
router.get('/analytics/defense-score/by-org', async (req: Request, res: Response) => {
  try {
    if (!isConfigured()) {
      return res.status(400).json({ success: false, error: 'Elasticsearch not configured' });
    }

    const params = parseQueryParams(req.query);
    const data = await getDefenseScoreByOrg(params);
    res.json({ success: true, data });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET /api/analytics/executions - Recent test executions
router.get('/analytics/executions', async (req: Request, res: Response) => {
  try {
    if (!isConfigured()) {
      return res.status(400).json({ success: false, error: 'Elasticsearch not configured' });
    }

    const params = parseQueryParams(req.query);
    const data = await getTestExecutions(params);
    res.json({ success: true, data });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET /api/analytics/organizations - List of organizations
router.get('/analytics/organizations', async (_req: Request, res: Response) => {
  try {
    if (!isConfigured()) {
      return res.status(400).json({ success: false, error: 'Elasticsearch not configured' });
    }

    const data = await getOrganizations();
    res.json({ success: true, data });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET /api/analytics/unique-hostnames - Unique hostname count
router.get('/analytics/unique-hostnames', async (req: Request, res: Response) => {
  try {
    if (!isConfigured()) {
      return res.status(400).json({ success: false, error: 'Elasticsearch not configured' });
    }

    const params = parseQueryParams(req.query);
    const data = await getUniqueHostnames(params);
    res.json({ success: true, data });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET /api/analytics/unique-tests - Unique test count
router.get('/analytics/unique-tests', async (req: Request, res: Response) => {
  try {
    if (!isConfigured()) {
      return res.status(400).json({ success: false, error: 'Elasticsearch not configured' });
    }

    const params = parseQueryParams(req.query);
    const data = await getUniqueTests(params);
    res.json({ success: true, data });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET /api/analytics/results-by-error-type - Results by error type (for pie chart)
router.get('/analytics/results-by-error-type', async (req: Request, res: Response) => {
  try {
    if (!isConfigured()) {
      return res.status(400).json({ success: false, error: 'Elasticsearch not configured' });
    }

    const params = parseQueryParams(req.query);
    const data = await getResultsByErrorType(params);
    res.json({ success: true, data });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET /api/analytics/test-coverage - Test coverage (protected vs unprotected counts)
router.get('/analytics/test-coverage', async (req: Request, res: Response) => {
  try {
    if (!isConfigured()) {
      return res.status(400).json({ success: false, error: 'Elasticsearch not configured' });
    }

    const params = parseQueryParams(req.query);
    const data = await getTestCoverage(params);
    res.json({ success: true, data });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET /api/analytics/technique-distribution - Technique distribution (protected vs unprotected)
router.get('/analytics/technique-distribution', async (req: Request, res: Response) => {
  try {
    if (!isConfigured()) {
      return res.status(400).json({ success: false, error: 'Elasticsearch not configured' });
    }

    const params = parseQueryParams(req.query);
    const data = await getTechniqueDistribution(params);
    res.json({ success: true, data });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET /api/analytics/host-test-matrix - Host-test matrix for heatmap
router.get('/analytics/host-test-matrix', async (req: Request, res: Response) => {
  try {
    if (!isConfigured()) {
      return res.status(400).json({ success: false, error: 'Elasticsearch not configured' });
    }

    const params = parseQueryParams(req.query);
    const data = await getHostTestMatrix(params);
    res.json({ success: true, data });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET /api/analytics/available-tests - List of available tests for filter
router.get('/analytics/available-tests', async (_req: Request, res: Response) => {
  try {
    if (!isConfigured()) {
      return res.status(400).json({ success: false, error: 'Elasticsearch not configured' });
    }

    const data = await getAvailableTests();
    res.json({ success: true, data });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET /api/analytics/available-techniques - List of available techniques for filter
router.get('/analytics/available-techniques', async (_req: Request, res: Response) => {
  try {
    if (!isConfigured()) {
      return res.status(400).json({ success: false, error: 'Elasticsearch not configured' });
    }

    const data = await getAvailableTechniques();
    res.json({ success: true, data });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

export default router;
