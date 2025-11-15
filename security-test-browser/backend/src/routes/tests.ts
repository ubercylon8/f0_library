// API routes for security tests

import { Router, Request, Response } from 'express';
import { TestIndexer } from '../services/testIndexer';
import { FileService } from '../services/fileService';
import * as path from 'path';

const router = Router();
let testIndexer: TestIndexer;

/**
 * Initialize the test indexer
 */
export function initializeTestRoutes(testsSourcePath: string): Router {
  testIndexer = new TestIndexer(testsSourcePath);

  // Initial scan on startup
  console.log('Scanning security tests...');
  testIndexer.scanAllTests();
  console.log('Test indexing complete!');

  return router;
}

/**
 * GET /api/tests
 * Get all tests with optional filtering
 */
router.get('/', (req: Request, res: Response) => {
  try {
    const { search, technique, category, severity } = req.query;

    let tests = testIndexer.getAllTests();

    // Apply filters
    if (search && typeof search === 'string') {
      tests = testIndexer.searchTests(search);
    } else if (technique && typeof technique === 'string') {
      tests = testIndexer.filterByTechnique(technique);
    } else if (category && typeof category === 'string') {
      tests = testIndexer.filterByCategory(category);
    } else if (severity && typeof severity === 'string') {
      tests = testIndexer.filterBySeverity(severity);
    }

    // Return simplified test list (without full file details)
    const testList = tests.map(test => ({
      uuid: test.uuid,
      name: test.name,
      category: test.category,
      severity: test.severity,
      techniques: test.techniques,
      tactics: test.tactics,
      createdDate: test.createdDate,
      score: test.score,
      isMultiStage: test.isMultiStage,
      stageCount: test.stages.length,
      description: test.description,
      hasAttackFlow: test.hasAttackFlow,
      hasReadme: test.hasReadme,
      hasInfoCard: test.hasInfoCard,
      hasSafetyDoc: test.hasSafetyDoc,
    }));

    res.json({
      success: true,
      count: testList.length,
      tests: testList,
    });
  } catch (error) {
    console.error('Error fetching tests:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch tests',
    });
  }
});

/**
 * GET /api/tests/:uuid
 * Get detailed information about a specific test
 */
router.get('/:uuid', (req: Request, res: Response) => {
  try {
    const { uuid } = req.params;
    const test = testIndexer.getTest(uuid);

    if (!test) {
      return res.status(404).json({
        success: false,
        error: 'Test not found',
      });
    }

    res.json({
      success: true,
      test,
    });
  } catch (error) {
    console.error('Error fetching test:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch test details',
    });
  }
});

/**
 * GET /api/tests/:uuid/files
 * Get list of files in a test directory
 */
router.get('/:uuid/files', (req: Request, res: Response) => {
  try {
    const { uuid } = req.params;
    const test = testIndexer.getTest(uuid);

    if (!test) {
      return res.status(404).json({
        success: false,
        error: 'Test not found',
      });
    }

    res.json({
      success: true,
      files: test.files,
    });
  } catch (error) {
    console.error('Error fetching files:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch test files',
    });
  }
});

/**
 * GET /api/tests/:uuid/file/:filename
 * Get content of a specific file
 */
router.get('/:uuid/file/:filename', (req: Request, res: Response) => {
  try {
    const { uuid, filename } = req.params;
    const test = testIndexer.getTest(uuid);

    if (!test) {
      return res.status(404).json({
        success: false,
        error: 'Test not found',
      });
    }

    // Find the file in the test's file list
    const file = test.files.find(f => f.name === filename);

    if (!file) {
      return res.status(404).json({
        success: false,
        error: 'File not found',
      });
    }

    // Read file content
    const fileContent = FileService.readFileContent(file.path);

    res.json({
      success: true,
      file: {
        name: file.name,
        type: fileContent.type,
        content: fileContent.content,
        size: file.size,
      },
    });
  } catch (error) {
    console.error('Error reading file:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to read file content',
    });
  }
});

/**
 * GET /api/tests/:uuid/attack-flow
 * Get attack flow diagram HTML
 */
router.get('/:uuid/attack-flow', (req: Request, res: Response) => {
  try {
    const { uuid } = req.params;
    const test = testIndexer.getTest(uuid);

    if (!test) {
      return res.status(404).json({
        success: false,
        error: 'Test not found',
      });
    }

    if (!test.hasAttackFlow || !test.attackFlowPath) {
      return res.status(404).json({
        success: false,
        error: 'Attack flow diagram not available for this test',
      });
    }

    // Read HTML file
    const fileContent = FileService.readFileContent(test.attackFlowPath);

    res.json({
      success: true,
      html: fileContent.content,
    });
  } catch (error) {
    console.error('Error reading attack flow:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to read attack flow diagram',
    });
  }
});

/**
 * POST /api/refresh
 * Refresh test index (rescan tests_source directory)
 */
router.post('/refresh', (req: Request, res: Response) => {
  try {
    console.log('Refreshing test index...');
    const tests = testIndexer.refresh();

    res.json({
      success: true,
      message: 'Test index refreshed successfully',
      count: tests.length,
    });
  } catch (error) {
    console.error('Error refreshing test index:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to refresh test index',
    });
  }
});

export default router;
