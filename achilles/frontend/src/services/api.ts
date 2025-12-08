import axios from 'axios';
import {
  ApiResponse,
  AppSettings,
  ConnectionTestResult,
  DefenseScoreData,
  TrendDataPoint,
  BreakdownItem,
  OrgBreakdownItem,
  TestExecution,
  OrganizationInfo,
  ErrorTypeBreakdown,
  TestCoverageItem,
  TechniqueDistributionItem,
  HostTestMatrixCell
} from '../types/analytics';

const api = axios.create({
  baseURL: '/api',
  timeout: 30000,
});

// ============================================
// SETTINGS API
// ============================================

export async function getSettings(): Promise<AppSettings> {
  const response = await api.get<ApiResponse<AppSettings>>('/settings');
  if (!response.data.success || !response.data.data) {
    throw new Error(response.data.error || 'Failed to get settings');
  }
  return response.data.data;
}

export async function saveSettings(settings: AppSettings): Promise<void> {
  const response = await api.post<ApiResponse<void>>('/settings', settings);
  if (!response.data.success) {
    throw new Error(response.data.error || 'Failed to save settings');
  }
}

export async function testConnection(): Promise<ConnectionTestResult> {
  const response = await api.post<ApiResponse<ConnectionTestResult>>('/settings/test');
  if (!response.data.success || !response.data.data) {
    throw new Error(response.data.error || 'Failed to test connection');
  }
  return response.data.data;
}

// ============================================
// ANALYTICS API
// ============================================

interface AnalyticsParams {
  org?: string;
  from?: string;
  to?: string;
  interval?: 'hour' | 'day' | 'week';
  limit?: number;
}

export async function getDefenseScore(params?: AnalyticsParams): Promise<DefenseScoreData> {
  const response = await api.get<ApiResponse<DefenseScoreData>>('/analytics/defense-score', { params });
  if (!response.data.success || !response.data.data) {
    throw new Error(response.data.error || 'Failed to get defense score');
  }
  return response.data.data;
}

export async function getDefenseScoreTrend(params?: AnalyticsParams): Promise<TrendDataPoint[]> {
  const response = await api.get<ApiResponse<TrendDataPoint[]>>('/analytics/defense-score/trend', { params });
  if (!response.data.success || !response.data.data) {
    throw new Error(response.data.error || 'Failed to get defense score trend');
  }
  return response.data.data;
}

export async function getDefenseScoreByTest(params?: AnalyticsParams): Promise<BreakdownItem[]> {
  const response = await api.get<ApiResponse<BreakdownItem[]>>('/analytics/defense-score/by-test', { params });
  if (!response.data.success || !response.data.data) {
    throw new Error(response.data.error || 'Failed to get defense score by test');
  }
  return response.data.data;
}

export async function getDefenseScoreByTechnique(params?: AnalyticsParams): Promise<BreakdownItem[]> {
  const response = await api.get<ApiResponse<BreakdownItem[]>>('/analytics/defense-score/by-technique', { params });
  if (!response.data.success || !response.data.data) {
    throw new Error(response.data.error || 'Failed to get defense score by technique');
  }
  return response.data.data;
}

export async function getDefenseScoreByOrg(params?: AnalyticsParams): Promise<OrgBreakdownItem[]> {
  const response = await api.get<ApiResponse<OrgBreakdownItem[]>>('/analytics/defense-score/by-org', { params });
  if (!response.data.success || !response.data.data) {
    throw new Error(response.data.error || 'Failed to get defense score by org');
  }
  return response.data.data;
}

export async function getTestExecutions(params?: AnalyticsParams): Promise<TestExecution[]> {
  const response = await api.get<ApiResponse<TestExecution[]>>('/analytics/executions', { params });
  if (!response.data.success || !response.data.data) {
    throw new Error(response.data.error || 'Failed to get test executions');
  }
  return response.data.data;
}

export async function getOrganizations(): Promise<OrganizationInfo[]> {
  const response = await api.get<ApiResponse<OrganizationInfo[]>>('/analytics/organizations');
  if (!response.data.success || !response.data.data) {
    throw new Error(response.data.error || 'Failed to get organizations');
  }
  return response.data.data;
}

// ============================================
// NEW ANALYTICS API (Dashboard Enhancement)
// ============================================

export async function getUniqueHostnames(params?: AnalyticsParams): Promise<number> {
  const response = await api.get<ApiResponse<number>>('/analytics/unique-hostnames', { params });
  if (!response.data.success || response.data.data === undefined) {
    throw new Error(response.data.error || 'Failed to get unique hostnames');
  }
  return response.data.data;
}

export async function getUniqueTests(params?: AnalyticsParams): Promise<number> {
  const response = await api.get<ApiResponse<number>>('/analytics/unique-tests', { params });
  if (!response.data.success || response.data.data === undefined) {
    throw new Error(response.data.error || 'Failed to get unique tests');
  }
  return response.data.data;
}

export async function getResultsByErrorType(params?: AnalyticsParams): Promise<ErrorTypeBreakdown[]> {
  const response = await api.get<ApiResponse<ErrorTypeBreakdown[]>>('/analytics/results-by-error-type', { params });
  if (!response.data.success || !response.data.data) {
    throw new Error(response.data.error || 'Failed to get results by error type');
  }
  return response.data.data;
}

export async function getTestCoverage(params?: AnalyticsParams): Promise<TestCoverageItem[]> {
  const response = await api.get<ApiResponse<TestCoverageItem[]>>('/analytics/test-coverage', { params });
  if (!response.data.success || !response.data.data) {
    throw new Error(response.data.error || 'Failed to get test coverage');
  }
  return response.data.data;
}

export async function getTechniqueDistribution(params?: AnalyticsParams): Promise<TechniqueDistributionItem[]> {
  const response = await api.get<ApiResponse<TechniqueDistributionItem[]>>('/analytics/technique-distribution', { params });
  if (!response.data.success || !response.data.data) {
    throw new Error(response.data.error || 'Failed to get technique distribution');
  }
  return response.data.data;
}

export async function getHostTestMatrix(params?: AnalyticsParams): Promise<HostTestMatrixCell[]> {
  const response = await api.get<ApiResponse<HostTestMatrixCell[]>>('/analytics/host-test-matrix', { params });
  if (!response.data.success || !response.data.data) {
    throw new Error(response.data.error || 'Failed to get host-test matrix');
  }
  return response.data.data;
}

export async function getAvailableTests(): Promise<string[]> {
  const response = await api.get<ApiResponse<string[]>>('/analytics/available-tests');
  if (!response.data.success || !response.data.data) {
    throw new Error(response.data.error || 'Failed to get available tests');
  }
  return response.data.data;
}

export async function getAvailableTechniques(): Promise<string[]> {
  const response = await api.get<ApiResponse<string[]>>('/analytics/available-techniques');
  if (!response.data.success || !response.data.data) {
    throw new Error(response.data.error || 'Failed to get available techniques');
  }
  return response.data.data;
}
