// Elasticsearch connection settings
export interface ElasticsearchSettings {
  connectionType: 'cloud' | 'direct';
  cloudId?: string;
  node?: string;
  apiKey?: string;
  username?: string;
  password?: string;
  indexPattern: string;
}

// Application settings
export interface AppSettings {
  elasticsearch: ElasticsearchSettings;
  defaults: {
    dateRange: string;
    organization: string | null;
  };
  configured?: boolean;
}

// Defense Score response
export interface DefenseScoreData {
  overall: number;
  delta: number | null;
  total: number;
  protected: number;
}

// Trend data point
export interface TrendDataPoint {
  timestamp: string;
  score: number;
  total: number;
  protected: number;
}

// Breakdown item (for by-test, by-technique)
export interface BreakdownItem {
  name: string;
  score: number;
  count: number;
  protected: number;
}

// Organization breakdown
export interface OrgBreakdownItem {
  org: string;
  orgName: string;
  score: number;
  count: number;
  protected: number;
}

// Test execution
export interface TestExecution {
  test_uuid: string;
  test_name: string;
  hostname: string;
  is_protected: boolean;
  org: string;
  timestamp: string;
  error_code?: number;
  error_name?: string;
}

// Organization info
export interface OrganizationInfo {
  uuid: string;
  shortName: string;
  fullName: string;
}

// API response wrapper
export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
}

// Connection test result
export interface ConnectionTestResult {
  connected: boolean;
  version?: string;
  error?: string;
}

// Date range option
export interface DateRangeOption {
  label: string;
  value: string;
  from: string;
}

// Error type breakdown (for pie chart)
export interface ErrorTypeBreakdown {
  name: string;
  count: number;
}

// Test coverage item (protected vs unprotected counts)
export interface TestCoverageItem {
  name: string;
  protected: number;
  unprotected: number;
}

// Technique distribution item (protected vs unprotected counts)
export interface TechniqueDistributionItem {
  technique: string;
  protected: number;
  unprotected: number;
}

// Host-test matrix cell (for heatmap)
export interface HostTestMatrixCell {
  hostname: string;
  testName: string;
  count: number;
}
