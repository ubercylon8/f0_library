// Frontend type definitions for F0RT1KA security tests

export interface TestMetadata {
  uuid: string;
  name: string;
  category?: string;
  severity?: string;
  techniques: string[];
  tactics?: string[];
  createdDate?: string;
  version?: string;
  score?: number;
  scoreBreakdown?: ScoreBreakdown;
  isMultiStage: boolean;
  stageCount?: number;
  description?: string;
  tags?: string[];
  hasAttackFlow: boolean;
  hasReadme: boolean;
  hasInfoCard: boolean;
  hasSafetyDoc: boolean;
}

export interface ScoreBreakdown {
  realWorldAccuracy?: number;
  technicalSophistication?: number;
  safetyMechanisms?: number;
  detectionOpportunities?: number;
  loggingObservability?: number;
}

export interface StageInfo {
  stageId: number;
  technique: string;
  name: string;
  fileName: string;
}

export interface TestFile {
  name: string;
  path: string;
  type: 'go' | 'powershell' | 'markdown' | 'html' | 'bash' | 'other';
  size: number;
  category: 'source' | 'documentation' | 'diagram' | 'config';
}

export interface TestDetails extends TestMetadata {
  files: TestFile[];
  stages: StageInfo[];
  attackFlowPath?: string;
}

export interface FileContent {
  name: string;
  type: string;
  content: string;
  size: number;
}
