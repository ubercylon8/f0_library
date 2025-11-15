import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { getTestDetails, getFileContent, getAttackFlow } from '../services/api';
import { TestDetails, TestFile, FileContent } from '../types/test';
import TechniqueBadge from './TechniqueBadge';
import FileViewer from './FileViewer';
import { ArrowLeft, Calendar, Layers, Star, Loader2, FileText, Code, Shield, AlertTriangle, Workflow } from 'lucide-react';

export default function TestDetailPage() {
  const { uuid } = useParams<{ uuid: string }>();
  const navigate = useNavigate();
  const [test, setTest] = useState<TestDetails | null>(null);
  const [selectedFile, setSelectedFile] = useState<string | null>(null);
  const [fileContent, setFileContent] = useState<FileContent | null>(null);
  const [attackFlowHtml, setAttackFlowHtml] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [fileLoading, setFileLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeView, setActiveView] = useState<'file' | 'attack-flow'>('file');

  useEffect(() => {
    if (uuid) {
      loadTestDetails(uuid);
    }
  }, [uuid]);

  useEffect(() => {
    if (selectedFile && uuid && activeView === 'file') {
      loadFileContent(uuid, selectedFile);
    }
  }, [selectedFile, uuid, activeView]);

  async function loadTestDetails(testUuid: string) {
    try {
      setLoading(true);
      const data = await getTestDetails(testUuid);
      setTest(data);

      // Auto-select README if available
      if (data.hasReadme) {
        setSelectedFile('README.md');
      } else if (data.files.length > 0) {
        setSelectedFile(data.files[0].name);
      }
    } catch (err) {
      setError('Failed to load test details');
      console.error(err);
    } finally {
      setLoading(false);
    }
  }

  async function loadFileContent(testUuid: string, filename: string) {
    try {
      setFileLoading(true);
      const content = await getFileContent(testUuid, filename);
      setFileContent(content);
    } catch (err) {
      console.error('Failed to load file content:', err);
      setFileContent(null);
    } finally {
      setFileLoading(false);
    }
  }

  async function loadAttackFlow() {
    if (!uuid || !test?.hasAttackFlow) return;

    try {
      setFileLoading(true);
      const html = await getAttackFlow(uuid);
      setAttackFlowHtml(html);
      setActiveView('attack-flow');
    } catch (err) {
      console.error('Failed to load attack flow:', err);
    } finally {
      setFileLoading(false);
    }
  }

  function handleFileSelect(filename: string) {
    setSelectedFile(filename);
    setActiveView('file');
  }

  function handleAttackFlowClick() {
    if (!attackFlowHtml) {
      loadAttackFlow();
    } else {
      setActiveView('attack-flow');
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="flex items-center gap-2 text-muted-foreground">
          <Loader2 className="w-6 h-6 animate-spin" />
          <span>Loading test details...</span>
        </div>
      </div>
    );
  }

  if (error || !test) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-center">
          <p className="text-red-500 mb-4">{error || 'Test not found'}</p>
          <button
            onClick={() => navigate('/')}
            className="px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:opacity-90"
          >
            Back to Tests
          </button>
        </div>
      </div>
    );
  }

  // Categorize files
  const documentationFiles = test.files.filter(f => f.category === 'documentation');
  const sourceFiles = test.files.filter(f => f.category === 'source');
  const configFiles = test.files.filter(f => f.category === 'config');
  const otherFiles = test.files.filter(f => f.category === 'other');

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="border-b border-border bg-background/95 backdrop-blur">
        <div className="container mx-auto px-4 py-4">
          <button
            onClick={() => navigate('/')}
            className="flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground mb-3"
          >
            <ArrowLeft className="w-4 h-4" />
            Back to tests
          </button>

          <div className="flex items-start justify-between gap-4 mb-3">
            <div className="flex-1">
              <h1 className="text-2xl font-bold mb-2">{test.name}</h1>
              <div className="flex items-center gap-4 text-sm text-muted-foreground flex-wrap">
                {test.severity && (
                  <span className="font-medium uppercase text-orange-500">
                    {test.severity}
                  </span>
                )}
                {test.isMultiStage && (
                  <div className="flex items-center gap-1">
                    <Layers className="w-4 h-4" />
                    <span>{test.stages.length} stages</span>
                  </div>
                )}
                {test.createdDate && (
                  <div className="flex items-center gap-1">
                    <Calendar className="w-4 h-4" />
                    <span>{test.createdDate}</span>
                  </div>
                )}
                <span className="font-mono text-xs">{test.uuid}</span>
              </div>
            </div>

            {test.score && (
              <div className="flex items-center gap-2 px-4 py-2 rounded-lg bg-amber-500/10 border border-amber-500/20">
                <Star className="w-5 h-5 text-amber-500 fill-current" />
                <div>
                  <div className="text-2xl font-bold text-amber-500">{test.score.toFixed(1)}</div>
                  <div className="text-xs text-muted-foreground">Test Score</div>
                </div>
              </div>
            )}
          </div>

          {/* Techniques */}
          <div className="flex flex-wrap gap-2 mb-3">
            {test.techniques.map(technique => (
              <TechniqueBadge key={technique} technique={technique} />
            ))}
          </div>

          {/* Description */}
          {test.description && (
            <p className="text-sm text-muted-foreground">{test.description}</p>
          )}
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left Sidebar - File Browser */}
        <div className="w-80 border-r border-border bg-muted/30 overflow-y-auto">
          <div className="p-4 space-y-4">
            {/* Documentation Files */}
            {documentationFiles.length > 0 && (
              <div>
                <h3 className="text-xs font-semibold uppercase text-muted-foreground mb-2 flex items-center gap-2">
                  <FileText className="w-3 h-3" />
                  Documentation
                </h3>
                <div className="space-y-1">
                  {documentationFiles.map(file => (
                    <button
                      key={file.name}
                      onClick={() => handleFileSelect(file.name)}
                      className={`w-full text-left px-3 py-2 rounded-md text-sm transition-colors ${
                        selectedFile === file.name && activeView === 'file'
                          ? 'bg-primary text-primary-foreground'
                          : 'hover:bg-accent'
                      }`}
                    >
                      {file.name === 'SAFETY.md' && <AlertTriangle className="w-3 h-3 inline mr-2 text-orange-500" />}
                      {file.name}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* Attack Flow */}
            {test.hasAttackFlow && (
              <div>
                <h3 className="text-xs font-semibold uppercase text-muted-foreground mb-2 flex items-center gap-2">
                  <Workflow className="w-3 h-3" />
                  Visualization
                </h3>
                <button
                  onClick={handleAttackFlowClick}
                  className={`w-full text-left px-3 py-2 rounded-md text-sm transition-colors ${
                    activeView === 'attack-flow'
                      ? 'bg-primary text-primary-foreground'
                      : 'hover:bg-accent'
                  }`}
                >
                  Attack Flow Diagram
                </button>
              </div>
            )}

            {/* Source Files */}
            {sourceFiles.length > 0 && (
              <div>
                <h3 className="text-xs font-semibold uppercase text-muted-foreground mb-2 flex items-center gap-2">
                  <Code className="w-3 h-3" />
                  Source Code
                </h3>
                <div className="space-y-1">
                  {sourceFiles.map(file => (
                    <button
                      key={file.name}
                      onClick={() => handleFileSelect(file.name)}
                      className={`w-full text-left px-3 py-2 rounded-md text-sm font-mono transition-colors ${
                        selectedFile === file.name && activeView === 'file'
                          ? 'bg-primary text-primary-foreground'
                          : 'hover:bg-accent'
                      }`}
                    >
                      {file.name}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* Config Files */}
            {configFiles.length > 0 && (
              <div>
                <h3 className="text-xs font-semibold uppercase text-muted-foreground mb-2 flex items-center gap-2">
                  <Shield className="w-3 h-3" />
                  Configuration
                </h3>
                <div className="space-y-1">
                  {configFiles.map(file => (
                    <button
                      key={file.name}
                      onClick={() => handleFileSelect(file.name)}
                      className={`w-full text-left px-3 py-2 rounded-md text-sm font-mono transition-colors ${
                        selectedFile === file.name && activeView === 'file'
                          ? 'bg-primary text-primary-foreground'
                          : 'hover:bg-accent'
                      }`}
                    >
                      {file.name}
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Right Panel - Content Viewer */}
        <div className="flex-1 overflow-hidden">
          {fileLoading ? (
            <div className="flex items-center justify-center h-full">
              <div className="flex items-center gap-2 text-muted-foreground">
                <Loader2 className="w-6 h-6 animate-spin" />
                <span>Loading...</span>
              </div>
            </div>
          ) : activeView === 'attack-flow' && attackFlowHtml ? (
            <iframe
              srcDoc={attackFlowHtml}
              className="w-full h-full border-0"
              title="Attack Flow Diagram"
              sandbox="allow-scripts allow-same-origin"
            />
          ) : fileContent ? (
            <FileViewer file={fileContent} />
          ) : (
            <div className="flex items-center justify-center h-full text-muted-foreground">
              Select a file to view its content
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
