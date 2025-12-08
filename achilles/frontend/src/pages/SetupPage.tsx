import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Target, Database, ArrowRight, Loader2, Check, AlertCircle } from 'lucide-react';
import { AppSettings, ConnectionTestResult } from '../types/analytics';
import { saveSettings, testConnection } from '../services/api';

export default function SetupPage() {
  const navigate = useNavigate();

  const [connectionType, setConnectionType] = useState<'cloud' | 'direct'>('cloud');
  const [cloudId, setCloudId] = useState('');
  const [apiKey, setApiKey] = useState('');
  const [node, setNode] = useState('');
  const [indexPattern, setIndexPattern] = useState('f0rtika-results-*');

  const [step, setStep] = useState<'form' | 'testing' | 'success'>('form');
  const [testResult, setTestResult] = useState<ConnectionTestResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleConnect() {
    setStep('testing');
    setError(null);

    try {
      // Save settings first
      const settings: AppSettings = {
        elasticsearch: {
          connectionType,
          cloudId: connectionType === 'cloud' ? cloudId : undefined,
          apiKey,
          node: connectionType === 'direct' ? node : undefined,
          indexPattern
        },
        defaults: {
          dateRange: '7d',
          organization: null
        }
      };

      await saveSettings(settings);

      // Test connection
      const result = await testConnection();
      setTestResult(result);

      if (result.connected) {
        setStep('success');
        // Navigate to dashboard after short delay
        setTimeout(() => {
          navigate('/');
        }, 1500);
      } else {
        setError(result.error || 'Connection failed');
        setStep('form');
      }
    } catch (err: any) {
      setError(err.message || 'Failed to save settings');
      setStep('form');
    }
  }

  return (
    <div className="min-h-screen bg-background flex flex-col items-center justify-center p-4">
      <div className="w-full max-w-md">
        {/* Logo */}
        <div className="flex flex-col items-center mb-8">
          <div className="flex items-center justify-center w-20 h-20 rounded-xl bg-primary/10 mb-4">
            <Target className="w-12 h-12 text-primary" />
          </div>
          <h1 className="text-3xl font-bold">ACHILLES</h1>
          <p className="text-muted-foreground">Test Results Visualizer</p>
        </div>

        {/* Setup Card */}
        <div className="bg-secondary/50 border border-border rounded-xl p-6">
          {step === 'success' ? (
            <div className="flex flex-col items-center py-8">
              <div className="w-16 h-16 rounded-full bg-green-500/10 flex items-center justify-center mb-4">
                <Check className="w-8 h-8 text-green-500" />
              </div>
              <h2 className="text-xl font-semibold mb-2">Connected!</h2>
              <p className="text-muted-foreground text-center">
                Elasticsearch v{testResult?.version}
              </p>
              <p className="text-sm text-muted-foreground mt-2">
                Redirecting to dashboard...
              </p>
            </div>
          ) : step === 'testing' ? (
            <div className="flex flex-col items-center py-8">
              <Loader2 className="w-12 h-12 animate-spin text-primary mb-4" />
              <h2 className="text-xl font-semibold">Testing Connection</h2>
              <p className="text-muted-foreground">Please wait...</p>
            </div>
          ) : (
            <>
              <div className="flex items-center gap-2 mb-6">
                <Database className="w-5 h-5 text-primary" />
                <h2 className="text-xl font-semibold">Connect to Elasticsearch</h2>
              </div>

              <div className="space-y-4">
                {/* Connection Type */}
                <div>
                  <label className="block text-sm font-medium mb-2">Connection Type</label>
                  <div className="flex gap-4">
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="radio"
                        checked={connectionType === 'cloud'}
                        onChange={() => setConnectionType('cloud')}
                        className="w-4 h-4 text-primary"
                      />
                      <span>Elastic Cloud</span>
                    </label>
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="radio"
                        checked={connectionType === 'direct'}
                        onChange={() => setConnectionType('direct')}
                        className="w-4 h-4 text-primary"
                      />
                      <span>Direct URL</span>
                    </label>
                  </div>
                </div>

                {/* Cloud ID */}
                {connectionType === 'cloud' && (
                  <div>
                    <label className="block text-sm font-medium mb-1">Cloud ID</label>
                    <input
                      type="text"
                      value={cloudId}
                      onChange={(e) => setCloudId(e.target.value)}
                      placeholder="your-deployment:dXMtY2..."
                      className="w-full px-3 py-2 bg-background border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
                    />
                  </div>
                )}

                {/* Node URL */}
                {connectionType === 'direct' && (
                  <div>
                    <label className="block text-sm font-medium mb-1">Elasticsearch URL</label>
                    <input
                      type="text"
                      value={node}
                      onChange={(e) => setNode(e.target.value)}
                      placeholder="https://localhost:9200"
                      className="w-full px-3 py-2 bg-background border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
                    />
                  </div>
                )}

                {/* API Key */}
                <div>
                  <label className="block text-sm font-medium mb-1">API Key</label>
                  <input
                    type="password"
                    value={apiKey}
                    onChange={(e) => setApiKey(e.target.value)}
                    placeholder="Enter API key"
                    className="w-full px-3 py-2 bg-background border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
                  />
                </div>

                {/* Index Pattern */}
                <div>
                  <label className="block text-sm font-medium mb-1">Index Pattern</label>
                  <input
                    type="text"
                    value={indexPattern}
                    onChange={(e) => setIndexPattern(e.target.value)}
                    placeholder="f0rtika-results-*"
                    className="w-full px-3 py-2 bg-background border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
                  />
                </div>

                {/* Error */}
                {error && (
                  <div className="p-3 rounded-lg bg-red-500/10 text-red-600 dark:text-red-400">
                    <div className="flex items-center gap-2">
                      <AlertCircle className="w-5 h-5 flex-shrink-0" />
                      <span className="text-sm">{error}</span>
                    </div>
                  </div>
                )}

                {/* Connect Button */}
                <button
                  onClick={handleConnect}
                  disabled={!apiKey || (connectionType === 'cloud' ? !cloudId : !node)}
                  className="w-full mt-2 px-4 py-3 rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 font-medium"
                >
                  Connect
                  <ArrowRight className="w-4 h-4" />
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
