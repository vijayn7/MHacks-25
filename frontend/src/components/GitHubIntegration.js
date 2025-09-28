import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  Github, 
  Settings, 
  CheckCircle, 
  AlertCircle, 
  Loader2,
  ExternalLink,
  Code,
  Shield,
  Zap,
  LogOut,
  User,
  Repository
} from 'lucide-react';

const GitHubIntegration = ({ onTestGenerated, onError, onRepositorySelected }) => {
  const [isConnected, setIsConnected] = useState(false);
  const [isConnecting, setIsConnecting] = useState(false);
  const [repositories, setRepositories] = useState([]);
  const [selectedRepo, setSelectedRepo] = useState('');
  const [testRequest, setTestRequest] = useState('');
  const [isGenerating, setIsGenerating] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState('disconnected');
  const [userInfo, setUserInfo] = useState(null);

  // Check GitHub connection status
  useEffect(() => {
    checkGitHubConnection();
  }, []);

  const checkGitHubConnection = async () => {
    try {
      // Check if we have a state parameter from OAuth callback
      const urlParams = new URLSearchParams(window.location.search);
      const githubConnected = urlParams.get('github_connected');
      const state = urlParams.get('state');
      
      if (githubConnected === 'true' && state) {
        // We just connected, check status
        const response = await fetch(`/api/github/status?state=${state}`);
        if (response.ok) {
          const data = await response.json();
          setIsConnected(data.connected);
          setRepositories(data.repositories || []);
          setUserInfo(data.user || null);
          setConnectionStatus(data.connected ? 'connected' : 'disconnected');
          
          // Store state for future API calls
          localStorage.setItem('github_state', state);
        }
      } else {
        // Check existing connection
        const savedState = localStorage.getItem('github_state');
        if (savedState) {
          const response = await fetch(`/api/github/status?state=${savedState}`);
          if (response.ok) {
            const data = await response.json();
            setIsConnected(data.connected);
            setRepositories(data.repositories || []);
            setUserInfo(data.user || null);
            setConnectionStatus(data.connected ? 'connected' : 'disconnected');
          }
        }
      }
    } catch (error) {
      console.error('Failed to check GitHub connection:', error);
      setConnectionStatus('error');
    }
  };

  const connectToGitHub = async () => {
    setIsConnecting(true);
    try {
      // Get OAuth URL from backend
      const response = await fetch('/api/github/connect');
      if (response.ok) {
        const data = await response.json();
        // Redirect to GitHub OAuth
        window.location.href = data.auth_url;
      } else {
        throw new Error('Failed to get OAuth URL');
      }
    } catch (error) {
      console.error('Failed to connect to GitHub:', error);
      onError && onError('Failed to connect to GitHub');
    } finally {
      setIsConnecting(false);
    }
  };

  const generateTestsFromRepo = async () => {
    if (!selectedRepo || !testRequest.trim()) {
      onError && onError('Please select a repository and enter a test request');
      return;
    }

    setIsGenerating(true);
    try {
      const [owner, repo] = selectedRepo.split('/');
      const state = localStorage.getItem('github_state');
      
      const response = await fetch('/api/github/analyze-repo', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          repo_owner: owner,
          repo_name: repo,
          state: state,
          test_request: testRequest
        })
      });

      if (response.ok) {
        const data = await response.json();
        onTestGenerated && onTestGenerated(data);
      } else {
        const error = await response.json();
        onError && onError(error.detail || 'Failed to generate tests');
      }
    } catch (error) {
      console.error('Failed to generate tests:', error);
      onError && onError('Failed to generate tests from repository');
    } finally {
      setIsGenerating(false);
    }
  };

  const signOut = () => {
    // Clear all GitHub-related data
    localStorage.removeItem('github_state');
    setIsConnected(false);
    setRepositories([]);
    setSelectedRepo('');
    setTestRequest('');
    setUserInfo(null);
    setConnectionStatus('disconnected');
    
    // Clear URL parameters
    const url = new URL(window.location);
    url.searchParams.delete('github_connected');
    url.searchParams.delete('state');
    window.history.replaceState({}, '', url);
    
    // Notify parent component
    onRepositorySelected && onRepositorySelected(null);
  };

  const handleRepositoryChange = (repo) => {
    setSelectedRepo(repo);
    onRepositorySelected && onRepositorySelected(repo);
  };

  const triggerGitHubWorkflow = async () => {
    if (!selectedRepo || !testRequest.trim()) {
      onError && onError('Please select a repository and enter a test request');
      return;
    }

    setIsGenerating(true);
    try {
      const [owner, repo] = selectedRepo.split('/');
      
      const response = await fetch('/api/trigger-github-tests', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          repo_owner: owner,
          repo_name: repo,
          target_url: 'https://your-app.com', // This should be configurable
          test_request: testRequest,
          branch: 'main'
        })
      });

      if (response.ok) {
        const data = await response.json();
        onTestGenerated && onTestGenerated({
          type: 'workflow_triggered',
          workflow_id: data.workflow_id,
          workflow_url: data.workflow_url,
          message: 'GitHub workflow triggered successfully!'
        });
      } else {
        const error = await response.json();
        onError && onError(error.detail || 'Failed to trigger workflow');
      }
    } catch (error) {
      console.error('Failed to trigger workflow:', error);
      onError && onError('Failed to trigger GitHub workflow');
    } finally {
      setIsGenerating(false);
    }
  };

  const getStatusIcon = () => {
    switch (connectionStatus) {
      case 'connected':
        return <CheckCircle className="h-5 w-5 text-green-500" />;
      case 'error':
        return <AlertCircle className="h-5 w-5 text-red-500" />;
      default:
        return <AlertCircle className="h-5 w-5 text-yellow-500" />;
    }
  };

  const getStatusText = () => {
    switch (connectionStatus) {
      case 'connected':
        return 'Connected to GitHub';
      case 'error':
        return 'Connection Error';
      default:
        return 'Not Connected';
    }
  };

  return (
    <div className="space-y-6">
      {/* GitHub Connection Status */}
      <motion.div 
        className="glass-card rounded-xl p-6"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center space-x-3">
            <Github className="h-6 w-6 text-primary" />
            <h3 className="text-lg font-semibold text-foreground">GitHub Integration</h3>
          </div>
          <div className="flex items-center space-x-3">
            {isConnected && userInfo && (
              <div className="flex items-center space-x-2 text-sm text-muted-foreground">
                <User className="h-4 w-4" />
                <span>{userInfo.login}</span>
              </div>
            )}
            <div className="flex items-center space-x-2">
              {getStatusIcon()}
              <span className="text-sm text-muted-foreground">{getStatusText()}</span>
            </div>
            {isConnected && (
              <motion.button
                onClick={signOut}
                className="p-2 text-muted-foreground hover:text-foreground transition-colors glass-card rounded-lg"
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                title="Sign out"
              >
                <LogOut className="h-4 w-4" />
              </motion.button>
            )}
          </div>
        </div>

        {!isConnected ? (
          <div className="text-center py-4">
            <p className="text-muted-foreground mb-4">
              Connect to GitHub to analyze your repositories and generate targeted security tests
            </p>
            <motion.button
              onClick={connectToGitHub}
              disabled={isConnecting}
              className="px-6 py-3 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center space-x-2 mx-auto"
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
            >
              {isConnecting ? (
                <Loader2 className="h-5 w-5 animate-spin" />
              ) : (
                <Github className="h-5 w-5" />
              )}
              <span>{isConnecting ? 'Connecting...' : 'Connect to GitHub'}</span>
            </motion.button>
          </div>
        ) : (
          <div className="space-y-4">
            {/* Repository Selection */}
            <div>
              <label className="block text-sm font-medium text-foreground mb-2">
                Select Repository
              </label>
              <select
                value={selectedRepo}
                onChange={(e) => handleRepositoryChange(e.target.value)}
                className="w-full px-4 py-3 glass-card border border-border/50 rounded-lg text-foreground focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
              >
                <option value="">Choose a repository...</option>
                {repositories.map((repo) => (
                  <option key={repo.full_name} value={repo.full_name}>
                    {repo.full_name}
                  </option>
                ))}
              </select>
            </div>

            {/* Test Request */}
            <div>
              <label className="block text-sm font-medium text-foreground mb-2">
                What do you want to test?
              </label>
              <textarea
                value={testRequest}
                onChange={(e) => setTestRequest(e.target.value)}
                placeholder="Describe what you want to test in your repository..."
                className="w-full px-4 py-3 glass-card border border-border/50 rounded-lg text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent resize-none"
                rows={3}
              />
            </div>

            {/* Action Buttons */}
            <div className="flex space-x-3">
              <motion.button
                onClick={generateTestsFromRepo}
                disabled={!selectedRepo || !testRequest.trim() || isGenerating}
                className="flex-1 px-4 py-3 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center justify-center space-x-2"
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
              >
                {isGenerating ? (
                  <Loader2 className="h-5 w-5 animate-spin" />
                ) : (
                  <Code className="h-5 w-5" />
                )}
                <span>Generate Tests</span>
              </motion.button>

              <motion.button
                onClick={triggerGitHubWorkflow}
                disabled={!selectedRepo || !testRequest.trim() || isGenerating}
                className="flex-1 px-4 py-3 bg-secondary text-secondary-foreground rounded-lg hover:bg-secondary/90 disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center justify-center space-x-2"
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
              >
                {isGenerating ? (
                  <Loader2 className="h-5 w-5 animate-spin" />
                ) : (
                  <Zap className="h-5 w-5" />
                )}
                <span>Run Workflow</span>
              </motion.button>
            </div>
          </div>
        )}
      </motion.div>

      {/* GitHub Features Info */}
      <motion.div 
        className="glass-card rounded-xl p-6"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2, duration: 0.5 }}
      >
        <h3 className="text-lg font-semibold text-foreground mb-4 flex items-center space-x-2">
          <Shield className="h-5 w-5 text-primary" />
          <span>GitHub Integration Features</span>
        </h3>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="space-y-2">
            <h4 className="font-medium text-foreground">Code Analysis</h4>
            <ul className="text-sm text-muted-foreground space-y-1">
              <li>• Analyzes your actual code</li>
              <li>• Finds real vulnerabilities</li>
              <li>• Extracts function definitions</li>
              <li>• Identifies attack vectors</li>
            </ul>
          </div>
          
          <div className="space-y-2">
            <h4 className="font-medium text-foreground">Targeted Testing</h4>
            <ul className="text-sm text-muted-foreground space-y-1">
              <li>• Creates specific test cases</li>
              <li>• Uses real parameter names</li>
              <li>• Targets actual functions</li>
              <li>• Provides realistic payloads</li>
            </ul>
          </div>
          
          <div className="space-y-2">
            <h4 className="font-medium text-foreground">Automated Execution</h4>
            <ul className="text-sm text-muted-foreground space-y-1">
              <li>• Runs tests via GitHub Actions</li>
              <li>• Comments on PRs automatically</li>
              <li>• Creates security issues</li>
              <li>• Generates detailed reports</li>
            </ul>
          </div>
          
          <div className="space-y-2">
            <h4 className="font-medium text-foreground">Real-time Updates</h4>
            <ul className="text-sm text-muted-foreground space-y-1">
              <li>• Tests update with code changes</li>
              <li>• Monitors new vulnerabilities</li>
              <li>• Integrates with CI/CD</li>
              <li>• Provides continuous security</li>
            </ul>
          </div>
        </div>
      </motion.div>
    </div>
  );
};

export default GitHubIntegration;
