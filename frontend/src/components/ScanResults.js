"use client"

import { useState, useEffect, useCallback } from "react"
import { useParams, useNavigate } from "react-router-dom"
import { motion, AnimatePresence } from "framer-motion"
import axios from "axios"
import {
  Shield,
  AlertTriangle,
  AlertCircle,
  Info,
  Copy,
  RefreshCw,
  Clock,
  CheckCircle,
  ExternalLink,
  Activity,
  Search,
  Settings,
  Play,
} from "lucide-react"


const ScanResults = ({ currentScan }) => {
  const { runId } = useParams();
  const navigate = useNavigate();
  const [scanStatus, setScanStatus] = useState(null);
  const [findings, setFindings] = useState([]);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [loading, setLoading] = useState(true);
  const [events, setEvents] = useState([]);
  const [codebasePath, setCodebasePath] = useState('');
  const [dynamicScanning, setDynamicScanning] = useState(false);
  const [newAIFindings, setNewAIFindings] = useState(0);

  // Handle navigation functions for "No Scans Found" message
  const handleDashboardClick = () => {
    navigate("/")
  }

  const handleBuildClick = () => {
    console.log("Build screen - to be implemented")
    alert("Build screen - to be implemented")
  }

  const runDynamicScan = async () => {
    if (!codebasePath.trim()) {
      alert('Please provide a codebase path for AI-powered analysis');
      return;
    }
    try {
      setDynamicScanning(true);
      setNewAIFindings(0); // Reset counter for new analysis
      const response = await axios.post(`http://localhost:8000/runs/${runId}/dynamic-scan`, {
        codebase_path: codebasePath.trim()
      });
      if (response.data.status === 'completed') {
        console.log(`AI-powered analysis completed! Found ${response.data.ai_generated_findings} new findings.`);
      }
    } catch (error) {
      console.error('Dynamic scan error:', error);
      alert('Dynamic scan failed: ' + (error.response?.data?.detail || error.message));
      setDynamicScanning(false);
    }
  };

  const fetchScanStatus = useCallback(async () => {
    try {
      const response = await axios.get(`/runs/${runId}`);
      setScanStatus(response.data);
      setLoading(false);
    } catch (error) {
      console.error('Failed to fetch scan status:', error);
      setLoading(false);
    }
  }, [runId]);

  const fetchFindings = useCallback(async () => {
    try {
      console.log(`🔍 Fetching findings for run ${runId}`);
      const response = await axios.get(`/runs/${runId}/findings`);
      console.log(`✅ Found ${response.data.length} findings:`, response.data.slice(0, 3));
      setFindings(response.data);
    } catch (error) {
      console.error('Failed to fetch findings:', error);
    }
  }, [runId]);

  useEffect(() => {
    // If we're on /results route without a runId, check for current scan
    if (!runId) {
      if (currentScan && currentScan.runId) {
        // Redirect to the current scan
        navigate(`/scan/${currentScan.runId}`, { replace: true })
        return
      }
      // No runId and no current scan - show "No Scans Found" message
      setLoading(false)
      return
    }

    // Fetch initial scan status and findings
    fetchScanStatus();
    fetchFindings();

    // Set up SSE for real-time updates
    const eventSource = new EventSource(`http://localhost:8000/runs/${runId}/stream`);

    eventSource.onmessage = async (event) => {
      const data = JSON.parse(event.data);
      setEvents(prev => [...prev, data]);

      if (data.event_type === 'status_update') {
        setScanStatus(prev => ({ ...prev, status: data.data.status }));
      } else if (data.event_type === 'finding_discovered') {
        // Check if it's an AI-generated finding
        if (data.data.ai_generated) {
          setNewAIFindings(prev => prev + 1);
        }
        fetchFindings(); // Refresh findings when new one is discovered
      } else if (data.event_type === 'scan_completed') {
        fetchScanStatus();
        fetchFindings();
      } else if (data.event_type === 'dynamic_scan_completed') {
        setDynamicScanning(false);
        setNewAIFindings(0); // Reset counter
        // Auto-refresh findings to show AI-generated ones
        await fetchFindings();
        console.log(`✅ AI analysis completed! Found ${data.data.ai_generated_findings} new findings.`);
      } else if (data.event_type === 'dynamic_scan_error') {
        setDynamicScanning(false);
        setNewAIFindings(0); // Reset counter
        alert('AI-powered analysis failed: ' + data.data.error);
      }
    };

    eventSource.onerror = (error) => {
      console.error('SSE error:', error);
    };

    return () => {
      eventSource.close();
    };

  }, [runId, fetchScanStatus, fetchFindings]);

  const getSeverityColor = (severity) => {
    switch (severity) {
      case "critical":
        return "text-red-400 bg-red-500/10 border-red-500/20"
      case "high":
        return "text-orange-400 bg-orange-500/10 border-orange-500/20"
      case "medium":
        return "text-yellow-400 bg-yellow-500/10 border-yellow-500/20"
      case "low":
        return "text-blue-400 bg-blue-500/10 border-blue-500/20"
      default:
        return "text-muted-foreground bg-muted/10 border-border"
    }
  }

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case 'critical': return <AlertCircle className="h-4 w-4" />;
      case 'high': return <AlertTriangle className="h-4 w-4" />;
      case 'medium': return <AlertTriangle className="h-4 w-4" />;
      case 'low': return <Info className="h-4 w-4" />;
      default: return <Info className="h-4 w-4" />;
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    // TODO: Add toast notification
  };

  const handleReplay = async (findingId) => {
    try {
      const response = await axios.post(`/runs/${runId}/findings/${findingId}/replay`);
      alert('Replay completed: ' + response.data.message);
    } catch (error) {
      console.error('Failed to replay finding:', error);
      alert('Failed to replay finding');
    }
  };

  // Show "No Scans Found" message when no runId and no current scan
  if (!runId && !currentScan) {
    return (
      <motion.div 
        className="px-4 py-6" 
        initial={{ opacity: 0, y: 20 }} 
        animate={{ opacity: 1, y: 0 }} 
        transition={{ duration: 0.5 }}
      >
        {/* Header */}
        <motion.div
          className="glass-card p-8 mb-8 rounded-2xl"
          initial={{ y: -20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ delay: 0.1 }}
        >
          <div className="flex items-center space-x-6">
            <motion.div
              className="w-16 h-16 bg-primary/20 rounded-xl flex items-center justify-center"
              whileHover={{ scale: 1.1, rotate: 5 }}
            >
              <Search className="h-8 w-8 text-primary" />
            </motion.div>
            <div>
              <h1 className="text-3xl font-bold text-foreground mb-2">Scan Results</h1>
              <p className="text-muted-foreground text-lg">
                View and analyze your security scan results
              </p>
            </div>
          </div>
        </motion.div>

        {/* No Scans Message */}
        <motion.div
          className="glass-card p-8 rounded-2xl text-center"
          initial={{ y: 20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ delay: 0.2 }}
        >
          <motion.div
            className="w-24 h-24 bg-blue-500/20 rounded-2xl flex items-center justify-center mx-auto mb-6"
            whileHover={{ scale: 1.1 }}
          >
            <Search className="h-12 w-12 text-blue-400" />
          </motion.div>
          
          <h2 className="text-2xl font-bold text-foreground mb-4">No Scans Found</h2>
          <p className="text-muted-foreground text-lg mb-8 max-w-2xl mx-auto">
            You currently have no scans. Go to the Dashboard to start a full scan or customize your own on the Build screen.
          </p>

          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <motion.button
              onClick={handleDashboardClick}
              className="glass-card px-8 py-4 text-foreground hover:bg-primary/10 transition-all duration-300 font-medium rounded-lg border border-primary/20 hover:border-primary/40 flex items-center justify-center"
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
            >
              <Play className="h-5 w-5 mr-2" />
              Go to Dashboard
            </motion.button>

            <motion.button
              onClick={handleBuildClick}
              className="glass-card px-8 py-4 text-foreground hover:bg-primary/10 transition-all duration-300 font-medium rounded-lg border border-primary/20 hover:border-primary/40 flex items-center justify-center"
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
            >
              <Settings className="h-5 w-5 mr-2" />
              Build Screen
            </motion.button>
          </div>
        </motion.div>
      </motion.div>
    )
  }

  if (loading) {
    return (
      <motion.div className="flex items-center justify-center h-64" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
        <div className="text-center">
          <motion.div
            animate={{ rotate: 360 }}
            transition={{ duration: 2, repeat: Number.POSITIVE_INFINITY, ease: "linear" }}
          >
            <RefreshCw className="h-12 w-12 text-primary mx-auto mb-4" />
          </motion.div>
          <p className="text-muted-foreground text-lg">Loading scan results...</p>
        </div>
      </motion.div>
    )
  }

  if (!scanStatus) {
    return (
      <motion.div className="text-center py-12" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
        <AlertTriangle className="h-16 w-16 text-red-400 mx-auto mb-4" />
        <h2 className="text-2xl font-bold text-foreground mb-2">Scan Not Found</h2>
        <p className="text-muted-foreground">The scan you're looking for doesn't exist.</p>
      </motion.div>
    )
  }

  return (
    <motion.div className="px-4 py-6" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.5 }}>
      {/* Scan Status Header */}
      <motion.div
        className="glass-card p-8 mb-8 rounded-2xl"
        initial={{ y: -20, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ delay: 0.1 }}
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-6">
            <motion.div
              className="w-16 h-16 bg-primary/20 rounded-xl flex items-center justify-center overflow-hidden"
              whileHover={{ scale: 1.1, rotate: 5 }}
            >
              <img 
                src="/Favicon.png" 
                alt="Swarm Logo" 
                className="w-10 h-10 object-contain"
              />
            </motion.div>
            <div>
              <h1 className="text-3xl font-bold text-foreground mb-2">Security Scan Results</h1>
              <p className="text-muted-foreground text-lg">
                Target: <span className="font-semibold text-foreground">{scanStatus.target_url}</span>
              </p>
            </div>
          </div>
          <div className="text-right">
            <motion.div className="flex items-center space-x-3 mb-3" whileHover={{ scale: 1.05 }}>
              {scanStatus.status === "completed" && <CheckCircle className="h-6 w-6 text-green-400" />}
              {scanStatus.status === "running" && (
                <motion.div
                  animate={{ rotate: 360 }}
                  transition={{ duration: 2, repeat: Number.POSITIVE_INFINITY, ease: "linear" }}
                >
                  <RefreshCw className="h-6 w-6 text-blue-400" />
                </motion.div>
              )}
              {scanStatus.status === "queued" && <Clock className="h-6 w-6 text-yellow-400" />}
              <span className="font-semibold text-lg capitalize text-foreground">{scanStatus.status}</span>
            </motion.div>
            <div className="glass-card px-4 py-2 rounded-lg">
              <span className="text-sm text-muted-foreground">Risk Score: </span>
              <span className="font-bold text-xl text-primary">{scanStatus.risk_score}/100</span>
            </div>
          </div>
        </div>
      </motion.div>

      {/* AI-Powered Dynamic Scan Section */}
      <motion.div
        className="glass-card p-6 mb-8 rounded-2xl border border-primary/20"
        initial={{ y: -20, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ delay: 0.2 }}
      >
        <div className="flex items-center space-x-3 mb-4">
          <div className="w-10 h-10 bg-gradient-to-r from-purple-500 to-pink-500 rounded-lg flex items-center justify-center">
            <Activity className="h-5 w-5 text-white" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-foreground">AI-Powered Dynamic Analysis</h2>
            <p className="text-muted-foreground">Analyze your codebase with advanced AI-generated security tests</p>
          </div>
        </div>
        
        <div className="flex items-center space-x-4">
          <input
            type="text"
            placeholder="Enter codebase path (e.g., /path/to/your/code)"
            value={codebasePath}
            onChange={(e) => setCodebasePath(e.target.value)}
            className="flex-1 px-4 py-2 bg-background/50 border border-border/50 rounded-lg text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/50"
          />
          <motion.button
            onClick={runDynamicScan}
            disabled={dynamicScanning || !codebasePath.trim()}
            className="px-6 py-2 bg-gradient-to-r from-purple-500 to-pink-500 text-white rounded-lg font-medium disabled:opacity-50 disabled:cursor-not-allowed flex items-center space-x-2"
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            {dynamicScanning ? (
              <>
                <motion.div
                  animate={{ rotate: 360 }}
                  transition={{ duration: 1, repeat: Number.POSITIVE_INFINITY, ease: "linear" }}
                >
                  <RefreshCw className="h-4 w-4" />
                </motion.div>
                <span>Analyzing...</span>
                {newAIFindings > 0 && (
                  <span className="ml-2 px-2 py-1 bg-green-500 text-white text-xs rounded-full">
                    +{newAIFindings} found
                  </span>
                )}
              </>
            ) : (
              <>
                <Activity className="h-4 w-4" />
                <span>Run AI Analysis</span>
              </>
            )}
          </motion.button>
        </div>
        
        <div className="mt-4 text-sm text-muted-foreground">
          <p>🤖 Uses Gemini AI to generate targeted security tests based on your actual code patterns</p>
          <p>🎯 Covers 8 attack categories with 50+ sophisticated attack vectors</p>
          <p>⚡ Results appear in real-time below with traditional findings</p>
          {newAIFindings > 0 && (
            <motion.p 
              className="text-green-400 font-medium"
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5 }}
            >
              ✅ {newAIFindings} AI-generated findings discovered and added to the list below!
            </motion.p>
          )}
        </div>
      </motion.div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Findings List */}
        <motion.div
          className="lg:col-span-2"
          initial={{ x: -20, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          transition={{ delay: 0.2 }}
        >
          <div className="glass-card rounded-2xl overflow-hidden">
            <div className="p-6 border-b border-border/50">
              <div className="flex items-center space-x-3">
                <Activity className="h-6 w-6 text-primary" />
                <h2 className="text-xl font-bold text-foreground">Security Findings ({findings.length})</h2>
              </div>
            </div>
            <div className="divide-y divide-border/50">
              <AnimatePresence>
                {findings.length === 0 ? (
                  <motion.div
                    className="p-8 text-center text-muted-foreground"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                  >
                    {scanStatus.status === "running" ? (
                      <div className="space-y-4">
                        <motion.div
                          animate={{ rotate: 360 }}
                          transition={{ duration: 2, repeat: Number.POSITIVE_INFINITY, ease: "linear" }}
                        >
                          <RefreshCw className="h-8 w-8 text-primary mx-auto" />
                        </motion.div>
                        <p className="text-lg">Scanning in progress...</p>
                      </div>
                    ) : (
                      <div className="space-y-4">
                        <Shield className="h-12 w-12 text-green-400 mx-auto" />
                        <p className="text-lg">No vulnerabilities found</p>
                      </div>
                    )}
                  </motion.div>
                ) : (
                  findings.map((finding, index) => (
                    <motion.div
                      key={finding.id}
                      className={`p-6 cursor-pointer hover:bg-muted/20 transition-all duration-300 ${
                        selectedFinding?.id === finding.id ? "bg-primary/5 border-l-4 border-l-primary" : ""
                      }`}
                      onClick={() => setSelectedFinding(finding)}
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: index * 0.1 }}
                      whileHover={{ scale: 1.01 }}
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center space-x-3 mb-3">
                            <span
                              className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium border ${getSeverityColor(finding.severity)}`}
                            >
                              {getSeverityIcon(finding.severity)}
                              <span className="ml-2 capitalize">{finding.severity}</span>
                            </span>
                            <span className="text-xs text-muted-foreground uppercase tracking-wider font-medium">
                              {finding.category}
                            </span>
                            {finding.ai_generated && (
                              <span className="px-2 py-1 bg-gradient-to-r from-purple-500 to-pink-500 text-white text-xs rounded-full font-medium">
                                AI-Generated
                              </span>
                            )}
                            {finding.owasp_category && (
                              <span className="px-2 py-1 bg-blue-500/20 text-blue-400 text-xs rounded-full font-medium">
                                {finding.owasp_category}
                              </span>
                            )}
                          </div>
                          <h3 className="font-bold text-foreground mb-2 text-lg">{finding.title}</h3>
                          <p className="text-muted-foreground line-clamp-2 leading-relaxed">{finding.description}</p>
                        </div>
                        <div className="ml-6 text-right">
                          <div className="glass-card px-3 py-1 rounded-lg">
                            <span className="text-sm font-semibold text-foreground">
                              Priority: {finding.priority_score}
                            </span>
                          </div>
                        </div>
                      </div>
                    </motion.div>
                  ))
                )}
              </AnimatePresence>
            </div>
          </div>
        </motion.div>

        {/* Finding Details */}
        <motion.div
          className="lg:col-span-1"
          initial={{ x: 20, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          transition={{ delay: 0.3 }}
        >
          <AnimatePresence mode="wait">
            {selectedFinding ? (
              <motion.div
                className="glass-card rounded-2xl overflow-hidden"
                key={selectedFinding.id}
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.95 }}
                transition={{ duration: 0.3 }}
              >
                <div className="p-6 border-b border-border/50">
                  <div className="flex items-center space-x-3 mb-3">
                    <span
                      className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium border ${getSeverityColor(selectedFinding.severity)}`}
                    >
                      {getSeverityIcon(selectedFinding.severity)}
                      <span className="ml-2 capitalize">{selectedFinding.severity}</span>
                    </span>
                  </div>
                  <h3 className="font-bold text-foreground text-lg">{selectedFinding.title}</h3>
                </div>

                <div className="p-6 space-y-6">
                  <div>
                    <h4 className="font-semibold text-foreground mb-3 flex items-center">
                      <Info className="h-4 w-4 mr-2 text-primary" />
                      Description
                    </h4>
                    <p className="text-muted-foreground leading-relaxed">{selectedFinding.description}</p>
                  </div>

                  {selectedFinding.evidence && (
                    <div>
                      <h4 className="font-semibold text-foreground mb-3 flex items-center">
                        <ExternalLink className="h-4 w-4 mr-2 text-primary" />
                        Evidence
                      </h4>
                      <div className="glass-card p-4 rounded-lg">
                        <pre className="text-sm text-muted-foreground whitespace-pre-wrap overflow-x-auto">
                          {JSON.stringify(selectedFinding.evidence, null, 2)}
                        </pre>
                      </div>
                    </div>
                  )}

                  {selectedFinding.fix_snippet && (
                    <div>
                      <h4 className="font-semibold text-foreground mb-3 flex items-center">
                        <Copy className="h-4 w-4 mr-2 text-primary" />
                        Fix Snippet
                      </h4>
                      <div className="bg-black/50 rounded-lg p-4 relative">
                        <motion.button
                          onClick={() => copyToClipboard(selectedFinding.fix_snippet)}
                          className="absolute top-3 right-3 p-2 text-muted-foreground hover:text-foreground transition-colors rounded-lg hover:bg-muted/20"
                          title="Copy to clipboard"
                          whileHover={{ scale: 1.1 }}
                          whileTap={{ scale: 0.9 }}
                        >
                          <Copy className="h-4 w-4" />
                        </motion.button>
                        <pre className="text-sm text-green-400 whitespace-pre-wrap pr-12 overflow-x-auto">
                          {selectedFinding.fix_snippet}
                        </pre>
                      </div>
                    </div>
                  )}

                  {selectedFinding.reproduce_command && (
                    <div>
                      <h4 className="font-semibold text-foreground mb-3 flex items-center">
                        <RefreshCw className="h-4 w-4 mr-2 text-primary" />
                        Reproduce
                      </h4>
                      <div className="glass-card p-4 rounded-lg mb-3">
                        <code className="text-sm text-muted-foreground">{selectedFinding.reproduce_command}</code>
                      </div>
                      <motion.button
                        onClick={() => handleReplay(selectedFinding.id)}
                        className="inline-flex items-center px-4 py-2 glass-card text-foreground hover:bg-primary/10 transition-all duration-300 font-medium rounded-lg border border-primary/20 hover:border-primary/40"
                        whileHover={{ scale: 1.05 }}
                        whileTap={{ scale: 0.95 }}
                      >
                        <RefreshCw className="h-4 w-4 mr-2" />
                        Replay Test
                      </motion.button>
                    </div>
                  )}
                </div>
              </motion.div>
            ) : (
              <motion.div
                className="glass-card p-8 rounded-2xl"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
              >
                <div className="text-center text-muted-foreground">
                  <Shield className="h-16 w-16 mx-auto mb-4 text-muted-foreground/50" />
                  <p className="text-lg">Select a finding to view details</p>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </motion.div>
      </div>

      {/* Real-time Events (Development) */}
      {process.env.NODE_ENV === "development" && events.length > 0 && (
        <motion.div
          className="mt-8 glass-card rounded-2xl overflow-hidden"
          initial={{ y: 20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ delay: 0.4 }}
        >
          <div className="p-4 border-b border-border/50">
            <h3 className="font-semibold text-foreground flex items-center">
              <Activity className="h-5 w-5 mr-2 text-primary" />
              Live Events
            </h3>
          </div>
          <div className="p-4 max-h-32 overflow-y-auto">
            {events.slice(-5).map((event, index) => (
              <motion.div
                key={index}
                className="text-sm text-muted-foreground mb-2 font-mono"
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: index * 0.1 }}
              >
                <span className="text-primary">{new Date(event.timestamp).toLocaleTimeString()}</span>{" "}
                <span className="font-semibold text-foreground">{event.event_type}</span> {JSON.stringify(event.data)}
              </motion.div>
            ))}
          </div>
        </motion.div>
      )}
    </motion.div>
  );
};

export default ScanResults;