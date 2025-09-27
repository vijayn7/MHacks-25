import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import axios from 'axios';
import {
  Shield,
  AlertTriangle,
  AlertCircle,
  Info,
  Copy,
  RefreshCw,
  Clock,
  CheckCircle,
  ExternalLink
} from 'lucide-react';

const ScanResults = () => {
  const { runId } = useParams();
  const [scanStatus, setScanStatus] = useState(null);
  const [findings, setFindings] = useState([]);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [loading, setLoading] = useState(true);
  const [events, setEvents] = useState([]);

  useEffect(() => {
    if (!runId) return;

    // Fetch initial scan status
    fetchScanStatus();

    // Set up SSE for real-time updates
    const eventSource = new EventSource(`http://localhost:8000/runs/${runId}/stream`);

    eventSource.onmessage = (event) => {
      const data = JSON.parse(event.data);
      setEvents(prev => [...prev, data]);

      if (data.event_type === 'status_update') {
        setScanStatus(prev => ({ ...prev, status: data.data.status }));
      } else if (data.event_type === 'finding_discovered') {
        fetchFindings(); // Refresh findings when new one is discovered
      } else if (data.event_type === 'scan_completed') {
        fetchScanStatus();
        fetchFindings();
      }
    };

    eventSource.onerror = (error) => {
      console.error('SSE error:', error);
    };

    return () => {
      eventSource.close();
    };
  }, [runId]);

  const fetchScanStatus = async () => {
    try {
      const response = await axios.get(`/runs/${runId}`);
      setScanStatus(response.data);
      setLoading(false);
    } catch (error) {
      console.error('Failed to fetch scan status:', error);
      setLoading(false);
    }
  };

  const fetchFindings = async () => {
    try {
      const response = await axios.get(`/runs/${runId}/findings`);
      setFindings(response.data);
    } catch (error) {
      console.error('Failed to fetch findings:', error);
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return 'text-red-600 bg-red-50 border-red-200';
      case 'high': return 'text-orange-600 bg-orange-50 border-orange-200';
      case 'medium': return 'text-yellow-600 bg-yellow-50 border-yellow-200';
      case 'low': return 'text-blue-600 bg-blue-50 border-blue-200';
      default: return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

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

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <RefreshCw className="h-8 w-8 animate-spin text-primary-600 mx-auto mb-4" />
          <p className="text-gray-600">Loading scan results...</p>
        </div>
      </div>
    );
  }

  if (!scanStatus) {
    return (
      <div className="text-center py-12">
        <AlertTriangle className="h-12 w-12 text-red-500 mx-auto mb-4" />
        <h2 className="text-xl font-semibold text-gray-900 mb-2">Scan Not Found</h2>
        <p className="text-gray-600">The scan you're looking for doesn't exist.</p>
      </div>
    );
  }

  return (
    <div className="px-4 py-6">
      {/* Scan Status Header */}
      <div className="bg-white rounded-lg shadow-sm border p-6 mb-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900 mb-2">
              Security Scan Results
            </h1>
            <p className="text-gray-600">
              Target: <span className="font-medium">{scanStatus.target_url}</span>
            </p>
          </div>
          <div className="text-right">
            <div className="flex items-center space-x-2 mb-2">
              {scanStatus.status === 'completed' && <CheckCircle className="h-5 w-5 text-green-600" />}
              {scanStatus.status === 'running' && <RefreshCw className="h-5 w-5 animate-spin text-blue-600" />}
              {scanStatus.status === 'queued' && <Clock className="h-5 w-5 text-yellow-600" />}
              <span className="font-medium capitalize">{scanStatus.status}</span>
            </div>
            <div className="text-sm text-gray-500">
              Risk Score: <span className="font-semibold text-red-600">{scanStatus.risk_score}/100</span>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Findings List */}
        <div className="lg:col-span-2">
          <div className="bg-white rounded-lg shadow-sm border">
            <div className="p-6 border-b">
              <h2 className="text-lg font-semibold text-gray-900">
                Security Findings ({findings.length})
              </h2>
            </div>
            <div className="divide-y">
              {findings.length === 0 ? (
                <div className="p-6 text-center text-gray-500">
                  {scanStatus.status === 'running' ? 'Scanning in progress...' : 'No vulnerabilities found'}
                </div>
              ) : (
                findings.map((finding) => (
                  <div
                    key={finding.id}
                    className={`p-6 cursor-pointer hover:bg-gray-50 transition-colors ${
                      selectedFinding?.id === finding.id ? 'bg-blue-50' : ''
                    }`}
                    onClick={() => setSelectedFinding(finding)}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center space-x-2 mb-2">
                          <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium border ${getSeverityColor(finding.severity)}`}>
                            {getSeverityIcon(finding.severity)}
                            <span className="ml-1 capitalize">{finding.severity}</span>
                          </span>
                          <span className="text-xs text-gray-500 uppercase tracking-wide">
                            {finding.category}
                          </span>
                        </div>
                        <h3 className="font-semibold text-gray-900 mb-1">
                          {finding.title}
                        </h3>
                        <p className="text-sm text-gray-600 line-clamp-2">
                          {finding.description}
                        </p>
                      </div>
                      <div className="ml-4 text-right">
                        <div className="text-sm font-medium text-gray-900">
                          Priority: {finding.priority_score}
                        </div>
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Finding Details */}
        <div className="lg:col-span-1">
          {selectedFinding ? (
            <div className="bg-white rounded-lg shadow-sm border">
              <div className="p-6 border-b">
                <div className="flex items-center space-x-2 mb-2">
                  <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium border ${getSeverityColor(selectedFinding.severity)}`}>
                    {getSeverityIcon(selectedFinding.severity)}
                    <span className="ml-1 capitalize">{selectedFinding.severity}</span>
                  </span>
                </div>
                <h3 className="font-semibold text-gray-900">
                  {selectedFinding.title}
                </h3>
              </div>

              <div className="p-6 space-y-6">
                <div>
                  <h4 className="font-medium text-gray-900 mb-2">Description</h4>
                  <p className="text-sm text-gray-600">
                    {selectedFinding.description}
                  </p>
                </div>

                {selectedFinding.evidence && (
                  <div>
                    <h4 className="font-medium text-gray-900 mb-2">Evidence</h4>
                    <div className="bg-gray-50 rounded-md p-3">
                      <pre className="text-xs text-gray-700 whitespace-pre-wrap">
                        {JSON.stringify(selectedFinding.evidence, null, 2)}
                      </pre>
                    </div>
                  </div>
                )}

                {selectedFinding.fix_snippet && (
                  <div>
                    <h4 className="font-medium text-gray-900 mb-2">Fix Snippet</h4>
                    <div className="bg-gray-900 rounded-md p-3 relative">
                      <button
                        onClick={() => copyToClipboard(selectedFinding.fix_snippet)}
                        className="absolute top-2 right-2 p-1 text-gray-400 hover:text-white transition-colors"
                        title="Copy to clipboard"
                      >
                        <Copy className="h-4 w-4" />
                      </button>
                      <pre className="text-sm text-green-400 whitespace-pre-wrap pr-8">
                        {selectedFinding.fix_snippet}
                      </pre>
                    </div>
                  </div>
                )}

                {selectedFinding.reproduce_command && (
                  <div>
                    <h4 className="font-medium text-gray-900 mb-2">Reproduce</h4>
                    <div className="bg-gray-50 rounded-md p-3">
                      <code className="text-sm text-gray-700">
                        {selectedFinding.reproduce_command}
                      </code>
                    </div>
                    <button
                      onClick={() => handleReplay(selectedFinding.id)}
                      className="mt-2 inline-flex items-center px-3 py-1 border border-gray-300 rounded-md text-xs font-medium text-gray-700 bg-white hover:bg-gray-50 transition-colors"
                    >
                      <RefreshCw className="h-3 w-3 mr-1" />
                      Replay Test
                    </button>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="bg-white rounded-lg shadow-sm border p-6">
              <div className="text-center text-gray-500">
                <Shield className="h-12 w-12 mx-auto mb-3 text-gray-300" />
                <p>Select a finding to view details</p>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Real-time Events (Development) */}
      {process.env.NODE_ENV === 'development' && events.length > 0 && (
        <div className="mt-6 bg-white rounded-lg shadow-sm border">
          <div className="p-4 border-b">
            <h3 className="font-medium text-gray-900">Live Events</h3>
          </div>
          <div className="p-4 max-h-32 overflow-y-auto">
            {events.slice(-5).map((event, index) => (
              <div key={index} className="text-xs text-gray-600 mb-1">
                <span className="text-gray-400">{new Date(event.timestamp).toLocaleTimeString()}</span>
                {' '}
                <span className="font-medium">{event.event_type}</span>
                {' '}
                {JSON.stringify(event.data)}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default ScanResults;