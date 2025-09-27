import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import axios from 'axios';
import ScanDashboard from './components/ScanDashboard';
import ScanResults from './components/ScanResults';
import ConsentModal from './components/ConsentModal';
import './index.css';

// Configure axios defaults
axios.defaults.baseURL = 'http://localhost:8000';

function App() {
  const [currentScan, setCurrentScan] = useState(null);
  const [showConsent, setShowConsent] = useState(false);
  const [pendingScanRequest, setPendingScanRequest] = useState(null);

  const handleStartScan = async (scanRequest) => {
    setPendingScanRequest(scanRequest);
    setShowConsent(true);
  };

  const handleConsentAccepted = async () => {
    if (!pendingScanRequest) return;

    try {
      const response = await axios.post('/runs', {
        ...pendingScanRequest,
        consent: true
      });

      setCurrentScan({
        runId: response.data.run_id,
        targetUrl: pendingScanRequest.target_url,
        status: 'queued'
      });

      setShowConsent(false);
      setPendingScanRequest(null);
    } catch (error) {
      console.error('Failed to start scan:', error);
      alert('Failed to start scan: ' + (error.response?.data?.detail || error.message));
    }
  };

  const handleConsentDeclined = () => {
    setShowConsent(false);
    setPendingScanRequest(null);
  };

  const handleNewScan = () => {
    setCurrentScan(null);
  };

  return (
    <Router>
      <div className="min-h-screen bg-gray-50">
        <header className="bg-white shadow-sm border-b">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex justify-between items-center py-6">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <h1 className="text-2xl font-bold text-gray-900">
                    🛡️ Swarm
                  </h1>
                </div>
                <div className="ml-4">
                  <p className="text-sm text-gray-600">
                    Web Security Scanner
                  </p>
                </div>
              </div>
              {currentScan && (
                <button
                  onClick={handleNewScan}
                  className="bg-primary-600 text-white px-4 py-2 rounded-md hover:bg-primary-700 transition-colors"
                >
                  New Scan
                </button>
              )}
            </div>
          </div>
        </header>

        <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
          <Routes>
            <Route
              path="/"
              element={
                currentScan ? (
                  <Navigate to={`/scan/${currentScan.runId}`} replace />
                ) : (
                  <ScanDashboard onStartScan={handleStartScan} />
                )
              }
            />
            <Route
              path="/scan/:runId"
              element={<ScanResults />}
            />
          </Routes>
        </main>

        {showConsent && (
          <ConsentModal
            isOpen={showConsent}
            onAccept={handleConsentAccepted}
            onDecline={handleConsentDeclined}
            targetUrl={pendingScanRequest?.target_url}
          />
        )}
      </div>
    </Router>
  );
}

export default App;