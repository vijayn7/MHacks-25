import React, { useState } from 'react';
import { Shield, AlertTriangle, Target, Settings } from 'lucide-react';

const ScanDashboard = ({ onStartScan }) => {
  const [targetUrl, setTargetUrl] = useState('http://localhost:3001');
  const [maxPages, setMaxPages] = useState(30);
  const [notifyEmail, setNotifyEmail] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!targetUrl) {
      alert('Please enter a target URL');
      return;
    }

    try {
      new URL(targetUrl);
    } catch {
      alert('Please enter a valid URL');
      return;
    }

    setIsLoading(true);

    const scanRequest = {
      target_url: targetUrl,
      max_pages: maxPages,
      notify_email: notifyEmail || null
    };

    await onStartScan(scanRequest);
    setIsLoading(false);
  };

  return (
    <div className="px-4 py-6">
      {/* Hero Section */}
      <div className="text-center mb-12">
        <Shield className="mx-auto h-16 w-16 text-primary-600 mb-4" />
        <h1 className="text-4xl font-bold text-gray-900 mb-4">
          Web Security Scanner
        </h1>
        <p className="text-xl text-gray-600 max-w-3xl mx-auto">
          Quickly identify common web vulnerabilities like clickjacking, CORS misconfigurations,
          XSS, and missing security headers. Get actionable fix snippets instantly.
        </p>
      </div>

      {/* Main Form */}
      <div className="max-w-2xl mx-auto">
        <div className="bg-white rounded-lg shadow-md p-8">
          <form onSubmit={handleSubmit} className="space-y-6">
            <div>
              <label htmlFor="targetUrl" className="block text-sm font-medium text-gray-700 mb-2">
                Target URL
              </label>
              <div className="relative">
                <Target className="absolute left-3 top-3 h-5 w-5 text-gray-400" />
                <input
                  type="url"
                  id="targetUrl"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  placeholder="https://example.com"
                  className="block w-full pl-10 pr-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                  required
                />
              </div>
              <p className="mt-2 text-sm text-gray-500">
                Enter the URL you want to scan for security vulnerabilities
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <label htmlFor="maxPages" className="block text-sm font-medium text-gray-700 mb-2">
                  Max Pages
                </label>
                <input
                  type="number"
                  id="maxPages"
                  value={maxPages}
                  onChange={(e) => setMaxPages(parseInt(e.target.value))}
                  min="1"
                  max="100"
                  className="block w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                />
              </div>

              <div>
                <label htmlFor="notifyEmail" className="block text-sm font-medium text-gray-700 mb-2">
                  Notification Email (Optional)
                </label>
                <input
                  type="email"
                  id="notifyEmail"
                  value={notifyEmail}
                  onChange={(e) => setNotifyEmail(e.target.value)}
                  placeholder="you@example.com"
                  className="block w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full bg-primary-600 text-white py-3 px-4 rounded-md hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed transition-colors font-medium"
            >
              {isLoading ? 'Starting Scan...' : 'Start Security Scan'}
            </button>
          </form>
        </div>

        {/* Info Cards */}
        <div className="mt-12 grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="bg-white rounded-lg p-6 shadow-sm border">
            <Shield className="h-8 w-8 text-green-600 mb-3" />
            <h3 className="font-semibold text-gray-900 mb-2">Non-Destructive</h3>
            <p className="text-sm text-gray-600">
              Safe, read-only scans that don't modify your application or data
            </p>
          </div>

          <div className="bg-white rounded-lg p-6 shadow-sm border">
            <AlertTriangle className="h-8 w-8 text-yellow-600 mb-3" />
            <h3 className="font-semibold text-gray-900 mb-2">OWASP Coverage</h3>
            <p className="text-sm text-gray-600">
              Detects common vulnerabilities from the OWASP Top 10
            </p>
          </div>

          <div className="bg-white rounded-lg p-6 shadow-sm border">
            <Settings className="h-8 w-8 text-blue-600 mb-3" />
            <h3 className="font-semibold text-gray-900 mb-2">Actionable Fixes</h3>
            <p className="text-sm text-gray-600">
              Get copy-paste code snippets to fix issues immediately
            </p>
          </div>
        </div>

        {/* Legal Notice */}
        <div className="mt-8 p-4 bg-yellow-50 border border-yellow-200 rounded-md">
          <div className="flex">
            <AlertTriangle className="h-5 w-5 text-yellow-400 mt-0.5 mr-3" />
            <div>
              <h3 className="text-sm font-medium text-yellow-800">
                Legal Notice
              </h3>
              <p className="mt-1 text-sm text-yellow-700">
                Only scan websites you own or have explicit written permission to test.
                By starting a scan, you confirm you have the legal right to do so.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ScanDashboard;