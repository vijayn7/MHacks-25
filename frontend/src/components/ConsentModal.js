import React from 'react';
import { AlertTriangle, Shield } from 'lucide-react';

const ConsentModal = ({ isOpen, onAccept, onDecline, targetUrl }) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
      <div className="bg-white rounded-lg shadow-xl max-w-md w-full">
        <div className="p-6">
          <div className="flex items-center mb-4">
            <Shield className="h-8 w-8 text-primary-600 mr-3" />
            <h2 className="text-xl font-bold text-gray-900">
              Consent Required
            </h2>
          </div>

          <div className="mb-6">
            <p className="text-gray-700 mb-4">
              You are about to scan: <span className="font-semibold">{targetUrl}</span>
            </p>

            <div className="bg-yellow-50 border border-yellow-200 rounded-md p-4 mb-4">
              <div className="flex">
                <AlertTriangle className="h-5 w-5 text-yellow-400 mt-0.5 mr-3" />
                <div>
                  <h3 className="text-sm font-medium text-yellow-800 mb-2">
                    Legal Requirement
                  </h3>
                  <p className="text-sm text-yellow-700">
                    By proceeding, you confirm that you:
                  </p>
                </div>
              </div>
            </div>

            <ul className="text-sm text-gray-600 space-y-2 mb-4">
              <li className="flex items-start">
                <span className="text-primary-600 mr-2">•</span>
                Own this website OR have explicit written permission to scan it
              </li>
              <li className="flex items-start">
                <span className="text-primary-600 mr-2">•</span>
                Understand this scan will perform non-destructive security tests
              </li>
              <li className="flex items-start">
                <span className="text-primary-600 mr-2">•</span>
                Accept responsibility for compliance with applicable laws
              </li>
              <li className="flex items-start">
                <span className="text-primary-600 mr-2">•</span>
                Acknowledge that scan results and evidence will be stored temporarily
              </li>
            </ul>

            <div className="bg-blue-50 border border-blue-200 rounded-md p-4">
              <h4 className="text-sm font-medium text-blue-800 mb-2">
                What we scan for:
              </h4>
              <ul className="text-sm text-blue-700 space-y-1">
                <li>• Missing security headers (X-Frame-Options, CSP, HSTS)</li>
                <li>• CORS misconfigurations</li>
                <li>• Reflected XSS vulnerabilities</li>
                <li>• Open redirect vulnerabilities</li>
                <li>• Insecure cookie configurations</li>
                <li>• Information disclosure</li>
              </ul>
            </div>
          </div>

          <div className="flex space-x-3">
            <button
              onClick={onDecline}
              className="flex-1 px-4 py-2 border border-gray-300 rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={onAccept}
              className="flex-1 px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 transition-colors font-medium"
            >
              I Consent - Start Scan
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ConsentModal;