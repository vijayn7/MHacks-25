"use client"

import { useState } from "react"
import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom"
import { motion, AnimatePresence } from "framer-motion"
import axios from "axios"
import ScanDashboard from "./components/ScanDashboard"
import ScanResults from "./components/ScanResults"
import BuildScreen from "./components/BuildScreen"
import ConsentModal from "./components/ConsentModal"
import NavigationBar from "./components/NavigationBar"
import { Shield } from "lucide-react"
import "./index.css"

// Configure axios defaults
axios.defaults.baseURL = "http://localhost:8000"

function App() {
  const [currentScan, setCurrentScan] = useState(null)
  const [showConsent, setShowConsent] = useState(false)
  const [pendingScanRequest, setPendingScanRequest] = useState(null)

  const handleStartScan = async (scanRequest) => {
    setPendingScanRequest(scanRequest)
    setShowConsent(true)
  }

  const handleConsentAccepted = async () => {
    if (!pendingScanRequest) return

    try {
      const response = await axios.post("/runs", {
        ...pendingScanRequest,
        consent: true,
      })

      setCurrentScan({
        runId: response.data.run_id,
        targetUrl: pendingScanRequest.target_url,
        status: "queued",
      })

      setShowConsent(false)
      setPendingScanRequest(null)
      
      // Navigate to results page after successful scan start
      window.location.href = `/scan/${response.data.run_id}`
    } catch (error) {
      console.error("Failed to start scan:", error)
      alert("Failed to start scan: " + (error.response?.data?.detail || error.message))
    }
  }

  const handleConsentDeclined = () => {
    setShowConsent(false)
    setPendingScanRequest(null)
  }

  const handleNewScan = () => {
    setCurrentScan(null); 
  }

  return (
    <Router>
      <div className="min-h-screen bg-background relative overflow-hidden" style={{ 
        transform: 'translateZ(0)', 
        WebkitTransform: 'translateZ(0)',
        willChange: 'scroll-position'
      }}>
        {/* Background Grid */}
        <div className="fixed inset-0 swarm-grid pointer-events-none" />

        {/* Static Background Elements */}
        <div className="fixed inset-0 pointer-events-none">
          <div className="absolute top-20 left-20 w-48 h-48 bg-primary/2 rounded-full blur-xl" />
          <div className="absolute bottom-20 right-20 w-64 h-64 bg-primary/1 rounded-full blur-xl" />
        </div>

        <NavigationBar currentScan={currentScan} onNewScan={handleNewScan} />

        <main className="max-w-7xl mx-auto py-8 sm:px-6 lg:px-8 relative z-10">
          <AnimatePresence mode="wait">
            <Routes>
              <Route
                path="/"
                element={
                  <motion.div
                    key="dashboard"
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -20 }}
                    transition={{ duration: 0.5 }}
                  >
                    <ScanDashboard onStartScan={handleStartScan} />
                  </motion.div>
                }
              />
              <Route
                path="/results"
                element={
                  <motion.div
                    key="results"
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -20 }}
                    transition={{ duration: 0.5 }}
                  >
                    <ScanResults currentScan={currentScan} />
                  </motion.div>
                }
              />
              <Route
                path="/blocks"
                element={
                  <motion.div
                    key="blocks"
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -20 }}
                    transition={{ duration: 0.5 }}
                    className="h-screen"
                  >
                    <BuildScreen />
                  </motion.div>
                }
              />
              <Route
                path="/scan/:runId"
                element={
                  <motion.div
                    key="scan-results"
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -20 }}
                    transition={{ duration: 0.5 }}
                  >
                    <ScanResults currentScan={currentScan} />
                  </motion.div>
                }
              />
            </Routes>
          </AnimatePresence>
        </main>

        <AnimatePresence>
          {showConsent && (
            <ConsentModal
              isOpen={showConsent}
              onAccept={handleConsentAccepted}
              onDecline={handleConsentDeclined}
              targetUrl={pendingScanRequest?.target_url}
            />
          )}
        </AnimatePresence>
      </div>
    </Router>
  )
}

export default App