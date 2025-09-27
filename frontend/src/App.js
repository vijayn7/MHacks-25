"use client"

import { useState } from "react"
import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom"
import { motion, AnimatePresence } from "framer-motion"
import axios from "axios"
import ScanDashboard from "./components/ScanDashboard"
import ScanResults from "./components/ScanResults"
import ConsentModal from "./components/ConsentModal"
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
    setCurrentScan(null)
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

        <motion.header
          className="glass-card border-b border-border/50 relative z-10"
          initial={{ y: -100, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ duration: 0.6, ease: "easeOut" }}
        >
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex justify-between items-center py-6">
              <motion.div
                className="flex items-center"
                whileHover={{ scale: 1.02 }}
                transition={{ type: "spring", stiffness: 400, damping: 10 }}
              >
                <div className="flex-shrink-0 mr-4">
                  {/* Logo Placeholder */}
                  <motion.div
                    className="w-12 h-12 bg-primary/20 rounded-xl flex items-center justify-center glass-card pulse-glow"
                    whileHover={{ scale: 1.1 }}
                    transition={{ type: "spring", stiffness: 400, damping: 10 }}
                  >
                    <Shield className="h-6 w-6 text-primary" />
                  </motion.div>
                </div>
                <div>
                  <h1 className="text-3xl font-bold gradient-text">Swarm</h1>
                  <p className="text-sm text-muted-foreground font-medium">Advanced Security Scanner</p>
                </div>
              </motion.div>

              <AnimatePresence>
                {currentScan && (
                  <motion.button
                    onClick={handleNewScan}
                    className="glass-card px-6 py-3 text-foreground hover:bg-primary/10 transition-all duration-300 font-medium rounded-lg border border-primary/20 hover:border-primary/40"
                    initial={{ opacity: 0, scale: 0.8 }}
                    animate={{ opacity: 1, scale: 1 }}
                    exit={{ opacity: 0, scale: 0.8 }}
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                  >
                    New Scan
                  </motion.button>
                )}
              </AnimatePresence>
            </div>
          </div>
        </motion.header>

        <main className="max-w-7xl mx-auto py-8 sm:px-6 lg:px-8 relative z-10">
          <AnimatePresence mode="wait">
            <Routes>
              <Route
                path="/"
                element={
                  currentScan ? (
                    <Navigate to={`/scan/${currentScan.runId}`} replace />
                  ) : (
                    <motion.div
                      key="dashboard"
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -20 }}
                      transition={{ duration: 0.5 }}
                    >
                      <ScanDashboard onStartScan={handleStartScan} />
                    </motion.div>
                  )
                }
              />
              <Route
                path="/scan/:runId"
                element={
                  <motion.div
                    key="results"
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -20 }}
                    transition={{ duration: 0.5 }}
                  >
                    <ScanResults />
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