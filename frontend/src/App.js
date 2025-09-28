"use client"

import { useState } from "react"
import { BrowserRouter as Router, Routes, Route, Navigate, useNavigate } from "react-router-dom"
import { motion, AnimatePresence } from "framer-motion"
import ScanDashboard from "./components/ScanDashboard"
import ScanResults from "./components/ScanResults"
import ConsentModal from "./components/ConsentModal"
import NavigationBar from "./components/NavigationBar"
import ProtectedRoute from "./components/ProtectedRoute"
import LoginPage from "./pages/LoginPage"
import SignupPage from "./pages/SignupPage"
import ScanHistoryPage from "./pages/ScanHistoryPage"
import { AuthProvider, useAuth } from "./context/AuthContext"
import { api } from "./lib/api"
import "./index.css"

const AppRoutes = () => {
  const [currentScan, setCurrentScan] = useState(null)
  const [showConsent, setShowConsent] = useState(false)
  const [pendingScanRequest, setPendingScanRequest] = useState(null)
  const { user, logout, loading } = useAuth()
  const navigate = useNavigate()

  const handleStartScan = async (scanRequest) => {
    setPendingScanRequest(scanRequest)
    setShowConsent(true)
  }

  const handleConsentAccepted = async () => {
    if (!pendingScanRequest) return

    try {
      const response = await api("/runs", {
        method: "POST",
        body: JSON.stringify({
          ...pendingScanRequest,
          consent: true,
        }),
      })

      setCurrentScan({
        runId: response.run_id,
        targetUrl: pendingScanRequest.target_url,
        status: "queued",
      })

      setShowConsent(false)
      setPendingScanRequest(null)

      navigate(`/scan/${response.run_id}`)
    } catch (error) {
      console.error("Failed to start scan:", error)
      if (error.message.includes('401') || error.message.includes('unauthorized')) {
        navigate("/login")
      } else {
        alert("Failed to start scan: " + error.message)
      }
    }
  }

  const handleConsentDeclined = () => {
    setShowConsent(false)
    setPendingScanRequest(null)
  }

  const handleNewScan = () => {
    setCurrentScan(null)
  }

  const handleLogout = async () => {
    await logout()
    setCurrentScan(null)
    setPendingScanRequest(null)
    setShowConsent(false)
    navigate("/login")
  }

  return (
    <div
      className="min-h-screen bg-background relative overflow-hidden"
      style={{
        transform: "translateZ(0)",
        WebkitTransform: "translateZ(0)",
        willChange: "scroll-position",
      }}
    >
      <div className="fixed inset-0 swarm-grid pointer-events-none" />

      <div className="fixed inset-0 pointer-events-none">
        <div className="absolute top-20 left-20 w-48 h-48 bg-primary/2 rounded-full blur-xl" />
        <div className="absolute bottom-20 right-20 w-64 h-64 bg-primary/1 rounded-full blur-xl" />
      </div>

      <NavigationBar
        currentScan={currentScan}
        onNewScan={handleNewScan}
        user={user}
        onLogout={handleLogout}
        authLoading={loading}
      />

      <main className="max-w-7xl mx-auto py-8 sm:px-6 lg:px-8 relative z-10">
        <AnimatePresence mode="wait">
          <Routes>
            <Route
              path="/login"
              element={
                <motion.div
                  key="login"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  transition={{ duration: 0.5 }}
                >
                  <LoginPage />
                </motion.div>
              }
            />
            <Route
              path="/signup"
              element={
                <motion.div
                  key="signup"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  transition={{ duration: 0.5 }}
                >
                  <SignupPage />
                </motion.div>
              }
            />
            <Route
              path="/"
              element={
                <ProtectedRoute>
                  <motion.div
                    key="dashboard"
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -20 }}
                    transition={{ duration: 0.5 }}
                  >
                    <ScanDashboard onStartScan={handleStartScan} />
                  </motion.div>
                </ProtectedRoute>
                }
              />
              <Route
              path="/scan/:runId"
              element={
                <ProtectedRoute>
                  <motion.div
                    key="scan-results"
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -20 }}
                    transition={{ duration: 0.5 }}
                    className="h-screen"
                  >
                    <ScanResults />
                  </motion.div>
                </ProtectedRoute>
              }
            />
            <Route
              path="/blocks"
              element={
                <ProtectedRoute>
                  <motion.div
                    key="blocks"
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -20 }}
                    transition={{ duration: 0.5 }}
                  >
                    <div>Blocks page - to be implemented</div>
                  </motion.div>
                </ProtectedRoute>
              }
            />
            <Route
              path="/runs"
              element={
                <ProtectedRoute>
                  <motion.div
                    key="history"
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -20 }}
                    transition={{ duration: 0.5 }}
                  >
                    <ScanHistoryPage />
                  </motion.div>
                </ProtectedRoute>
              }
            />
            <Route path="*" element={<Navigate to="/" replace />} />
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
  )
}

function App() {
  return (
    <AuthProvider>
      <Router>
        <AppRoutes />
      </Router>
    </AuthProvider>
  )
}

export default App
