"use client"

import { useState, useEffect, useCallback, useRef } from "react"
import axios from "axios"
import { Link, useLocation, useNavigate } from "react-router-dom"
import { motion, AnimatePresence } from "framer-motion"
import { Shield, Play, AlertTriangle, LogOut, User, ChevronDown } from "lucide-react"

const STATUS_STYLES = {
  queued: "bg-amber-500/10 text-amber-400",
  running: "bg-sky-500/10 text-sky-400",
  completed: "bg-emerald-500/10 text-emerald-400",
  failed: "bg-rose-500/10 text-rose-400"
}

const formatStatusLabel = (status) => {
  if (!status) return ""
  return status.charAt(0).toUpperCase() + status.slice(1)
}

const formatDateTime = (value) => {
  if (!value) return ""
  try {
    return new Date(value).toLocaleString(undefined, {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit"
    })
  } catch (error) {
    return value
  }
}

const NavigationBar = ({ currentScan, onNewScan, user, onLogout, authLoading = false }) => {
  const location = useLocation()
  const navigate = useNavigate()
  const isMountedRef = useRef(true)
  const [isMenuOpen, setIsMenuOpen] = useState(false)
  const [showConfirmDialog, setShowConfirmDialog] = useState(false)
  const [showResultsDropdown, setShowResultsDropdown] = useState(false)
  const [showMobileResults, setShowMobileResults] = useState(false)
  const [scanHistory, setScanHistory] = useState([])
  const [isLoadingHistory, setIsLoadingHistory] = useState(false)
  const [historyError, setHistoryError] = useState(null)

  const isAuthenticated = Boolean(user)
  const canStartScan = isAuthenticated && !authLoading
  const isDashboardActive = location.pathname === "/"
  const isResultsActive = location.pathname.startsWith("/scan/")
  const resultsDisabled = !isAuthenticated || authLoading

  useEffect(() => {
    isMountedRef.current = true
    return () => {
      isMountedRef.current = false
    }
  }, [])

  const fetchScanHistory = useCallback(async () => {
    if (!isMountedRef.current) {
      return
    }

    if (!isAuthenticated || authLoading) {
      if (isMountedRef.current) {
        setScanHistory([])
        setHistoryError(null)
        setIsLoadingHistory(false)
      }
      return
    }

    if (isMountedRef.current) {
      setIsLoadingHistory(true)
      setHistoryError(null)
    }

    try {
      const response = await axios.get("/runs")
      if (isMountedRef.current) {
        setScanHistory(response.data || [])
      }
    } catch (error) {
      if (!isMountedRef.current) {
        return
      }
      if (error.response?.status === 401) {
        setScanHistory([])
      } else {
        setHistoryError(error.response?.data?.detail || "Unable to load scan history")
      }
    } finally {
      if (isMountedRef.current) {
        setIsLoadingHistory(false)
      }
    }
  }, [isAuthenticated, authLoading])

  useEffect(() => {
    fetchScanHistory()
  }, [fetchScanHistory, currentScan?.runId])

  useEffect(() => {
    if (!isAuthenticated) {
      setScanHistory([])
      setHistoryError(null)
    }
  }, [isAuthenticated])

  useEffect(() => {
    setShowResultsDropdown(false)
    setShowMobileResults(false)
  }, [location.pathname])

  const handleNewScanClick = () => {
    if (!canStartScan) {
      if (!authLoading) {
        navigate("/login")
      }
      return
    }

    if (currentScan && (currentScan.status === "running" || currentScan.status === "completed")) {
      setShowConfirmDialog(true)
    } else {
      navigate("/")
    }
  }

  const handleConfirmNewScan = () => {
    setShowConfirmDialog(false)
    navigate("/")
    if (onNewScan) {
      onNewScan()
    }
  }

  const handleCancelNewScan = () => {
    setShowConfirmDialog(false)
  }

  const handleLogoutClick = async () => {
    if (onLogout) {
      await onLogout()
      setIsMenuOpen(false)
    }
  }

  const handleToggleDesktopResults = async () => {
    if (resultsDisabled) return
    if (!showResultsDropdown && !isLoadingHistory) {
      await fetchScanHistory()
    }
    setShowResultsDropdown((prev) => !prev)
  }

  const handleToggleMobileResults = async () => {
    if (resultsDisabled) return
    if (!showMobileResults && !isLoadingHistory) {
      await fetchScanHistory()
    }
    setShowMobileResults((prev) => !prev)
  }

  const handleSelectScan = () => {
    setShowResultsDropdown(false)
    setShowMobileResults(false)
    setIsMenuOpen(false)
  }

  const renderHistoryList = () => {
    if (isLoadingHistory) {
      return (
        <div className="py-6 text-center text-sm text-muted-foreground">
          Loading scan history...
        </div>
      )
    }

    if (historyError) {
      return (
        <div className="py-6 px-4 text-sm text-rose-400">
          {historyError}
        </div>
      )
    }

    if (!scanHistory.length) {
      return (
        <div className="py-6 px-4 text-sm text-muted-foreground">
          No scans yet. Start a scan to see your history here.
        </div>
      )
    }

    return (
      <div className="py-2">
        {scanHistory.map((scan) => {
          const isActiveScan = location.pathname === `/scan/${scan.id}`
          return (
            <Link
              key={scan.id}
              to={`/scan/${scan.id}`}
              className="block"
              onClick={handleSelectScan}
            >
              <div
                className={`px-4 py-3 transition-colors rounded-lg ${
                  isActiveScan
                    ? "bg-primary/10 border border-primary/30"
                    : "hover:bg-primary/5"
                }`}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-foreground truncate">
                      {scan.target_url}
                    </p>
                    <p className="mt-1 text-xs text-muted-foreground">
                      Started {formatDateTime(scan.created_at)}
                    </p>
                    <p className="mt-2 text-xs text-muted-foreground">
                      Findings: <span className="font-medium text-foreground">{scan.finding_count ?? 0}</span>
                      <span className="mx-1">•</span>
                      Risk score: <span className="font-medium text-foreground">{scan.risk_score ?? 0}</span>
                    </p>
                  </div>
                  <span
                    className={`shrink-0 px-2 py-1 text-xs font-semibold rounded-full ${
                      STATUS_STYLES[scan.status] || "bg-muted text-foreground/80"
                    }`}
                  >
                    {formatStatusLabel(scan.status)}
                  </span>
                </div>
              </div>
            </Link>
          )
        })}
      </div>
    )
  }

  return (
    <>
      <motion.header
        className="glass-card border-b border-border/50 relative z-10"
        initial={{ y: -100, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ duration: 0.6, ease: "easeOut" }}
      >
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            {/* Logo and Brand */}
            <motion.div
              className="flex items-center"
              whileHover={{ scale: 1.02 }}
              transition={{ type: "spring", stiffness: 400, damping: 10 }}
            >
              <Link to="/" className="flex items-center">
                <div className="flex-shrink-0 mr-3">
                  <motion.div
                    className="w-10 h-10 bg-primary rounded-lg flex items-center justify-center"
                    whileHover={{ scale: 1.1 }}
                    transition={{ type: "spring", stiffness: 400, damping: 10 }}
                  >
                    <Shield className="h-5 w-5 text-white" />
                  </motion.div>
                </div>
                <div>
                  <h1 className="text-xl font-bold text-foreground">Swarm AI</h1>
                </div>
              </Link>
            </motion.div>

            {/* Navigation Links */}
            <nav className="hidden md:flex items-center space-x-8">
              <Link
                to="/"
                className={`relative text-sm font-medium transition-colors duration-200 ${
                  !isAuthenticated || authLoading
                    ? "text-foreground/30 cursor-not-allowed"
                    : isDashboardActive
                    ? "text-primary"
                    : "text-foreground/70 hover:text-foreground"
                }`}
              >
                Dashboard
                {isDashboardActive && isAuthenticated && !authLoading && (
                  <motion.div
                    className="absolute -bottom-1 left-0 right-0 h-0.5 bg-primary"
                    layoutId="activeTab"
                    initial={false}
                    transition={{ type: "spring", stiffness: 500, damping: 30 }}
                  />
                )}
              </Link>

              <div className="relative">
                <button
                  type="button"
                  onClick={handleToggleDesktopResults}
                  className={`relative flex items-center space-x-1 text-sm font-medium transition-colors duration-200 ${
                    resultsDisabled
                      ? "text-foreground/30 cursor-not-allowed"
                      : isResultsActive
                      ? "text-primary"
                      : "text-foreground/70 hover:text-foreground"
                  }`}
                  disabled={resultsDisabled}
                >
                  <span>Results</span>
                  <ChevronDown
                    className={`h-4 w-4 transition-transform ${
                      showResultsDropdown ? "rotate-180" : "rotate-0"
                    }`}
                  />
                  {isResultsActive && !resultsDisabled && (
                    <motion.div
                      className="absolute -bottom-1 left-0 right-0 h-0.5 bg-primary"
                      layoutId="activeTab"
                      initial={false}
                      transition={{ type: "spring", stiffness: 500, damping: 30 }}
                    />
                  )}
                </button>

                <AnimatePresence>
                  {showResultsDropdown && !resultsDisabled && (
                    <motion.div
                      key="results-dropdown"
                      className="absolute right-0 mt-3 w-80 glass-card border border-border/50 rounded-xl shadow-2xl overflow-hidden"
                      initial={{ opacity: 0, y: -8 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -8 }}
                      transition={{ duration: 0.2 }}
                    >
                      <div className="max-h-96 overflow-y-auto">
                        {renderHistoryList()}
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            </nav>

            {/* Auth Actions */}
            <div className="hidden md:flex items-center space-x-3">
              {isAuthenticated ? (
                <>
                  <div className="glass-card flex items-center space-x-2 rounded-lg border border-border/50 px-3 py-2 text-xs text-muted-foreground">
                    <User className="h-4 w-4" />
                    <span className="font-medium text-foreground/80">{user.email}</span>
                  </div>
                  <motion.button
                    onClick={handleNewScanClick}
                    disabled={!canStartScan}
                    className="glass-card px-6 py-2 text-sm font-medium text-foreground hover:bg-primary/10 transition-all duration-300 rounded-lg border border-border/50 hover:border-primary/40 flex items-center space-x-2 disabled:opacity-50"
                    whileHover={{ scale: canStartScan ? 1.05 : 1 }}
                    whileTap={{ scale: canStartScan ? 0.95 : 1 }}
                  >
                    <Play className="h-4 w-4" />
                    <span>New Scan</span>
                  </motion.button>
                  <motion.button
                    onClick={handleLogoutClick}
                    className="glass-card px-4 py-2 text-sm font-medium text-foreground hover:bg-muted/20 transition-all duration-300 rounded-lg border border-border/50 flex items-center space-x-2"
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                  >
                    <LogOut className="h-4 w-4" />
                    <span>Log out</span>
                  </motion.button>
                </>
              ) : (
                <>
                  <Link
                    to="/login"
                    className="glass-card px-4 py-2 text-sm font-medium text-foreground hover:bg-muted/20 transition-all duration-300 rounded-lg border border-border/50"
                  >
                    Log in
                  </Link>
                  <Link
                    to="/signup"
                    className="bg-primary text-primary-foreground px-4 py-2 text-sm font-medium rounded-lg hover:bg-primary/90 transition-all duration-300"
                  >
                    Sign up
                  </Link>
                </>
              )}
            </div>

            {/* Mobile Menu Button */}
            <button
              className="md:hidden p-2 text-foreground hover:bg-muted/20 rounded-lg transition-colors"
              onClick={() => setIsMenuOpen(!isMenuOpen)}
            >
              <svg
                className="w-6 h-6"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                {isMenuOpen ? (
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M6 18L18 6M6 6l12 12"
                  />
                ) : (
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M4 6h16M4 12h16M4 18h16"
                  />
                )}
              </svg>
            </button>
          </div>

          {/* Mobile Menu */}
          <AnimatePresence initial={false}>
            {isMenuOpen && (
              <motion.div
                className="md:hidden py-4 border-t border-border/50"
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: "auto" }}
                exit={{ opacity: 0, height: 0 }}
                transition={{ duration: 0.2 }}
              >
                <div className="flex flex-col space-y-4">
                  <Link
                    to="/"
                    className={`text-sm font-medium transition-colors duration-200 ${
                      !isAuthenticated || authLoading
                        ? "text-foreground/30 cursor-not-allowed"
                        : isDashboardActive
                        ? "text-primary"
                        : "text-foreground/70 hover:text-foreground"
                    }`}
                    onClick={() => {
                      if (isAuthenticated && !authLoading) {
                        setIsMenuOpen(false)
                      }
                    }}
                  >
                    Dashboard
                  </Link>

                  <div className="glass-card border border-border/50 rounded-lg">
                    <button
                      type="button"
                      onClick={handleToggleMobileResults}
                      className={`w-full flex items-center justify-between px-4 py-2 text-sm font-medium transition-colors ${
                        resultsDisabled
                          ? "text-foreground/30 cursor-not-allowed"
                          : isResultsActive
                          ? "text-primary"
                          : "text-foreground/70 hover:text-foreground"
                      }`}
                      disabled={resultsDisabled}
                    >
                      <span>Results</span>
                      <ChevronDown
                        className={`h-4 w-4 transition-transform ${
                          showMobileResults ? "rotate-180" : "rotate-0"
                        }`}
                      />
                    </button>
                    <AnimatePresence initial={false}>
                      {showMobileResults && !resultsDisabled && (
                        <motion.div
                          key="mobile-results"
                          initial={{ opacity: 0, height: 0 }}
                          animate={{ opacity: 1, height: "auto" }}
                          exit={{ opacity: 0, height: 0 }}
                          transition={{ duration: 0.2 }}
                          className="border-t border-border/40"
                        >
                          <div className="max-h-80 overflow-y-auto">
                            {renderHistoryList()}
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </div>

                  {isAuthenticated ? (
                    <>
                      <button
                        onClick={handleNewScanClick}
                        disabled={!canStartScan}
                        className="glass-card px-4 py-2 text-left text-sm font-medium text-foreground border border-border/50 rounded-lg hover:bg-primary/10 disabled:opacity-50"
                      >
                        Start new scan
                      </button>
                      <button
                        onClick={handleLogoutClick}
                        className="glass-card px-4 py-2 text-left text-sm font-medium text-foreground border border-border/50 rounded-lg hover:bg-muted/20"
                      >
                        Log out
                      </button>
                    </>
                  ) : (
                    <div className="flex flex-col space-y-3">
                      <Link
                        to="/login"
                        className="glass-card px-4 py-2 text-sm font-medium text-foreground border border-border/50 rounded-lg hover:bg-muted/20"
                        onClick={() => setIsMenuOpen(false)}
                      >
                        Log in
                      </Link>
                      <Link
                        to="/signup"
                        className="bg-primary text-primary-foreground px-4 py-2 text-sm font-medium rounded-lg hover:bg-primary/90"
                        onClick={() => setIsMenuOpen(false)}
                      >
                        Sign up
                      </Link>
                    </div>
                  )}
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </motion.header>

      {/* Confirmation Dialog */}
      <AnimatePresence>
        {showConfirmDialog && (
          <motion.div
            className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={handleCancelNewScan}
          >
            <motion.div
              className="glass-card p-8 rounded-2xl max-w-md mx-4"
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              onClick={(e) => e.stopPropagation()}
            >
              <div className="flex items-center space-x-3 mb-6">
                <div className="w-12 h-12 bg-orange-500/20 rounded-xl flex items-center justify-center">
                  <AlertTriangle className="h-6 w-6 text-orange-400" />
                </div>
                <div>
                  <h3 className="text-xl font-bold text-foreground">Override Current Scan?</h3>
                  <p className="text-sm text-muted-foreground">This will start a new scan</p>
                </div>
              </div>

              <div className="space-y-4 mb-6">
                <p className="text-foreground">
                  You have a {currentScan?.status} scan in progress. Starting a new scan will override the current one.
                </p>
                <div className="glass-card p-4 rounded-lg">
                  <p className="text-sm text-muted-foreground">
                    <span className="font-medium">Current Target:</span> {currentScan?.targetUrl}
                  </p>
                  <p className="text-sm text-muted-foreground">
                    <span className="font-medium">Status:</span> {currentScan?.status}
                  </p>
                </div>
              </div>

              <div className="flex space-x-3">
                <motion.button
                  onClick={handleCancelNewScan}
                  className="flex-1 px-4 py-2 glass-card text-foreground hover:bg-muted/20 transition-colors rounded-lg border border-border/50"
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                >
                  Cancel
                </motion.button>
                <motion.button
                  onClick={handleConfirmNewScan}
                  className="flex-1 px-4 py-2 bg-primary text-primary-foreground hover:bg-primary/90 transition-colors rounded-lg font-medium"
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                >
                  Start New Scan
                </motion.button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  )
}

export default NavigationBar
