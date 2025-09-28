"use client"

import { useState, useEffect } from "react"
import { Link, useLocation, useNavigate } from "react-router-dom"
import { motion, AnimatePresence } from "framer-motion"
import { Shield, Play, AlertTriangle, LogOut, User } from "lucide-react"

const NavigationBar = ({ currentScan, onNewScan, user, onLogout, authLoading = false }) => {
  const location = useLocation()
  const navigate = useNavigate()
  const [isMenuOpen, setIsMenuOpen] = useState(false)
  const [showConfirmDialog, setShowConfirmDialog] = useState(false)
  const isAuthenticated = Boolean(user)
  const canStartScan = isAuthenticated && !authLoading
  const resultsDisabled = !isAuthenticated || authLoading

  useEffect(() => {
    setIsMenuOpen(false)
  }, [location.pathname])

  const navItems = [
    { name: "Dashboard", path: "/" },
    { name: "AI Assistant", path: "/agentic" },
    { name: "Blocks", path: "/blocks" },
    { name: "Results", path: "/runs" },
  ]

  const isActive = (path) => {
    if (path === "/") {
      return location.pathname === "/"
    }
    if (path === "/runs") {
      return location.pathname === "/runs" || location.pathname.startsWith("/scan/")
    }
    if (path === "/blocks") {
      return location.pathname === "/blocks"
    }
    if (path === "/agentic") {
      return location.pathname === "/agentic"
    }
    return location.pathname === path
  }

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

  const handleResultsClick = (event) => {
    if (resultsDisabled) {
      event.preventDefault()
      if (!authLoading) {
        navigate("/login")
      }
    }
  }

  return (
    <>
      <motion.header
        className="glass-card no-contain border-b border-border/50 relative z-30"
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
              {navItems.map((item) => (
                <Link
                  key={item.name}
                  to={item.path}
                  onClick={item.name === "Results" ? handleResultsClick : undefined}
                  className={`relative text-sm font-medium transition-colors duration-200 ${
                    item.name === "Results" && resultsDisabled
                      ? "text-foreground/30 cursor-not-allowed"
                      : item.name === "Dashboard" && (!isAuthenticated || authLoading)
                      ? "text-foreground/30 cursor-not-allowed"
                      : isActive(item.path)
                      ? "text-primary"
                      : "text-foreground/70 hover:text-foreground"
                  }`}
                >
                  {item.name}
                  {isActive(item.path) && (
                    <motion.div
                      className="absolute -bottom-1 left-0 right-0 h-0.5 bg-primary"
                      layoutId="activeTab"
                      initial={false}
                      transition={{ type: "spring", stiffness: 500, damping: 30 }}
                    />
                  )}
                </Link>
              ))}
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
                  {navItems.map((item) => (
                    <Link
                      key={item.name}
                      to={item.path}
                      onClick={(event) => {
                        if (item.name === "Results") {
                          handleResultsClick(event)
                          if (!resultsDisabled) {
                            setIsMenuOpen(false)
                          }
                        } else if (item.name === "Dashboard") {
                          if (isAuthenticated && !authLoading) {
                            setIsMenuOpen(false)
                          }
                        } else {
                          setIsMenuOpen(false)
                        }
                      }}
                      className={`glass-card px-4 py-2 text-sm font-medium border border-border/50 rounded-lg transition-colors ${
                        item.name === "Results" && resultsDisabled
                          ? "text-foreground/30 cursor-not-allowed"
                          : item.name === "Dashboard" && (!isAuthenticated || authLoading)
                          ? "text-foreground/30 cursor-not-allowed"
                          : isActive(item.path)
                          ? "text-primary"
                          : "text-foreground/70 hover:text-foreground"
                      }`}
                    >
                      {item.name}
                    </Link>
                  ))}

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
