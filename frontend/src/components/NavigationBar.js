"use client"

import { useState } from "react"
import { Link, useLocation, useNavigate } from "react-router-dom"
import { motion, AnimatePresence } from "framer-motion"
import { Shield, Play, AlertTriangle, Settings, Search } from "lucide-react"

const NavigationBar = ({ currentScan, onNewScan }) => {
  const location = useLocation()
  const navigate = useNavigate()
  const [isMenuOpen, setIsMenuOpen] = useState(false)
  const [showConfirmDialog, setShowConfirmDialog] = useState(false)

  // Check if we're currently on a scan results page
  const isOnScanResults = location.pathname.startsWith("/scan/")

  const navItems = [
    { name: "Dashboard", path: "/" },
    { name: "Results", path: "/results" },
    { name: "Build", path: "/build" }
  ]

  const isActive = (path) => {
    if (path === "/") {
      return location.pathname === "/"
    }
    if (path === "/results") {
      return location.pathname === "/results" || location.pathname.startsWith("/scan/")
    }
    if (path === "/build") {
      return location.pathname === "/build"
    }
    return location.pathname === path
  }

  const handleNewScanClick = () => {
    // If there's an active scan, show confirmation dialog
    if (currentScan && (currentScan.status === "running" || currentScan.status === "completed")) {
      setShowConfirmDialog(true)
    } else {
      // No active scan, go directly to dashboard
      navigate("/")
    }
  }

  const handleConfirmNewScan = () => {
    setShowConfirmDialog(false)
    navigate("/")
    // Call the onNewScan callback to reset the current scan state
    if (onNewScan) {
      onNewScan()
    }
  }

  const handleCancelNewScan = () => {
    setShowConfirmDialog(false)
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
              {navItems.map((item) => (
                <Link
                  key={item.name}
                  to={item.path}
                  className={`relative text-sm font-medium transition-colors duration-200 ${
                    isActive(item.path)
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

            {/* CTA Button */}
            <motion.button
              onClick={handleNewScanClick}
              className="glass-card px-6 py-2 text-sm font-medium text-foreground hover:bg-primary/10 transition-all duration-300 rounded-lg border border-border/50 hover:border-primary/40 flex items-center space-x-2"
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
            >
              <Play className="h-4 w-4" />
              <span>New Scan</span>
            </motion.button>

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
                    className={`text-sm font-medium transition-colors duration-200 ${
                      isActive(item.path)
                        ? "text-primary"
                        : "text-foreground/70 hover:text-foreground"
                    }`}
                    onClick={() => setIsMenuOpen(false)}
                  >
                    {item.name}
                  </Link>
                ))}
              </div>
            </motion.div>
          )}
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

