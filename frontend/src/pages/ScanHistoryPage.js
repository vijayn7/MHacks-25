"use client"

import { useEffect, useState, useMemo, useCallback } from "react"
import { useNavigate, Link } from "react-router-dom"
import { api } from "../lib/api"
import { motion } from "framer-motion"
import { History, RefreshCw, ArrowRight, AlertTriangle, Clock, Search, Filter, X, Trash2 } from "lucide-react"

const STATUS_STYLES = {
  queued: "bg-amber-500/10 text-amber-400 border border-amber-500/20",
  running: "bg-sky-500/10 text-sky-400 border border-sky-500/20",
  completed: "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20",
  failed: "bg-rose-500/10 text-rose-400 border border-rose-500/20",
}

const formatDateTime = (value) => {
  if (!value) return ""
  try {
    return new Intl.DateTimeFormat(undefined, {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    }).format(new Date(value))
  } catch (error) {
    return value
  }
}

const ScanHistoryPage = () => {
  const navigate = useNavigate()
  const [runs, setRuns] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [searchQuery, setSearchQuery] = useState("")
  const [statusFilter, setStatusFilter] = useState("")
  const [showFilters, setShowFilters] = useState(false)
  const [deletingRunId, setDeletingRunId] = useState(null)

  const hasRuns = runs.length > 0

  const fetchRuns = useCallback(async (isRefresh = false) => {
    if (isRefresh) {
      setIsRefreshing(true)
    } else {
      setLoading(true)
    }
    setError(null)

    try {
      const params = new URLSearchParams()
      if (searchQuery.trim()) {
        params.append('search', searchQuery.trim())
      }
      if (statusFilter) {
        params.append('status', statusFilter)
      }
      
      const response = await api(`/runs?${params.toString()}`)
      setRuns(Array.isArray(response) ? response : [])
    } catch (err) {
      if (err.message.includes('401') || err.message.includes('unauthorized')) {
        navigate("/login")
        return
      }
      setError(err.message || "Unable to load scan history")
    } finally {
      setLoading(false)
      setIsRefreshing(false)
    }
  }, [searchQuery, statusFilter, navigate])

  const handleSearchChange = (e) => {
    setSearchQuery(e.target.value)
  }

  const handleStatusFilterChange = (e) => {
    setStatusFilter(e.target.value)
  }

  const clearFilters = () => {
    setSearchQuery("")
    setStatusFilter("")
  }

  const handleSearch = () => {
    fetchRuns()
  }

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      handleSearch()
    }
  }

  const handleDeleteRun = async (runId, e) => {
    e.stopPropagation() // Prevent navigation when clicking delete
    
    if (!window.confirm('Are you sure you want to delete this scan? This action cannot be undone and will delete all findings and data associated with this scan.')) {
      return
    }

    setDeletingRunId(runId)
    try {
      await api(`/runs/${runId}`, { method: 'DELETE' })
      // Remove the deleted run from the local state
      setRuns(runs.filter(run => run.id !== runId))
    } catch (error) {
      console.error('Delete error:', error)
      alert('Failed to delete scan: ' + error.message)
    } finally {
      setDeletingRunId(null)
    }
  }

  useEffect(() => {
    fetchRuns()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Auto-search when filters change (with debounce)
  useEffect(() => {
    const timeoutId = setTimeout(() => {
      if (searchQuery || statusFilter) {
        fetchRuns()
      }
    }, 300)

    return () => clearTimeout(timeoutId)
  }, [searchQuery, statusFilter, fetchRuns])

  const summaryStats = useMemo(() => {
    if (!runs.length) {
      return { totalFindings: 0, avgRisk: 0 }
    }

    const totals = runs.reduce(
      (acc, run) => {
        acc.totalFindings += run.finding_count || 0
        acc.totalRisk += run.risk_score || 0
        return acc
      },
      { totalFindings: 0, totalRisk: 0 }
    )

    return {
      totalFindings: totals.totalFindings,
      avgRisk: Math.round((totals.totalRisk / runs.length) * 10) / 10,
    }
  }, [runs])

  return (
    <div className="space-y-8">
      <div className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-4">
        <div>
          <h2 className="text-3xl font-semibold text-foreground flex items-center gap-3">
            <span className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-primary/10 text-primary">
              <History className="w-6 h-6" />
            </span>
            Scan History
          </h2>
          <p className="mt-2 text-sm text-muted-foreground max-w-2xl">
            Review every scan executed by your account, including when it was started,
            how many findings were detected, and the overall risk scores.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setShowFilters(!showFilters)}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-border/50 text-sm font-medium text-foreground hover:bg-muted/30 transition"
          >
            <Filter className="w-4 h-4" />
            Filters
          </button>
          <button
            type="button"
            onClick={() => fetchRuns(true)}
            disabled={loading || isRefreshing}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-border/50 text-sm font-medium text-foreground hover:bg-muted/30 transition disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${isRefreshing ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Search and Filter Section */}
      {showFilters && (
        <motion.div
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: "auto" }}
          exit={{ opacity: 0, height: 0 }}
          className="glass-card p-6 rounded-2xl border border-border/50"
        >
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label htmlFor="search" className="block text-sm font-medium text-foreground mb-2">
                Search
              </label>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <input
                  type="text"
                  id="search"
                  value={searchQuery}
                  onChange={handleSearchChange}
                  onKeyPress={handleKeyPress}
                  placeholder="Search by name or URL..."
                  className="w-full pl-10 pr-4 py-2 bg-input border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
                />
              </div>
            </div>
            <div>
              <label htmlFor="status" className="block text-sm font-medium text-foreground mb-2">
                Status
              </label>
              <select
                id="status"
                value={statusFilter}
                onChange={handleStatusFilterChange}
                className="w-full px-3 py-2 bg-input border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
              >
                <option value="">All Statuses</option>
                <option value="queued">Queued</option>
                <option value="running">Running</option>
                <option value="completed">Completed</option>
                <option value="failed">Failed</option>
              </select>
            </div>
            <div className="flex items-end">
              <button
                type="button"
                onClick={clearFilters}
                className="w-full inline-flex items-center justify-center gap-2 px-4 py-2 rounded-lg border border-border/50 text-sm font-medium text-foreground hover:bg-muted/30 transition"
              >
                <X className="w-4 h-4" />
                Clear Filters
              </button>
            </div>
          </div>
        </motion.div>
      )}

      <motion.div
        className="grid grid-cols-1 md:grid-cols-3 gap-4"
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.1 }}
      >
        <div className="glass-card border border-border/40 rounded-2xl p-6">
          <p className="text-sm text-muted-foreground">Total Scans</p>
          <p className="mt-2 text-3xl font-semibold text-foreground">{runs.length}</p>
        </div>
        <div className="glass-card border border-border/40 rounded-2xl p-6">
          <p className="text-sm text-muted-foreground">Total Findings Logged</p>
          <p className="mt-2 text-3xl font-semibold text-foreground">{summaryStats.totalFindings}</p>
        </div>
        <div className="glass-card border border-border/40 rounded-2xl p-6">
          <p className="text-sm text-muted-foreground">Average Risk Score</p>
          <p className="mt-2 text-3xl font-semibold text-foreground">{summaryStats.avgRisk}</p>
        </div>
      </motion.div>

      <motion.div
        className="glass-card no-contain border border-border/50 rounded-2xl overflow-hidden"
        initial={{ opacity: 0, y: 24 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.2 }}
      >
        {loading ? (
          <div className="py-16 text-center text-muted-foreground text-sm">Loading scan history…</div>
        ) : error ? (
          <div className="py-16 px-6 text-center">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-rose-500/10 text-rose-400 text-sm font-medium">
              <AlertTriangle className="w-4 h-4" />
              Error loading history
            </div>
            <p className="mt-4 text-sm text-muted-foreground">{error}</p>
            <button
              type="button"
              onClick={() => fetchRuns()}
              className="mt-6 inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-border/50 text-sm font-medium text-foreground hover:bg-muted/30 transition"
            >
              Try again
            </button>
          </div>
        ) : !hasRuns ? (
          <div className="py-16 px-6 text-center space-y-4">
            <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-muted/10 text-muted-foreground">
              <Clock className="w-7 h-7" />
            </div>
            <div>
              <h3 className="text-lg font-semibold text-foreground">No scans yet</h3>
              <p className="mt-2 text-sm text-muted-foreground">
                Start a new scan from the dashboard to begin building your security history.
              </p>
            </div>
            <Link
              to="/"
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-primary text-primary-foreground text-sm font-medium hover:bg-primary/90 transition"
            >
              Launch your first scan
              <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
        ) : (
          <div className="divide-y divide-border/50">
            <div className="grid grid-cols-12 gap-4 px-6 py-4 text-xs font-medium uppercase tracking-wide text-muted-foreground">
              <span className="col-span-4">Target</span>
              <span className="col-span-2">Status</span>
              <span className="col-span-2">Findings</span>
              <span className="col-span-2">Risk Score</span>
              <span className="col-span-1 text-right">Started</span>
              <span className="col-span-1 text-center">Actions</span>
            </div>
            <div className="divide-y divide-border/40">
              {runs.map((run) => (
                <button
                  key={run.id}
                  type="button"
                  onClick={() => navigate(`/scan/${run.id}`)}
                  className="w-full text-left px-6 py-5 transition hover:bg-primary/5 focus:outline-none focus-visible:ring-2 focus-visible:ring-primary/50"
                >
                  <div className="grid grid-cols-12 gap-4 items-center">
                    <div className="col-span-4 min-w-0">
                      <p className="text-sm font-medium text-foreground truncate">
                        {run.name || run.target_url}
                      </p>
                      <p className="mt-1 text-xs text-muted-foreground">
                        {run.name ? `Target: ${run.target_url}` : `Run ID: ${run.id}`}
                      </p>
                      {run.name && (
                        <p className="mt-1 text-xs text-muted-foreground">Run ID: {run.id}</p>
                      )}
                    </div>
                    <div className="col-span-2">
                      <span
                        className={`inline-flex items-center px-2.5 py-1 text-xs font-semibold rounded-full ${
                          STATUS_STYLES[run.status] || "bg-muted text-foreground/80"
                        }`}
                      >
                        {run.status ? run.status.charAt(0).toUpperCase() + run.status.slice(1) : "Unknown"}
                      </span>
                    </div>
                    <div className="col-span-2 text-sm text-foreground">
                      {run.finding_count ?? 0}
                    </div>
                    <div className="col-span-2 text-sm text-foreground">
                      {run.risk_score ?? 0}
                    </div>
                    <div className="col-span-1 text-right text-xs text-muted-foreground">
                      {formatDateTime(run.created_at)}
                    </div>
                    <div className="col-span-1 text-center">
                      <motion.button
                        onClick={(e) => handleDeleteRun(run.id, e)}
                        disabled={deletingRunId === run.id}
                        className="p-1 text-red-400 hover:text-red-300 transition-colors disabled:opacity-50"
                        whileHover={{ scale: 1.1 }}
                        whileTap={{ scale: 0.9 }}
                        title="Delete scan"
                      >
                        <Trash2 className="h-4 w-4" />
                      </motion.button>
                    </div>
                  </div>
                </button>
              ))}
            </div>
          </div>
        )}
      </motion.div>
    </div>
  )
}

export default ScanHistoryPage
