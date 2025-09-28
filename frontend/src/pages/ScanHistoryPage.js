"use client"

import { useEffect, useState, useMemo } from "react"
import { useNavigate, Link } from "react-router-dom"
import axios from "axios"
import { motion } from "framer-motion"
import { History, RefreshCw, ArrowRight, AlertTriangle, Clock } from "lucide-react"

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

  const hasRuns = runs.length > 0

  const fetchRuns = async (isRefresh = false) => {
    if (isRefresh) {
      setIsRefreshing(true)
    } else {
      setLoading(true)
    }
    setError(null)

    try {
      const response = await axios.get("/runs")
      setRuns(Array.isArray(response.data) ? response.data : [])
    } catch (err) {
      if (err.response?.status === 401) {
        navigate("/login")
        return
      }
      setError(err.response?.data?.detail || "Unable to load scan history")
    } finally {
      setLoading(false)
      setIsRefreshing(false)
    }
  }

  useEffect(() => {
    fetchRuns()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

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
              <span className="col-span-5">Target</span>
              <span className="col-span-2">Status</span>
              <span className="col-span-2">Findings</span>
              <span className="col-span-2">Risk Score</span>
              <span className="col-span-1 text-right">Started</span>
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
                    <div className="col-span-5 min-w-0">
                      <p className="text-sm font-medium text-foreground truncate">{run.target_url}</p>
                      <p className="mt-1 text-xs text-muted-foreground">Run ID: {run.id}</p>
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
