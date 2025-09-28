"use client"

import { useState } from "react"
import { motion } from "framer-motion"
import { Shield, AlertTriangle, Target, Zap, Lock, Search } from "lucide-react"

const ScanDashboard = ({ onStartScan }) => {
  const [targetUrl, setTargetUrl] = useState("http://localhost:3001")
  const [scanName, setScanName] = useState("")
  const [maxPages, setMaxPages] = useState(30)
  const [notifyEmail, setNotifyEmail] = useState("")
  const [isLoading, setIsLoading] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()

    if (!targetUrl) {
      alert("Please enter a target URL")
      return
    }

    try {
      new URL(targetUrl)
    } catch {
      alert("Please enter a valid URL")
      return
    }

    setIsLoading(true)

    const scanRequest = {
      target_url: targetUrl,
      name: scanName || null,
      max_pages: maxPages,
      notify_email: notifyEmail || null,
    }

    await onStartScan(scanRequest)
    setIsLoading(false)
  }

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: 0.1,
        delayChildren: 0.2,
      },
    },
  }

  const itemVariants = {
    hidden: { y: 20, opacity: 0 },
    visible: {
      y: 0,
      opacity: 1,
      transition: {
        type: "spring",
        stiffness: 100,
        damping: 10,
      },
    },
  }

  return (
    <motion.div className="px-4 py-6" variants={containerVariants} initial="hidden" animate="visible">
      {/* Hero Section */}
      <motion.div className="text-center mb-16" variants={itemVariants}>
        <motion.div
          className="inline-flex items-center justify-center w-24 h-24 glass-card rounded-2xl mb-8 pulse-glow overflow-hidden"
          whileHover={{ scale: 1.1, rotate: 5 }}
          transition={{ type: "spring", stiffness: 400, damping: 10 }}
        >
          <img 
            src="/Favicon.png" 
            alt="Swarm Logo" 
            className="w-16 h-16 object-contain"
          />
        </motion.div>

        <motion.h1 className="text-6xl font-bold mb-6 text-balance" variants={itemVariants}>
          <span className="gradient-text">Advanced Security</span>
          <br />
          <span className="text-foreground">Scanner</span>
        </motion.h1>

        <motion.p className="text-xl text-muted-foreground max-w-4xl mx-auto leading-relaxed" variants={itemVariants}>
          Identify critical vulnerabilities with enterprise-grade scanning technology. Get actionable insights and fix
          snippets to secure your web applications instantly.
        </motion.p>
      </motion.div>

      {/* Main Form */}
      <motion.div className="max-w-3xl mx-auto mb-16" variants={itemVariants}>
        <motion.div
          className="glass-card p-10 rounded-2xl"
          whileHover={{ scale: 1.01 }}
          transition={{ type: "spring", stiffness: 400, damping: 10 }}
        >
          <form onSubmit={handleSubmit} className="space-y-8">
            <motion.div variants={itemVariants}>
              <label htmlFor="targetUrl" className="block text-lg font-semibold text-foreground mb-4">
                Target URL
              </label>
              <div className="relative">
                <Target className="absolute left-4 top-4 h-6 w-6 text-muted-foreground" />
                <motion.input
                  type="url"
                  id="targetUrl"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  placeholder="https://example.com"
                  className="block w-full pl-14 pr-4 py-4 bg-input border border-border rounded-xl focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent text-lg transition-all duration-300"
                  required
                  whileFocus={{ scale: 1.02 }}
                />
              </div>
              <p className="mt-3 text-muted-foreground">Enter the URL you want to scan for security vulnerabilities</p>
            </motion.div>

            <motion.div variants={itemVariants}>
              <label htmlFor="scanName" className="block text-lg font-semibold text-foreground mb-4">
                Scan Instance Name (Optional)
              </label>
              <motion.input
                type="text"
                id="scanName"
                value={scanName}
                onChange={(e) => setScanName(e.target.value)}
                placeholder="My Security Scan"
                className="block w-full px-4 py-4 bg-input border border-border rounded-xl focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent text-lg transition-all duration-300"
                whileFocus={{ scale: 1.02 }}
              />
              <p className="mt-3 text-muted-foreground">Give your scan a custom name to easily identify it later</p>
            </motion.div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
              <motion.div variants={itemVariants}>
                <label htmlFor="maxPages" className="block text-lg font-semibold text-foreground mb-4">
                  Max Pages
                </label>
                <motion.input
                  type="number"
                  id="maxPages"
                  value={maxPages}
                  onChange={(e) => setMaxPages(Number.parseInt(e.target.value))}
                  min="1"
                  max="100"
                  className="block w-full px-4 py-4 bg-input border border-border rounded-xl focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent text-lg transition-all duration-300"
                  whileFocus={{ scale: 1.02 }}
                />
              </motion.div>

              <motion.div variants={itemVariants}>
                <label htmlFor="notifyEmail" className="block text-lg font-semibold text-foreground mb-4">
                  Notification Email
                </label>
                <motion.input
                  type="email"
                  id="notifyEmail"
                  value={notifyEmail}
                  onChange={(e) => setNotifyEmail(e.target.value)}
                  placeholder="you@example.com"
                  className="block w-full px-4 py-4 bg-input border border-border rounded-xl focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent text-lg transition-all duration-300"
                  whileFocus={{ scale: 1.02 }}
                />
              </motion.div>
            </div>

            <motion.button
              type="submit"
              disabled={isLoading}
              className="w-full bg-primary text-primary-foreground py-5 px-8 rounded-xl hover:bg-primary/90 focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 font-semibold text-lg flex items-center justify-center space-x-3"
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
              variants={itemVariants}
            >
              {isLoading ? (
                <>
                  <motion.div
                    className="w-6 h-6 border-2 border-primary-foreground/30 border-t-primary-foreground rounded-full"
                    animate={{ rotate: 360 }}
                    transition={{ duration: 1, repeat: Number.POSITIVE_INFINITY, ease: "linear" }}
                  />
                  <span>Initializing Scan...</span>
                </>
              ) : (
                <>
                  <Search className="h-6 w-6" />
                  <span>Start Security Scan</span>
                </>
              )}
            </motion.button>
          </form>
        </motion.div>
      </motion.div>

      {/* Feature Cards */}
      <motion.div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-16" variants={containerVariants}>
        {[
          {
            icon: Shield,
            title: "Non-Destructive",
            description: "Safe, read-only scans that don't modify your application or data",
            color: "text-green-400",
          },
          {
            icon: Zap,
            title: "Lightning Fast",
            description: "Advanced parallel scanning technology for rapid vulnerability detection",
            color: "text-yellow-400",
          },
          {
            icon: Lock,
            title: "Enterprise Security",
            description: "Military-grade encryption and secure data handling protocols",
            color: "text-blue-400",
          },
        ].map((feature, index) => (
          <motion.div
            key={index}
            className="glass-card p-8 rounded-2xl text-center group"
            variants={itemVariants}
            whileHover={{ scale: 1.05, y: -5 }}
            transition={{ type: "spring", stiffness: 400, damping: 10 }}
          >
            <motion.div
              className={`inline-flex items-center justify-center w-16 h-16 rounded-xl mb-6 ${feature.color} bg-current/10`}
              whileHover={{ rotate: 10 }}
            >
              <feature.icon className={`h-8 w-8 ${feature.color}`} />
            </motion.div>
            <h3 className="text-xl font-bold text-foreground mb-4 group-hover:text-primary transition-colors">
              {feature.title}
            </h3>
            <p className="text-muted-foreground leading-relaxed">{feature.description}</p>
          </motion.div>
        ))}
      </motion.div>

      {/* Legal Notice */}
      <motion.div className="max-w-4xl mx-auto" variants={itemVariants}>
        <motion.div
          className="glass-card p-6 rounded-xl border border-yellow-500/20 bg-yellow-500/5"
          whileHover={{ scale: 1.01 }}
        >
          <div className="flex items-start space-x-4">
            <AlertTriangle className="h-6 w-6 text-yellow-400 mt-1 flex-shrink-0" />
            <div>
              <h3 className="text-lg font-semibold text-yellow-400 mb-2">Legal Compliance Notice</h3>
              <p className="text-muted-foreground leading-relaxed">
                Only scan websites you own or have explicit written permission to test. By starting a scan, you confirm
                you have the legal right to do so and accept full responsibility for compliance with applicable laws and
                regulations.
              </p>
            </div>
          </div>
        </motion.div>
      </motion.div>
    </motion.div>
  )
}

export default ScanDashboard