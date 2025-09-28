"use client"

import { useState } from "react"
import { motion } from "framer-motion"
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  Copy, 
  ExternalLink,
  Github,
  Key,
  Settings,
  Zap,
  Lock,
  Search,
  Code,
  FileText,
  Users,
  Star
} from "lucide-react"

const GitHubAuditor = () => {
  const [copiedSection, setCopiedSection] = useState(null)

  const copyToClipboard = (text, section) => {
    // Convert escaped braces back to GitHub Actions syntax for copying
    const correctedText = text.replace(/\$\{\{/g, '${{').replace(/\}\}/g, '}}')
    navigator.clipboard.writeText(correctedText)
    setCopiedSection(section)
    setTimeout(() => setCopiedSection(null), 2000)
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

  const workflowYaml = `name: Security Analysis

on:
  pull_request:
    types: [opened, synchronize]
    branches: [main]

jobs:
  security-analysis:
    uses: vannapu7/MHacks-25/.github/workflows/pr-code-analysis.yml@main
    with:
      analysis_scope: 'full'  # Options: full, focused, quick
      fail_on_critical: true   # Set to false to not fail PR on critical issues
    secrets:
      GEMINI_API_KEY: $\{\{ secrets.GEMINI_API_KEY \}\}`

  const features = [
    {
      icon: Shield,
      title: "OWASP Top 10 Coverage",
      description: "Comprehensive analysis covering all OWASP Top 10 vulnerabilities",
      color: "text-green-400",
    },
    {
      icon: Zap,
      title: "Lightning Fast",
      description: "AI-powered analysis that completes in minutes, not hours",
      color: "text-yellow-400",
    },
    {
      icon: Lock,
      title: "Enterprise Security",
      description: "Military-grade security analysis with detailed remediation steps",
      color: "text-blue-400",
    },
  ]

  const attackCategories = [
    "Injection Attacks (SQL, NoSQL, Command)",
    "Authentication Attacks (Brute force, JWT flaws)",
    "Authorization Attacks (IDOR, privilege escalation)",
    "Business Logic Attacks (Price manipulation, race conditions)",
    "Data Exposure Attacks (Sensitive data leaks)",
    "Cryptography Attacks (Weak encryption)",
    "Insecure Design Attacks (Missing validation)",
    "Vulnerable Components (Outdated dependencies)"
  ]

  const riskLevels = [
    { level: "Critical", color: "text-red-400", description: "Immediate action required" },
    { level: "High", color: "text-orange-400", description: "Fix before production" },
    { level: "Medium", color: "text-yellow-400", description: "Address in next release" },
    { level: "Low", color: "text-green-400", description: "Best practice recommendations" }
  ]

  return (
    <motion.div className="px-4 py-6" variants={containerVariants} initial="hidden" animate="visible">
      {/* Hero Section */}
      <motion.div className="text-center mb-16" variants={itemVariants}>
        <motion.div
          className="inline-flex items-center justify-center w-24 h-24 glass-card rounded-2xl mb-8 pulse-glow overflow-hidden"
          whileHover={{ scale: 1.1, rotate: 5 }}
          transition={{ type: "spring", stiffness: 400, damping: 10 }}
        >
          <Github className="w-16 h-16 text-primary" />
        </motion.div>

        <motion.h1 className="text-6xl font-bold mb-6 text-balance" variants={itemVariants}>
          <span className="gradient-text">SwarmAI Auditor</span>
          <br />
          <span className="text-foreground">GitHub Integration</span>
        </motion.h1>

        <motion.p className="text-xl text-muted-foreground max-w-4xl mx-auto leading-relaxed" variants={itemVariants}>
          Automatically analyze your pull requests for security vulnerabilities with AI-powered scanning. 
          Get instant feedback and fix suggestions to keep your code secure.
        </motion.p>
      </motion.div>

      {/* Quick Setup Section */}
      <motion.div className="max-w-4xl mx-auto mb-16" variants={itemVariants}>
        <motion.div
          className="glass-card p-10 rounded-2xl"
          whileHover={{ scale: 1.01 }}
          transition={{ type: "spring", stiffness: 400, damping: 10 }}
        >
          <div className="flex items-center space-x-3 mb-8">
            <div className="w-12 h-12 bg-green-500/20 rounded-xl flex items-center justify-center">
              <Zap className="h-6 w-6 text-green-400" />
            </div>
            <div>
              <h2 className="text-3xl font-bold text-foreground">🚀 Quick Setup (2 minutes)</h2>
              <p className="text-muted-foreground">Get started with automated security analysis in just 2 minutes</p>
            </div>
          </div>

          <div className="space-y-8">
            {/* Step 1 */}
            <div className="space-y-4">
              <div className="flex items-center space-x-3">
                <div className="w-8 h-8 bg-primary rounded-full flex items-center justify-center text-primary-foreground font-bold text-sm">1</div>
                <h3 className="text-xl font-semibold text-foreground">Add the Workflow</h3>
              </div>
              <p className="text-muted-foreground ml-11">Create <code className="bg-muted px-2 py-1 rounded text-sm">.github/workflows/security-analysis.yml</code> in your repository:</p>
              
              <div className="ml-11 relative">
                <div className="glass-card p-4 rounded-lg border border-border/50">
                  <pre className="text-sm text-foreground overflow-x-auto">
                    <code>{workflowYaml.replace(/\$\{\{/g, '${{').replace(/\}\}/g, '}}')}</code>
                  </pre>
                </div>
                <motion.button
                  onClick={() => copyToClipboard(workflowYaml, 'workflow')}
                  className="absolute top-2 right-2 p-2 glass-card rounded-lg hover:bg-primary/10 transition-colors"
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                >
                  {copiedSection === 'workflow' ? (
                    <CheckCircle className="h-4 w-4 text-green-400" />
                  ) : (
                    <Copy className="h-4 w-4 text-muted-foreground" />
                  )}
                </motion.button>
              </div>
            </div>

            {/* Step 2 */}
            <div className="space-y-4">
              <div className="flex items-center space-x-3">
                <div className="w-8 h-8 bg-primary rounded-full flex items-center justify-center text-primary-foreground font-bold text-sm">2</div>
                <h3 className="text-xl font-semibold text-foreground">Add Your Gemini API Key</h3>
              </div>
              <div className="ml-11 space-y-3">
                <div className="flex items-center space-x-2">
                  <div className="w-6 h-6 bg-blue-500/20 rounded-lg flex items-center justify-center">
                    <Settings className="h-4 w-4 text-blue-400" />
                  </div>
                  <p className="text-muted-foreground">Go to <strong>Settings</strong> → <strong>Secrets and variables</strong> → <strong>Actions</strong></p>
                </div>
                <div className="flex items-center space-x-2">
                  <div className="w-6 h-6 bg-green-500/20 rounded-lg flex items-center justify-center">
                    <CheckCircle className="h-4 w-4 text-green-400" />
                  </div>
                  <p className="text-muted-foreground">Click <strong>"New repository secret"</strong></p>
                </div>
                <div className="flex items-center space-x-2">
                  <div className="w-6 h-6 bg-yellow-500/20 rounded-lg flex items-center justify-center">
                    <Key className="h-4 w-4 text-yellow-400" />
                  </div>
                  <p className="text-muted-foreground"><strong>Name:</strong> <code className="bg-muted px-2 py-1 rounded text-sm">GEMINI_API_KEY</code></p>
                </div>
                <div className="flex items-center space-x-2">
                  <div className="w-6 h-6 bg-purple-500/20 rounded-lg flex items-center justify-center">
                    <Key className="h-4 w-4 text-purple-400" />
                  </div>
                  <p className="text-muted-foreground"><strong>Value:</strong> Your Gemini API key</p>
                </div>
                <div className="flex items-center space-x-2">
                  <div className="w-6 h-6 bg-green-500/20 rounded-lg flex items-center justify-center">
                    <CheckCircle className="h-4 w-4 text-green-400" />
                  </div>
                  <p className="text-muted-foreground">Click <strong>"Add secret"</strong></p>
                </div>
              </div>
            </div>

            {/* Step 3 */}
            <div className="space-y-4">
              <div className="flex items-center space-x-3">
                <div className="w-8 h-8 bg-primary rounded-full flex items-center justify-center text-primary-foreground font-bold text-sm">3</div>
                <h3 className="text-xl font-semibold text-foreground">Test It!</h3>
              </div>
              <p className="text-muted-foreground ml-11">Create a pull request to trigger the security analysis.</p>
            </div>
          </div>
        </motion.div>
      </motion.div>

      {/* Configuration Options */}
      <motion.div className="max-w-4xl mx-auto mb-16" variants={itemVariants}>
        <motion.div
          className="glass-card p-8 rounded-2xl"
          whileHover={{ scale: 1.01 }}
          transition={{ type: "spring", stiffness: 400, damping: 10 }}
        >
          <div className="flex items-center space-x-3 mb-6">
            <div className="w-10 h-10 bg-blue-500/20 rounded-xl flex items-center justify-center">
              <Settings className="h-5 w-5 text-blue-400" />
            </div>
            <h2 className="text-2xl font-bold text-foreground">🔧 Configuration Options</h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            <div>
              <h3 className="text-lg font-semibold text-foreground mb-4">Analysis Scope</h3>
              <div className="space-y-3">
                <div className="flex items-center space-x-3">
                  <div className="w-2 h-2 bg-green-400 rounded-full"></div>
                  <div>
                    <code className="text-sm font-mono text-foreground">full</code>
                    <span className="text-muted-foreground ml-2">(default): Comprehensive analysis</span>
                  </div>
                </div>
                <div className="flex items-center space-x-3">
                  <div className="w-2 h-2 bg-yellow-400 rounded-full"></div>
                  <div>
                    <code className="text-sm font-mono text-foreground">focused</code>
                    <span className="text-muted-foreground ml-2">: Key security areas only</span>
                  </div>
                </div>
                <div className="flex items-center space-x-3">
                  <div className="w-2 h-2 bg-blue-400 rounded-full"></div>
                  <div>
                    <code className="text-sm font-mono text-foreground">quick</code>
                    <span className="text-muted-foreground ml-2">: Basic security check</span>
                  </div>
                </div>
              </div>
            </div>

            <div>
              <h3 className="text-lg font-semibold text-foreground mb-4">Failure Behavior</h3>
              <div className="space-y-3">
                <div className="flex items-center space-x-3">
                  <div className="w-2 h-2 bg-red-400 rounded-full"></div>
                  <div>
                    <code className="text-sm font-mono text-foreground">true</code>
                    <span className="text-muted-foreground ml-2">(default): PR fails on critical issues</span>
                  </div>
                </div>
                <div className="flex items-center space-x-3">
                  <div className="w-2 h-2 bg-green-400 rounded-full"></div>
                  <div>
                    <code className="text-sm font-mono text-foreground">false</code>
                    <span className="text-muted-foreground ml-2">: Only warns, doesn't block PR</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </motion.div>
      </motion.div>

      {/* What It Analyzes */}
      <motion.div className="max-w-4xl mx-auto mb-16" variants={itemVariants}>
        <motion.div
          className="glass-card p-8 rounded-2xl"
          whileHover={{ scale: 1.01 }}
          transition={{ type: "spring", stiffness: 400, damping: 10 }}
        >
          <div className="flex items-center space-x-3 mb-6">
            <div className="w-10 h-10 bg-purple-500/20 rounded-xl flex items-center justify-center">
              <Search className="h-5 w-5 text-purple-400" />
            </div>
            <h2 className="text-2xl font-bold text-foreground">🛡️ What It Analyzes</h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            <div>
              <h3 className="text-lg font-semibold text-foreground mb-4">OWASP Top 10 Coverage</h3>
              <div className="space-y-2">
                {[
                  "A01: Broken Access Control",
                  "A02: Cryptographic Failures",
                  "A03: Injection",
                  "A04: Insecure Design",
                  "A05: Security Misconfiguration",
                  "A06: Vulnerable Components",
                  "A07: Authentication Failures",
                  "A08: Software Integrity Failures",
                  "A09: Logging Failures",
                  "A10: Server-Side Request Forgery"
                ].map((item, index) => (
                  <div key={index} className="flex items-center space-x-2">
                    <div className="w-1.5 h-1.5 bg-primary rounded-full"></div>
                    <span className="text-muted-foreground text-sm">{item}</span>
                  </div>
                ))}
              </div>
            </div>

            <div>
              <h3 className="text-lg font-semibold text-foreground mb-4">Attack Categories</h3>
              <div className="space-y-2">
                {attackCategories.map((category, index) => (
                  <div key={index} className="flex items-center space-x-2">
                    <div className="w-1.5 h-1.5 bg-orange-400 rounded-full"></div>
                    <span className="text-muted-foreground text-sm">{category}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </motion.div>
      </motion.div>

      {/* Getting API Key */}
      <motion.div className="max-w-4xl mx-auto mb-16" variants={itemVariants}>
        <motion.div
          className="glass-card p-8 rounded-2xl"
          whileHover={{ scale: 1.01 }}
          transition={{ type: "spring", stiffness: 400, damping: 10 }}
        >
          <div className="flex items-center space-x-3 mb-6">
            <div className="w-10 h-10 bg-yellow-500/20 rounded-xl flex items-center justify-center">
              <Key className="h-5 w-5 text-yellow-400" />
            </div>
            <h2 className="text-2xl font-bold text-foreground">🔑 Getting Your Gemini API Key</h2>
          </div>

          <div className="space-y-4">
            <div className="flex items-center space-x-3">
              <div className="w-8 h-8 bg-blue-500/20 rounded-lg flex items-center justify-center">
                <ExternalLink className="h-4 w-4 text-blue-400" />
              </div>
              <p className="text-muted-foreground">
                Visit <a href="https://aistudio.google.com/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Google AI Studio</a>
              </p>
            </div>
            <div className="flex items-center space-x-3">
              <div className="w-8 h-8 bg-green-500/20 rounded-lg flex items-center justify-center">
                <CheckCircle className="h-4 w-4 text-green-400" />
              </div>
              <p className="text-muted-foreground">Sign in with your Google account</p>
            </div>
            <div className="flex items-center space-x-3">
              <div className="w-8 h-8 bg-purple-500/20 rounded-lg flex items-center justify-center">
                <Key className="h-4 w-4 text-purple-400" />
              </div>
              <p className="text-muted-foreground">Create API key in the API keys section</p>
            </div>
            <div className="flex items-center space-x-3">
              <div className="w-8 h-8 bg-orange-500/20 rounded-lg flex items-center justify-center">
                <Copy className="h-4 w-4 text-orange-400" />
              </div>
              <p className="text-muted-foreground">Copy the key and add it to your repository secrets</p>
            </div>
          </div>
        </motion.div>
      </motion.div>

      {/* Understanding Results */}
      <motion.div className="max-w-4xl mx-auto mb-16" variants={itemVariants}>
        <motion.div
          className="glass-card p-8 rounded-2xl"
          whileHover={{ scale: 1.01 }}
          transition={{ type: "spring", stiffness: 400, damping: 10 }}
        >
          <div className="flex items-center space-x-3 mb-6">
            <div className="w-10 h-10 bg-green-500/20 rounded-xl flex items-center justify-center">
              <FileText className="h-5 w-5 text-green-400" />
            </div>
            <h2 className="text-2xl font-bold text-foreground">📊 Understanding Results</h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {riskLevels.map((risk, index) => (
              <div key={index} className="flex items-center space-x-3 p-4 glass-card rounded-lg">
                <div className={`w-3 h-3 rounded-full ${risk.color.replace('text-', 'bg-')}`}></div>
                <div>
                  <div className={`font-semibold ${risk.color}`}>
                    {risk.level === "Critical" && "🚨"} {risk.level}
                  </div>
                  <div className="text-sm text-muted-foreground">{risk.description}</div>
                </div>
              </div>
            ))}
          </div>
        </motion.div>
      </motion.div>

      {/* Best Practices */}
      <motion.div className="max-w-4xl mx-auto mb-16" variants={itemVariants}>
        <motion.div
          className="glass-card p-8 rounded-2xl"
          whileHover={{ scale: 1.01 }}
          transition={{ type: "spring", stiffness: 400, damping: 10 }}
        >
          <div className="flex items-center space-x-3 mb-6">
            <div className="w-10 h-10 bg-blue-500/20 rounded-xl flex items-center justify-center">
              <Star className="h-5 w-5 text-blue-400" />
            </div>
            <h2 className="text-2xl font-bold text-foreground">🎯 Best Practices</h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="space-y-3">
              <h3 className="text-lg font-semibold text-foreground">For Teams</h3>
              <div className="space-y-2">
                <div className="flex items-start space-x-2">
                  <div className="w-1.5 h-1.5 bg-primary rounded-full mt-2"></div>
                  <span className="text-muted-foreground text-sm">Set <code className="bg-muted px-1 rounded text-xs">fail_on_critical: true</code> for production</span>
                </div>
                <div className="flex items-start space-x-2">
                  <div className="w-1.5 h-1.5 bg-primary rounded-full mt-2"></div>
                  <span className="text-muted-foreground text-sm">Use <code className="bg-muted px-1 rounded text-xs">analysis_scope: 'full'</code> for comprehensive coverage</span>
                </div>
              </div>
            </div>

            <div className="space-y-3">
              <h3 className="text-lg font-semibold text-foreground">For Open Source</h3>
              <div className="space-y-2">
                <div className="flex items-start space-x-2">
                  <div className="w-1.5 h-1.5 bg-orange-400 rounded-full mt-2"></div>
                  <span className="text-muted-foreground text-sm">Set <code className="bg-muted px-1 rounded text-xs">fail_on_critical: false</code> to avoid blocking contributors</span>
                </div>
                <div className="flex items-start space-x-2">
                  <div className="w-1.5 h-1.5 bg-orange-400 rounded-full mt-2"></div>
                  <span className="text-muted-foreground text-sm">Use <code className="bg-muted px-1 rounded text-xs">analysis_scope: 'focused'</code> for faster analysis</span>
                </div>
              </div>
            </div>

            <div className="space-y-3">
              <h3 className="text-lg font-semibold text-foreground">For Personal Projects</h3>
              <div className="space-y-2">
                <div className="flex items-start space-x-2">
                  <div className="w-1.5 h-1.5 bg-green-400 rounded-full mt-2"></div>
                  <span className="text-muted-foreground text-sm">Start with <code className="bg-muted px-1 rounded text-xs">analysis_scope: 'quick'</code> for learning</span>
                </div>
                <div className="flex items-start space-x-2">
                  <div className="w-1.5 h-1.5 bg-green-400 rounded-full mt-2"></div>
                  <span className="text-muted-foreground text-sm">Gradually increase scope as you understand the tool</span>
                </div>
              </div>
            </div>
          </div>
        </motion.div>
      </motion.div>

      {/* Feature Cards */}
      <motion.div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-16" variants={containerVariants}>
        {features.map((feature, index) => (
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

      {/* Footer */}
      <motion.div className="max-w-4xl mx-auto" variants={itemVariants}>
        <motion.div
          className="glass-card p-8 rounded-2xl text-center"
          whileHover={{ scale: 1.01 }}
        >
          <div className="flex items-center justify-center space-x-3 mb-4">
            <Shield className="h-8 w-8 text-primary" />
            <h3 className="text-2xl font-bold text-foreground">🛡️ SwarmAI Auditor</h3>
          </div>
          <p className="text-muted-foreground mb-4">
            <strong>Powered by Dynamic AI Scanner | OWASP Top 10 Analysis</strong>
          </p>
          <p className="text-sm text-muted-foreground italic">
            Keep your code secure with AI-powered security analysis
          </p>
        </motion.div>
      </motion.div>
    </motion.div>
  )
}

export default GitHubAuditor
