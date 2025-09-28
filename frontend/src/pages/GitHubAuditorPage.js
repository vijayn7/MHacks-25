"use client"

import { motion } from "framer-motion"
import { Github, Shield, CheckCircle, AlertCircle, Copy, ExternalLink, Code, Settings, Key, Zap, Lock, Eye, Bug } from "lucide-react"
import { useState } from "react"

const GitHubAuditorPage = () => {
  const [copiedStep, setCopiedStep] = useState(null)

  const copyToClipboard = (text, stepNumber) => {
    navigator.clipboard.writeText(text)
    setCopiedStep(stepNumber)
    setTimeout(() => setCopiedStep(null), 2000)
  }

  const quickSetupSteps = [
    {
      id: 1,
      title: "Add the Workflow",
      description: "Create the security analysis workflow file in your repository",
      icon: <Code className="h-6 w-6" />,
      details: [
        "Create `.github/workflows/security-analysis.yml` in your repository",
        "Copy the workflow configuration below",
        "Commit and push the file to your repository"
      ],
      code: `name: Security Analysis

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
      GEMINI_API_KEY: \${{ secrets.GEMINI_API_KEY }}`
    },
    {
      id: 2,
      title: "Add Your Gemini API Key",
      description: "Configure the API key for AI-powered security analysis",
      icon: <Key className="h-6 w-6" />,
      details: [
        "Go to **Settings** → **Secrets and variables** → **Actions**",
        "Click **'New repository secret'**",
        "**Name**: `GEMINI_API_KEY`",
        "**Value**: Your Gemini API key",
        "Click **'Add secret'**"
      ],
      code: `# Secret Configuration:
# Name: GEMINI_API_KEY
# Value: Your Gemini API key from Google AI Studio

# Getting your API key:
# 1. Visit https://aistudio.google.com/
# 2. Sign in with your Google account
# 3. Create API key in the API keys section
# 4. Copy the key and add it to your repository secrets`
    },
    {
      id: 3,
      title: "Test It!",
      description: "Create a pull request to trigger the security analysis",
      icon: <Zap className="h-6 w-6" />,
      details: [
        "Create a new pull request to your main branch",
        "The SwarmAI Auditor will automatically analyze your code",
        "Check the Actions tab to see the analysis results",
        "Review any security findings in the PR comments"
      ],
      code: `# Test the integration:
# 1. Create a new branch
# 2. Make some changes to your code
# 3. Create a pull request to main branch
# 4. Watch the security analysis run automatically
# 5. Review findings in the PR comments`
    }
  ]

  const analysisCoverage = [
    {
      category: "OWASP Top 10",
      icon: <Shield className="h-5 w-5 text-primary" />,
      items: [
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
      ]
    },
    {
      category: "Attack Categories",
      icon: <Bug className="h-5 w-5 text-red-500" />,
      items: [
        "Injection Attacks (SQL, NoSQL, Command)",
        "Authentication Attacks (Brute force, JWT flaws)",
        "Authorization Attacks (IDOR, privilege escalation)",
        "Business Logic Attacks (Price manipulation, race conditions)",
        "Data Exposure Attacks (Sensitive data leaks)",
        "Cryptography Attacks (Weak encryption)",
        "Insecure Design Attacks (Missing validation)",
        "Vulnerable Components (Outdated dependencies)"
      ]
    }
  ]

  const configurationOptions = [
    {
      title: "Analysis Scope",
      icon: <Eye className="h-5 w-5 text-blue-500" />,
      options: [
        { name: "full", description: "Comprehensive analysis (default)" },
        { name: "focused", description: "Key security areas only" },
        { name: "quick", description: "Basic security check" }
      ]
    },
    {
      title: "Failure Behavior",
      icon: <Lock className="h-5 w-5 text-orange-500" />,
      options: [
        { name: "true", description: "PR fails on critical issues (default)" },
        { name: "false", description: "Only warns, doesn't block PR" }
      ]
    }
  ]

  const riskLevels = [
    { level: "Critical", color: "text-red-500", bgColor: "bg-red-500/10", description: "Immediate action required" },
    { level: "High", color: "text-red-400", bgColor: "bg-red-400/10", description: "Fix before production" },
    { level: "Medium", color: "text-yellow-500", bgColor: "bg-yellow-500/10", description: "Address in next release" },
    { level: "Low", color: "text-green-500", bgColor: "bg-green-500/10", description: "Best practice recommendations" }
  ]

  const bestPractices = [
    {
      category: "For Teams",
      icon: <Shield className="h-5 w-5 text-blue-500" />,
      practices: [
        "Set `fail_on_critical: true` for production",
        "Use `analysis_scope: 'full'` for comprehensive coverage"
      ]
    },
    {
      category: "For Open Source",
      icon: <Github className="h-5 w-5 text-gray-500" />,
      practices: [
        "Set `fail_on_critical: false` to avoid blocking contributors",
        "Use `analysis_scope: 'focused'` for faster analysis"
      ]
    },
    {
      category: "For Personal Projects",
      icon: <Code className="h-5 w-5 text-green-500" />,
      practices: [
        "Start with `analysis_scope: 'quick'` for learning",
        "Gradually increase scope as you understand the tool"
      ]
    }
  ]

  return (
    <div className="min-h-screen bg-background">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <motion.div
          className="text-center mb-12"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
        >
          <div className="flex items-center justify-center mb-6">
            <div className="w-16 h-16 bg-primary/10 rounded-2xl flex items-center justify-center mr-4">
              <Github className="h-8 w-8 text-primary" />
            </div>
            <div className="w-16 h-16 bg-primary/10 rounded-2xl flex items-center justify-center">
              <Shield className="h-8 w-8 text-primary" />
            </div>
          </div>
          <h1 className="text-4xl font-bold text-foreground mb-4">
            SwarmAI Auditor Setup
          </h1>
          <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
            Install the SwarmAI Auditor GitHub App for automated security analysis on every pull request. 
            Get AI-powered vulnerability detection with OWASP Top 10 coverage.
          </p>
        </motion.div>

        {/* Quick Setup Section */}
        <motion.div
          className="mb-16"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.2 }}
        >
          <div className="text-center mb-8">
            <h2 className="text-3xl font-bold text-foreground mb-4">
              🚀 Quick Setup (2 minutes)
            </h2>
            <p className="text-muted-foreground text-lg">
              Get started with automated security analysis in just 3 simple steps
            </p>
          </div>

          <div className="space-y-8">
            {quickSetupSteps.map((step, index) => (
              <motion.div
                key={step.id}
                className="glass-card p-8 rounded-2xl border border-border/50"
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.6, delay: 0.4 + index * 0.1 }}
              >
                <div className="flex items-start space-x-4">
                  <div className="flex-shrink-0">
                    <div className="w-12 h-12 bg-primary/10 rounded-xl flex items-center justify-center">
                      {step.icon}
                    </div>
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center justify-between mb-4">
                      <div>
                        <h3 className="text-2xl font-bold text-foreground mb-2">
                          Step {step.id}: {step.title}
                        </h3>
                        <p className="text-muted-foreground text-lg">
                          {step.description}
                        </p>
                      </div>
                    </div>

                    <div className="space-y-4">
                      <div>
                        <h4 className="text-lg font-semibold text-foreground mb-3">
                          Instructions:
                        </h4>
                        <ul className="space-y-2">
                          {step.details.map((detail, detailIndex) => (
                            <li key={detailIndex} className="flex items-start space-x-3">
                              <CheckCircle className="h-5 w-5 text-green-500 mt-0.5 flex-shrink-0" />
                              <span className="text-muted-foreground">{detail}</span>
                            </li>
                          ))}
                        </ul>
                      </div>

                      {step.code && (
                        <div>
                          <div className="flex items-center justify-between mb-3">
                            <h4 className="text-lg font-semibold text-foreground">
                              Configuration:
                            </h4>
                            <button
                              onClick={() => copyToClipboard(step.code, step.id)}
                              className="flex items-center space-x-2 px-3 py-1 text-sm bg-muted/50 hover:bg-muted rounded-lg transition-colors"
                            >
                              <Copy className="h-4 w-4" />
                              <span>{copiedStep === step.id ? "Copied!" : "Copy"}</span>
                            </button>
                          </div>
                          <div className="bg-muted/30 rounded-lg p-4 overflow-x-auto">
                            <pre className="text-sm text-foreground whitespace-pre-wrap">
                              {step.code}
                            </pre>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        </motion.div>

        {/* Analysis Coverage */}
        <motion.div
          className="mb-16"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.8 }}
        >
          <h2 className="text-3xl font-bold text-foreground text-center mb-8">
            🛡️ What It Analyzes
          </h2>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            {analysisCoverage.map((section, index) => (
              <motion.div
                key={index}
                className="glass-card p-6 rounded-xl border border-border/50"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6, delay: 1.0 + index * 0.1 }}
              >
                <div className="flex items-center mb-4">
                  {section.icon}
                  <h3 className="text-xl font-bold text-foreground ml-3">
                    {section.category}
                  </h3>
                </div>
                <ul className="space-y-2">
                  {section.items.map((item, itemIndex) => (
                    <li key={itemIndex} className="flex items-start space-x-3">
                      <CheckCircle className="h-4 w-4 text-green-500 mt-1 flex-shrink-0" />
                      <span className="text-muted-foreground text-sm">{item}</span>
                    </li>
                  ))}
                </ul>
              </motion.div>
            ))}
          </div>
        </motion.div>

        {/* Configuration Options */}
        <motion.div
          className="mb-16"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 1.2 }}
        >
          <h2 className="text-3xl font-bold text-foreground text-center mb-8">
            🔧 Configuration Options
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            {configurationOptions.map((config, index) => (
              <motion.div
                key={index}
                className="glass-card p-6 rounded-xl border border-border/50"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6, delay: 1.4 + index * 0.1 }}
              >
                <div className="flex items-center mb-4">
                  {config.icon}
                  <h3 className="text-xl font-bold text-foreground ml-3">
                    {config.title}
                  </h3>
                </div>
                <div className="space-y-3">
                  {config.options.map((option, optionIndex) => (
                    <div key={optionIndex} className="flex items-start space-x-3">
                      <div className="w-2 h-2 bg-primary rounded-full mt-2 flex-shrink-0" />
                      <div>
                        <code className="text-primary font-mono text-sm bg-primary/10 px-2 py-1 rounded">
                          {option.name}
                        </code>
                        <p className="text-muted-foreground text-sm mt-1">
                          {option.description}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              </motion.div>
            ))}
          </div>
        </motion.div>

        {/* Risk Levels */}
        <motion.div
          className="mb-16"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 1.6 }}
        >
          <h2 className="text-3xl font-bold text-foreground text-center mb-8">
            📊 Understanding Results
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {riskLevels.map((risk, index) => (
              <motion.div
                key={index}
                className={`glass-card p-4 rounded-xl border border-border/50 ${risk.bgColor}`}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6, delay: 1.8 + index * 0.1 }}
              >
                <div className="flex items-center mb-2">
                  <AlertCircle className={`h-5 w-5 ${risk.color}`} />
                  <h3 className={`text-lg font-bold ml-2 ${risk.color}`}>
                    {risk.level}
                  </h3>
                </div>
                <p className="text-muted-foreground text-sm">
                  {risk.description}
                </p>
              </motion.div>
            ))}
          </div>
        </motion.div>

        {/* Best Practices */}
        <motion.div
          className="mb-16"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 2.0 }}
        >
          <h2 className="text-3xl font-bold text-foreground text-center mb-8">
            🎯 Best Practices
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {bestPractices.map((practice, index) => (
              <motion.div
                key={index}
                className="glass-card p-6 rounded-xl border border-border/50"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6, delay: 2.2 + index * 0.1 }}
              >
                <div className="flex items-center mb-4">
                  {practice.icon}
                  <h3 className="text-lg font-bold text-foreground ml-3">
                    {practice.category}
                  </h3>
                </div>
                <ul className="space-y-2">
                  {practice.practices.map((item, itemIndex) => (
                    <li key={itemIndex} className="flex items-start space-x-3">
                      <CheckCircle className="h-4 w-4 text-green-500 mt-1 flex-shrink-0" />
                      <span className="text-muted-foreground text-sm">{item}</span>
                    </li>
                  ))}
                </ul>
              </motion.div>
            ))}
          </div>
        </motion.div>

        {/* Troubleshooting */}
        <motion.div
          className="mb-16"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 2.4 }}
        >
          <h2 className="text-3xl font-bold text-foreground text-center mb-8">
            🚨 Troubleshooting
          </h2>
          <div className="glass-card p-8 rounded-2xl border border-border/50">
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-semibold text-foreground mb-2">
                  "GEMINI_API_KEY not found"
                </h3>
                <p className="text-muted-foreground">
                  Check secret name is exactly <code className="bg-muted/50 px-2 py-1 rounded text-sm">GEMINI_API_KEY</code>
                </p>
              </div>
              <div>
                <h3 className="text-lg font-semibold text-foreground mb-2">
                  "Workflow not triggering"
                </h3>
                <p className="text-muted-foreground">
                  Verify file is in <code className="bg-muted/50 px-2 py-1 rounded text-sm">.github/workflows/</code> and check branch name matches trigger (default: <code className="bg-muted/50 px-2 py-1 rounded text-sm">main</code>)
                </p>
              </div>
              <div>
                <h3 className="text-lg font-semibold text-foreground mb-2">
                  "Analysis failed"
                </h3>
                <p className="text-muted-foreground">
                  Verify Gemini API key is valid and check API quota
                </p>
              </div>
            </div>
          </div>
        </motion.div>

        {/* Footer */}
        <motion.div
          className="text-center"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 2.6 }}
        >
          <div className="glass-card p-8 rounded-2xl border border-border/50">
            <h3 className="text-2xl font-bold text-foreground mb-4">
              🔄 Automatic Updates
            </h3>
            <p className="text-muted-foreground mb-6">
              SwarmAI Auditor automatically updates when we improve our analysis logic. You get:
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-left">
              <div className="space-y-2">
                <div className="flex items-center space-x-2">
                  <CheckCircle className="h-4 w-4 text-green-500" />
                  <span className="text-muted-foreground">New vulnerability detection patterns</span>
                </div>
                <div className="flex items-center space-x-2">
                  <CheckCircle className="h-4 w-4 text-green-500" />
                  <span className="text-muted-foreground">Improved analysis accuracy</span>
                </div>
              </div>
              <div className="space-y-2">
                <div className="flex items-center space-x-2">
                  <CheckCircle className="h-4 w-4 text-green-500" />
                  <span className="text-muted-foreground">Enhanced reporting formats</span>
                </div>
                <div className="flex items-center space-x-2">
                  <CheckCircle className="h-4 w-4 text-green-500" />
                  <span className="text-muted-foreground">Performance optimizations</span>
                </div>
              </div>
            </div>
            <div className="mt-8 pt-6 border-t border-border/50">
              <p className="text-sm text-muted-foreground">
                <strong className="text-foreground">🛡️ SwarmAI Auditor</strong> | Powered by Dynamic AI Scanner | OWASP Top 10 Analysis
              </p>
              <p className="text-sm text-muted-foreground mt-2">
                <em>Keep your code secure with AI-powered security analysis</em>
              </p>
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  )
}

export default GitHubAuditorPage
