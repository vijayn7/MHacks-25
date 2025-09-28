"use client"

import { useState, useRef, useEffect } from "react"
import { motion, AnimatePresence } from "framer-motion"
import { 
  Send, 
  Bot, 
  User, 
  Loader2, 
  CheckCircle, 
  AlertTriangle,
  Code,
  Play,
  Settings,
  MessageSquare,
  Zap,
  Github
} from "lucide-react"
import GitHubIntegration from "./GitHubIntegration"

const AgenticChat = ({ onStartTestGeneration }) => {
  const [messages, setMessages] = useState([
    {
      id: 1,
      type: "bot",
      content: "Hi! I'm your AI security testing assistant. What would you like to test on your website? I can help you create custom security test cases for things like authentication bypass, data access controls, business logic flaws, and more.",
      timestamp: new Date()
    }
  ])
  const [inputValue, setInputValue] = useState("")
  const [isLoading, setIsLoading] = useState(false)
  const [isGenerating, setIsGenerating] = useState(false)
  const [currentTestRequest, setCurrentTestRequest] = useState(null)
  const [activeTab, setActiveTab] = useState("chat")
  const [selectedRepository, setSelectedRepository] = useState(null)
  const messagesEndRef = useRef(null)

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" })
  }

  useEffect(() => {
    scrollToBottom()
  }, [messages])

  const handleRepositorySelected = (repo) => {
    setSelectedRepository(repo);
    
    if (repo) {
      // Add a message about repository selection
      const repoMessage = {
        id: Date.now(),
        type: "bot",
        content: `🎯 **Repository Selected**: \`${repo}\`\n\nI can now analyze your code and generate highly targeted test cases based on your actual codebase. What specific security concerns would you like me to test for?`,
        timestamp: new Date(),
        suggestions: [
          "Test authentication functions in this repo",
          "Check for SQL injection vulnerabilities",
          "Scan for XSS in user inputs",
          "Test authorization and access controls"
        ]
      };
      setMessages(prev => [...prev, repoMessage]);
    }
  };

  const handleSendMessage = async () => {
    if (!inputValue.trim() || isLoading) return

    const userMessage = {
      id: Date.now(),
      type: "user",
      content: inputValue.trim(),
      timestamp: new Date()
    }

    setMessages(prev => [...prev, userMessage])
    setInputValue("")
    setIsLoading(true)

    try {
      // Send request to backend for test generation
      const response = await fetch('/api/generate-tests', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          user_request: inputValue.trim(),
          target_url: "http://localhost:3001", // This would come from user settings
          conversation_history: messages
        })
      })

      const data = await response.json()
      
      if (data.success) {
        // Add bot response
        const botMessage = {
          id: Date.now() + 1,
          type: "bot",
          content: data.response,
          timestamp: new Date(),
          suggestions: data.suggestions || [],
          testRequest: data.testRequest
        }

        setMessages(prev => [...prev, botMessage])
        setCurrentTestRequest(data.testRequest)
        setIsGenerating(true)
      } else {
        throw new Error(data.error || 'Failed to generate tests')
      }
    } catch (error) {
      console.error('Error generating tests:', error)
      const errorMessage = {
        id: Date.now() + 1,
        type: "bot",
        content: `Sorry, I encountered an error: ${error.message}. Please try again or rephrase your request.`,
        timestamp: new Date(),
        isError: true
      }
      setMessages(prev => [...prev, errorMessage])
    } finally {
      setIsLoading(false)
    }
  }

  const handleStartGeneration = async () => {
    if (!currentTestRequest) return

    setIsGenerating(true)
    
    try {
      // Trigger GitHub workflow
      const response = await fetch('/api/trigger-workflow', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(currentTestRequest)
      })

      const data = await response.json()
      
      if (data.success) {
        const statusMessage = {
          id: Date.now(),
          type: "bot",
          content: `🚀 Great! I've started generating and executing your custom test cases. This process typically takes 5-10 minutes. I'll keep you updated on the progress!`,
          timestamp: new Date(),
          workflowId: data.workflowId
        }
        setMessages(prev => [...prev, statusMessage])
        
        // Start polling for updates
        pollWorkflowStatus(data.workflowId)
      } else {
        throw new Error(data.error || 'Failed to start workflow')
      }
    } catch (error) {
      console.error('Error starting workflow:', error)
      const errorMessage = {
        id: Date.now(),
        type: "bot",
        content: `Sorry, I couldn't start the test generation: ${error.message}`,
        timestamp: new Date(),
        isError: true
      }
      setMessages(prev => [...prev, errorMessage])
    } finally {
      setIsGenerating(false)
    }
  }

  const pollWorkflowStatus = async (workflowId) => {
    const pollInterval = setInterval(async () => {
      try {
        const response = await fetch(`/api/workflow-status/${workflowId}`)
        const data = await response.json()
        
        if (data.status === 'completed') {
          clearInterval(pollInterval)
          const completionMessage = {
            id: Date.now(),
            type: "bot",
            content: `✅ Test generation and execution completed! Found ${data.findingsCount} potential vulnerabilities. Check the results below:`,
            timestamp: new Date(),
            results: data.results
          }
          setMessages(prev => [...prev, completionMessage])
        } else if (data.status === 'failed') {
          clearInterval(pollInterval)
          const errorMessage = {
            id: Date.now(),
            type: "bot",
            content: `❌ Test generation failed: ${data.error}`,
            timestamp: new Date(),
            isError: true
          }
          setMessages(prev => [...prev, errorMessage])
        }
      } catch (error) {
        console.error('Error polling workflow status:', error)
      }
    }, 5000) // Poll every 5 seconds
  }

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSendMessage()
    }
  }

  const examplePrompts = [
    "Test if users can access other users' private data",
    "Check for payment bypass vulnerabilities in our checkout flow",
    "Find authentication bypass methods in our admin panel",
    "Test for SQL injection in our search functionality",
    "Check if our API endpoints are properly protected"
  ]

  return (
    <div className="flex flex-col h-screen bg-background">
      {/* Header */}
      <div className="glass-card border-b border-border/50 p-4">
        <div className="max-w-4xl mx-auto flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <motion.div 
              className="p-2 glass-card rounded-xl pulse-glow"
              whileHover={{ scale: 1.1, rotate: 5 }}
              transition={{ type: "spring", stiffness: 400, damping: 10 }}
            >
              <Bot className="h-6 w-6 text-primary" />
            </motion.div>
            <div>
              <h1 className="text-xl font-bold gradient-text">AI Security Testing Assistant</h1>
              <p className="text-sm text-muted-foreground">
                {selectedRepository 
                  ? `Analyzing repository: ${selectedRepository}` 
                  : "Describe what you want to test, and I'll create custom test cases for you"
                }
              </p>
            </div>
          </div>
              <div className="flex items-center space-x-2">
                {/* Tab Navigation */}
                <div className="flex glass-card rounded-lg p-1">
                  <motion.button
                    onClick={() => setActiveTab("chat")}
                    className={`px-3 py-2 rounded-md text-sm font-medium transition-all flex items-center space-x-2 ${
                      activeTab === "chat" 
                        ? "bg-primary text-primary-foreground" 
                        : "text-muted-foreground hover:text-foreground"
                    }`}
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                  >
                    <MessageSquare className="h-4 w-4" />
                    <span>Chat</span>
                  </motion.button>
                  <motion.button
                    onClick={() => setActiveTab("github")}
                    className={`px-3 py-2 rounded-md text-sm font-medium transition-all flex items-center space-x-2 ${
                      activeTab === "github" 
                        ? "bg-primary text-primary-foreground" 
                        : "text-muted-foreground hover:text-foreground"
                    }`}
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                  >
                    <Github className="h-4 w-4" />
                    <span>GitHub</span>
                  </motion.button>
                </div>
                
                <motion.button 
                  className="p-2 text-muted-foreground hover:text-foreground transition-colors glass-card rounded-lg"
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                >
                  <Settings className="h-5 w-5" />
                </motion.button>
              </div>
        </div>
      </div>

      {/* Tab Content */}
      {activeTab === "chat" ? (
        <>
          {/* Hero Section - Only show when no messages */}
          {messages.length === 1 && (
        <motion.div 
          className="text-center py-16 px-4"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
        >
          <motion.div
            className="inline-flex items-center justify-center w-20 h-20 glass-card rounded-2xl mb-8 pulse-glow overflow-hidden mx-auto"
            whileHover={{ scale: 1.1, rotate: 5 }}
            transition={{ type: "spring", stiffness: 400, damping: 10 }}
          >
            <Bot className="w-12 h-12 text-primary" />
          </motion.div>
          
          <motion.h2 
            className="text-4xl font-bold mb-4 text-balance"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2, duration: 0.6 }}
          >
            <span className="gradient-text">AI-Powered Security Testing</span>
          </motion.h2>
          
          <motion.p 
            className="text-lg text-muted-foreground max-w-2xl mx-auto leading-relaxed"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4, duration: 0.6 }}
          >
            Describe what you want to test in natural language, and I'll create comprehensive security test cases tailored to your application.
          </motion.p>
        </motion.div>
      )}

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4">
        <div className="max-w-4xl mx-auto space-y-4">
          <AnimatePresence>
            {messages.map((message) => (
              <motion.div
                key={message.id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                className={`flex ${message.type === 'user' ? 'justify-end' : 'justify-start'}`}
              >
                <div className={`flex max-w-[80%] ${message.type === 'user' ? 'flex-row-reverse' : 'flex-row'} items-start space-x-3`}>
                  <motion.div 
                    className={`p-2 rounded-full glass-card ${
                      message.type === 'user' 
                        ? 'bg-primary' 
                        : 'bg-secondary'
                    }`}
                    whileHover={{ scale: 1.1 }}
                    transition={{ type: "spring", stiffness: 400, damping: 10 }}
                  >
                    {message.type === 'user' ? (
                      <User className="h-5 w-5 text-primary-foreground" />
                    ) : (
                      <Bot className="h-5 w-5 text-secondary-foreground" />
                    )}
                  </motion.div>
                  
                  <motion.div 
                    className={`rounded-2xl px-4 py-3 ${
                      message.type === 'user'
                        ? 'bg-primary text-primary-foreground'
                        : message.isError
                        ? 'bg-destructive/20 text-destructive-foreground border border-destructive/50'
                        : 'glass-card text-foreground'
                    }`}
                    whileHover={{ scale: 1.02 }}
                    transition={{ type: "spring", stiffness: 400, damping: 10 }}
                  >
                    <p className="whitespace-pre-wrap">{message.content}</p>
                    
                    {message.suggestions && message.suggestions.length > 0 && (
                      <div className="mt-3 space-y-2">
                        <p className="text-sm text-muted-foreground">I can help you test:</p>
                        <div className="flex flex-wrap gap-2">
                          {message.suggestions.map((suggestion, index) => (
                            <motion.button
                              key={index}
                              onClick={() => setInputValue(suggestion)}
                              className="px-3 py-1 glass-card rounded-full text-sm hover:bg-primary/10 transition-colors text-foreground"
                              whileHover={{ scale: 1.05 }}
                              whileTap={{ scale: 0.95 }}
                            >
                              {suggestion}
                            </motion.button>
                          ))}
                        </div>
                      </div>
                    )}

                    {message.testRequest && (
                      <motion.div 
                        className="mt-4 p-3 glass-card rounded-lg"
                        initial={{ opacity: 0, scale: 0.95 }}
                        animate={{ opacity: 1, scale: 1 }}
                        transition={{ type: "spring", stiffness: 300, damping: 20 }}
                      >
                        <div className="flex items-center justify-between">
                          <div>
                            <h4 className="font-semibold text-sm text-foreground">Ready to generate tests for:</h4>
                            <p className="text-sm text-muted-foreground">{message.testRequest.description}</p>
                          </div>
                          <motion.button
                            onClick={handleStartGeneration}
                            disabled={isGenerating}
                            className="px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center space-x-2"
                            whileHover={{ scale: 1.05 }}
                            whileTap={{ scale: 0.95 }}
                          >
                            {isGenerating ? (
                              <Loader2 className="h-4 w-4 animate-spin" />
                            ) : (
                              <Play className="h-4 w-4" />
                            )}
                            <span>{isGenerating ? 'Generating...' : 'Start Testing'}</span>
                          </motion.button>
                        </div>
                      </motion.div>
                    )}

                    {message.results && (
                      <motion.div 
                        className="mt-4 p-3 glass-card border border-primary/50 rounded-lg"
                        initial={{ opacity: 0, scale: 0.95 }}
                        animate={{ opacity: 1, scale: 1 }}
                        transition={{ type: "spring", stiffness: 300, damping: 20 }}
                      >
                        <div className="flex items-center space-x-2 mb-2">
                          <CheckCircle className="h-5 w-5 text-primary" />
                          <span className="font-semibold text-primary">Test Results</span>
                        </div>
                        <p className="text-sm text-muted-foreground">
                          Found {message.results.findingsCount} potential vulnerabilities
                        </p>
                        <motion.button
                          onClick={() => onStartTestGeneration && onStartTestGeneration(message.results)}
                          className="mt-2 px-3 py-1 bg-primary text-primary-foreground rounded text-sm hover:bg-primary/90 transition-colors"
                          whileHover={{ scale: 1.05 }}
                          whileTap={{ scale: 0.95 }}
                        >
                          View Detailed Results
                        </motion.button>
                      </motion.div>
                    )}
                  </motion.div>
                </div>
              </motion.div>
            ))}
          </AnimatePresence>
          <div ref={messagesEndRef} />
        </div>
      </div>

      {/* Example Prompts */}
      {messages.length === 1 && (
        <motion.div 
          className="max-w-4xl mx-auto px-4 pb-8"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.6 }}
        >
          <div className="glass-card rounded-xl p-6">
            <h3 className="text-lg font-semibold text-foreground mb-4 text-center">Try asking me to test:</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {examplePrompts.map((prompt, index) => (
                <motion.button
                  key={index}
                  onClick={() => setInputValue(prompt)}
                  className="text-left p-4 glass-card hover:bg-primary/10 rounded-lg text-sm transition-colors text-foreground border border-border/50 hover:border-primary/50"
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.7 + index * 0.1 }}
                >
                  {prompt}
                </motion.button>
              ))}
            </div>
          </div>
        </motion.div>
      )}

          {/* Input */}
          <div className="glass-card border-t border-border/50 p-4">
            <div className="max-w-4xl mx-auto">
              <div className="flex items-end space-x-3">
                <div className="flex-1 relative">
                  <motion.textarea
                    value={inputValue}
                    onChange={(e) => setInputValue(e.target.value)}
                    onKeyPress={handleKeyPress}
                    placeholder="Describe what you want to test on your website..."
                    className="w-full px-4 py-3 glass-card border border-border/50 rounded-xl text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent resize-none"
                    rows={1}
                    style={{ minHeight: '48px', maxHeight: '120px' }}
                    onInput={(e) => {
                      e.target.style.height = 'auto'
                      e.target.style.height = e.target.scrollHeight + 'px'
                    }}
                    whileFocus={{ scale: 1.02 }}
                    transition={{ type: "spring", stiffness: 400, damping: 10 }}
                  />
                </div>
                <motion.button
                  onClick={handleSendMessage}
                  disabled={!inputValue.trim() || isLoading}
                  className="p-3 bg-primary text-primary-foreground rounded-xl hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed transition-all glass-card"
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                >
                  {isLoading ? (
                    <Loader2 className="h-5 w-5 animate-spin" />
                  ) : (
                    <Send className="h-5 w-5" />
                  )}
                </motion.button>
              </div>
            </div>
          </div>
        </>
      ) : (
        /* GitHub Integration Tab */
        <div className="flex-1 overflow-y-auto p-4">
          <div className="max-w-4xl mx-auto">
            <GitHubIntegration 
              onTestGenerated={(data) => {
                // Handle test generation results
                if (data.type === 'workflow_triggered') {
                  setMessages(prev => [...prev, {
                    id: Date.now(),
                    type: "bot",
                    content: `🚀 GitHub workflow triggered successfully!\n\nWorkflow ID: ${data.workflow_id}\n\nYou can view the progress at: ${data.workflow_url}`,
                    timestamp: new Date()
                  }]);
                } else {
                  setMessages(prev => [...prev, {
                    id: Date.now(),
                    type: "bot",
                    content: `✅ Generated ${data.test_cases_generated} test cases from your repository!\n\nThese tests are specifically tailored to your code and will be more accurate than generic tests.`,
                    timestamp: new Date()
                  }]);
                }
                setActiveTab("chat");
              }}
              onError={(error) => {
                setMessages(prev => [...prev, {
                  id: Date.now(),
                  type: "bot",
                  isError: true,
                  content: `❌ Error: ${error}`,
                  timestamp: new Date()
                }]);
                setActiveTab("chat");
              }}
              onRepositorySelected={handleRepositorySelected}
            />
          </div>
        </div>
      )}
    </div>
  )
}

export default AgenticChat
