"use client"

import { useState } from "react"
import { motion } from "framer-motion"
import { Settings, AlertTriangle } from "lucide-react"

const BuildScreen = () => {
  const handleBuildClick = () => {
    console.log("Build screen - to be implemented")
    alert("Build screen - to be implemented")
  }

  return (
    <motion.div 
      className="px-4 py-6" 
      initial={{ opacity: 0, y: 20 }} 
      animate={{ opacity: 1, y: 0 }} 
      transition={{ duration: 0.5 }}
    >
      {/* Header */}
      <motion.div
        className="glass-card p-8 mb-8 rounded-2xl"
        initial={{ y: -20, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ delay: 0.1 }}
      >
        <div className="flex items-center space-x-6">
          <motion.div
            className="w-16 h-16 bg-primary/20 rounded-xl flex items-center justify-center"
            whileHover={{ scale: 1.1, rotate: 5 }}
          >
            <Settings className="h-8 w-8 text-primary" />
          </motion.div>
          <div>
            <h1 className="text-3xl font-bold text-foreground mb-2">Build Screen</h1>
            <p className="text-muted-foreground text-lg">
              Customize and configure your security scans
            </p>
          </div>
        </div>
      </motion.div>

      {/* Coming Soon Message */}
      <motion.div
        className="glass-card p-8 rounded-2xl text-center"
        initial={{ y: 20, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ delay: 0.2 }}
      >
        <motion.div
          className="w-24 h-24 bg-orange-500/20 rounded-2xl flex items-center justify-center mx-auto mb-6"
          whileHover={{ scale: 1.1 }}
        >
          <AlertTriangle className="h-12 w-12 text-orange-400" />
        </motion.div>
        
        <h2 className="text-2xl font-bold text-foreground mb-4">Coming Soon</h2>
        <p className="text-muted-foreground text-lg mb-8 max-w-2xl mx-auto">
          The Build screen is currently under development. This will be where you can customize 
          scan parameters, configure security rules, and build custom scanning workflows.
        </p>

        <motion.button
          onClick={handleBuildClick}
          className="glass-card px-8 py-4 text-foreground hover:bg-primary/10 transition-all duration-300 font-medium rounded-lg border border-primary/20 hover:border-primary/40"
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
        >
          <Settings className="h-5 w-5 mr-2 inline" />
          Try Build Feature
        </motion.button>
      </motion.div>
    </motion.div>
  )
}

export default BuildScreen
