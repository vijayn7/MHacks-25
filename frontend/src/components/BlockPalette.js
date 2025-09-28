"use client"


import { useState } from "react"
import { motion, AnimatePresence } from "framer-motion"
import { 
  ChevronLeft, 
  ChevronRight, 
  Zap, 
  Brain, 
  Code, 
  Package,
  Lock,
  Settings
} from "lucide-react"


const BlockPalette = ({ onAddBlock, isCollapsed, onToggleCollapse, usedBlocks = [], onConfigureBlock }) => {
  const [showConfigButton, setShowConfigButton] = useState(null)


  const blockTypes = [
    {
      type: "credentialed_scan",
      name: "Auth & Session Tests",
      description: "Auth bypass, weak passwords, session flaws",
      icon: Lock,
      emoji: "🔐",
      color: "bg-pink-100/80 border-pink-200/60 text-pink-700",
      usedColor: "bg-pink-200/60 border-pink-300/70 text-pink-600",
      severity: "high"
    },
    {
      type: "logic_fuzzer",
      name: "Business Logic Tests",
      description: "Price manipulation, workflow bypass",
      icon: Zap,
      emoji: "⚡",
      color: "bg-orange-100/80 border-orange-200/60 text-orange-700",
      usedColor: "bg-orange-200/60 border-orange-300/70 text-orange-600",
      severity: "medium"
    },
    {
      type: "llm_generator",
      name: "AI Security Tests",
      description: "Prompt injection, AI jailbreak",
      icon: Brain,
      emoji: "🤖",
      color: "bg-purple-100/80 border-purple-200/60 text-purple-700",
      usedColor: "bg-purple-200/60 border-purple-300/70 text-purple-600",
      severity: "medium"
    },
    {
      type: "json_fuzzer",
      name: "API Fuzzing Tests",
      description: "JSON injection, schema bypass",
      icon: Code,
      emoji: "📄",
      color: "bg-blue-100/80 border-blue-200/60 text-blue-700",
      usedColor: "bg-blue-200/60 border-blue-300/70 text-blue-600",
      severity: "high"
    },
    {
      type: "supply_chain_scan",
      name: "Dependency Security",
      description: "Vulnerable deps, typosquatting",
      icon: Package,
      emoji: "📦",
      color: "bg-green-100/80 border-green-200/60 text-green-700",
      usedColor: "bg-green-200/60 border-green-300/70 text-green-600",
      severity: "high"
    }
  ]


  const handleBlockClick = (blockType) => {
    onAddBlock(blockType)
  }


  // Check if block type is already used
  const isBlockUsed = (blockType) => {
    return usedBlocks.some(block => block.type === blockType)
  }


  // Get block display name
  const getBlockDisplayName = (type) => {
    const names = {
      credentialed_scan: "Auth & Session Test",
      logic_fuzzer: "Business Logic Test",
      llm_generator: "AI Security Test",
      json_fuzzer: "API Fuzzing Test",
      supply_chain_scan: "Dependency Test"
    }
    return names[type] || type.replace('_', ' ')
  }


  return (
    <motion.div
      className={`bg-background/95 backdrop-blur-sm border-r border-border/50 flex flex-col transition-all duration-300 ${
        isCollapsed ? 'w-16' : 'w-80'
      }`}
      initial={{ x: -320 }}
      animate={{ x: 0 }}
      transition={{ duration: 0.3 }}
    >
      {/* Header */}
      <div className="p-4 border-b border-border/50 flex items-center justify-between">
        {!isCollapsed && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.2 }}
          >
            <h2 className="text-lg font-semibold text-foreground">Block Palette</h2>
            <p className="text-sm text-muted-foreground">Drag blocks to canvas</p>
          </motion.div>
        )}
       
        <motion.button
          onClick={onToggleCollapse}
          className="p-2 hover:bg-muted/20 rounded-lg transition-colors"
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
        >
          {isCollapsed ? (
            <ChevronRight className="h-5 w-5 text-foreground" />
          ) : (
            <ChevronLeft className="h-5 w-5 text-foreground" />
          )}
        </motion.button>
      </div>


      {/* Block Types */}
      <div className="flex-1 overflow-y-auto p-4">
        <AnimatePresence>
          {!isCollapsed && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              transition={{ duration: 0.3 }}
              className="grid grid-cols-2 gap-3"
            >
              {blockTypes.map((blockType, index) => {
                return (
                  <motion.div
                    key={blockType.type}
                    className={`relative w-28 h-28 rounded-xl border-2 cursor-pointer ${
                      isBlockUsed(blockType.type) ? blockType.usedColor : blockType.color
                    } hover:scale-105 transition-all duration-200 ${
                      isBlockUsed(blockType.type) ? 'cursor-not-allowed' : ''
                    } group shadow-lg hover:shadow-xl`}
                    style={{ userSelect: 'none' }}
                    onMouseEnter={() => {
                      setShowConfigButton(blockType.type)
                    }}
                    onMouseLeave={() => {
                      setShowConfigButton(null)
                    }}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: index * 0.1 }}
                    whileHover={{ scale: isBlockUsed(blockType.type) ? 1 : 1.05 }}
                    whileTap={{ scale: isBlockUsed(blockType.type) ? 1 : 0.95 }}
                    onClick={() => !isBlockUsed(blockType.type) && onAddBlock(blockType)}
                  >
                    <div className="p-4 h-full flex flex-col justify-center items-center text-center relative" style={{ userSelect: 'none' }}>
                      {/* Block Icon */}
                      <div className="text-3xl mb-2" style={{ userSelect: 'none' }}>
                        {blockType.emoji}
                      </div>
                     
                      <h3 className="font-bold text-xs capitalize mb-1 leading-tight" style={{ userSelect: 'none' }}>
                        {getBlockDisplayName(blockType.type)}
                      </h3>
                      <div className="text-xs opacity-90" style={{ userSelect: 'none' }}>
                        {blockType.severity}
                      </div>
                     
                      {/* Config Button */}
                      {onConfigureBlock && (
                        <motion.button
                          className={`config-button absolute -top-1 -right-1 w-8 h-8 bg-white/95 text-gray-800 rounded-full flex items-center justify-center shadow-lg z-20 hover:bg-white hover:shadow-xl transition-all duration-200 ${
                            showConfigButton === blockType.type ? 'opacity-100 scale-100' : 'opacity-0 scale-75 pointer-events-none'
                          }`}
                          whileHover={{ scale: 1.15 }}
                          whileTap={{ scale: 0.85 }}
                          onClick={(e) => {
                            e.stopPropagation()
                            e.preventDefault()
                            onConfigureBlock(blockType)
                          }}
                          title="Configure block template"
                          style={{ userSelect: 'none' }}
                        >
                          <Settings className="h-4 w-4" />
                        </motion.button>
                      )}
                    </div>


                  </motion.div>
                )
              })}
            </motion.div>
          )}
        </AnimatePresence>


        {/* Collapsed view */}
        {isCollapsed && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.2 }}
            className="space-y-3"
          >
            {blockTypes.map((blockType, index) => {
              return (
                <motion.button
                  key={blockType.type}
                  className={`w-12 h-12 rounded-lg border-2 flex items-center justify-center ${
                    isBlockUsed(blockType.type) ? blockType.usedColor : blockType.color
                  } hover:scale-110 transition-transform ${
                    isBlockUsed(blockType.type) ? 'cursor-not-allowed' : ''
                  }`}
                  style={{ userSelect: 'none' }}
                  onClick={() => !isBlockUsed(blockType.type) && onAddBlock(blockType)}
                  initial={{ opacity: 0, scale: 0 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ delay: index * 0.1 }}
                  whileHover={{ scale: isBlockUsed(blockType.type) ? 1 : 1.1 }}
                  whileTap={{ scale: isBlockUsed(blockType.type) ? 1 : 0.9 }}
                  title={isBlockUsed(blockType.type) ? `${blockType.name} (Already Used)` : blockType.name}
                >
                  <span className="text-lg" style={{ userSelect: 'none' }}>{blockType.emoji}</span>
                </motion.button>
              )
            })}
          </motion.div>
        )}
      </div>


      {/* Footer */}
      {!isCollapsed && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.4 }}
          className="p-4 border-t border-border/50"
        >
          <div className="text-xs text-muted-foreground text-center">
            <p>Click blocks to add to canvas</p>
            <p className="mt-1">Click to place, then connect blocks</p>
          </div>
        </motion.div>
      )}
    </motion.div>
  )
}


export default BlockPalette