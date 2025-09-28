"use client"

import { useState } from "react"
import { motion, AnimatePresence } from "framer-motion"
import { 
  ChevronLeft, 
  ChevronRight, 
  Shield, 
  Zap, 
  Brain, 
  Code, 
  Package,
  Lock,
  Settings
} from "lucide-react"

const BlockPalette = ({ onAddBlock, isCollapsed, onToggleCollapse, usedBlocks = [], onConfigureBlock }) => {
  const [draggedBlock, setDraggedBlock] = useState(null)
  const [showConfigButton, setShowConfigButton] = useState(null)

  const blockTypes = [
    {
      type: "credentialed_scan",
      name: "Credentialed Scan",
      description: "Authenticated security testing with user credentials",
      icon: Lock,
      emoji: "🔐",
      color: "bg-red-700/20 border-red-600/40 text-red-300",
      usedColor: "bg-red-900/30 border-red-800/50 text-red-500",
      severity: "high"
    },
    {
      type: "logic_fuzzer",
      name: "Logic Fuzzer",
      description: "Test application logic and business rules",
      icon: Zap,
      emoji: "⚡",
      color: "bg-orange-700/20 border-orange-600/40 text-orange-300",
      usedColor: "bg-orange-900/30 border-orange-800/50 text-orange-500",
      severity: "medium"
    },
    {
      type: "llm_generator",
      name: "LLM Generator",
      description: "AI-powered test case generation",
      icon: Brain,
      emoji: "🤖",
      color: "bg-purple-700/20 border-purple-600/40 text-purple-300",
      usedColor: "bg-purple-900/30 border-purple-800/50 text-purple-500",
      severity: "low"
    },
    {
      type: "json_fuzzer",
      name: "JSON Fuzzer",
      description: "Fuzz JSON APIs and data structures",
      icon: Code,
      emoji: "📄",
      color: "bg-blue-700/20 border-blue-600/40 text-blue-300",
      usedColor: "bg-blue-900/30 border-blue-800/50 text-blue-500",
      severity: "medium"
    },
    {
      type: "supply_chain_scan",
      name: "Supply Chain Scan",
      description: "Analyze dependencies and supply chain risks",
      icon: Package,
      emoji: "📦",
      color: "bg-green-700/20 border-green-600/40 text-green-300",
      usedColor: "bg-green-900/30 border-green-800/50 text-green-500",
      severity: "high"
    }
  ]

  const handleDragStart = (blockType, event) => {
    setDraggedBlock(blockType)
    event.dataTransfer.effectAllowed = 'copy'
    event.dataTransfer.setData('application/json', JSON.stringify(blockType))
    
    // Create a custom drag image with enhanced styling
    const dragImage = event.target.cloneNode(true)
    dragImage.style.transform = 'rotate(8deg) scale(1.1)'
    dragImage.style.opacity = '0.9'
    dragImage.style.filter = 'drop-shadow(0 10px 20px rgba(0,0,0,0.3))'
    dragImage.style.border = '2px solid rgba(59, 130, 246, 0.8)'
    dragImage.style.borderRadius = '12px'
    dragImage.style.backgroundColor = 'rgba(255, 255, 255, 0.95)'
    dragImage.style.padding = '8px'
    dragImage.style.zIndex = '1000'
    dragImage.style.position = 'absolute'
    dragImage.style.pointerEvents = 'none'
    dragImage.style.left = '-1000px'
    dragImage.style.top = '-1000px'
    
    document.body.appendChild(dragImage)
    event.dataTransfer.setDragImage(dragImage, 64, 64)
    
    // Clean up the drag image after a short delay
    setTimeout(() => {
      if (document.body.contains(dragImage)) {
        document.body.removeChild(dragImage)
      }
    }, 0)
  }

  const handleDragEnd = () => {
    setDraggedBlock(null)
  }

  // Check if block type is already used
  const isBlockUsed = (blockType) => {
    return usedBlocks.some(block => block.type === blockType)
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
                const IconComponent = blockType.icon
                return (
                  <motion.div
                    key={blockType.type}
                    className={`relative w-28 h-28 rounded-xl border-2 cursor-grab active:cursor-grabbing ${
                      isBlockUsed(blockType.type) ? blockType.usedColor : blockType.color
                    } hover:scale-105 transition-all duration-200 ${
                      isBlockUsed(blockType.type) ? 'cursor-not-allowed' : ''
                    } group shadow-lg hover:shadow-xl ${
                      draggedBlock?.type === blockType.type ? 'ring-2 ring-blue-400 shadow-blue-400/50' : ''
                    }`}
                    style={{ 
                      userSelect: 'none',
                      transform: draggedBlock?.type === blockType.type ? 'rotate(2deg)' : 'rotate(0deg)',
                      filter: draggedBlock?.type === blockType.type ? 'drop-shadow(0 5px 15px rgba(0,0,0,0.2))' : 'none'
                    }}
                    draggable={!isBlockUsed(blockType.type)}
                    onDragStart={(e) => !isBlockUsed(blockType.type) && handleDragStart(blockType, e)}
                    onDragEnd={handleDragEnd}
                    onMouseEnter={() => setShowConfigButton(blockType.type)}
                    onMouseLeave={() => setShowConfigButton(null)}
                    initial={{ opacity: 0, y: 20, rotate: -10 }}
                    animate={{ 
                      opacity: 1, 
                      y: 0, 
                      rotate: draggedBlock?.type === blockType.type ? 2 : 0
                    }}
                    transition={{ 
                      delay: index * 0.1,
                      type: "spring",
                      stiffness: 100,
                      damping: 10
                    }}
                    whileHover={{ 
                      scale: isBlockUsed(blockType.type) ? 1 : 1.08,
                      rotate: isBlockUsed(blockType.type) ? 0 : 2,
                      y: isBlockUsed(blockType.type) ? 0 : -2
                    }}
                    whileTap={{ 
                      scale: isBlockUsed(blockType.type) ? 1 : 0.95,
                      rotate: isBlockUsed(blockType.type) ? 0 : -1
                    }}
                    onClick={() => !isBlockUsed(blockType.type) && onAddBlock(blockType)}
                  >
                    <div className="p-4 h-full flex flex-col justify-center items-center text-center relative" style={{ userSelect: 'none' }}>
                      {/* Block Icon */}
                      <div className="text-3xl mb-2" style={{ userSelect: 'none' }}>
                        {blockType.emoji}
                      </div>
                      
                      <h3 className="font-bold text-xs capitalize mb-1 leading-tight" style={{ userSelect: 'none' }}>
                        {blockType.type.replace('_', ' ').split(' ')[0]}
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
              const IconComponent = blockType.icon
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
            <p>Drag blocks to canvas or click to add</p>
            <p className="mt-1">Connect blocks to create workflows</p>
          </div>
        </motion.div>
      )}
    </motion.div>
  )
}

export default BlockPalette
