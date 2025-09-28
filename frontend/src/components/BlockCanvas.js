"use client"

import { useState, useRef, useCallback, useEffect } from "react"
import { motion, AnimatePresence } from "framer-motion"
import { 
  Play, 
  Save, 
  FolderOpen, 
  Download, 
  Upload,
  Settings,
  Trash2,
  Plus,
  Link as LinkIcon,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  RotateCw,
  Grid,
  AlertTriangle,
  CheckCircle,
  X
} from "lucide-react"

const BlockCanvas = ({ 
  blocks, 
  setBlocks, 
  edges, 
  setEdges, 
  selectedBlock, 
  setSelectedBlock,
  onStartScan,
  onSaveProject,
  onLoadProject,
  onExportProject,
  onImportProject,
  onOpenProperties
}) => {
  const canvasRef = useRef(null)
  const [connectingFrom, setConnectingFrom] = useState(null)
  const [zoom, setZoom] = useState(1)
  const [pan, setPan] = useState({ x: 0, y: 0 })
  const [showGrid, setShowGrid] = useState(true)
  const [isPanning, setIsPanning] = useState(false)
  const [panStart, setPanStart] = useState({ x: 0, y: 0 })
  const [history, setHistory] = useState([])
  const [historyIndex, setHistoryIndex] = useState(-1)
  const [validationErrors, setValidationErrors] = useState([])
  const [showValidation, setShowValidation] = useState(false)
  const [showDeleteAllModal, setShowDeleteAllModal] = useState(false)
  const [dontShowAgain, setDontShowAgain] = useState(false)
  const [isMoving, setIsMoving] = useState(false)
  const [moveTarget, setMoveTarget] = useState(null)

  // Handle canvas click to move selected block
  const handleCanvasClick = useCallback((event) => {
    if (!selectedBlock || isMoving) return

    const rect = canvasRef.current.getBoundingClientRect()
    const mouseX = event.clientX - rect.left
    const mouseY = event.clientY - rect.top
    
    // Convert screen coordinates to canvas coordinates
    const canvasX = (mouseX - pan.x) / zoom
    const canvasY = (mouseY - pan.y) / zoom

    // Move the selected block to the clicked position
    setBlocks(prev => prev.map(block =>
      block.id === selectedBlock.id
        ? { ...block, x: canvasX - 64, y: canvasY - 64 } // Center the block on click
        : block
    ))

    // Save to history
    saveToHistory()
  }, [selectedBlock, isMoving, pan, zoom, setBlocks])

  // Handle block click to select
  const handleBlockClick = useCallback((blockId, event) => {
    event.stopPropagation()
    setSelectedBlock(blocks.find(b => b.id === blockId))
    setIsMoving(true)
    setMoveTarget(blockId)
  }, [blocks])

  // Handle block double click to open properties
  const handleBlockDoubleClick = useCallback((blockId, event) => {
    event.stopPropagation()
    onOpenProperties(blocks.find(b => b.id === blockId))
  }, [blocks, onOpenProperties])

  // Handle canvas panning
  const handleMouseDown = useCallback((event) => {
    if (event.button === 1 || (event.button === 0 && event.ctrlKey)) {
      event.preventDefault()
      setIsPanning(true)
      setPanStart({ x: event.clientX - pan.x, y: event.clientY - pan.y })
    }
  }, [pan])

  const handleMouseMove = useCallback((event) => {
    if (isPanning) {
      setPan({
        x: event.clientX - panStart.x,
        y: event.clientY - panStart.y
      })
    }
  }, [isPanning, panStart])

  const handleMouseUp = useCallback(() => {
    setIsPanning(false)
    setIsMoving(false)
    setMoveTarget(null)
  }, [])

  // Handle wheel zoom
  const handleWheel = useCallback((event) => {
    event.preventDefault()
    const delta = event.deltaY > 0 ? 0.9 : 1.1
    setZoom(prev => Math.max(0.1, Math.min(3, prev * delta)))
  }, [])

  // Handle keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (event) => {
      if (event.target.tagName === 'INPUT' || event.target.tagName === 'TEXTAREA') return

      switch (event.key) {
        case 'Delete':
        case 'Backspace':
          if (selectedBlock) {
            deleteBlock(selectedBlock.id)
          }
          break
        case 'Escape':
          setSelectedBlock(null)
          setConnectingFrom(null)
          break
        case 's':
          if (event.ctrlKey || event.metaKey) {
    event.preventDefault()
            onSaveProject()
          }
          break
        case 'o':
          if (event.ctrlKey || event.metaKey) {
            event.preventDefault()
            onLoadProject()
          }
          break
        case 'z':
          if (event.ctrlKey || event.metaKey) {
            event.preventDefault()
            if (event.shiftKey) {
              redo()
            } else {
              undo()
            }
          }
          break
        case 'y':
          if (event.ctrlKey || event.metaKey) {
            event.preventDefault()
            redo()
          }
          break
        case '=':
        case '+':
          if (event.ctrlKey || event.metaKey) {
            event.preventDefault()
            setZoom(prev => Math.min(3, prev * 1.1))
          }
          break
        case '-':
          if (event.ctrlKey || event.metaKey) {
            event.preventDefault()
            setZoom(prev => Math.max(0.1, prev * 0.9))
          }
          break
        case '0':
          if (event.ctrlKey || event.metaKey) {
            event.preventDefault()
            setZoom(1)
            setPan({ x: 0, y: 0 })
          }
          break
        case 'g':
          if (event.ctrlKey || event.metaKey) {
      event.preventDefault()
            setShowGrid(!showGrid)
          }
          break
      }
    }

    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [selectedBlock, showGrid, onSaveProject, onLoadProject])

  // History management
  const saveToHistory = useCallback(() => {
    const newState = { blocks: [...blocks], edges: [...edges] }
    setHistory(prev => {
      const newHistory = prev.slice(0, historyIndex + 1)
      newHistory.push(newState)
      return newHistory.slice(-50) // Keep last 50 states
    })
    setHistoryIndex(prev => Math.min(prev + 1, 49))
  }, [blocks, edges, historyIndex])

  const undo = useCallback(() => {
    if (historyIndex > 0) {
      const prevState = history[historyIndex - 1]
      setBlocks(prevState.blocks)
      setEdges(prevState.edges)
      setHistoryIndex(prev => prev - 1)
    }
  }, [history, historyIndex, setBlocks, setEdges])

  const redo = useCallback(() => {
    if (historyIndex < history.length - 1) {
      const nextState = history[historyIndex + 1]
      setBlocks(nextState.blocks)
      setEdges(nextState.edges)
      setHistoryIndex(prev => prev + 1)
    }
  }, [history, historyIndex, setBlocks, setEdges])

  // Block operations
  const deleteBlock = useCallback((blockId) => {
    setBlocks(prev => prev.filter(block => block.id !== blockId))
    setEdges(prev => prev.filter(edge => edge.from !== blockId && edge.to !== blockId))
    if (selectedBlock?.id === blockId) {
      setSelectedBlock(null)
    }
    saveToHistory()
  }, [setBlocks, setEdges, selectedBlock, saveToHistory])

  const deleteAllBlocks = useCallback(() => {
    setBlocks([])
    setEdges([])
    setSelectedBlock(null)
    setConnectingFrom(null)
    saveToHistory()
  }, [setBlocks, setEdges, setSelectedBlock, setConnectingFrom, saveToHistory])

  // Connection handling
  const handleConnectionStart = useCallback((blockId, event) => {
    event.stopPropagation()
    setConnectingFrom(blockId)
  }, [])

  const handleConnectionEnd = useCallback((blockId, event) => {
    event.stopPropagation()
    
    if (connectingFrom && connectingFrom !== blockId) {
      // Check if connection already exists
      const existingConnection = edges.find(
        edge => edge.from === connectingFrom && edge.to === blockId
      )
      
      if (!existingConnection) {
        setEdges(prev => [...prev, { from: connectingFrom, to: blockId }])
        saveToHistory()
      }
    }
    
    setConnectingFrom(null)
  }, [connectingFrom, edges, saveToHistory])

  // Validation
  const validateWorkflow = useCallback(() => {
    const errors = []
    
    if (blocks.length === 0) {
      errors.push("No blocks in workflow")
      return errors
    }

    // Check for isolated blocks
    const connectedBlocks = new Set()
    edges.forEach(edge => {
      connectedBlocks.add(edge.from)
      connectedBlocks.add(edge.to)
    })

    blocks.forEach(block => {
      if (!connectedBlocks.has(block.id)) {
        errors.push(`Block "${block.name}" is not connected to any other block`)
      }
    })

    // Check for cycles
    const visited = new Set()
    const recStack = new Set()
    
    const hasCycle = (nodeId) => {
      if (recStack.has(nodeId)) return true
      if (visited.has(nodeId)) return false
      
      visited.add(nodeId)
      recStack.add(nodeId)
      
      const outgoingEdges = edges.filter(edge => edge.from === nodeId)
      for (const edge of outgoingEdges) {
        if (hasCycle(edge.to)) return true
      }
      
      recStack.delete(nodeId)
      return false
    }
    
    for (const block of blocks) {
      if (hasCycle(block.id)) {
        errors.push("Workflow contains cycles")
        break
      }
    }
    
    return errors
  }, [blocks, edges])

  // Get block type color
  const getBlockColor = (type) => {
    const colors = {
      credentialed_scan: "bg-pink-200/90 border-pink-300/70 text-pink-800",
      logic_fuzzer: "bg-orange-200/90 border-orange-300/70 text-orange-800",
      llm_generator: "bg-purple-200/90 border-purple-300/70 text-purple-800",
      json_fuzzer: "bg-blue-200/90 border-blue-300/70 text-blue-800",
      supply_chain_scan: "bg-green-200/90 border-green-300/70 text-green-800"
    }
    return colors[type] || "bg-gray-200/90 border-gray-300/70 text-gray-800"
  }

  // Get block type icon
  const getBlockIcon = (type) => {
    const icons = {
      credentialed_scan: "🔐",
      logic_fuzzer: "⚡",
      llm_generator: "🤖",
      json_fuzzer: "📄",
      supply_chain_scan: "📦"
    }
    return icons[type] || "❓"
  }

  // Get block type name
  const getBlockName = (type) => {
    const names = {
      credentialed_scan: "Auth & Session Tests",
      logic_fuzzer: "Business Logic Tests",
      llm_generator: "AI Security Tests",
      json_fuzzer: "API Fuzzing Tests",
      supply_chain_scan: "Dependency Security"
    }
    return names[type] || type
  }

  return (
    <div className="flex-1 relative overflow-hidden bg-background">
      {/* Toolbar */}
      <div className="absolute top-4 left-4 z-20 flex gap-2">
        <div className="glass-card px-4 py-2 rounded-lg flex items-center gap-2">
          <button
            onClick={() => setZoom(prev => Math.max(0.1, prev * 0.9))}
            className="p-1 hover:bg-muted rounded"
            title="Zoom Out"
          >
            <ZoomOut className="w-4 h-4" />
          </button>
          <span className="text-sm text-muted-foreground min-w-[3rem] text-center">
            {Math.round(zoom * 100)}%
          </span>
          <button
            onClick={() => setZoom(prev => Math.min(3, prev * 1.1))}
            className="p-1 hover:bg-muted rounded"
            title="Zoom In"
          >
            <ZoomIn className="w-4 h-4" />
          </button>
          <div className="w-px h-4 bg-border mx-1" />
          <button
            onClick={() => setShowGrid(!showGrid)}
            className={`p-1 rounded ${showGrid ? 'bg-primary text-primary-foreground' : 'hover:bg-muted'}`}
            title="Toggle Grid"
          >
            <Grid className="w-4 h-4" />
          </button>
          <div className="w-px h-4 bg-border mx-1" />
          <button
            onClick={undo}
            disabled={historyIndex <= 0}
            className="p-1 hover:bg-muted rounded disabled:opacity-50"
            title="Undo"
          >
            <RotateCcw className="w-4 h-4" />
          </button>
          <button
            onClick={redo}
            disabled={historyIndex >= history.length - 1}
            className="p-1 hover:bg-muted rounded disabled:opacity-50"
            title="Redo"
          >
            <RotateCw className="w-4 h-4" />
          </button>
        </div>

        <div className="glass-card px-4 py-2 rounded-lg flex items-center gap-2">
          <button
            onClick={() => setShowValidation(!showValidation)}
            className={`p-1 rounded ${showValidation ? 'bg-primary text-primary-foreground' : 'hover:bg-muted'}`}
            title="Validate Workflow"
          >
            <CheckCircle className="w-4 h-4" />
          </button>
          <button
            onClick={onSaveProject}
            className="p-1 hover:bg-muted rounded"
            title="Save Project"
          >
            <Save className="w-4 h-4" />
          </button>
          <button
            onClick={onLoadProject}
            className="p-1 hover:bg-muted rounded"
            title="Load Project"
          >
            <FolderOpen className="w-4 h-4" />
          </button>
          <button
            onClick={onExportProject}
            className="p-1 hover:bg-muted rounded"
            title="Export Project"
          >
            <Download className="w-4 h-4" />
          </button>
          <button
            onClick={onImportProject}
            className="p-1 hover:bg-muted rounded"
            title="Import Project"
          >
            <Upload className="w-4 h-4" />
          </button>
        </div>

        <div className="glass-card px-4 py-2 rounded-lg flex items-center gap-2">
          <button
            onClick={() => setShowDeleteAllModal(true)}
            disabled={blocks.length === 0}
            className="p-1 hover:bg-muted rounded disabled:opacity-50 text-destructive"
            title="Delete All Blocks"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Canvas */}
      <div 
        ref={canvasRef}
        className="w-full h-full relative overflow-hidden cursor-crosshair"
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onWheel={handleWheel}
        onClick={handleCanvasClick}
        style={{
          cursor: isPanning ? 'grabbing' : 'crosshair',
          backgroundImage: showGrid 
            ? `radial-gradient(circle, hsl(var(--border)) 1px, transparent 1px)`
            : 'none',
          backgroundSize: `${20 * zoom}px ${20 * zoom}px`,
          backgroundPosition: `${pan.x}px ${pan.y}px`
        }}
      >
        {/* Blocks */}
        <AnimatePresence>
          {blocks.map((block) => (
            <motion.div
              key={block.id}
              className={`absolute w-32 h-32 rounded-xl border-2 cursor-pointer select-none ${
                getBlockColor(block.type)
              } ${
                selectedBlock?.id === block.id 
                  ? 'ring-2 ring-primary ring-offset-2 ring-offset-background' 
                  : ''
              } ${
                moveTarget === block.id
                  ? 'opacity-70 scale-105' 
                  : ''
              }`}
              style={{ 
                left: block.x * zoom + pan.x,
                top: block.y * zoom + pan.y,
                transform: `scale(${zoom})`,
                transformOrigin: 'top left'
              }}
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.8 }}
              transition={{ duration: 0.2 }}
              onClick={(e) => handleBlockClick(block.id, e)}
              onDoubleClick={(e) => handleBlockDoubleClick(block.id, e)}
            >
              {/* Block Content */}
              <div className="flex flex-col items-center justify-center h-full p-2">
                <div className="text-2xl mb-1">
                  {getBlockIcon(block.type)}
                </div>
                <div className="text-xs font-medium text-center leading-tight">
                  {getBlockName(block.type)}
                </div>
                </div>
                
              {/* Connection Points */}
              <div className="absolute -right-2 top-1/2 transform -translate-y-1/2">
                <button
                  className="w-4 h-4 bg-primary rounded-full border-2 border-background hover:bg-primary/80 transition-colors"
                  onMouseDown={(e) => handleConnectionStart(block.id, e)}
                  onMouseUp={(e) => handleConnectionEnd(block.id, e)}
                  title="Connect to other blocks"
                />
                </div>
                
              <div className="absolute -left-2 top-1/2 transform -translate-y-1/2">
                <button
                  className="w-4 h-4 bg-muted rounded-full border-2 border-background hover:bg-muted/80 transition-colors"
                  onMouseUp={(e) => {
                    e.stopPropagation()
                    handleConnectionEnd(block.id, e)
                  }}
                  title="Connect from other blocks"
                />
              </div>

              {/* Delete Button */}
              <button
                className="absolute -top-2 -right-2 w-6 h-6 bg-destructive text-destructive-foreground rounded-full border-2 border-background hover:bg-destructive/80 transition-colors flex items-center justify-center"
                onClick={(e) => {
                  e.stopPropagation()
                  deleteBlock(block.id)
                }}
                title="Delete Block"
              >
                <X className="w-3 h-3" />
              </button>
            </motion.div>
          ))}
        </AnimatePresence>

        {/* Connections */}
        <svg
          className="absolute inset-0 pointer-events-none"
          style={{ zIndex: 1 }}
        >
          {edges.map((edge, index) => {
            const fromBlock = blocks.find(b => b.id === edge.from)
            const toBlock = blocks.find(b => b.id === edge.to)
            
            if (!fromBlock || !toBlock) return null

            const fromX = (fromBlock.x + 128) * zoom + pan.x
            const fromY = (fromBlock.y + 64) * zoom + pan.y
            const toX = toBlock.x * zoom + pan.x
            const toY = (toBlock.y + 64) * zoom + pan.y

            return (
              <motion.line
                key={index}
                x1={fromX}
                y1={fromY}
                x2={toX}
                y2={toY}
                stroke="hsl(var(--primary))"
                strokeWidth="2"
                fill="none"
                initial={{ pathLength: 0 }}
                animate={{ pathLength: 1 }}
                transition={{ duration: 0.3 }}
              />
            )
          })}
        </svg>

        {/* Connection Preview */}
        {connectingFrom && (
          <svg className="absolute inset-0 pointer-events-none" style={{ zIndex: 2 }}>
            <line
              x1={(blocks.find(b => b.id === connectingFrom)?.x + 128) * zoom + pan.x}
              y1={(blocks.find(b => b.id === connectingFrom)?.y + 64) * zoom + pan.y}
              x2={0} // Will be updated by mouse position
              y2={0} // Will be updated by mouse position
              stroke="hsl(var(--primary))"
              strokeWidth="2"
              strokeDasharray="5,5"
              fill="none"
            />
          </svg>
        )}

        {/* Instructions */}
        {blocks.length === 0 && (
          <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
            <div className="glass-card px-8 py-6 rounded-xl text-center">
              <h3 className="text-lg font-semibold text-foreground mb-2">
                Click to Place Blocks
              </h3>
              <p className="text-sm text-muted-foreground">
                Select a block from the palette, then click anywhere on the canvas to place it.
              </p>
            </div>
              </div>
        )}

        {/* Moving Instructions */}
        {isMoving && selectedBlock && (
          <div className="absolute top-20 left-1/2 transform -translate-x-1/2 pointer-events-none">
            <div className="glass-card px-4 py-2 rounded-lg">
              <p className="text-sm text-foreground">
                Click anywhere to move the selected block
              </p>
            </div>
          </div>
        )}
      </div>

      {/* Validation Errors */}
      <AnimatePresence>
        {showValidation && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 20 }}
            className="absolute bottom-4 right-4 z-20"
          >
            <div className="glass-card p-4 rounded-lg max-w-sm">
              <div className="flex items-center gap-2 mb-2">
                <AlertTriangle className="w-4 h-4 text-destructive" />
                <h4 className="font-semibold text-foreground">Validation Errors</h4>
              </div>
              <div className="space-y-1">
                {validateWorkflow().map((error, index) => (
                  <p key={index} className="text-sm text-muted-foreground">
                    • {error}
                  </p>
                ))}
              </div>
              </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Delete All Modal */}
      <AnimatePresence>
        {showDeleteAllModal && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
            onClick={() => setShowDeleteAllModal(false)}
          >
            <motion.div
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              className="glass-card p-6 rounded-xl max-w-sm mx-4"
              onClick={(e) => e.stopPropagation()}
            >
              <h3 className="text-lg font-semibold text-foreground mb-2">
                Delete All Blocks
              </h3>
              <p className="text-sm text-muted-foreground mb-4">
                This will permanently delete all blocks and connections. This action cannot be undone.
              </p>
              <div className="flex gap-2">
                <button
                  onClick={() => setShowDeleteAllModal(false)}
                  className="flex-1 px-4 py-2 bg-muted text-muted-foreground rounded-lg hover:bg-muted/80 transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={() => {
                    deleteAllBlocks()
                    setShowDeleteAllModal(false)
                  }}
                  className="flex-1 px-4 py-2 bg-destructive text-destructive-foreground rounded-lg hover:bg-destructive/80 transition-colors"
                >
                  Delete All
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

export default BlockCanvas