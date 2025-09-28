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
  const [isDragging, setIsDragging] = useState(false)
  const [dragOffset, setDragOffset] = useState({ x: 0, y: 0 })
  const [dragStartPos, setDragStartPos] = useState({ x: 0, y: 0 })
  const [connectingFrom, setConnectingFrom] = useState(null)
  const [showProperties, setShowProperties] = useState(false)
  const [zoom, setZoom] = useState(1)
  const [pan, setPan] = useState({ x: 0, y: 0 })
  const [showGrid, setShowGrid] = useState(true)
  const [isPanning, setIsPanning] = useState(false)
  const [panStart, setPanStart] = useState({ x: 0, y: 0 })
  const [history, setHistory] = useState([])
  const [historyIndex, setHistoryIndex] = useState(-1)
  const [validationErrors, setValidationErrors] = useState([])
  const [showValidation, setShowValidation] = useState(false)
  const [deleteZoneActive, setDeleteZoneActive] = useState(false)
  const [showConfigButton, setShowConfigButton] = useState(null)
  const [showDeleteButton, setShowDeleteButton] = useState(null)
  const [draggedBlockId, setDraggedBlockId] = useState(null)
  const [magneticSnap, setMagneticSnap] = useState(null)
  const [isMouseDown, setIsMouseDown] = useState(false)
  const [dragOverCanvas, setDragOverCanvas] = useState(false)
  const [showDeleteAllModal, setShowDeleteAllModal] = useState(false)
  const [dontShowAgain, setDontShowAgain] = useState(false)

  // Handle block drag start
  const handleBlockDragStart = useCallback((blockId, event) => {
    event.preventDefault()
    event.stopPropagation()
    
    const block = blocks.find(b => b.id === blockId)
    if (!block) return

    const rect = canvasRef.current.getBoundingClientRect()
    const mouseX = event.clientX - rect.left
    const mouseY = event.clientY - rect.top
    
    setDragOffset({
      x: mouseX - block.x,
      y: mouseY - block.y
    })
    setDragStartPos({ x: mouseX, y: mouseY })
    setIsDragging(true)
    setDraggedBlockId(blockId)
    setDeleteZoneActive(true)
    setShowConfigButton(null)
    setShowDeleteButton(null)
    setMagneticSnap(null)
    setIsMouseDown(true)
  }, [blocks])

  // Handle mouse move for smooth dragging
  const handleMouseMove = useCallback((event) => {
    if (!isDragging || !draggedBlockId) return

    event.preventDefault()
    const rect = canvasRef.current.getBoundingClientRect()
    const mouseX = event.clientX - rect.left
    const mouseY = event.clientY - rect.top
    
    let newX = mouseX - dragOffset.x
    let newY = mouseY - dragOffset.y

    // Smooth movement without grid snapping during drag
    // Only apply grid snapping when not near other blocks
    
    // Magnetic snapping to other blocks (strong and responsive)
    const blockSize = 128
    const magneticThreshold = 50  // Increased for more responsive snapping
    const snapThreshold = 15      // Increased for easier snapping
    const currentBlock = blocks.find(b => b.id === draggedBlockId)
    
    if (currentBlock) {
      let magneticTarget = null
      let minDistance = Infinity
      
      for (const otherBlock of blocks) {
        if (otherBlock.id === draggedBlockId) continue
        
        // Calculate distances to connection points with better precision
        const distances = {
          rightToLeft: Math.sqrt(Math.pow(otherBlock.x - blockSize - newX, 2) + Math.pow(otherBlock.y - newY, 2)),
          leftToRight: Math.sqrt(Math.pow(otherBlock.x + blockSize - newX, 2) + Math.pow(otherBlock.y - newY, 2)),
          bottomToTop: Math.sqrt(Math.pow(otherBlock.y - blockSize - newY, 2) + Math.pow(otherBlock.x - newX, 2)),
          topToBottom: Math.sqrt(Math.pow(otherBlock.y + blockSize - newY, 2) + Math.pow(otherBlock.x - newX, 2))
        }
        
        // Check for magnetic attraction
        for (const [connection, distance] of Object.entries(distances)) {
          if (distance < magneticThreshold && distance < minDistance) {
            minDistance = distance
            magneticTarget = { block: otherBlock, connection, distance }
          }
        }
      }
      
      // Apply magnetic snapping with smooth transition
      if (magneticTarget && magneticTarget.distance < snapThreshold) {
        const { block: otherBlock, connection } = magneticTarget
        
        switch (connection) {
          case 'rightToLeft':
            newX = otherBlock.x - blockSize
            newY = otherBlock.y
            break
          case 'leftToRight':
            newX = otherBlock.x + blockSize
            newY = otherBlock.y
            break
          case 'bottomToTop':
            newX = otherBlock.x
            newY = otherBlock.y - blockSize
            break
          case 'topToBottom':
            newX = otherBlock.x
            newY = otherBlock.y + blockSize
            break
        }
        setMagneticSnap({ blockId: draggedBlockId, targetBlock: otherBlock.id, connection })
      } else {
        setMagneticSnap(null)
        // Apply light grid snapping only when not magnetically attracted
        const gridSize = 20
        newX = Math.round(newX / gridSize) * gridSize
        newY = Math.round(newY / gridSize) * gridSize
      }
    }

    // Keep within canvas bounds
    newX = Math.max(0, Math.min(newX, 800))
    newY = Math.max(0, Math.min(newY, 600))

    setBlocks(prev => prev.map(block => 
      block.id === draggedBlockId 
        ? { ...block, x: newX, y: newY }
        : block
    ))
  }, [isDragging, dragOffset, setBlocks, blocks, draggedBlockId])

  // Handle mouse up
  const handleMouseUp = useCallback(() => {
    if (isDragging && draggedBlockId) {
      handleBlockDragEnd(draggedBlockId)
    }
    setIsMouseDown(false)
  }, [isDragging, draggedBlockId])

    // Delete block
    const deleteBlock = useCallback((blockId) => {
      setBlocks(prev => prev.filter(b => b.id !== blockId))
      setEdges(prev => prev.filter(e => e.from !== blockId && e.to !== blockId))
      if (selectedBlock?.id === blockId) {
        setSelectedBlock(null)
        setShowProperties(false)
      }
    }, [setBlocks, setEdges, selectedBlock, setSelectedBlock])

  // Handle block drag end
  const handleBlockDragEnd = useCallback((blockId) => {
    setIsDragging(false)
    setDraggedBlockId(null)
    setDeleteZoneActive(false)
    setMagneticSnap(null)
    setShowConfigButton(null)
    setShowDeleteButton(null)
  }, [])

  // Add global mouse event listeners
  useEffect(() => {
    if (isDragging) {
      document.addEventListener('mousemove', handleMouseMove)
      document.addEventListener('mouseup', handleMouseUp)
      return () => {
        document.removeEventListener('mousemove', handleMouseMove)
        document.removeEventListener('mouseup', handleMouseUp)
      }
    }
  }, [isDragging, handleMouseMove, handleMouseUp])

  // Handle drag over canvas
  const handleDragOver = useCallback((event) => {
    event.preventDefault()
    event.dataTransfer.dropEffect = 'copy'
    setDragOverCanvas(true)
  }, [])

  // Handle drag leave canvas
  const handleDragLeave = useCallback((event) => {
    if (!canvasRef.current?.contains(event.relatedTarget)) {
      setDragOverCanvas(false)
    }
  }, [])

  // Handle drop on canvas
  const handleDrop = useCallback((event) => {
    event.preventDefault()
    setDragOverCanvas(false)
    
    try {
      const blockTypeData = event.dataTransfer.getData('application/json')
      if (blockTypeData) {
        const blockType = JSON.parse(blockTypeData)
        
        // Get drop position
        const rect = canvasRef.current.getBoundingClientRect()
        const x = event.clientX - rect.left - 64 // Center the block
        const y = event.clientY - rect.top - 64
        
        // Check if block type already exists
        const existingBlock = blocks.find(block => block.type === blockType.type)
        if (existingBlock) {
          alert(`Block type "${blockType.type}" is already on the canvas`)
          return
        }

        // Create new block
        const newBlock = {
          id: `block-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
          type: blockType.type,
          x: Math.max(0, Math.min(x, 800)),
          y: Math.max(0, Math.min(y, 600)),
          script: `tests/${blockType.type}.py::run_scan`,
          inputs: {
            target_url: "https://demo.app",
            ...(blockType.type === 'credentialed_scan' && { username: "vaultRef:cred-1" })
          },
          safe_mode: true,
          timeout_seconds: 600,
          metadata: {
            severity: blockType.severity,
            mvp: true
          }
        }
        
        setBlocks(prev => [...prev, newBlock])
      }
    } catch (error) {
      console.error('Error handling drop:', error)
    }
  }, [blocks, setBlocks])

  // Handle delete all blocks
  const handleDeleteAllBlocks = useCallback(() => {
    // Check if user has disabled confirmations
    const skipConfirmation = localStorage.getItem('skipDeleteAllConfirmation') === 'true'
    
    if (skipConfirmation) {
      // Delete without confirmation
      setBlocks([])
      setEdges([])
      setSelectedBlock(null)
    } else {
      // Show custom confirmation modal
      setShowDeleteAllModal(true)
    }
  }, [setBlocks, setEdges, setSelectedBlock])

  // Confirm delete all blocks
  const confirmDeleteAll = useCallback(() => {
    setBlocks([])
    setEdges([])
    setSelectedBlock(null)
    setShowDeleteAllModal(false)
    
    // Save preference if checkbox was checked
    if (dontShowAgain) {
      localStorage.setItem('skipDeleteAllConfirmation', 'true')
    }
    setDontShowAgain(false)
  }, [setBlocks, setEdges, setSelectedBlock, dontShowAgain])

  // Cancel delete all
  const cancelDeleteAll = useCallback(() => {
    setShowDeleteAllModal(false)
    setDontShowAgain(false)
  }, [])

  // Handle block click
  const handleBlockClick = useCallback((block, event) => {
    // Don't handle clicks during drag
    if (isDragging) return
    
    // Check if clicking on config button
    if (event.target.closest('.config-button')) {
      event.stopPropagation()
      event.preventDefault()
      setSelectedBlock(block)
      onOpenProperties(block)
      return
    }
    
    // If clicking on the block itself (not config button), just select it
    setSelectedBlock(block)
  }, [isDragging, setSelectedBlock, onOpenProperties])

  // Handle block hover for buttons
  const handleBlockHover = useCallback((blockId, isHovering) => {
    if (!isDragging && draggedBlockId !== blockId) {
      setShowConfigButton(isHovering ? blockId : null)
      setShowDeleteButton(isHovering ? blockId : null)
    }
  }, [isDragging, draggedBlockId])

  // Handle connection start
  const handleConnectionStart = useCallback((blockId) => {
    setConnectingFrom(blockId)
  }, [])

  // Handle connection end
  const handleConnectionEnd = useCallback((targetBlockId) => {
    if (connectingFrom && connectingFrom !== targetBlockId) {
      const newEdge = { from: connectingFrom, to: targetBlockId }
      setEdges(prev => [...prev, newEdge])
    }
    setConnectingFrom(null)
  }, [connectingFrom, setEdges])



  // Save state to history for undo/redo
  const saveToHistory = useCallback(() => {
    const state = { blocks: [...blocks], edges: [...edges] }
    const newHistory = history.slice(0, historyIndex + 1)
    newHistory.push(state)
    setHistory(newHistory)
    setHistoryIndex(newHistory.length - 1)
  }, [blocks, edges, history, historyIndex])

  // Undo
  const undo = useCallback(() => {
    if (historyIndex > 0) {
      const prevState = history[historyIndex - 1]
      setBlocks(prevState.blocks)
      setEdges(prevState.edges)
      setHistoryIndex(historyIndex - 1)
    }
  }, [history, historyIndex, setBlocks, setEdges])

  // Redo
  const redo = useCallback(() => {
    if (historyIndex < history.length - 1) {
      const nextState = history[historyIndex + 1]
      setBlocks(nextState.blocks)
      setEdges(nextState.edges)
      setHistoryIndex(historyIndex + 1)
    }
  }, [history, historyIndex, setBlocks, setEdges])

  // Validate graph
  const validateGraph = useCallback(() => {
    const errors = []
    
    // Check for missing required inputs
    blocks.forEach(block => {
      if (block.type === 'credentialed_scan' && !block.inputs?.username) {
        errors.push(`Block ${block.id}: Missing required username input`)
      }
      if (block.type === 'json_fuzzer' && !block.inputs?.api_endpoint) {
        errors.push(`Block ${block.id}: Missing required api_endpoint input`)
      }
    })
    
    // Check for cycles (simple cycle detection)
    const visited = new Set()
    const recStack = new Set()
    
    const hasCycle = (nodeId) => {
      if (recStack.has(nodeId)) return true
      if (visited.has(nodeId)) return false
      
      visited.add(nodeId)
      recStack.add(nodeId)
      
      const outgoingEdges = edges.filter(e => e.from === nodeId)
      for (const edge of outgoingEdges) {
        if (hasCycle(edge.to)) return true
      }
      
      recStack.delete(nodeId)
      return false
    }
    
    for (const block of blocks) {
      if (hasCycle(block.id)) {
        errors.push(`Cycle detected involving block ${block.id}`)
        break
      }
    }
    
    setValidationErrors(errors)
    return errors.length === 0
  }, [blocks, edges])

  // Handle start scan with validation
  const handleStartScan = useCallback(async () => {
    if (!validateGraph()) {
      setShowValidation(true)
      return
    }
    
    // Check for vault references and require consent
    const hasVaultRefs = blocks.some(block => 
      Object.values(block.inputs || {}).some(value => 
        typeof value === 'string' && value.startsWith('vaultRef:')
      )
    )
    
    if (hasVaultRefs) {
      const consent = window.confirm(
        'This scan contains vault references (credentials). Do you consent to using these credentials for this scan?\n\n' +
        'Note: Credentials will be handled securely and not logged in plaintext.'
      )
      if (!consent) return
    }
    
    await onStartScan()
  }, [validateGraph, blocks, onStartScan])

  // Handle zoom
  const handleZoom = useCallback((delta) => {
    setZoom(prev => Math.max(0.1, Math.min(3, prev + delta)))
  }, [])

  // Handle pan start
  const handlePanStart = useCallback((event) => {
    if (event.button === 1 || (event.button === 0 && event.ctrlKey)) { // Middle mouse or Ctrl+click
      setIsPanning(true)
      setPanStart({ x: event.clientX - pan.x, y: event.clientY - pan.y })
    }
  }, [pan])

  // Handle pan move
  const handlePanMove = useCallback((event) => {
    if (isPanning) {
      setPan({
        x: event.clientX - panStart.x,
        y: event.clientY - panStart.y
      })
    }
  }, [isPanning, panStart])

  // Handle pan end
  const handlePanEnd = useCallback(() => {
    setIsPanning(false)
  }, [])

  // Keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (event) => {
      if (event.ctrlKey || event.metaKey) {
        switch (event.key) {
          case 'z':
            event.preventDefault()
            if (event.shiftKey) {
              redo()
            } else {
              undo()
            }
            break
          case 's':
            event.preventDefault()
            onSaveProject()
            break
          case 'o':
            event.preventDefault()
            onLoadProject()
            break
          case '+':
          case '=':
            event.preventDefault()
            handleZoom(0.1)
            break
          case '-':
            event.preventDefault()
            handleZoom(-0.1)
            break
        }
      }
      
      if (event.key === 'Delete' && selectedBlock) {
        deleteBlock(selectedBlock.id)
      }
    }
    
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [undo, redo, onSaveProject, onLoadProject, handleZoom, selectedBlock, deleteBlock])

  // Get block type color
  const getBlockColor = (type) => {
    const colors = {
      credentialed_scan: "bg-red-700/80 border-red-600/60 text-red-100",
      logic_fuzzer: "bg-orange-700/80 border-orange-600/60 text-orange-100",
      llm_generator: "bg-purple-700/80 border-purple-600/60 text-purple-100",
      json_fuzzer: "bg-blue-700/80 border-blue-600/60 text-blue-100",
      supply_chain_scan: "bg-green-700/80 border-green-600/60 text-green-100"
    }
    return colors[type] || "bg-gray-700/80 border-gray-600/60 text-gray-100"
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
    return icons[type] || "🔧"
  }

  return (
    <div className="flex-1 relative overflow-hidden">
      {/* Canvas */}
      <div 
        ref={canvasRef}
        className={`w-full h-full relative bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 cursor-grab active:cursor-grabbing transition-all duration-200 ${
          dragOverCanvas ? 'ring-2 ring-primary/50 bg-primary/5' : ''
        }`}
        style={{
          backgroundImage: `
            radial-gradient(circle at 20% 50%, rgba(120, 119, 198, 0.1) 0%, transparent 50%),
            radial-gradient(circle at 80% 20%, rgba(255, 119, 198, 0.1) 0%, transparent 50%),
            radial-gradient(circle at 40% 80%, rgba(120, 219, 255, 0.1) 0%, transparent 50%)
          `,
          transform: `scale(${zoom}) translate(${pan.x}px, ${pan.y}px)`,
          transformOrigin: '0 0'
        }}
        onMouseDown={handlePanStart}
        onMouseMove={handlePanMove}
        onMouseUp={handlePanEnd}
        onMouseLeave={handlePanEnd}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
      >
        {/* Grid Pattern */}
        {showGrid && (
          <div 
            className="absolute inset-0 opacity-20"
            style={{
              backgroundImage: `
                linear-gradient(rgba(255,255,255,0.1) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255,255,255,0.1) 1px, transparent 1px)
              `,
              backgroundSize: `${20 * zoom}px ${20 * zoom}px`
            }}
          />
        )}

        {/* Edges */}
        <svg className="absolute inset-0 pointer-events-none" style={{ zIndex: 1 }}>
          {edges.map((edge, index) => {
            const fromBlock = blocks.find(b => b.id === edge.from)
            const toBlock = blocks.find(b => b.id === edge.to)
            if (!fromBlock || !toBlock) return null

            const startX = fromBlock.x + 64 // center of 128px block
            const startY = fromBlock.y + 64
            const endX = toBlock.x + 64
            const endY = toBlock.y + 64

            // Create curved path for better visual appeal
            const midX = (startX + endX) / 2
            const midY = (startY + endY) / 2
            const controlX = midX + (endY - startY) * 0.3
            const controlY = midY - (endX - startX) * 0.3
            
            const pathData = `M ${startX} ${startY} Q ${controlX} ${controlY} ${endX} ${endY}`

            return (
              <motion.path
                key={index}
                d={pathData}
                stroke="rgba(59, 130, 246, 0.6)"
                strokeWidth="2"
                fill="none"
                strokeDasharray="5,5"
                initial={{ pathLength: 0 }}
                animate={{ pathLength: 1 }}
                transition={{ duration: 0.5, delay: index * 0.1 }}
              />
            )
          })}
        </svg>

        {/* Blocks */}
        <AnimatePresence>
          {blocks.map((block) => (
            <motion.div
              key={block.id}
              className={`absolute w-32 h-32 rounded-xl border-2 cursor-move select-none ${getBlockColor(block.type)} ${
                selectedBlock?.id === block.id ? 'ring-2 ring-white' : ''
              } ${
                draggedBlockId === block.id ? 'opacity-80 scale-105' : ''
              } ${
                magneticSnap?.targetBlock === block.id ? 'ring-2 ring-yellow-400' : ''
              } group transition-all duration-200`}
              style={{ 
                left: block.x, 
                top: block.y,
                zIndex: draggedBlockId === block.id ? 10 : 2,
                userSelect: 'none',
                WebkitUserSelect: 'none',
                MozUserSelect: 'none',
                msUserSelect: 'none'
              }}
              initial={{ scale: 0, opacity: 0 }}
              animate={{ 
                scale: draggedBlockId === block.id ? 1.05 : 1, 
                opacity: 1,
                rotate: 0
              }}
              exit={{ scale: 0, opacity: 0 }}
              whileHover={{ scale: draggedBlockId === block.id ? 1.05 : 1.05 }}
              whileTap={{ scale: 0.95 }}
              onMouseDown={(e) => handleBlockDragStart(block.id, e)}
              onMouseEnter={() => handleBlockHover(block.id, true)}
              onMouseLeave={() => handleBlockHover(block.id, false)}
              onClick={(e) => handleBlockClick(block, e)}
            >
              <div className="p-4 h-full flex flex-col justify-center items-center text-center relative" style={{ userSelect: 'none' }}>
                {/* Block Icon */}
                <div className="text-3xl mb-2">
                  {getBlockIcon(block.type)}
                </div>
                
                <h3 className="font-bold text-xs capitalize mb-1 leading-tight" style={{ userSelect: 'none' }}>
                  {block.type.replace('_', ' ')}
                </h3>
                <div className="text-xs opacity-90" style={{ userSelect: 'none' }}>
                  {block.metadata?.severity || 'medium'}
                </div>
                
                {/* Delete Button */}
                <motion.button
                  className={`delete-button absolute -top-1 -right-1 w-8 h-8 bg-red-500/90 text-white rounded-full flex items-center justify-center shadow-lg z-20 hover:bg-red-600 hover:shadow-xl transition-all duration-200 ${
                    showDeleteButton === block.id ? 'opacity-100 scale-100' : 'opacity-0 scale-75 pointer-events-none'
                  }`}
                  whileHover={{ scale: 1.15 }}
                  whileTap={{ scale: 0.85 }}
                  onClick={(e) => {
                    e.stopPropagation()
                    e.preventDefault()
                    if (window.confirm('Are you sure you want to delete this block?')) {
                      deleteBlock(block.id)
                    }
                  }}
                  title="Delete block"
                  style={{ userSelect: 'none' }}
                >
                  <X className="h-4 w-4" />
                </motion.button>
              </div>

              {/* Connection points */}
              <div 
                className="absolute -right-2 top-1/2 transform -translate-y-1/2 w-4 h-4 bg-white rounded-full cursor-pointer opacity-0 hover:opacity-100 transition-opacity border-2 border-gray-800"
                onMouseDown={(e) => {
                  e.stopPropagation()
                  handleConnectionStart(block.id)
                }}
                title="Connect to other blocks"
              />
              <div 
                className="absolute -left-2 top-1/2 transform -translate-y-1/2 w-4 h-4 bg-white rounded-full cursor-pointer opacity-0 hover:opacity-100 transition-opacity border-2 border-gray-800"
                onMouseUp={(e) => {
                  e.stopPropagation()
                  handleConnectionEnd(block.id)
                }}
                title="Connect from other blocks"
              />
            </motion.div>
          ))}
        </AnimatePresence>

        {/* Delete All Blocks Button */}
        {blocks.length > 0 && (
          <motion.div
            className="absolute bottom-8 left-1/2 transform -translate-x-1/2 z-30"
            initial={{ scale: 0, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0, opacity: 0 }}
          >
            <motion.button
              onClick={handleDeleteAllBlocks}
              className="flex items-center space-x-2 px-4 py-2 bg-red-600/90 hover:bg-red-600 text-white rounded-xl font-medium shadow-lg hover:shadow-xl transition-all duration-200"
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              style={{ userSelect: 'none' }}
            >
              <Trash2 className="h-5 w-5" />
              <span>Delete All Blocks</span>
            </motion.button>
          </motion.div>
        )}

        {/* Empty state */}
        {blocks.length === 0 && (
          <motion.div
            className="absolute inset-0 flex items-center justify-center"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
          >
            <div className="text-center text-muted-foreground">
              <div className="w-24 h-24 mx-auto mb-4 rounded-full bg-primary/10 flex items-center justify-center">
                <Plus className="h-12 w-12 text-primary" />
              </div>
              <h3 className="text-xl font-semibold mb-2">Empty Canvas</h3>
              <p>Drag blocks from the palette to start building your scan workflow</p>
            </div>
          </motion.div>
        )}
      </div>

      {/* Toolbar */}
      <div className="absolute top-4 right-4 flex space-x-2 z-10">
        {/* Undo/Redo */}
        <motion.button
          onClick={undo}
          disabled={historyIndex <= 0}
          className="glass-card p-3 text-foreground hover:bg-primary/10 transition-colors rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
          title="Undo (Ctrl+Z)"
        >
          <RotateCcw className="h-5 w-5" />
        </motion.button>
        
        <motion.button
          onClick={redo}
          disabled={historyIndex >= history.length - 1}
          className="glass-card p-3 text-foreground hover:bg-primary/10 transition-colors rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
          title="Redo (Ctrl+Shift+Z)"
        >
          <RotateCw className="h-5 w-5" />
        </motion.button>
        
        {/* Zoom Controls */}
        <motion.button
          onClick={() => handleZoom(0.1)}
          className="glass-card p-3 text-foreground hover:bg-primary/10 transition-colors rounded-lg"
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
          title="Zoom In (Ctrl++)"
        >
          <ZoomIn className="h-5 w-5" />
        </motion.button>
        
        <motion.button
          onClick={() => handleZoom(-0.1)}
          className="glass-card p-3 text-foreground hover:bg-primary/10 transition-colors rounded-lg"
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
          title="Zoom Out (Ctrl+-)"
        >
          <ZoomOut className="h-5 w-5" />
        </motion.button>
        
        {/* Grid Toggle */}
        <motion.button
          onClick={() => setShowGrid(!showGrid)}
          className={`glass-card p-3 transition-colors rounded-lg ${
            showGrid ? 'text-primary bg-primary/10' : 'text-foreground hover:bg-primary/10'
          }`}
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
          title="Toggle Grid"
        >
          <Grid className="h-5 w-5" />
        </motion.button>
        
        {/* Project Controls */}
        <motion.button
          onClick={onSaveProject}
          className="glass-card p-3 text-foreground hover:bg-primary/10 transition-colors rounded-lg"
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
          title="Save Project (Ctrl+S)"
        >
          <Save className="h-5 w-5" />
        </motion.button>
        
        <motion.button
          onClick={onLoadProject}
          className="glass-card p-3 text-foreground hover:bg-primary/10 transition-colors rounded-lg"
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
          title="Load Project (Ctrl+O)"
        >
          <FolderOpen className="h-5 w-5" />
        </motion.button>

        <motion.button
          onClick={onExportProject}
          className="glass-card p-3 text-foreground hover:bg-primary/10 transition-colors rounded-lg"
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
          title="Export Project"
        >
          <Download className="h-5 w-5" />
        </motion.button>

        <motion.button
          onClick={onImportProject}
          className="glass-card p-3 text-foreground hover:bg-primary/10 transition-colors rounded-lg"
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
          title="Import Project"
        >
          <Upload className="h-5 w-5" />
        </motion.button>
      </div>

      {/* Start Scan Button */}
      <div className="absolute bottom-6 right-6 z-10">
        <motion.button
          onClick={handleStartScan}
          disabled={blocks.length === 0}
          className="bg-primary text-primary-foreground px-8 py-4 rounded-xl font-semibold text-lg flex items-center space-x-3 disabled:opacity-50 disabled:cursor-not-allowed hover:bg-primary/90 transition-colors shadow-lg"
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
        >
          <Play className="h-6 w-6" />
          <span>Start Scan</span>
        </motion.button>
      </div>
      
      {/* Validation Errors Modal */}
      <AnimatePresence>
        {showValidation && validationErrors.length > 0 && (
          <motion.div
            className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => setShowValidation(false)}
          >
            <motion.div
              className="glass-card p-6 rounded-2xl max-w-md mx-4"
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              onClick={(e) => e.stopPropagation()}
            >
              <div className="flex items-center space-x-3 mb-4">
                <div className="w-10 h-10 bg-red-500/20 rounded-xl flex items-center justify-center">
                  <AlertTriangle className="h-5 w-5 text-red-400" />
                </div>
                <div>
                  <h3 className="text-lg font-semibold text-foreground">Validation Errors</h3>
                  <p className="text-sm text-muted-foreground">Please fix these issues before starting the scan</p>
                </div>
              </div>
              
              <div className="space-y-2 mb-6">
                {validationErrors.map((error, index) => (
                  <div key={index} className="text-sm text-red-400 bg-red-500/10 p-2 rounded">
                    {error}
                  </div>
                ))}
              </div>
              
              <div className="flex justify-end">
                <motion.button
                  onClick={() => setShowValidation(false)}
                  className="px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors"
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                >
                  OK
                </motion.button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Custom Delete All Confirmation Modal */}
      <AnimatePresence>
        {showDeleteAllModal && (
          <motion.div
            className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={cancelDeleteAll}
          >
            <motion.div
              className="glass-card p-8 rounded-2xl max-w-md mx-4"
              initial={{ scale: 0.9, opacity: 0, y: 20 }}
              animate={{ scale: 1, opacity: 1, y: 0 }}
              exit={{ scale: 0.9, opacity: 0, y: 20 }}
              onClick={(e) => e.stopPropagation()}
            >
              {/* Header */}
              <div className="flex items-center space-x-3 mb-6">
                <div className="w-12 h-12 bg-red-500/20 rounded-xl flex items-center justify-center">
                  <Trash2 className="h-6 w-6 text-red-400" />
                </div>
                <div>
                  <h3 className="text-xl font-bold text-foreground">Delete All Blocks</h3>
                  <p className="text-sm text-muted-foreground">This action cannot be undone</p>
                </div>
              </div>

              {/* Content */}
              <div className="mb-6">
                <p className="text-foreground mb-4">
                  Are you sure you want to delete all blocks? This will remove all blocks and connections from your canvas.
                </p>
                
                {/* Checkbox */}
                <div className="flex items-center space-x-3">
                  <input
                    type="checkbox"
                    id="dontShowAgain"
                    checked={dontShowAgain}
                    onChange={(e) => setDontShowAgain(e.target.checked)}
                    className="w-4 h-4 text-primary bg-input border-border rounded focus:ring-primary"
                  />
                  <label htmlFor="dontShowAgain" className="text-sm text-foreground">
                    Don't show this confirmation again
                  </label>
                </div>
              </div>

              {/* Actions */}
              <div className="flex items-center justify-end space-x-3">
                <motion.button
                  onClick={cancelDeleteAll}
                  className="px-6 py-2 glass-card text-foreground hover:bg-muted/20 rounded-lg transition-colors"
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                >
                  Cancel
                </motion.button>
                <motion.button
                  onClick={confirmDeleteAll}
                  className="flex items-center space-x-2 px-6 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors"
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                >
                  <Trash2 className="h-4 w-4" />
                  <span>Delete All</span>
                </motion.button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

export default BlockCanvas
