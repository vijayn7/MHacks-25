"use client"

import { useState, useCallback } from "react"
import { motion } from "framer-motion"
import { Settings, AlertTriangle, Play, Save, FolderOpen, Download, Upload } from "lucide-react"
import BlockCanvas from "./BlockCanvas"
import BlockPalette from "./BlockPalette"
import BlockPropertiesModal from "./BlockPropertiesModal"
import { api } from "../lib/api"

const BuildScreen = () => {
  const [blocks, setBlocks] = useState([])
  const [edges, setEdges] = useState([])
  const [selectedBlock, setSelectedBlock] = useState(null)
  const [isPaletteCollapsed, setIsPaletteCollapsed] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [showProperties, setShowProperties] = useState(false)
  const [propertiesBlock, setPropertiesBlock] = useState(null)

  // Generate unique ID for blocks
  const generateId = () => `block-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`

  // Add block to canvas with physics and snapping
  const handleAddBlock = useCallback((blockType) => {
    // Check if block type already exists
    const existingBlock = blocks.find(block => block.type === blockType.type)
    if (existingBlock) {
      alert(`Block type "${blockType.type}" is already on the canvas`)
      return
    }

    // Find a good position with physics-based placement
    const blockSize = 128 // 32 * 4 (w-32 = 8rem = 128px)
    const gridSize = 20
    const snapThreshold = 20
    
    let x = Math.random() * 400 + 100
    let y = Math.random() * 300 + 100
    
    // Snap to grid
    x = Math.round(x / gridSize) * gridSize
    y = Math.round(y / gridSize) * gridSize
    
    // Check for collisions and adjust position
    let attempts = 0
    while (attempts < 50) {
      const collision = blocks.some(block => {
        const dx = Math.abs(block.x - x)
        const dy = Math.abs(block.y - y)
        return dx < blockSize + snapThreshold && dy < blockSize + snapThreshold
      })
      
      if (!collision) break
      
      // Try a new position
      x = Math.random() * 600 + 100
      y = Math.random() * 400 + 100
      x = Math.round(x / gridSize) * gridSize
      y = Math.round(y / gridSize) * gridSize
      attempts++
    }

    const newBlock = {
      id: generateId(),
      type: blockType.type,
      x,
      y,
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
  }, [blocks])

  // Handle block selection
  const handleBlockSelect = useCallback((block) => {
    setSelectedBlock(block)
    setShowProperties(true)
  }, [])

  // Handle opening properties
  const handleOpenProperties = useCallback((block) => {
    setPropertiesBlock(block)
    setShowProperties(true)
  }, [])

  // Save block changes
  const handleSaveBlock = useCallback((updatedBlock) => {
    setBlocks(prev => prev.map(block => 
      block.id === updatedBlock.id ? updatedBlock : block
    ))
    setShowProperties(false)
    setPropertiesBlock(null)
  }, [])

  // Delete block
  const handleDeleteBlock = useCallback((blockId) => {
    setBlocks(prev => prev.filter(block => block.id !== blockId))
    setEdges(prev => prev.filter(edge => edge.from !== blockId && edge.to !== blockId))
    if (propertiesBlock?.id === blockId) {
      setShowProperties(false)
      setPropertiesBlock(null)
    }
  }, [propertiesBlock])

  // Start scan
  const handleStartScan = useCallback(async () => {
    if (blocks.length === 0) {
      alert("Please add at least one block to start scanning")
      return
    }

    setIsLoading(true)
    try {
      const projectData = {
        projectId: `project-${Date.now()}`,
        blocks: blocks,
        edges: edges,
        options: {
          mode: "non-destructive"
        }
      }

      const response = await api("/api/orchestrator/run", {
        method: "POST",
        body: JSON.stringify(projectData)
      })
      
      if (response.scanId) {
        // Navigate to scan results
        window.location.href = `/scan/${response.scanId}`
      }
    } catch (error) {
      console.error("Failed to start scan:", error)
      alert("Failed to start scan: " + error.message)
    } finally {
      setIsLoading(false)
    }
  }, [blocks, edges])

  // Save project
  const handleSaveProject = useCallback(() => {
    const projectData = {
      blocks,
      edges,
      timestamp: new Date().toISOString()
    }
    localStorage.setItem("blocks-project", JSON.stringify(projectData))
    alert("Project saved successfully!")
  }, [blocks, edges])

  // Load project
  const handleLoadProject = useCallback(() => {
    const saved = localStorage.getItem("blocks-project")
    if (saved) {
      const projectData = JSON.parse(saved)
      setBlocks(projectData.blocks || [])
      setEdges(projectData.edges || [])
      alert("Project loaded successfully!")
    } else {
      alert("No saved project found")
    }
  }, [])

  // Export project
  const handleExportProject = useCallback(() => {
    const projectData = {
      blocks,
      edges,
      timestamp: new Date().toISOString()
    }
    const blob = new Blob([JSON.stringify(projectData, null, 2)], { type: "application/json" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = `blocks-project-${Date.now()}.json`
    a.click()
    URL.revokeObjectURL(url)
  }, [blocks, edges])

  // Import project
  const handleImportProject = useCallback(() => {
    const input = document.createElement("input")
    input.type = "file"
    input.accept = ".json"
    input.onchange = (e) => {
      const file = e.target.files[0]
      if (file) {
        const reader = new FileReader()
        reader.onload = (e) => {
          try {
            const projectData = JSON.parse(e.target.result)
            setBlocks(projectData.blocks || [])
            setEdges(projectData.edges || [])
            alert("Project imported successfully!")
          } catch (error) {
            alert("Failed to import project: Invalid JSON")
          }
        }
        reader.readAsText(file)
      }
    }
    input.click()
  }, [])

  return (
    <div className="h-screen flex flex-col">
      {/* Header */}
      <motion.div
        className="glass-card border-b border-border/50 p-4"
        initial={{ y: -20, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ duration: 0.3 }}
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <motion.div
              className="w-12 h-12 bg-primary/20 rounded-xl flex items-center justify-center"
              whileHover={{ scale: 1.1, rotate: 5 }}
            >
              <Settings className="h-6 w-6 text-primary" />
            </motion.div>
            <div>
              <h1 className="text-2xl font-bold text-foreground">Blocks Orchestrator</h1>
              <p className="text-muted-foreground">
                Drag and drop blocks to build custom security scan workflows
              </p>
            </div>
          </div>
          
          <div className="flex items-center space-x-3">
            <div className="text-sm text-muted-foreground">
              {blocks.length} blocks, {edges.length} connections
            </div>
            {isLoading && (
              <motion.div
                className="w-6 h-6 border-2 border-primary/30 border-t-primary rounded-full"
                animate={{ rotate: 360 }}
                transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
              />
            )}
          </div>
        </div>
      </motion.div>

      {/* Main Content */}
      <div className="flex-1 flex overflow-hidden">
        {/* Block Palette */}
        <BlockPalette
          onAddBlock={handleAddBlock}
          isCollapsed={isPaletteCollapsed}
          onToggleCollapse={() => setIsPaletteCollapsed(!isPaletteCollapsed)}
          usedBlocks={blocks}
          onConfigureBlock={(blockType) => {
            // Create a template block for configuration
            const templateBlock = {
              id: `template-${blockType.type}`,
              type: blockType.type,
              x: 0,
              y: 0,
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
            handleOpenProperties(templateBlock)
          }}
        />
        
        {/* Block Canvas */}
        <BlockCanvas
          blocks={blocks}
          setBlocks={setBlocks}
          edges={edges}
          setEdges={setEdges}
          selectedBlock={selectedBlock}
          setSelectedBlock={setSelectedBlock}
          onStartScan={handleStartScan}
          onSaveProject={handleSaveProject}
          onLoadProject={handleLoadProject}
          onExportProject={handleExportProject}
          onImportProject={handleImportProject}
          onOpenProperties={handleOpenProperties}
        />
      </div>

      {/* Block Properties Modal */}
      <BlockPropertiesModal
        isOpen={showProperties}
        onClose={() => {
          setShowProperties(false)
          setPropertiesBlock(null)
        }}
        block={propertiesBlock}
        onSave={handleSaveBlock}
        onDelete={handleDeleteBlock}
      />
    </div>
  )
}

export default BuildScreen
