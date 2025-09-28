"use client"

import { useState, useEffect } from "react"
import { motion, AnimatePresence } from "framer-motion"
import { 
  X, 
  Save, 
  Trash2, 
  Settings, 
  Lock, 
  AlertTriangle,
  Code,
  Clock,
  Shield
} from "lucide-react"

const BlockPropertiesModal = ({ 
  isOpen, 
  onClose, 
  block, 
  onSave, 
  onDelete 
}) => {
  const [formData, setFormData] = useState({
    id: "",
    type: "",
    script: "",
    inputs: {},
    safe_mode: true,
    timeout_seconds: 600,
    metadata: {
      severity: "medium",
      mvp: true
    }
  })

  useEffect(() => {
    if (block) {
      setFormData({
        id: block.id || "",
        type: block.type || "",
        script: block.script || "",
        inputs: block.inputs || {},
        safe_mode: block.safe_mode !== undefined ? block.safe_mode : true,
        timeout_seconds: block.timeout_seconds || 600,
        metadata: {
          severity: block.metadata?.severity || "medium",
          mvp: block.metadata?.mvp !== undefined ? block.metadata.mvp : true
        }
      })
    }
  }, [block])

  const handleInputChange = (field, value) => {
    if (field.includes('.')) {
      const [parent, child] = field.split('.')
      setFormData(prev => ({
        ...prev,
        [parent]: {
          ...prev[parent],
          [child]: value
        }
      }))
    } else {
      setFormData(prev => ({
        ...prev,
        [field]: value
      }))
    }
  }

  const handleInputsChange = (key, value) => {
    setFormData(prev => ({
      ...prev,
      inputs: {
        ...prev.inputs,
        [key]: value
      }
    }))
  }

  // Check if input contains vault reference
  const isVaultRef = (value) => {
    return typeof value === 'string' && value.startsWith('vaultRef:')
  }

  // Mask vault reference for display
  const maskVaultRef = (value) => {
    if (isVaultRef(value)) {
      const ref = value.replace('vaultRef:', '')
      return `vaultRef:${ref.substring(0, 4)}${'*'.repeat(Math.max(4, ref.length - 4))}`
    }
    return value
  }

  const addInputField = () => {
    setFormData(prev => ({
      ...prev,
      inputs: {
        ...prev.inputs,
        "": ""
      }
    }))
  }

  const removeInputField = (key) => {
    setFormData(prev => {
      const newInputs = { ...prev.inputs }
      delete newInputs[key]
      return {
        ...prev,
        inputs: newInputs
      }
    })
  }

  const handleSave = () => {
    onSave(formData)
    onClose()
  }

  const handleDelete = () => {
    onDelete(block.id)
    onClose()
  }

  const getBlockIcon = (type) => {
    const icons = {
      credentialed_scan: Lock,
      logic_fuzzer: Settings,
      llm_generator: Code,
      json_fuzzer: Code,
      supply_chain_scan: Shield
    }
    return icons[type] || Settings
  }

  const getBlockColor = (type) => {
    const colors = {
      credentialed_scan: "text-red-400",
      logic_fuzzer: "text-orange-400",
      llm_generator: "text-purple-400",
      json_fuzzer: "text-blue-400",
      supply_chain_scan: "text-green-400"
    }
    return colors[type] || "text-gray-400"
  }

  if (!isOpen || !block) return null

  const IconComponent = getBlockIcon(block.type)

  return (
    <AnimatePresence>
      <motion.div
        className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        onClick={onClose}
      >
        <motion.div
          className="glass-card p-8 rounded-2xl max-w-2xl w-full mx-4 max-h-[90vh] overflow-y-auto"
          initial={{ scale: 0.9, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.9, opacity: 0 }}
          onClick={(e) => e.stopPropagation()}
        >
          {/* Header */}
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center space-x-3">
              <div className={`w-12 h-12 bg-primary/20 rounded-xl flex items-center justify-center ${getBlockColor(block.type)}`}>
                <IconComponent className="h-6 w-6" />
              </div>
              <div>
                <h2 className="text-2xl font-bold text-foreground">
                  {block.type.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase())}
                </h2>
                <p className="text-muted-foreground">Configure block properties</p>
              </div>
            </div>
            <button
              onClick={onClose}
              className="p-2 hover:bg-muted/20 rounded-lg transition-colors"
            >
              <X className="h-5 w-5 text-foreground" />
            </button>
          </div>

          {/* Form */}
          <div className="space-y-6">
            {/* Basic Properties */}
            <div className="space-y-4">
              <h3 className="text-lg font-semibold text-foreground flex items-center">
                <Settings className="h-5 w-5 mr-2" />
                Basic Properties
              </h3>
              
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-foreground mb-2">
                    Block ID
                  </label>
                  <input
                    type="text"
                    value={formData.id}
                    onChange={(e) => handleInputChange('id', e.target.value)}
                    className="w-full px-3 py-2 bg-input border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
                    placeholder="block-uuid"
                  />
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-foreground mb-2">
                    Script Path
                  </label>
                  <input
                    type="text"
                    value={formData.script}
                    onChange={(e) => handleInputChange('script', e.target.value)}
                    className="w-full px-3 py-2 bg-input border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
                    placeholder="tests/block_type.py::run_scan"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-foreground mb-2">
                    Timeout (seconds)
                  </label>
                  <input
                    type="number"
                    value={formData.timeout_seconds}
                    onChange={(e) => handleInputChange('timeout_seconds', parseInt(e.target.value))}
                    className="w-full px-3 py-2 bg-input border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
                    min="1"
                    max="3600"
                  />
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-foreground mb-2">
                    Severity
                  </label>
                  <select
                    value={formData.metadata.severity}
                    onChange={(e) => handleInputChange('metadata.severity', e.target.value)}
                    className="w-full px-3 py-2 bg-input border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
                  >
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                    <option value="critical">Critical</option>
                  </select>
                </div>
              </div>
            </div>

            {/* Inputs */}
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-semibold text-foreground flex items-center">
                  <Code className="h-5 w-5 mr-2" />
                  Input Parameters
                </h3>
                <button
                  onClick={addInputField}
                  className="px-3 py-1 bg-primary text-primary-foreground rounded-lg text-sm hover:bg-primary/90 transition-colors"
                >
                  Add Input
                </button>
              </div>
              
              <div className="space-y-3">
                {Object.entries(formData.inputs).map(([key, value], index) => (
                  <div key={index} className="flex items-center space-x-3">
                    <input
                      type="text"
                      value={key}
                      onChange={(e) => {
                        const newInputs = { ...formData.inputs }
                        delete newInputs[key]
                        newInputs[e.target.value] = value
                        setFormData(prev => ({ ...prev, inputs: newInputs }))
                      }}
                      className="flex-1 px-3 py-2 bg-input border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
                      placeholder="Parameter name"
                    />
                    <div className="flex-1 relative">
                      <input
                        type={isVaultRef(value) ? "password" : "text"}
                        value={isVaultRef(value) ? maskVaultRef(value) : value}
                        onChange={(e) => handleInputsChange(key, e.target.value)}
                        className="w-full px-3 py-2 bg-input border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
                        placeholder="Parameter value (use vaultRef: for secrets)"
                      />
                      {isVaultRef(value) && (
                        <div className="absolute right-2 top-1/2 transform -translate-y-1/2">
                          <div className="w-2 h-2 bg-yellow-400 rounded-full" title="Vault Reference - Credentials Required"></div>
                        </div>
                      )}
                    </div>
                    <button
                      onClick={() => removeInputField(key)}
                      className="p-2 text-red-400 hover:bg-red-500/10 rounded-lg transition-colors"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                ))}
              </div>
            </div>

            {/* Security Settings */}
            <div className="space-y-4">
              <h3 className="text-lg font-semibold text-foreground flex items-center">
                <Shield className="h-5 w-5 mr-2" />
                Security Settings
              </h3>
              
              <div className="flex items-center space-x-3">
                <input
                  type="checkbox"
                  id="safe_mode"
                  checked={formData.safe_mode}
                  onChange={(e) => handleInputChange('safe_mode', e.target.checked)}
                  className="w-4 h-4 text-primary bg-input border-border rounded focus:ring-primary"
                />
                <label htmlFor="safe_mode" className="text-sm text-foreground">
                  Safe Mode (Non-destructive testing only)
                </label>
              </div>
              
              <div className="flex items-center space-x-3">
                <input
                  type="checkbox"
                  id="mvp"
                  checked={formData.metadata.mvp}
                  onChange={(e) => handleInputChange('metadata.mvp', e.target.checked)}
                  className="w-4 h-4 text-primary bg-input border-border rounded focus:ring-primary"
                />
                <label htmlFor="mvp" className="text-sm text-foreground">
                  MVP Block (Include in quick scans)
                </label>
              </div>
              
              {/* Vault Reference Warning */}
              {Object.values(formData.inputs || {}).some(value => isVaultRef(value)) && (
                <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-lg p-4">
                  <div className="flex items-start space-x-3">
                    <AlertTriangle className="h-5 w-5 text-yellow-400 mt-0.5 flex-shrink-0" />
                    <div>
                      <h4 className="text-sm font-semibold text-yellow-400 mb-1">Vault References Detected</h4>
                      <p className="text-xs text-muted-foreground">
                        This block contains vault references (credentials). You will be required to provide explicit consent before running the scan.
                      </p>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Actions */}
          <div className="flex items-center justify-between mt-8 pt-6 border-t border-border/50">
            <motion.button
              onClick={handleDelete}
              className="flex items-center space-x-2 px-4 py-2 text-red-400 hover:bg-red-500/10 rounded-lg transition-colors"
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
            >
              <Trash2 className="h-4 w-4" />
              <span>Delete Block</span>
            </motion.button>
            
            <div className="flex items-center space-x-3">
              <motion.button
                onClick={onClose}
                className="px-6 py-2 glass-card text-foreground hover:bg-muted/20 rounded-lg transition-colors"
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
              >
                Cancel
              </motion.button>
              <motion.button
                onClick={handleSave}
                className="flex items-center space-x-2 px-6 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors"
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
              >
                <Save className="h-4 w-4" />
                <span>Save Changes</span>
              </motion.button>
            </div>
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  )
}

export default BlockPropertiesModal
