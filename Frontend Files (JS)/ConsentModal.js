"use client"
import { motion, AnimatePresence } from "framer-motion"
import { AlertTriangle, Shield, X } from "lucide-react"

const ConsentModal = ({ isOpen, onAccept, onDecline, targetUrl }) => {
  return (
    <AnimatePresence>
      {isOpen && (
        <motion.div
          className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4 z-50"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.3 }}
        >
          <motion.div
            className="glass-card max-w-2xl w-full rounded-2xl overflow-hidden"
            initial={{ scale: 0.9, opacity: 0, y: 20 }}
            animate={{ scale: 1, opacity: 1, y: 0 }}
            exit={{ scale: 0.9, opacity: 0, y: 20 }}
            transition={{ type: "spring", stiffness: 300, damping: 30 }}
          >
            <div className="p-8">
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center space-x-4">
                  <motion.div
                    className="w-12 h-12 bg-primary/20 rounded-xl flex items-center justify-center"
                    whileHover={{ scale: 1.1, rotate: 5 }}
                  >
                    <Shield className="h-6 w-6 text-primary" />
                  </motion.div>
                  <h2 className="text-2xl font-bold text-foreground">Security Scan Authorization</h2>
                </div>
                <motion.button
                  onClick={onDecline}
                  className="p-2 hover:bg-muted rounded-lg transition-colors"
                  whileHover={{ scale: 1.1 }}
                  whileTap={{ scale: 0.9 }}
                >
                  <X className="h-5 w-5 text-muted-foreground" />
                </motion.button>
              </div>

              <div className="space-y-6">
                <div className="glass-card p-4 rounded-xl border border-primary/20">
                  <p className="text-foreground font-medium">
                    Target: <span className="text-primary font-bold">{targetUrl}</span>
                  </p>
                </div>

                <motion.div
                  className="glass-card p-6 rounded-xl border border-yellow-500/20 bg-yellow-500/5"
                  initial={{ x: -20, opacity: 0 }}
                  animate={{ x: 0, opacity: 1 }}
                  transition={{ delay: 0.2 }}
                >
                  <div className="flex items-start space-x-4">
                    <AlertTriangle className="h-6 w-6 text-yellow-400 mt-1 flex-shrink-0" />
                    <div>
                      <h3 className="text-lg font-semibold text-yellow-400 mb-3">Legal Authorization Required</h3>
                      <p className="text-muted-foreground mb-4 leading-relaxed">By proceeding, you confirm that you:</p>
                    </div>
                  </div>
                </motion.div>

                <motion.ul
                  className="space-y-3 text-muted-foreground"
                  initial={{ y: 20, opacity: 0 }}
                  animate={{ y: 0, opacity: 1 }}
                  transition={{ delay: 0.3 }}
                >
                  {[
                    "Own this website OR have explicit written permission to scan it",
                    "Understand this scan will perform non-destructive security tests",
                    "Accept responsibility for compliance with applicable laws",
                    "Acknowledge that scan results and evidence will be stored temporarily",
                  ].map((item, index) => (
                    <motion.li
                      key={index}
                      className="flex items-start space-x-3"
                      initial={{ x: -20, opacity: 0 }}
                      animate={{ x: 0, opacity: 1 }}
                      transition={{ delay: 0.4 + index * 0.1 }}
                    >
                      <span className="text-primary font-bold mt-1">•</span>
                      <span className="leading-relaxed">{item}</span>
                    </motion.li>
                  ))}
                </motion.ul>

                <motion.div
                  className="glass-card p-6 rounded-xl border border-blue-500/20 bg-blue-500/5"
                  initial={{ y: 20, opacity: 0 }}
                  animate={{ y: 0, opacity: 1 }}
                  transition={{ delay: 0.5 }}
                >
                  <h4 className="text-lg font-semibold text-blue-400 mb-4">Vulnerability Detection Coverage:</h4>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm text-muted-foreground">
                    {[
                      "Missing security headers (X-Frame-Options, CSP, HSTS)",
                      "CORS misconfigurations",
                      "Reflected XSS vulnerabilities",
                      "Open redirect vulnerabilities",
                      "Insecure cookie configurations",
                      "Information disclosure",
                    ].map((item, index) => (
                      <motion.div
                        key={index}
                        className="flex items-center space-x-2"
                        initial={{ scale: 0.8, opacity: 0 }}
                        animate={{ scale: 1, opacity: 1 }}
                        transition={{ delay: 0.6 + index * 0.05 }}
                      >
                        <div className="w-2 h-2 bg-blue-400 rounded-full" />
                        <span>{item}</span>
                      </motion.div>
                    ))}
                  </div>
                </motion.div>
              </div>

              <motion.div
                className="flex space-x-4 mt-8"
                initial={{ y: 20, opacity: 0 }}
                animate={{ y: 0, opacity: 1 }}
                transition={{ delay: 0.7 }}
              >
                <motion.button
                  onClick={onDecline}
                  className="flex-1 px-6 py-4 glass-card text-muted-foreground hover:text-foreground hover:bg-muted/50 focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2 transition-all duration-300 font-semibold rounded-xl"
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                >
                  Cancel
                </motion.button>
                <motion.button
                  onClick={onAccept}
                  className="flex-1 px-6 py-4 bg-primary text-primary-foreground rounded-xl hover:bg-primary/90 focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2 transition-all duration-300 font-semibold"
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                >
                  I Consent - Start Scan
                </motion.button>
              </motion.div>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}

export default ConsentModal
