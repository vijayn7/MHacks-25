"use client"

import { createContext, useCallback, useContext, useEffect, useState } from "react"
import { login as loginRequest, logout as logoutRequest, me as fetchMe, signup as signupRequest } from "../lib/auth"

const AuthContext = createContext({
  user: null,
  loading: true,
  login: async () => {},
  signup: async () => {},
  logout: async () => {},
  refresh: async () => {},
})

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)

  const refresh = useCallback(async () => {
    setLoading(true)
    try {
      const currentUser = await fetchMe()
      setUser(currentUser)
    } catch (error) {
      setUser(null)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    refresh()
  }, [refresh])

  const login = useCallback(async (email, password) => {
    try {
      await loginRequest(email, password)
      await refresh()
    } catch (error) {
      throw new Error(error.message || "Login failed")
    }
  }, [refresh])

  const signup = useCallback(async (email, password, name) => {
    try {
      await signupRequest(email, password, name)
      await refresh()
    } catch (error) {
      throw new Error(error.message || "Signup failed")
    }
  }, [refresh])

  const logout = useCallback(async () => {
    try {
      await logoutRequest()
    } finally {
      setUser(null)
      setLoading(false)
    }
  }, [])

  return (
    <AuthContext.Provider value={{ user, loading, login, signup, logout, refresh }}>
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = () => useContext(AuthContext)
