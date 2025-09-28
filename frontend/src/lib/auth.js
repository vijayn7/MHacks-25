import { api } from "./api"

export const signup = (email, password, name) =>
  api("/api/auth/signup", {
    method: "POST",
    body: JSON.stringify({ email, password, name }),
  })

export const login = (email, password) =>
  api("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  })

export const me = () => api("/api/auth/me")

export const logout = () =>
  api("/api/auth/logout", {
    method: "POST",
  })
