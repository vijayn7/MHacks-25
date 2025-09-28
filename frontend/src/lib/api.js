export const API_BASE_URL = import.meta.env.VITE_API_URL ?? "http://localhost:8000"

export async function api(path, init = {}) {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...(init.headers || {}),
    },
    ...init,
  })

  if (!response.ok) {
    const message = await response.text().catch(() => response.statusText)
    throw new Error(message || `HTTP ${response.status}`)
  }

  const contentType = response.headers.get("content-type") || ""
  if (response.status === 204 || !contentType.includes("application/json")) {
    return null
  }

  return response.json()
}
