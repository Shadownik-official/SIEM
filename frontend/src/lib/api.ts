const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api'

interface ApiResponse<T> {
  success: boolean
  data?: T
  error?: string
}

async function handleResponse<T>(response: Response): Promise<ApiResponse<T>> {
  if (!response.ok) {
    const error = await response.json().catch(() => ({}))
    return {
      success: false,
      error: error.message || 'An error occurred'
    }
  }

  const data = await response.json()
  return {
    success: true,
    data
  }
}

export async function loginUser(email: string, password: string) {
  try {
    const response = await fetch(`${API_BASE_URL}/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email, password }),
      credentials: 'include'
    })

    return handleResponse<{ token: string }>(response)
  } catch (error) {
    return {
      success: false,
      error: 'Network error occurred'
    }
  }
}

export async function logoutUser() {
  try {
    const response = await fetch(`${API_BASE_URL}/auth/logout`, {
      method: 'POST',
      credentials: 'include'
    })

    return handleResponse(response)
  } catch (error) {
    return {
      success: false,
      error: 'Network error occurred'
    }
  }
}

export async function getSystemMetrics() {
  try {
    const response = await fetch(`${API_BASE_URL}/metrics/system`, {
      credentials: 'include'
    })

    return handleResponse(response)
  } catch (error) {
    return {
      success: false,
      error: 'Network error occurred'
    }
  }
} 