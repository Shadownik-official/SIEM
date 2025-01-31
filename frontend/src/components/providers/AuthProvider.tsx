'use client'

import React, { createContext, useContext, useEffect, useState } from 'react'
import { getAuthToken } from '@/lib/auth'
import { jwtDecode } from 'jwt-decode'

interface User {
  id: string
  email: string
  role: string
}

interface AuthContextType {
  user: User | null
  loading: boolean
}

const AuthContext = createContext<AuthContextType>({
  user: null,
  loading: true
})

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const token = getAuthToken()
    
    if (token) {
      try {
        const decoded = jwtDecode<User>(token)
        setUser(decoded)
      } catch (error) {
        console.error('Invalid token:', error)
      }
    }
    
    setLoading(false)
  }, [])

  return (
    <AuthContext.Provider value={{ user, loading }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  return useContext(AuthContext)
} 