'use client'

import {
  signInWithEmailAndPassword,
  signOut as firebaseSignOut,
  onAuthStateChanged,
  User as FirebaseUser,
  setPersistence,
  browserLocalPersistence,
  browserSessionPersistence
} from 'firebase/auth'
import { auth } from './firebase'
import { Session, User } from './types'
import { loginUser, logoutUser } from './api'

const API_URL = process.env.NEXT_PUBLIC_API_URL

export async function getSession(): Promise<Session | null> {
  const session = localStorage.getItem('session')
  if (!session) return null
  
  try {
    const parsedSession = JSON.parse(session) as Session
    // Check if session is expired
    if (parsedSession.expires && new Date(parsedSession.expires) < new Date()) {
      localStorage.removeItem('session')
      return null
    }
    return parsedSession
  } catch (error) {
    console.error('Failed to parse session:', error)
    return null
  }
}

export async function getCurrentUser(): Promise<User | null> {
  const session = await getSession()
  return session?.user || null
}

export async function isAuthenticated(): Promise<boolean> {
  const session = await getSession()
  return !!session?.user
}

export async function signIn(email: string, password: string, rememberMe: boolean = false): Promise<boolean> {
  try {
    console.log('Starting sign in process...');
    
    // Set persistence based on remember me
    await setPersistence(auth, rememberMe ? browserLocalPersistence : browserSessionPersistence)
    console.log('Persistence set:', rememberMe ? 'LOCAL' : 'SESSION');
    
    // Sign in with Firebase
    const userCredential = await signInWithEmailAndPassword(auth, email, password)
    console.log('Firebase sign in successful');
    
    const idToken = await userCredential.user.getIdToken()
    console.log('Got ID token');
    
    // Verify token with backend
    console.log('Verifying token with backend...');
    const response = await fetch(`${API_URL}/auth/verify-token`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${idToken}`,
        'Content-Type': 'application/json'
      },
      credentials: 'include'
    })

    if (!response.ok) {
      const errorData = await response.json();
      console.error('Backend verification failed:', errorData);
      throw new Error(errorData.detail || 'Failed to verify token');
    }

    const data = await response.json()
    console.log('Backend verification successful:', data);
    
    // Store user info in localStorage if remember me is enabled
    if (rememberMe) {
      localStorage.setItem('auth_token', idToken)
      localStorage.setItem('user', JSON.stringify(data.user))
      console.log('User data stored in localStorage');
    }
    
    return true
  } catch (error) {
    console.error('Authentication error:', error);
    throw error
  }
}

export async function signOut(): Promise<void> {
  try {
    await firebaseSignOut(auth)
    localStorage.removeItem('auth_token')
    localStorage.removeItem('user')
    window.location.href = '/login'
  } catch (error) {
    console.error('Sign out error:', error)
  }
}

export function getAuthToken(): string | null {
  return localStorage.getItem('auth_token')
}

export function hasPermission(permission: string): boolean {
  const session = localStorage.getItem('session')
  if (!session) return false
  
  const { user } = JSON.parse(session) as Session
  return user.permissions.includes(permission) || user.role === 'superadmin'
}

export function hasRole(role: string): boolean {
  const session = localStorage.getItem('session')
  if (!session) return false
  
  const { user } = JSON.parse(session) as Session
  return user.role === role || user.role === 'superadmin'
}

export function onAuthStateChange(callback: (user: FirebaseUser | null) => void) {
  return onAuthStateChanged(auth, callback)
} 
