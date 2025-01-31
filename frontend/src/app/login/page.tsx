'use client'

import React, { useState } from 'react'
import { motion } from 'framer-motion'
import { useRouter } from 'next/navigation'
import { signIn } from '@/lib/auth'
import { LockClosedIcon, EnvelopeIcon, ShieldCheckIcon, GlobeAltIcon, ServerIcon } from '@heroicons/react/24/outline'
import { FirebaseError } from 'firebase/app'

export default function LoginPage() {
  const router = useRouter()
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [rememberMe, setRememberMe] = useState(false)

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError('')
    setLoading(true)

    const formData = new FormData(event.currentTarget)
    const email = formData.get('email') as string
    const password = formData.get('password') as string

    try {
      const success = await signIn(email, password, rememberMe)
      if (success) {
        router.push('/')
      } else {
        setError('Invalid email or password')
      }
    } catch (err) {
      if (err instanceof FirebaseError) {
        switch (err.code) {
          case 'auth/user-not-found':
          case 'auth/wrong-password':
            setError('Invalid email or password')
            break
          case 'auth/invalid-email':
            setError('Invalid email address')
            break
          case 'auth/too-many-requests':
            setError('Too many failed attempts. Please try again later')
            break
          default:
            setError('An error occurred. Please try again')
        }
      } else {
        setError('An error occurred. Please try again')
      }
      console.error('Login error:', err)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 flex items-center justify-center bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900">
      <div className="w-full max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 flex items-center justify-center">
        <div className="w-full grid grid-cols-1 lg:grid-cols-2 gap-8 lg:gap-16">
          {/* Left side - Hero Section */}
          <motion.div 
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.6 }}
            className="hidden lg:flex flex-col justify-center"
          >
            <div className="relative">
              <div className="absolute -left-6 -top-6 w-24 h-24 bg-blue-500/10 rounded-full blur-xl"></div>
              <div className="absolute right-12 bottom-12 w-32 h-32 bg-indigo-500/10 rounded-full blur-xl"></div>
              <ShieldCheckIcon className="w-20 h-20 text-blue-500 mb-8" />
              <h1 className="text-4xl font-bold text-white mb-4">Enterprise SIEM Security</h1>
              <p className="text-lg text-white/70 mb-8">
                Advanced threat detection and security monitoring for your organization
              </p>
              <div className="grid grid-cols-2 gap-6">
                <div className="flex items-center space-x-3">
                  <GlobeAltIcon className="w-6 h-6 text-blue-400" />
                  <span className="text-white/60">Global Monitoring</span>
                </div>
                <div className="flex items-center space-x-3">
                  <ServerIcon className="w-6 h-6 text-blue-400" />
                  <span className="text-white/60">Real-time Analytics</span>
                </div>
              </div>
            </div>
          </motion.div>

          {/* Right side - Login Form */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.2 }}
            className="w-full max-w-md mx-auto bg-white/5 backdrop-blur-xl rounded-2xl p-8 shadow-2xl border border-white/10"
          >
            <div className="text-center mb-8">
              <div className="inline-block p-3 bg-blue-500/10 rounded-xl mb-4">
                <LockClosedIcon className="w-8 h-8 text-blue-400" />
              </div>
              <h2 className="text-2xl font-bold text-white mb-2">Welcome Back</h2>
              <p className="text-white/60">Secure access to your SIEM dashboard</p>
            </div>

            <form onSubmit={handleSubmit} className="space-y-6">
              <div className="space-y-4">
                <div>
                  <div className="relative group">
                    <EnvelopeIcon className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-white/40 group-focus-within:text-blue-400 transition-colors" />
                    <input
                      type="email"
                      name="email"
                      id="email"
                      required
                      placeholder="Email"
                      className="w-full bg-white/5 border border-white/10 rounded-lg px-11 py-3 text-white placeholder:text-white/40 focus:outline-none focus:ring-2 focus:ring-blue-400/60 focus:border-transparent transition-all"
                    />
                  </div>
                </div>
                <div>
                  <div className="relative group">
                    <LockClosedIcon className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-white/40 group-focus-within:text-blue-400 transition-colors" />
                    <input
                      type="password"
                      name="password"
                      id="password"
                      required
                      placeholder="Password"
                      className="w-full bg-white/5 border border-white/10 rounded-lg px-11 py-3 text-white placeholder:text-white/40 focus:outline-none focus:ring-2 focus:ring-blue-400/60 focus:border-transparent transition-all"
                    />
                  </div>
                </div>
              </div>

              <div className="flex items-center justify-between">
                <label className="flex items-center group cursor-pointer">
                  <input
                    type="checkbox"
                    checked={rememberMe}
                    onChange={(e) => setRememberMe(e.target.checked)}
                    className="w-4 h-4 rounded border-white/10 bg-white/5 text-blue-500 focus:ring-blue-400/60 transition-colors"
                  />
                  <span className="ml-2 text-sm text-white/60 group-hover:text-white/80 transition-colors">Remember me</span>
                </label>
                <a href="/forgot-password" className="text-sm text-white/60 hover:text-white transition-colors">
                  Forgot password?
                </a>
              </div>

              {error && (
                <motion.div
                  initial={{ opacity: 0, y: -10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="bg-red-500/10 text-red-400 text-sm rounded-lg p-3 text-center"
                >
                  {error}
                </motion.div>
              )}

              <button
                type="submit"
                disabled={loading}
                className="w-full bg-gradient-to-r from-blue-500 to-blue-600 text-white rounded-lg py-3 font-medium hover:from-blue-600 hover:to-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-400/60 disabled:opacity-50 disabled:cursor-not-allowed transition-all relative overflow-hidden group"
              >
                {loading ? (
                  <motion.div
                    animate={{ rotate: 360 }}
                    transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
                    className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full mx-auto"
                  />
                ) : (
                  <>
                    <span className="relative z-10">SECURE LOGIN</span>
                    <div className="absolute inset-0 bg-gradient-to-r from-blue-600 to-blue-700 transform scale-x-0 group-hover:scale-x-100 transition-transform origin-left"></div>
                  </>
                )}
              </button>

              <div className="text-center mt-6">
                <p className="text-white/40 text-sm">
                  Protected by enterprise-grade security
                </p>
              </div>
            </form>
          </motion.div>
        </div>
      </div>
    </div>
  )
}