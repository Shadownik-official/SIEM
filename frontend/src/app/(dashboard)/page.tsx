'use client'

import React, { Suspense, useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import {
  ShieldExclamationIcon,
  BoltIcon,
  ServerIcon,
  ChartBarIcon
} from '@heroicons/react/24/outline'
import { Card } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { AlertsChart } from '@/components/charts/AlertsChart'
import { SecurityScore } from '@/components/metrics/SecurityScore'
import { RecentAlerts } from '@/components/alerts/RecentAlerts'
import { SystemHealth } from '@/components/metrics/SystemHealth'

const container = {
  hidden: { opacity: 0 },
  show: {
    opacity: 1,
    transition: {
      staggerChildren: 0.1
    }
  }
}

const item = {
  hidden: { opacity: 0, y: 20 },
  show: { opacity: 1, y: 0 }
}

export default function DashboardPage() {
  const [metrics, setMetrics] = useState({
    cpu: 0,
    memory: 0,
    disk: 0
  })
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    // Simulate fetching metrics
    const fetchMetrics = async () => {
      try {
        // Simulated API response
        const response = {
          cpu: Math.random() * 100,
          memory: Math.random() * 100,
          disk: Math.random() * 100
        }
        setMetrics(response)
        setLoading(false)
      } catch (error) {
        console.error('Failed to fetch metrics:', error)
        setLoading(false)
      }
    }

    fetchMetrics()
    const interval = setInterval(fetchMetrics, 30000)
    return () => clearInterval(interval)
  }, [])

  return (
    <motion.div
      variants={container}
      initial="hidden"
      animate="show"
      className="space-y-6 p-6"
    >
      {/* Page Header */}
      <motion.div variants={item}>
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
          Security Dashboard
        </h1>
        <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
          Real-time overview of your security posture
        </p>
      </motion.div>
      
      {/* Overview Cards */}
      <motion.div
        variants={container}
        className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4"
      >
        <Card>
          <div className="flex items-center p-4">
            <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-red-100 dark:bg-red-900">
              <ShieldExclamationIcon className="h-6 w-6 text-red-600 dark:text-red-200" />
            </div>
            <div className="ml-4">
              <h3 className="text-sm font-medium text-gray-900 dark:text-white">
                Active Alerts
              </h3>
              <Suspense fallback={<Skeleton className="h-8 w-16" />}>
                <p className="mt-1 text-2xl font-semibold text-gray-700 dark:text-gray-200">
                  24
                </p>
              </Suspense>
            </div>
          </div>
        </Card>
        
        <Card>
          <div className="flex items-center p-4">
            <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-yellow-100 dark:bg-yellow-900">
              <BoltIcon className="h-6 w-6 text-yellow-600 dark:text-yellow-200" />
            </div>
            <div className="ml-4">
              <h3 className="text-sm font-medium text-gray-900 dark:text-white">
                Active Scans
              </h3>
              <Suspense fallback={<Skeleton className="h-8 w-16" />}>
                <p className="mt-1 text-2xl font-semibold text-gray-700 dark:text-gray-200">
                  3
                </p>
              </Suspense>
            </div>
          </div>
        </Card>
        
        <Card>
          <div className="flex items-center p-4">
            <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-blue-100 dark:bg-blue-900">
              <ServerIcon className="h-6 w-6 text-blue-600 dark:text-blue-200" />
            </div>
            <div className="ml-4">
              <h3 className="text-sm font-medium text-gray-900 dark:text-white">
                Protected Assets
              </h3>
              <Suspense fallback={<Skeleton className="h-8 w-16" />}>
                <p className="mt-1 text-2xl font-semibold text-gray-700 dark:text-gray-200">
                  156
                </p>
              </Suspense>
            </div>
          </div>
        </Card>
        
        <Card>
          <div className="flex items-center p-4">
            <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-green-100 dark:bg-green-900">
              <ChartBarIcon className="h-6 w-6 text-green-600 dark:text-green-200" />
            </div>
            <div className="ml-4">
              <h3 className="text-sm font-medium text-gray-900 dark:text-white">
                Security Score
              </h3>
              <Suspense fallback={<Skeleton className="h-8 w-16" />}>
                <p className="mt-1 text-2xl font-semibold text-gray-700 dark:text-gray-200">
                  85%
                </p>
              </Suspense>
            </div>
          </div>
        </Card>
      </motion.div>
      
      {/* Charts and Metrics */}
      <motion.div
        variants={container}
        className="grid grid-cols-1 gap-6 lg:grid-cols-2"
      >
        <Card>
          <div className="p-4">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white">
              Alert Trends
            </h3>
            <Suspense fallback={<Skeleton className="h-64" />}>
              <AlertsChart />
            </Suspense>
          </div>
        </Card>
        
        <Card>
          <div className="p-4">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white">
              Security Score Breakdown
            </h3>
            <Suspense fallback={<Skeleton className="h-64" />}>
              <SecurityScore />
            </Suspense>
          </div>
        </Card>
      </motion.div>
      
      {/* Recent Activity */}
      <motion.div
        variants={container}
        className="grid grid-cols-1 gap-6 lg:grid-cols-2"
      >
        <Card>
          <div className="p-4">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white">
              Recent Alerts
            </h3>
            <Suspense fallback={<Skeleton className="h-64" />}>
              <RecentAlerts />
            </Suspense>
          </div>
        </Card>
        
        <Card>
          <div className="p-4">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white">
              System Health
            </h3>
            <Suspense fallback={<Skeleton className="h-64" />}>
              <SystemHealth 
                metrics={metrics}
                loading={loading}
                status="healthy"
              />
            </Suspense>
          </div>
        </Card>
      </motion.div>
    </motion.div>
  )
} 