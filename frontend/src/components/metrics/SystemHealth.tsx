'use client'

import React from 'react'
import { Card } from '@/components/ui/card'

interface SystemHealthProps {
  status?: 'healthy' | 'degraded' | 'critical'
  metrics?: {
    cpu: number
    memory: number
    disk: number
  }
  loading?: boolean
}

// Add default values for metrics
const defaultMetrics = {
  cpu: 0,
  memory: 0,
  disk: 0
}

export function SystemHealth({ 
  status = 'healthy',
  metrics = defaultMetrics,
  loading = false 
}: SystemHealthProps) {
  if (loading) {
    return (
      <Card className="p-4">
        <div className="animate-pulse space-y-4">
          <div className="h-4 bg-gray-200 rounded w-1/4" />
          <div className="space-y-2">
            {[...Array(3)].map((_, i) => (
              <div key={i} className="h-8 bg-gray-200 rounded" />
            ))}
          </div>
        </div>
      </Card>
    )
  }

  const getStatusColor = (value: number) => {
    if (value > 90) return 'bg-red-500'
    if (value > 70) return 'bg-yellow-500'
    return 'bg-green-500'
  }

  return (
    <Card className="p-4">
      <h3 className="text-sm font-medium text-gray-500">System Health</h3>
      <div className="mt-4 space-y-4">
        <div>
          <p className="text-sm text-gray-500">CPU Usage</p>
          <div className="h-2 bg-gray-200 rounded mt-1">
            <div
              className={`h-2 rounded transition-all ${getStatusColor(metrics.cpu)}`}
              style={{ width: `${metrics.cpu}%` }}
            />
          </div>
        </div>
        <div>
          <p className="text-sm text-gray-500">Memory Usage</p>
          <div className="h-2 bg-gray-200 rounded mt-1">
            <div
              className={`h-2 rounded transition-all ${getStatusColor(metrics.memory)}`}
              style={{ width: `${metrics.memory}%` }}
            />
          </div>
        </div>
        <div>
          <p className="text-sm text-gray-500">Disk Usage</p>
          <div className="h-2 bg-gray-200 rounded mt-1">
            <div
              className={`h-2 rounded transition-all ${getStatusColor(metrics.disk)}`}
              style={{ width: `${metrics.disk}%` }}
            />
          </div>
        </div>
      </div>
    </Card>
  )
}

export default SystemHealth 