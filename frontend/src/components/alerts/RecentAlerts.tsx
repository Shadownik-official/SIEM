'use client'

import React from 'react'
import { Card } from '@/components/ui/card'

interface Alert {
  id: string
  title: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  timestamp: string
}

interface RecentAlertsProps {
  alerts?: Alert[]
  loading?: boolean
}

const defaultAlerts: Alert[] = [
  {
    id: '1',
    title: 'Suspicious Login Attempt',
    severity: 'high',
    timestamp: new Date().toISOString()
  }
  // Add more default alerts as needed
]

export function RecentAlerts({ alerts = defaultAlerts, loading = false }: RecentAlertsProps) {
  if (loading) {
    return (
      <Card className="p-4">
        <div className="animate-pulse space-y-4">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="h-12 bg-gray-200 rounded" />
          ))}
        </div>
      </Card>
    )
  }

  return (
    <Card className="p-4">
      <h3 className="text-sm font-medium text-gray-500 mb-4">Recent Alerts</h3>
      <div className="space-y-4">
        {alerts.map((alert) => (
          <div
            key={alert.id}
            className="flex items-center justify-between p-2 bg-white rounded-lg shadow"
          >
            <div>
              <p className="font-medium">{alert.title}</p>
              <p className="text-sm text-gray-500">{alert.timestamp}</p>
            </div>
            <span
              className={`px-2 py-1 rounded-full text-xs font-medium ${
                {
                  low: 'bg-blue-100 text-blue-800',
                  medium: 'bg-yellow-100 text-yellow-800',
                  high: 'bg-orange-100 text-orange-800',
                  critical: 'bg-red-100 text-red-800',
                }[alert.severity]
              }`}
            >
              {alert.severity}
            </span>
          </div>
        ))}
      </div>
    </Card>
  )
} 