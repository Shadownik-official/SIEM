'use client'

import React from 'react'
import { Card } from '@/components/ui/card'

interface SecurityScoreProps {
  score?: number
  loading?: boolean
}

export function SecurityScore({ score = 85, loading = false }: SecurityScoreProps) {
  if (loading) {
    return (
      <Card className="p-4">
        <div className="animate-pulse space-y-2">
          <div className="h-4 bg-gray-200 rounded w-1/4" />
          <div className="h-8 bg-gray-200 rounded w-1/2" />
        </div>
      </Card>
    )
  }

  return (
    <Card className="p-4">
      <h3 className="text-sm font-medium text-gray-500">Security Score</h3>
      <div className="mt-2 flex items-baseline">
        <p className="text-3xl font-semibold text-gray-900">{score}</p>
        <p className="ml-2 text-sm text-gray-500">/100</p>
      </div>
    </Card>
  )
} 