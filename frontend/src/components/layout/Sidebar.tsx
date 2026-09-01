'use client'

import React from 'react'
import Link from 'next/link'

export default function Sidebar() {
  return (
    <div className="w-64 bg-white shadow-sm">
      <div className="h-full px-3 py-4">
        <ul className="space-y-2">
          <li>
            <Link 
              href="/"
              className="flex items-center p-2 text-gray-900 rounded-lg hover:bg-gray-100"
            >
              Dashboard
            </Link>
          </li>
          {/* Add more menu items as needed */}
        </ul>
      </div>
    </div>
  )
} 