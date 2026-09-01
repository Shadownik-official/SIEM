"use client";

import { ServerIcon } from '@heroicons/react/24/outline';

interface SystemHealthCardProps {
  status: 'OPERATIONAL' | 'DEGRADED' | 'CRITICAL';
  cpuUsage: number;
  memoryUsage: number;
}

export const SystemHealthCard: React.FC<SystemHealthCardProps> = ({ 
  status, 
  cpuUsage, 
  memoryUsage 
}) => {
  const getStatusColor = () => {
    switch(status) {
      case 'OPERATIONAL': return 'text-green-600 bg-green-100';
      case 'DEGRADED': return 'text-yellow-600 bg-yellow-100';
      case 'CRITICAL': return 'text-red-600 bg-red-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  return (
    <div className="bg-white shadow-md rounded-lg p-6 border-l-4 border-green-500 hover:shadow-lg transition-shadow">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-lg font-semibold text-gray-700">System Status</h2>
          <div className={`inline-block px-2 py-1 rounded-full text-xs font-bold mt-2 ${getStatusColor()}`}>
            {status}
          </div>
        </div>
        <ServerIcon className="h-8 w-8 text-green-500" />
      </div>
      <div className="mt-4">
        <div className="flex justify-between text-sm text-gray-600 mb-2">
          <span>CPU Usage</span>
          <span>{cpuUsage.toFixed(1)}%</span>
        </div>
        <div className="w-full bg-gray-200 rounded-full h-2.5">
          <div 
            className="bg-blue-600 h-2.5 rounded-full" 
            style={{ width: `${cpuUsage}%` }}
          ></div>
        </div>
        
        <div className="flex justify-between text-sm text-gray-600 mt-3 mb-2">
          <span>Memory Usage</span>
          <span>{memoryUsage.toFixed(1)}%</span>
        </div>
        <div className="w-full bg-gray-200 rounded-full h-2.5">
          <div 
            className="bg-purple-600 h-2.5 rounded-full" 
            style={{ width: `${memoryUsage}%` }}
          ></div>
        </div>
      </div>
    </div>
  );
};
