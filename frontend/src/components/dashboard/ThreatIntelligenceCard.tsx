"use client";

import { ShieldExclamationIcon } from '@heroicons/react/24/outline';

interface ThreatIntelligenceCardProps {
  activeThreatCount: number;
  blockedIPs: number;
  threatTrends: Array<{
    type: string;
    count: number;
  }>;
}

export const ThreatIntelligenceCard: React.FC<ThreatIntelligenceCardProps> = ({ 
  activeThreatCount, 
  blockedIPs, 
  threatTrends 
}) => {
  return (
    <div className="bg-white shadow-md rounded-lg p-6 border-l-4 border-red-500 hover:shadow-lg transition-shadow">
      <div className="flex justify-between items-center mb-4">
        <div>
          <h2 className="text-lg font-semibold text-gray-700">Threat Intelligence</h2>
          <p className="text-3xl font-bold text-red-600">{activeThreatCount}</p>
          <p className="text-sm text-gray-500">Active Threats</p>
        </div>
        <ShieldExclamationIcon className="h-8 w-8 text-red-500" />
      </div>
      
      <div className="grid grid-cols-2 gap-4 mt-4">
        <div className="bg-gray-100 rounded-lg p-3 text-center">
          <h3 className="text-sm font-semibold text-gray-700">Blocked IPs</h3>
          <p className="text-xl font-bold text-gray-800">{blockedIPs}</p>
        </div>
        
        {threatTrends.map((trend) => (
          <div 
            key={trend.type} 
            className="bg-gray-100 rounded-lg p-3 text-center hover:bg-gray-200 transition"
          >
            <h3 className="text-sm font-semibold text-gray-700">{trend.type}</h3>
            <p className="text-xl font-bold text-gray-800">{trend.count}</p>
          </div>
        ))}
      </div>
    </div>
  );
};
