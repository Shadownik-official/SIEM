"use client";

import { DashboardMetrics } from '@/types/dashboard';

interface RecentAlertsTableProps {
  alerts: DashboardMetrics['recent_alerts'];
}

export const RecentAlertsTable: React.FC<RecentAlertsTableProps> = ({ alerts }) => {
  const getSeverityColor = (severity: string) => {
    switch(severity) {
      case 'HIGH': return 'bg-red-200 text-red-800';
      case 'MEDIUM': return 'bg-yellow-200 text-yellow-800';
      case 'LOW': return 'bg-green-200 text-green-800';
      default: return 'bg-gray-200 text-gray-800';
    }
  };

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm text-left text-gray-600">
        <thead className="bg-gray-100 text-gray-600 uppercase">
          <tr>
            <th className="px-4 py-3">Alert ID</th>
            <th className="px-4 py-3">Severity</th>
            <th className="px-4 py-3">Description</th>
            <th className="px-4 py-3">Timestamp</th>
            <th className="px-4 py-3">Source IP</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert) => (
            <tr key={alert.id} className="border-b hover:bg-gray-50">
              <td className="px-4 py-3">{alert.id}</td>
              <td className="px-4 py-3">
                <span className={`
                  px-2 py-1 rounded-full text-xs font-bold
                  ${getSeverityColor(alert.severity)}
                `}>
                  {alert.severity}
                </span>
              </td>
              <td className="px-4 py-3">{alert.description}</td>
              <td className="px-4 py-3">{new Date(alert.timestamp).toLocaleString()}</td>
              <td className="px-4 py-3">{alert.source_ip}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};
