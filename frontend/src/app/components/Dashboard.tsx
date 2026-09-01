"use client";

import { useState, useEffect } from 'react';
import { 
  ArrowUpIcon, 
  ShieldExclamationIcon, 
  ServerIcon, 
  ChartBarIcon 
} from '@heroicons/react/24/outline';

interface DashboardMetrics {
  total_events: number;
  recent_alerts: Array<{
    id: string;
    severity: string;
    description: string;
    timestamp: string;
    source_ip: string;
  }>;
  system_health: {
    status: string;
    cpu_usage: number;
    memory_usage: number;
    disk_usage: number;
    network_latency: number;
  };
  threat_intelligence: {
    active_threats: number;
    blocked_ips: number;
    recent_threat_trends: Array<{
      type: string;
      count: number;
    }>;
  };
  performance_metrics: {
    logs_processed_per_minute: number;
    avg_log_processing_time_ms: number;
    total_logs_processed_today: number;
    log_sources_connected: number;
  };
}

const Dashboard = () => {
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchDashboardMetrics = async () => {
      try {
        const response = await fetch('http://localhost:8000/dashboard/summary');
        if (!response.ok) {
          throw new Error('Failed to fetch dashboard metrics');
        }
        const data = await response.json();
        setMetrics(data);
        setLoading(false);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'An unknown error occurred');
        setLoading(false);
      }
    };

    fetchDashboardMetrics();
    const intervalId = setInterval(fetchDashboardMetrics, 60000); // Refresh every minute

    return () => clearInterval(intervalId);
  }, []);

  if (loading) return <div className="text-center p-8">Loading dashboard...</div>;
  if (error) return <div className="text-red-500 p-8">Error: {error}</div>;
  if (!metrics) return null;

  return (
    <div className="p-6 bg-gray-50">
      <h1 className="text-3xl font-bold mb-6 text-gray-800">SIEM Dashboard</h1>
      
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {/* Total Events Card */}
        <div className="bg-white shadow-md rounded-lg p-6 border-l-4 border-blue-500">
          <div className="flex justify-between items-center">
            <div>
              <h2 className="text-lg font-semibold text-gray-700">Total Events</h2>
              <p className="text-3xl font-bold text-blue-600">{metrics.total_events}</p>
            </div>
            <ArrowUpIcon className="h-8 w-8 text-blue-500" />
          </div>
        </div>

        {/* Active Threats Card */}
        <div className="bg-white shadow-md rounded-lg p-6 border-l-4 border-red-500">
          <div className="flex justify-between items-center">
            <div>
              <h2 className="text-lg font-semibold text-gray-700">Active Threats</h2>
              <p className="text-3xl font-bold text-red-600">{metrics.threat_intelligence.active_threats}</p>
            </div>
            <ShieldExclamationIcon className="h-8 w-8 text-red-500" />
          </div>
        </div>

        {/* System Health Card */}
        <div className="bg-white shadow-md rounded-lg p-6 border-l-4 border-green-500">
          <div className="flex justify-between items-center">
            <div>
              <h2 className="text-lg font-semibold text-gray-700">System Status</h2>
              <p className="text-xl font-bold text-green-600">{metrics.system_health.status}</p>
            </div>
            <ServerIcon className="h-8 w-8 text-green-500" />
          </div>
          <div className="mt-4">
            <div className="flex justify-between text-sm text-gray-600">
              <span>CPU Usage</span>
              <span>{metrics.system_health.cpu_usage}%</span>
            </div>
            <div className="flex justify-between text-sm text-gray-600">
              <span>Memory Usage</span>
              <span>{metrics.system_health.memory_usage}%</span>
            </div>
          </div>
        </div>

        {/* Performance Metrics Card */}
        <div className="bg-white shadow-md rounded-lg p-6 border-l-4 border-purple-500">
          <div className="flex justify-between items-center">
            <div>
              <h2 className="text-lg font-semibold text-gray-700">Log Processing</h2>
              <p className="text-xl font-bold text-purple-600">{metrics.performance_metrics.logs_processed_per_minute} logs/min</p>
            </div>
            <ChartBarIcon className="h-8 w-8 text-purple-500" />
          </div>
          <div className="mt-4">
            <div className="flex justify-between text-sm text-gray-600">
              <span>Total Logs Today</span>
              <span>{metrics.performance_metrics.total_logs_processed_today}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Alerts Section */}
      <div className="mt-8 bg-white shadow-md rounded-lg p-6">
        <h2 className="text-xl font-semibold text-gray-800 mb-4">Recent Alerts</h2>
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
              {metrics.recent_alerts.map((alert) => (
                <tr key={alert.id} className="border-b hover:bg-gray-50">
                  <td className="px-4 py-3">{alert.id}</td>
                  <td className="px-4 py-3">
                    <span className={`
                      px-2 py-1 rounded-full text-xs font-bold
                      ${alert.severity === 'HIGH' ? 'bg-red-200 text-red-800' : 
                        alert.severity === 'MEDIUM' ? 'bg-yellow-200 text-yellow-800' : 
                        'bg-green-200 text-green-800'}
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
      </div>

      {/* Threat Trends Section */}
      <div className="mt-8 bg-white shadow-md rounded-lg p-6">
        <h2 className="text-xl font-semibold text-gray-800 mb-4">Threat Trends</h2>
        <div className="grid grid-cols-3 gap-4">
          {metrics.threat_intelligence.recent_threat_trends.map((trend) => (
            <div 
              key={trend.type} 
              className="bg-gray-100 rounded-lg p-4 text-center hover:bg-gray-200 transition"
            >
              <h3 className="text-lg font-semibold text-gray-700">{trend.type}</h3>
              <p className="text-2xl font-bold text-gray-800">{trend.count}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
