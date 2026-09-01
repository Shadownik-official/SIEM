"use client";

import { withAuth } from '@/components/withAuth';
import { useDashboardData } from '@/hooks/useDashboardData';
import { EventSummaryCard } from '@/components/dashboard/EventSummaryCard';
import { SystemHealthCard } from '@/components/dashboard/SystemHealthCard';
import { ThreatIntelligenceCard } from '@/components/dashboard/ThreatIntelligenceCard';
import { RecentAlertsTable } from '@/components/alerts/RecentAlertsTable';

function DashboardPage() {
  const { metrics, loading, error } = useDashboardData();

  if (loading) return <div className="text-center p-8">Loading dashboard...</div>;
  if (error) return <div className="text-red-500 p-8">Error: {error}</div>;
  if (!metrics) return null;

  return (
    <div className="p-6 bg-gray-50 min-h-screen">
      <h1 className="text-3xl font-bold mb-6 text-gray-800">SIEM Dashboard</h1>
      
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-6">
        <EventSummaryCard totalEvents={metrics.total_events} />
        <SystemHealthCard 
          status={metrics.system_health.status}
          cpuUsage={metrics.system_health.cpu_usage}
          memoryUsage={metrics.system_health.memory_usage}
        />
        <ThreatIntelligenceCard 
          activeThreatCount={metrics.threat_intelligence.active_threats}
          blockedIPs={metrics.threat_intelligence.blocked_ips}
          threatTrends={metrics.threat_intelligence.recent_threat_trends}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white shadow-md rounded-lg p-6">
          <h2 className="text-xl font-semibold text-gray-800 mb-4">Recent Alerts</h2>
          <RecentAlertsTable alerts={metrics.recent_alerts} />
        </div>
        
        <div className="bg-white shadow-md rounded-lg p-6">
          <h2 className="text-xl font-semibold text-gray-800 mb-4">Performance Metrics</h2>
          <div className="grid grid-cols-2 gap-4">
            <div className="bg-gray-100 p-4 rounded-lg text-center">
              <h3 className="text-sm font-semibold text-gray-700">Logs/Minute</h3>
              <p className="text-2xl font-bold text-blue-600">
                {metrics.performance_metrics.logs_processed_per_minute}
              </p>
            </div>
            <div className="bg-gray-100 p-4 rounded-lg text-center">
              <h3 className="text-sm font-semibold text-gray-700">Total Logs Today</h3>
              <p className="text-2xl font-bold text-green-600">
                {metrics.performance_metrics.total_logs_processed_today}
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default withAuth(DashboardPage);
