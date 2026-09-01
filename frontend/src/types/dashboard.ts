export interface DashboardMetrics {
  total_events: number;
  recent_alerts: Array<{
    id: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    description: string;
    timestamp: string;
    source_ip: string;
  }>;
  system_health: {
    status: 'OPERATIONAL' | 'DEGRADED' | 'CRITICAL';
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
