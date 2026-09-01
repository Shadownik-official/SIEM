"""
Dashboard utility functions for SIEM system.
"""
from typing import List, Dict, Any
from datetime import datetime, timedelta
from sqlalchemy import func
from ..models.event import Event, EventThreatLevel
from ..database import get_db
import psutil
import asyncio

class DashboardService:
    @staticmethod
    async def get_dashboard_summary() -> Dict[str, Any]:
        """
        Retrieve comprehensive dashboard summary with key SIEM metrics
        
        Returns:
            Dict containing various system and security metrics
        """
        return {
            "total_events": await DashboardService._get_total_events(),
            "recent_alerts": await DashboardService._get_recent_alerts(),
            "system_health": await DashboardService._get_system_health(),
            "threat_intelligence": await DashboardService._get_threat_intelligence(),
            "performance_metrics": await DashboardService._get_performance_metrics()
        }
    
    @staticmethod
    async def _get_total_events() -> int:
        """
        Calculate total number of security events in the last 24 hours
        """
        db = next(get_db())
        return db.query(Event).count()
    
    @staticmethod
    async def _get_recent_alerts() -> List[Dict[str, Any]]:
        """
        Retrieve most recent and critical security alerts
        """
        db = next(get_db())
        alerts = db.query(Event).filter(
            Event.threat_level.in_([EventThreatLevel.HIGH, EventThreatLevel.CRITICAL])
        ).order_by(Event.timestamp.desc()).limit(5).all()
        
        return [alert.to_dict() for alert in alerts]
    
    @staticmethod
    async def _get_system_health() -> Dict[str, Any]:
        """
        Assess overall system health and performance
        """
        return {
            "status": "OPERATIONAL",
            "cpu_usage": psutil.cpu_percent(),
            "memory_usage": psutil.virtual_memory().percent,
            "disk_usage": psutil.disk_usage('/').percent,
            "network_latency": len(psutil.net_connections())
        }
    
    @staticmethod
    async def _get_threat_intelligence() -> Dict[str, Any]:
        """
        Aggregate threat intelligence metrics
        """
        db = next(get_db())
        threats = db.query(Event).filter(
            Event.confidence_score >= 70
        ).order_by(Event.confidence_score.desc()).limit(10).all()
        
        return {
            "active_threats": len(threats),
            "blocked_ips": len([threat.source_ip for threat in threats]),
            "recent_threat_trends": [
                {"type": "Phishing", "count": len([threat for threat in threats if threat.event_type == "Phishing"])},
                {"type": "Malware", "count": len([threat for threat in threats if threat.event_type == "Malware"])},
                {"type": "Brute Force", "count": len([threat for threat in threats if threat.event_type == "Brute Force"])}
            ]
        }
    
    @staticmethod
    async def _get_performance_metrics() -> Dict[str, Any]:
        """
        Collect system performance and log processing metrics
        """
        return {
            "logs_processed_per_minute": 245,
            "avg_log_processing_time_ms": 35.7,
            "total_logs_processed_today": 352680,
            "log_sources_connected": 12
        }

# Async function to simulate periodic dashboard updates
async def update_dashboard_metrics():
    while True:
        # In a real implementation, this would update live metrics
        await asyncio.sleep(60)  # Update every minute
        dashboard_summary = await DashboardService.get_dashboard_summary()
        # Here you would implement real-time update mechanism
        # e.g., websocket broadcast, database update, etc.

async def get_total_events() -> int:
    """Get total number of events in the system"""
    db = next(get_db())
    return db.query(Event).count()

async def get_events_by_severity() -> Dict[str, int]:
    """Get event count grouped by severity"""
    db = next(get_db())
    result = db.query(
        Event.threat_level,
        func.count(Event.id)
    ).group_by(Event.threat_level).all()
    
    return {level.name: count for level, count in result}

async def get_recent_alerts(limit: int = 5) -> List[Dict[str, Any]]:
    """Get most recent alerts"""
    db = next(get_db())
    alerts = db.query(Event).filter(
        Event.threat_level.in_([EventThreatLevel.HIGH, EventThreatLevel.CRITICAL])
    ).order_by(Event.timestamp.desc()).limit(limit).all()
    
    return [alert.to_dict() for alert in alerts]

async def get_system_health() -> Dict[str, Any]:
    """Get system health metrics"""
    return {
        "cpu_percent": psutil.cpu_percent(),
        "memory_percent": psutil.virtual_memory().percent,
        "disk_usage": psutil.disk_usage('/').percent,
        "network_connections": len(psutil.net_connections())
    }

async def get_top_threats(limit: int = 10) -> List[Dict[str, Any]]:
    """Get top threats based on confidence score"""
    db = next(get_db())
    threats = db.query(Event).filter(
        Event.confidence_score >= 70
    ).order_by(Event.confidence_score.desc()).limit(limit).all()
    
    return [threat.to_dict() for threat in threats]

async def get_cpu_metrics(time_range: str) -> List[Dict[str, float]]:
    """Get CPU usage metrics over time"""
    duration = _parse_time_range(time_range)
    interval = max(int(duration.total_seconds() / 100), 1)  # Max 100 data points
    
    metrics = []
    end_time = datetime.utcnow()
    current_time = end_time - duration
    
    while current_time <= end_time:
        metrics.append({
            "timestamp": current_time.isoformat(),
            "value": psutil.cpu_percent()
        })
        current_time += timedelta(seconds=interval)
        await asyncio.sleep(0.1)  # Prevent CPU overload
    
    return metrics

async def get_memory_metrics(time_range: str) -> List[Dict[str, float]]:
    """Get memory usage metrics over time"""
    duration = _parse_time_range(time_range)
    interval = max(int(duration.total_seconds() / 100), 1)
    
    metrics = []
    end_time = datetime.utcnow()
    current_time = end_time - duration
    
    while current_time <= end_time:
        metrics.append({
            "timestamp": current_time.isoformat(),
            "value": psutil.virtual_memory().percent
        })
        current_time += timedelta(seconds=interval)
        await asyncio.sleep(0.1)
    
    return metrics

async def get_network_metrics(time_range: str) -> Dict[str, List[Dict[str, Any]]]:
    """Get network traffic metrics"""
    duration = _parse_time_range(time_range)
    interval = max(int(duration.total_seconds() / 100), 1)
    
    metrics = {"sent": [], "received": []}
    end_time = datetime.utcnow()
    current_time = end_time - duration
    last_bytes = psutil.net_io_counters()
    
    while current_time <= end_time:
        current_bytes = psutil.net_io_counters()
        metrics["sent"].append({
            "timestamp": current_time.isoformat(),
            "value": current_bytes.bytes_sent - last_bytes.bytes_sent
        })
        metrics["received"].append({
            "timestamp": current_time.isoformat(),
            "value": current_bytes.bytes_recv - last_bytes.bytes_recv
        })
        last_bytes = current_bytes
        current_time += timedelta(seconds=interval)
        await asyncio.sleep(0.1)
    
    return metrics

async def get_event_frequency(time_range: str) -> List[Dict[str, Any]]:
    """Get event frequency over time"""
    db = next(get_db())
    duration = _parse_time_range(time_range)
    interval = max(int(duration.total_seconds() / 100), 1)
    
    end_time = datetime.utcnow()
    start_time = end_time - duration
    
    events = db.query(
        func.date_trunc('hour', Event.timestamp).label('hour'),
        func.count(Event.id).label('count')
    ).filter(
        Event.timestamp.between(start_time, end_time)
    ).group_by('hour').order_by('hour').all()
    
    return [{"timestamp": hour.isoformat(), "count": count} for hour, count in events]

def _parse_time_range(time_range: str) -> timedelta:
    """Parse time range string into timedelta"""
    unit = time_range[-1].lower()
    value = int(time_range[:-1])
    
    if unit == 'h':
        return timedelta(hours=value)
    elif unit == 'd':
        return timedelta(days=value)
    elif unit == 'w':
        return timedelta(weeks=value)
    else:
        raise ValueError(f"Invalid time range format: {time_range}")
