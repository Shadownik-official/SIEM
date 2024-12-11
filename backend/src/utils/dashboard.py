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
