from typing import Dict, Any
import random
from datetime import datetime, timedelta

class DashboardService:
    @staticmethod
    async def get_dashboard_summary() -> Dict[str, Any]:
        """
        Generate a comprehensive dashboard summary with mock data.
        
        Returns:
            Dict[str, Any]: Dashboard summary with various metrics
        """
        now = datetime.utcnow()
        
        return {
            "total_events": random.randint(1000, 10000),
            "threat_intelligence": {
                "active_threats": random.randint(5, 50),
                "threat_score": random.uniform(0.1, 0.9)
            },
            "system_health": {
                "status": "Healthy" if random.random() > 0.1 else "Warning",
                "cpu_usage": round(random.uniform(10, 90), 2),
                "memory_usage": round(random.uniform(20, 80), 2)
            },
            "performance_metrics": {
                "logs_processed_per_minute": random.randint(50, 500),
                "total_logs_processed_today": random.randint(10000, 100000)
            },
            "recent_alerts": [
                {
                    "id": f"ALERT-{random.randint(1000, 9999)}",
                    "timestamp": (now - timedelta(minutes=random.randint(1, 60))).isoformat(),
                    "severity": random.choice(["low", "medium", "high", "critical"]),
                    "description": f"Potential security incident detected from IP {random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                    "source_ip": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
                } for _ in range(5)
            ]
        }

    @staticmethod
    async def get_recent_alerts(limit: int = 10) -> Dict[str, Any]:
        """
        Generate mock recent alerts.
        
        Args:
            limit (int): Maximum number of alerts to return
        
        Returns:
            Dict[str, Any]: Recent alerts
        """
        now = datetime.utcnow()
        return {
            "alerts": [
                {
                    "id": f"ALERT-{random.randint(1000, 9999)}",
                    "timestamp": (now - timedelta(minutes=random.randint(1, 60))).isoformat(),
                    "severity": random.choice(["low", "medium", "high", "critical"]),
                    "description": f"Security anomaly detected from IP {random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                    "source_ip": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
                } for _ in range(limit)
            ]
        }
