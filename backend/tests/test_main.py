import pytest
import httpx
import asyncio
from fastapi.testclient import TestClient
from src.api.main import app, create_access_token
from src.services.dashboard_service import DashboardService

# Create a test client
client = TestClient(app)

# Create a test token for authenticated routes
def get_test_token():
    return create_access_token({"sub": "admin"})

# Authentication Test Cases
def test_login_successful():
    response = client.post(
        "/token",
        data={"username": "admin", "password": "adminpassword"}
    )
    assert response.status_code == 200
    assert "access_token" in response.json()

def test_login_failed():
    response = client.post(
        "/token",
        data={"username": "wronguser", "password": "wrongpassword"}
    )
    assert response.status_code == 401

# Dashboard Service Test Cases
@pytest.mark.asyncio
async def test_dashboard_summary():
    summary = await DashboardService.get_dashboard_summary()
    
    assert "total_events" in summary
    assert "threat_intelligence" in summary
    assert "system_health" in summary
    assert "performance_metrics" in summary
    assert "recent_alerts" in summary

# Health Check Test
def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}

# Event Ingestion Test
def test_event_ingestion():
    test_event = {
        "source_ip": "192.168.1.100",
        "destination_ip": "10.0.0.50",
        "event_type": "network_connection",
        "severity": "medium"
    }
    
    response = client.post("/events", json=test_event)
    assert response.status_code == 200
    assert "event_id" in response.json()

# Alerts Retrieval Test
def test_get_alerts():
    response = client.get("/alerts?limit=10")
    assert response.status_code == 200
    alerts = response.json()
    assert len(alerts) <= 10
    
    for alert in alerts:
        assert "id" in alert
        assert "timestamp" in alert
        assert "severity" in alert

# System Metrics Test
def test_system_metrics():
    response = client.get("/system/metrics?time_range=24h")
    assert response.status_code == 200
    metrics = response.json()
    
    assert "cpu_usage" in metrics
    assert "memory_usage" in metrics
    assert "network_traffic" in metrics

# Threat Intelligence Test
def test_threat_intelligence():
    response = client.get("/threat-intelligence")
    assert response.status_code == 200
    threat_data = response.json()
    
    assert "active_threats" in threat_data
    assert "threat_score" in threat_data
    assert "recent_indicators" in threat_data

# Configuration Test
def test_get_configuration():
    response = client.get("/configuration")
    assert response.status_code == 200
    config = response.json()
    
    assert "log_level" in config
    assert "data_retention_days" in config
    assert "monitoring_enabled" in config

# Performance and Load Test
@pytest.mark.performance
def test_concurrent_requests():
    async def make_request():
        async with httpx.AsyncClient(base_url="http://localhost:8000") as client:
            response = await client.get("/health")
            assert response.status_code == 200

    async def run_concurrent_requests():
        tasks = [make_request() for _ in range(50)]
        await asyncio.gather(*tasks)

    asyncio.run(run_concurrent_requests())

# Error Handling Test
def test_invalid_endpoint():
    response = client.get("/nonexistent-endpoint")
    assert response.status_code == 404

# Security Headers Test
def test_security_headers():
    response = client.get("/health")
    headers = response.headers
    
    assert "X-Content-Type-Options" in headers
    assert "X-Frame-Options" in headers
    assert "Content-Security-Policy" in headers
