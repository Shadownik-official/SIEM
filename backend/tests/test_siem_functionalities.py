import pytest
import asyncio
from datetime import datetime, timedelta
import random
import uuid

from src.services.log_collector import LogCollector
from src.services.threat_intelligence import ThreatIntelligenceService
from src.services.dashboard_service import DashboardService
from src.models.event import Event, EventCategory, EventThreatLevel

# Mock configuration for testing
TEST_CONFIG = {
    'log_level': 'DEBUG',
    'collectors': [
        {
            'name': 'test_file_collector',
            'type': 'file',
            'path': '/tmp/test_logs',
            'enabled': True
        }
    ]
}

class TestSIEMFunctionalities:
    @pytest.fixture
    def log_collector(self):
        """Create a LogCollector instance for testing"""
        return LogCollector(TEST_CONFIG)

    @pytest.fixture
    def sample_log_event(self):
        """Generate a sample log event for testing"""
        return {
            'timestamp': datetime.utcnow().isoformat(),
            'source_ip': f'192.168.1.{random.randint(1, 254)}',
            'destination_ip': f'10.0.0.{random.randint(1, 254)}',
            'protocol': random.choice(['TCP', 'UDP', 'ICMP']),
            'event_type': random.choice([
                'network_connection', 
                'login_attempt', 
                'file_access', 
                'process_execution'
            ]),
            'severity': random.choice(['low', 'medium', 'high', 'critical'])
        }

    def test_log_collector_initialization(self, log_collector):
        """Test LogCollector initialization"""
        assert log_collector is not None
        assert len(log_collector.collectors) > 0
        assert log_collector.running == False

    @pytest.mark.asyncio
    async def test_log_collector_start(self, log_collector):
        """Test starting log collectors"""
        await log_collector.start()
        assert log_collector.running == True

    def test_event_creation(self, log_collector, sample_log_event):
        """Test creating an event from log data"""
        # Use the first collector for testing
        first_collector = list(log_collector.collectors.values())[0]
        
        # Process log event
        event = first_collector.process_log(sample_log_event)
        
        # Validate event
        assert isinstance(event, Event)
        assert event.source_ip == sample_log_event['source_ip']
        assert event.category in EventCategory
        assert event.threat_level in EventThreatLevel

    def test_log_parsing(self, log_collector, sample_log_event):
        """Test log parsing functionality"""
        # Use the first collector for testing
        first_collector = list(log_collector.collectors.values())[0]
        
        # Parse log event
        parsed_data = first_collector.parse_log_entry(sample_log_event)
        
        # Validate parsing
        assert isinstance(parsed_data, dict)
        assert 'source_ip' in parsed_data
        assert 'event_type' in parsed_data

    def test_event_categorization(self, log_collector, sample_log_event):
        """Test event categorization"""
        # Use the first collector for testing
        first_collector = list(log_collector.collectors.values())[0]
        
        # Determine event category
        category = first_collector.determine_category(sample_log_event)
        
        # Validate categorization
        assert category in EventCategory

    def test_threat_level_determination(self, log_collector, sample_log_event):
        """Test threat level determination"""
        # Use the first collector for testing
        first_collector = list(log_collector.collectors.values())[0]
        
        # Determine threat level
        threat_level = first_collector.determine_threat_level(sample_log_event)
        
        # Validate threat level
        assert threat_level in EventThreatLevel

    @pytest.mark.asyncio
    async def test_multiple_log_collection(self, log_collector):
        """Test collecting multiple log events"""
        # Generate multiple sample events
        sample_events = [
            {
                'timestamp': (datetime.utcnow() - timedelta(minutes=i)).isoformat(),
                'source_ip': f'192.168.1.{random.randint(1, 254)}',
                'event_type': random.choice(['login_attempt', 'network_connection'])
            } for i in range(10)
        ]
        
        # Use the first collector for testing
        first_collector = list(log_collector.collectors.values())[0]
        
        # Process events
        processed_events = [first_collector.process_log(event) for event in sample_events]
        
        # Validate processed events
        assert len(processed_events) == 10
        assert all(isinstance(event, Event) for event in processed_events)

    def test_log_collector_configuration(self, log_collector):
        """Test log collector configuration"""
        # Verify collectors are configured correctly
        for name, collector in log_collector.collectors.items():
            assert hasattr(collector, 'name')
            assert hasattr(collector, 'enabled')
            assert collector.enabled == True

    def test_log_collection(self, log_collector, sample_log_event):
        """Test log collection functionality"""
        # Collect log event
        event_id = log_collector.collect_event(sample_log_event)
        
        # Verify event collection
        assert event_id is not None
        assert isinstance(event_id, str)
        
        # Retrieve the collected event
        retrieved_event = log_collector.get_event(event_id)
        assert retrieved_event is not None
        assert retrieved_event['source_ip'] == sample_log_event['source_ip']

    def test_event_parsing(self, sample_log_event):
        """Test log event parsing"""
        from src.utils.event_parser import parse_log_event
        parsed_event = parse_log_event(sample_log_event)
        
        # Validate parsed event structure
        assert isinstance(parsed_event, Event)
        assert parsed_event.source_ip == sample_log_event['source_ip']
        assert parsed_event.event_type == sample_log_event['event_type']

    def test_threat_intelligence(self):
        """Test threat intelligence service"""
        ti_service = ThreatIntelligenceService()
        
        # Check IP reputation
        test_ips = [
            "8.8.8.8",  # Google DNS
            "1.1.1.1",  # Cloudflare DNS
            "192.168.1.100"  # Private IP
        ]
        
        for ip in test_ips:
            reputation = ti_service.check_ip_reputation(ip)
            assert reputation is not None
            assert 'score' in reputation
            assert 'threat_level' in reputation

    def test_alert_generation(self, sample_log_event):
        """Test alert generation from log events"""
        # Convert sample log to security event
        from src.utils.event_parser import parse_log_event
        security_event = parse_log_event(sample_log_event)
        
        # Generate alert
        from src.core.alert_generator import generate_alert
        alert = generate_alert(security_event)
        
        # Validate alert
        assert alert is not None
        assert 'id' in alert
        assert 'timestamp' in alert
        assert 'severity' in alert
        assert 'description' in alert

    def test_incident_response(self, sample_log_event):
        """Test incident response workflow"""
        # Create incident response service
        from src.services.incident_response import IncidentResponseService
        ir_service = IncidentResponseService()
        
        # Convert sample log to security event
        from src.utils.event_parser import parse_log_event
        security_event = parse_log_event(sample_log_event)
        
        # Generate alert
        from src.core.alert_generator import generate_alert
        alert = generate_alert(security_event)
        
        # Initiate incident response
        response = ir_service.handle_incident(alert)
        
        # Validate response
        assert response is not None
        assert 'status' in response
        assert 'actions' in response
        assert len(response['actions']) > 0

    @pytest.mark.asyncio
    async def test_dashboard_summary(self):
        """Test async dashboard summary generation"""
        dashboard_service = DashboardService()
        
        # Generate dashboard summary
        summary = await dashboard_service.get_dashboard_summary()
        
        # Validate summary structure
        assert "total_events" in summary
        assert "threat_intelligence" in summary
        assert "system_health" in summary
        assert "performance_metrics" in summary
        assert "recent_alerts" in summary

    def test_multi_event_correlation(self):
        """Test event correlation across multiple log sources"""
        log_collector = LogCollector(TEST_CONFIG)
        
        # Generate multiple events
        events = [
            {
                "timestamp": (datetime.utcnow() - timedelta(minutes=i)).isoformat(),
                "source_ip": f"192.168.1.{random.randint(1, 254)}",
                "event_type": random.choice(["login_attempt", "network_connection", "file_access"])
            } for i in range(10)
        ]
        
        # Collect multiple events
        event_ids = [log_collector.collect_event(event) for event in events]
        
        # Correlate events
        correlated_events = log_collector.correlate_events(event_ids)
        
        # Validate correlation
        assert len(correlated_events) > 0
        assert all('correlation_score' in event for event in correlated_events)

    def test_comprehensive_security_workflow(self, sample_log_event):
        """Comprehensive test of SIEM security workflow"""
        # Log Collection
        log_collector = LogCollector(TEST_CONFIG)
        event_id = log_collector.collect_event(sample_log_event)
        
        # Event Parsing
        from src.utils.event_parser import parse_log_event
        security_event = parse_log_event(sample_log_event)
        
        # Threat Intelligence Check
        ti_service = ThreatIntelligenceService()
        reputation = ti_service.check_ip_reputation(security_event.source_ip)
        
        # Alert Generation (if threat detected)
        if reputation['score'] > 0.7:
            from src.core.alert_generator import generate_alert
            alert = generate_alert(security_event)
            
            # Incident Response
            from src.services.incident_response import IncidentResponseService
            ir_service = IncidentResponseService()
            response = ir_service.handle_incident(alert)
            
            # Validate high-risk workflow
            assert response['status'] == 'critical'
            assert len(response['actions']) > 0

    def test_performance_metrics(self):
        """Test performance metrics generation"""
        dashboard_service = DashboardService()
        
        # Generate performance metrics
        metrics = dashboard_service.get_performance_metrics()
        
        # Validate metrics
        assert 'logs_processed' in metrics
        assert 'processing_time' in metrics
        assert 'error_rate' in metrics
        assert metrics['logs_processed'] >= 0
        assert metrics['processing_time'] >= 0
        assert 0 <= metrics['error_rate'] <= 1

# Stress and Load Testing
def test_log_ingestion_stress():
    """Simulate high-volume log ingestion"""
    log_collector = LogCollector(TEST_CONFIG)
    
    # Generate a large number of events
    events = [
        {
            "timestamp": datetime.utcnow().isoformat(),
            "source_ip": f"192.168.1.{random.randint(1, 254)}",
            "destination_ip": f"10.0.0.{random.randint(1, 254)}",
            "event_type": random.choice(["network_connection", "login_attempt"]),
            "severity": random.choice(["low", "medium", "high"])
        } for _ in range(1000)  # Simulate 1000 events
    ]
    
    # Collect events
    event_ids = [log_collector.collect_event(event) for event in events]
    
    # Validate event collection
    assert len(event_ids) == 1000
    assert all(isinstance(event_id, str) for event_id in event_ids)

# Security Anomaly Detection Test
def test_anomaly_detection():
    """Test anomaly detection capabilities"""
    log_collector = LogCollector(TEST_CONFIG)
    
    # Generate a series of events with an anomalous pattern
    anomalous_events = [
        {
            "timestamp": (datetime.utcnow() - timedelta(minutes=i)).isoformat(),
            "source_ip": "192.168.1.100",  # Same source IP
            "event_type": "login_attempt",
            "status": "failed" if i % 3 == 0 else "success"
        } for i in range(10)
    ]
    
    # Collect events
    event_ids = [log_collector.collect_event(event) for event in anomalous_events]
    
    # Detect anomalies
    anomalies = log_collector.detect_anomalies(event_ids)
    
    # Validate anomaly detection
    assert len(anomalies) > 0
    assert all('anomaly_score' in anomaly for anomaly in anomalies)

# Performance and Stress Testing
def test_high_volume_log_processing():
    """Simulate high-volume log processing"""
    config = {
        'log_level': 'ERROR',
        'collectors': [
            {
                'name': 'stress_test_collector',
                'type': 'file',
                'path': '/tmp/stress_logs',
                'enabled': True
            }
        ]
    }
    
    log_collector = LogCollector(config)
    
    # Generate a large number of events
    sample_events = [
        {
            'timestamp': datetime.utcnow().isoformat(),
            'source_ip': f'192.168.1.{random.randint(1, 254)}',
            'event_type': random.choice(['network_connection', 'login_attempt'])
        } for _ in range(1000)  # Simulate 1000 events
    ]
    
    # Use the first collector for testing
    first_collector = list(log_collector.collectors.values())[0]
    
    # Process events
    processed_events = [first_collector.process_log(event) for event in sample_events]
    
    # Validate event processing
    assert len(processed_events) == 1000
    assert all(isinstance(event, Event) for event in processed_events)
