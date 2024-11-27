"""
Integration tests for the SIEM system
"""
import unittest
import os
import json
from unittest.mock import patch
from src.agents.cross_platform_agent import UniversalAgent
from src.intelligence.threat_intelligence import ThreatIntelligence
from src.core.database import Database

class TestSIEMIntegration(unittest.TestCase):
    def setUp(self):
        """Set up test environment"""
        self.agent_config = {
            'log_level': 'DEBUG',
            'collection_interval': 60,
            'server_endpoint': 'https://siem-server.test',
            'encryption_key': 'test-key'
        }
        
        self.intel_config = {
            'feeds': ['test_feed1'],
            'stix_server': 'https://test.stix.server',
            'api_key': 'test-key'
        }
        
        self.agent = UniversalAgent(config=self.agent_config)
        self.intel = ThreatIntelligence(config=self.intel_config)

    @patch('src.core.database.Database.store_events')
    def test_end_to_end_event_processing(self, mock_store):
        """Test complete event processing pipeline"""
        # 1. Collect events from agent
        events = self.agent.collect_all_events()
        
        # 2. Process events through intelligence module
        analysis = self.intel.analyze_threat_pattern(events)
        
        # 3. Check analysis results
        self.assertIn('risk_score', analysis)
        self.assertIn('anomalies', analysis)
        self.assertIn('patterns', analysis)
        
        # 4. Verify events are stored
        mock_store.assert_called_once()

    def test_alert_generation(self):
        """Test alert generation based on threat detection"""
        test_event = {
            'type': 'suspicious_connection',
            'source_ip': '192.168.1.100',
            'destination_ip': '10.0.0.2',
            'port': 445,
            'protocol': 'SMB'
        }
        
        # Analyze event
        analysis = self.intel.analyze_threat_pattern([test_event])
        
        # Check if high-risk events generate alerts
        if analysis['risk_score'] > 7.0:
            self.assertIn('recommendations', analysis)
            self.assertTrue(len(analysis['recommendations']) > 0)

    @patch('requests.post')
    def test_incident_response_integration(self, mock_post):
        """Test incident response workflow"""
        # Simulate high-risk event
        high_risk_event = {
            'type': 'malware_detected',
            'severity': 'critical',
            'confidence': 0.95,
            'affected_system': 'workstation1'
        }
        
        # Process through intelligence
        analysis = self.intel.analyze_threat_pattern([high_risk_event])
        
        # Verify incident response triggered
        if analysis['risk_score'] > 8.0:
            mock_post.assert_called_with(
                f"{self.agent_config['server_endpoint']}/incident",
                json=high_risk_event
            )

    def test_data_consistency(self):
        """Test data consistency across components"""
        # 1. Collect events
        events = self.agent.collect_all_events()
        
        # 2. Process through intelligence
        analysis = self.intel.analyze_threat_pattern(events)
        
        # 3. Verify data structure consistency
        for event in events:
            self.assertIsInstance(event, dict)
            self.assertIn('type', event)
            
        self.assertIsInstance(analysis['risk_score'], float)
        self.assertIsInstance(analysis['anomalies'], list)
        self.assertIsInstance(analysis['patterns'], list)

    @patch('src.core.utils.encrypt_data')
    @patch('src.core.utils.decrypt_data')
    def test_data_encryption(self, mock_decrypt, mock_encrypt):
        """Test end-to-end data encryption"""
        # 1. Collect and encrypt events
        events = self.agent.collect_all_events()
        self.agent._process_and_forward_events(events)
        
        # 2. Verify encryption
        mock_encrypt.assert_called_once()
        
        # 3. Verify decryption before analysis
        self.intel.analyze_threat_pattern(events)
        mock_decrypt.assert_called_once()

if __name__ == '__main__':
    unittest.main()
