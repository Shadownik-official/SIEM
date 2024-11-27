"""
Test suite for the Threat Intelligence Module
"""
import unittest
from unittest.mock import Mock, patch
import numpy as np
from datetime import datetime
from src.intelligence.threat_intelligence import ThreatIntelligence, ThreatIndicator, ThreatActor

class TestThreatIntelligence(unittest.TestCase):
    def setUp(self):
        """Set up test environment"""
        self.config = {
            'feeds': ['test_feed1', 'test_feed2'],
            'stix_server': 'https://test.stix.server',
            'api_key': 'test-key'
        }
        self.intel = ThreatIntelligence(config=self.config)

    def test_threat_indicator_creation(self):
        """Test creation of threat indicators"""
        indicator = ThreatIndicator(
            id='TEST-001',
            type='ip',
            value='192.168.1.1',
            confidence=0.85,
            severity='high',
            source='test_source',
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            tags=['malware', 'c2'],
            related_indicators=[],
            context={}
        )
        
        self.assertEqual(indicator.type, 'ip')
        self.assertEqual(indicator.confidence, 0.85)
        self.assertEqual(indicator.severity, 'high')

    def test_threat_actor_creation(self):
        """Test creation of threat actor profiles"""
        actor = ThreatActor(
            id='APT-001',
            name='Test Actor',
            aliases=['TestGroup', 'APT-X'],
            description='Test threat actor',
            motivation=['financial'],
            sophistication='advanced',
            ttps=['T1195', 'T1190'],
            indicators=['TEST-001'],
            campaigns=['Campaign-X'],
            first_seen=datetime.now(),
            last_seen=datetime.now()
        )
        
        self.assertEqual(actor.name, 'Test Actor')
        self.assertEqual(actor.sophistication, 'advanced')
        self.assertIn('T1195', actor.ttps)

    @patch('src.intelligence.threat_intelligence.ThreatIntelligence._extract_features')
    def test_threat_pattern_analysis(self, mock_extract):
        """Test ML-based threat pattern analysis"""
        # Mock feature extraction
        mock_extract.return_value = np.array([[1.0, 0.0, 0.5]])
        
        # Mock ML model
        self.intel.ml_model = Mock()
        self.intel.ml_model.detect_anomalies.return_value = [{
            'type': 'anomaly',
            'severity': 'high',
            'confidence': 0.9
        }]
        
        # Mock pattern analyzer
        self.intel.pattern_analyzer = Mock()
        self.intel.pattern_analyzer.find_patterns.return_value = [{
            'pattern': 'test_pattern',
            'confidence': 0.8
        }]
        
        # Test analysis
        result = self.intel.analyze_threat_pattern([{'event': 'test'}])
        
        self.assertIn('risk_score', result)
        self.assertIn('anomalies', result)
        self.assertIn('patterns', result)
        self.assertTrue(len(result['anomalies']) > 0)
        self.assertTrue(len(result['patterns']) > 0)

    def test_risk_score_calculation(self):
        """Test risk score calculation"""
        anomalies = [
            {'severity': 'critical', 'confidence': 0.9},
            {'severity': 'high', 'confidence': 0.8},
            {'severity': 'medium', 'confidence': 0.7}
        ]
        
        score = self.intel._calculate_risk_score(anomalies)
        self.assertGreater(score, 0)
        self.assertLessEqual(score, 10)

    @patch('requests.get')
    def test_feed_updates(self, mock_get):
        """Test threat feed updates"""
        mock_get.return_value.json.return_value = {
            'indicators': [
                {
                    'id': 'TEST-002',
                    'type': 'domain',
                    'value': 'test.malicious.com',
                    'confidence': 0.9
                }
            ]
        }
        
        self.intel._update_feeds()
        self.assertTrue(len(self.intel.indicator_cache) > 0)

    def test_stix_integration(self):
        """Test STIX/TAXII integration"""
        with patch('taxii2client.v20.Server') as mock_server:
            mock_server.return_value.collections.return_value = []
            self.intel._initialize_stix_server()
            mock_server.assert_called_once()

if __name__ == '__main__':
    unittest.main()
