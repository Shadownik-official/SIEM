"""
Test suite for the Threat Intelligence Module
"""
import unittest
from unittest.mock import Mock, patch, MagicMock
import numpy as np
from datetime import datetime, timedelta
import threading
import time
import json
from src.intelligence.threat_intelligence import ThreatIntelligence, ThreatIndicator, ThreatActor

class TestThreatIntelligence(unittest.TestCase):
    def setUp(self):
        """Set up test environment"""
        self.config = {
            'feeds': ['test_feed1', 'test_feed2'],
            'stix_server': 'https://test.stix.server',
            'api_key': 'test-key',
            'update_interval': 1,
            'ml_config': {
                'model_path': 'models/test_model.pkl',
                'feature_extractor_path': 'models/test_extractor.pkl'
            }
        }
        self.intel = ThreatIntelligence(config=self.config)

    def tearDown(self):
        """Clean up after tests"""
        if hasattr(self, 'intel'):
            self.intel.shutdown()

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

    def test_initialization(self):
        """Test initialization of ThreatIntelligence"""
        self.assertIsNotNone(self.intel.feeds)
        self.assertIsNotNone(self.intel.stix_server)
        self.assertTrue(self.intel.running)
        self.assertIsNotNone(self.intel.update_thread)

    def test_shutdown(self):
        """Test shutdown functionality"""
        self.intel.running = True
        self.intel.shutdown()
        self.assertFalse(self.intel.running)
        self.assertIsNone(self.intel.ml_model)

    @patch('src.intelligence.threat_intelligence.ThreatIntelligence._update_feeds')
    def test_feed_updates(self, mock_update):
        """Test feed update mechanism"""
        # Start feed updates
        self.intel._start_feed_updates()
        time.sleep(2)  # Wait for update cycle
        
        # Verify update was called
        mock_update.assert_called()

    def test_indicator_caching(self):
        """Test indicator caching mechanism"""
        # Create test indicator
        indicator = ThreatIndicator(
            id='CACHE-001',
            type='domain',
            value='test.com',
            confidence=0.9,
            severity='high',
            source='test',
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            tags=[],
            related_indicators=[],
            context={}
        )
        
        # Add to cache
        self.intel.indicator_cache['CACHE-001'] = indicator
        
        # Test cache retrieval
        cached = self.intel._get_cached_indicator('CACHE-001')
        self.assertEqual(cached.id, 'CACHE-001')
        self.assertEqual(cached.value, 'test.com')

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

    def test_comprehensive_threat_analysis(self):
        """Test comprehensive threat analysis pipeline"""
        test_data = {
            'source_ip': '192.168.1.1',
            'destination_ip': '10.0.0.1',
            'protocol': 'TCP',
            'port': 445,
            'timestamp': datetime.now().isoformat()
        }
        
        # Mock indicator matches
        self.intel._find_matching_indicators = MagicMock(return_value=[
            ThreatIndicator(
                id='TEST-001',
                type='ip',
                value='192.168.1.1',
                confidence=0.9,
                severity='high',
                source='test',
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                tags=['malware'],
                related_indicators=[],
                context={}
            )
        ])
        
        # Mock actor identification
        self.intel._identify_threat_actors = MagicMock(return_value=[
            ThreatActor(
                id='APT-001',
                name='Test Actor',
                aliases=['TestGroup'],
                description='Test actor',
                motivation=['financial'],
                sophistication='advanced',
                ttps=['T1190'],
                indicators=['TEST-001'],
                campaigns=[],
                first_seen=datetime.now(),
                last_seen=datetime.now()
            )
        ])
        
        # Test analysis
        result = self.intel.analyze_threat(test_data)
        
        # Verify analysis results
        self.assertEqual(result['status'], 'completed')
        self.assertIn('indicators', result)
        self.assertIn('actors', result)
        self.assertIn('risk_score', result)
        self.assertIn('mitre_mapping', result)
        self.assertIn('recommendations', result)

    @patch('logging.Logger.error')
    def test_error_handling(self, mock_logger):
        """Test error handling in analysis"""
        # Force an error in analysis
        self.intel._find_matching_indicators = MagicMock(
            side_effect=Exception("Test error")
        )
        
        result = self.intel.analyze_threat({'test': 'data'})
        
        # Verify error handling
        self.assertEqual(result['status'], 'error')
        self.assertIn('error', result)
        mock_logger.assert_called()

    def test_feed_update_error_handling(self):
        """Test error handling in feed updates"""
        # Mock feed update to raise an error
        self.intel._update_feeds = MagicMock(
            side_effect=Exception("Feed update error")
        )
        
        # Start feed updates
        self.intel._start_feed_updates()
        time.sleep(2)  # Wait for update cycle
        
        # Verify thread is still running despite error
        self.assertTrue(self.intel.running)
        self.assertTrue(self.intel.update_thread.is_alive())

if __name__ == '__main__':
    unittest.main()
