"""
Test suite for the Universal Cross-Platform SIEM Agent
"""
import unittest
import platform
import os
import threading
import queue
import time
from unittest.mock import Mock, patch, MagicMock
from src.agents.cross_platform_agent import UniversalAgent

class TestUniversalAgent(unittest.TestCase):
    def setUp(self):
        """Set up test environment"""
        self.test_config = {
            'log_level': 'DEBUG',
            'collection_interval': 1,  # Short interval for testing
            'server_endpoint': 'https://siem-server.test',
            'encryption_key': 'test-key',
            'collectors': {
                'syslog': True,
                'eventlog': True,
                'security': True,
                'network': True,
                'process': True,
                'file': True
            }
        }
        self.agent = UniversalAgent(config=self.test_config)

    def tearDown(self):
        """Clean up after tests"""
        if hasattr(self, 'agent'):
            self.agent.shutdown()

    @patch('platform.system')
    def test_agent_initialization(self, mock_platform):
        """Test agent initialization across different platforms"""
        # Test Windows
        mock_platform.return_value = 'Windows'
        agent = UniversalAgent(config=self.test_config)
        self.assertEqual(agent.platform, 'windows')
        self.assertIn('eventlog', agent.collectors)
        self.assertIsNotNone(agent.event_queue)
        self.assertIsNotNone(agent.executor)

        # Test Linux
        mock_platform.return_value = 'Linux'
        agent = UniversalAgent(config=self.test_config)
        self.assertEqual(agent.platform, 'linux')
        self.assertIn('syslog', agent.collectors)

    def test_shutdown(self):
        """Test agent shutdown"""
        self.agent.running = True
        self.agent.shutdown()
        self.assertFalse(self.agent.running)
        
    @patch('threading.Thread')
    def test_start_monitoring(self, mock_thread):
        """Test monitoring startup"""
        self.agent.start_monitoring()
        # Verify collector threads started
        expected_calls = len([c for c, enabled in 
                            self.test_config['collectors'].items() 
                            if enabled])
        # Add 1 for event processor thread
        self.assertEqual(mock_thread.call_count, expected_calls + 1)

    @patch('psutil.net_connections')
    def test_network_event_collection(self, mock_net_conn):
        """Test network event collection"""
        mock_connection = Mock()
        mock_connection.laddr = ('127.0.0.1', 8080)
        mock_connection.raddr = ('192.168.1.1', 443)
        mock_connection.status = 'ESTABLISHED'
        mock_connection.pid = 1234
        
        mock_net_conn.return_value = [mock_connection]
        
        events = self.agent._collect_network_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['local_address'], ('127.0.0.1', 8080))
        self.assertEqual(events[0]['status'], 'ESTABLISHED')

    @patch('psutil.process_iter')
    def test_process_event_collection(self, mock_process):
        """Test process event collection"""
        mock_process.return_value = [
            Mock(info={
                'pid': 1,
                'name': 'test_process',
                'username': 'test_user',
                'cmdline': ['test', '-arg']
            })
        ]
        
        events = self.agent._collect_process_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['name'], 'test_process')
        self.assertEqual(events[0]['username'], 'test_user')

    def test_event_queue_processing(self):
        """Test event queue processing"""
        test_events = [
            {'type': 'test1', 'data': 'data1'},
            {'type': 'test2', 'data': 'data2'}
        ]
        
        # Add events to queue
        for event in test_events:
            self.agent.event_queue.put(event)
        
        # Mock process_and_forward_events
        self.agent._process_and_forward_events = MagicMock()
        
        # Run event processor once
        self.agent.running = True
        self.agent._event_processor()
        
        # Verify events were processed
        self.agent._process_and_forward_events.assert_called_once()
        processed_events = self.agent._process_and_forward_events.call_args[0][0]
        self.assertEqual(len(processed_events), 2)

    def test_collector_thread(self):
        """Test collector thread operation"""
        mock_collector = MagicMock(return_value=[{'type': 'test', 'data': 'test_data'}])
        
        # Start collector thread
        self.agent.running = True
        thread = threading.Thread(
            target=self.agent._collector_thread,
            args=('test_collector', mock_collector)
        )
        thread.daemon = True
        thread.start()
        
        # Wait for collection
        time.sleep(2)
        
        # Verify event was collected
        self.assertFalse(self.agent.event_queue.empty())
        event = self.agent.event_queue.get()
        self.assertEqual(event['type'], 'test')
        self.assertEqual(event['collector'], 'test_collector')
        self.assertIn('timestamp', event)

    def test_event_encryption(self):
        """Test event encryption before transmission"""
        test_event = {'type': 'test', 'data': 'sensitive'}
        with patch('src.core.utils.encrypt_data') as mock_encrypt:
            mock_encrypt.return_value = b'encrypted_data'
            self.agent._process_and_forward_events([test_event])
            mock_encrypt.assert_called_once()

    @patch('logging.Logger.error')
    def test_error_handling(self, mock_logger):
        """Test error handling during event collection"""
        def raise_error():
            raise Exception("Test error")
        
        self.agent.collectors['test'] = raise_error
        events = self.agent.collect_all_events()
        mock_logger.assert_called_with("Collection error: Test error")

    def test_collection_interval(self):
        """Test collection interval configuration"""
        # Test default interval
        agent = UniversalAgent({})
        self.assertEqual(agent.collection_interval, 60)
        
        # Test custom interval
        agent = UniversalAgent({'collection_interval': 30})
        self.assertEqual(agent.collection_interval, 30)

if __name__ == '__main__':
    unittest.main()
