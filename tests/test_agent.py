"""
Test suite for the Universal Cross-Platform SIEM Agent
"""
import unittest
import platform
import os
from unittest.mock import Mock, patch
from src.agents.cross_platform_agent import UniversalAgent

class TestUniversalAgent(unittest.TestCase):
    def setUp(self):
        """Set up test environment"""
        self.test_config = {
            'log_level': 'DEBUG',
            'collection_interval': 60,
            'server_endpoint': 'https://siem-server.test',
            'encryption_key': 'test-key'
        }
        self.agent = UniversalAgent(config=self.test_config)

    @patch('platform.system')
    def test_agent_initialization(self, mock_platform):
        """Test agent initialization across different platforms"""
        # Test Windows
        mock_platform.return_value = 'Windows'
        agent = UniversalAgent(config=self.test_config)
        self.assertEqual(agent.platform, 'windows')
        self.assertIn('eventlog', agent.collectors)

        # Test Linux
        mock_platform.return_value = 'Linux'
        agent = UniversalAgent(config=self.test_config)
        self.assertEqual(agent.platform, 'linux')
        self.assertIn('syslog', agent.collectors)

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

if __name__ == '__main__':
    unittest.main()
