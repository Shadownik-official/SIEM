"""
Universal Cross-Platform SIEM Agent
Supports Windows, Linux, macOS, and IoT devices
"""
import platform
import os
import sys
import logging
import threading
import queue
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional
import psutil
import wmi  # for Windows
import distro  # for Linux
from datetime import datetime
from ..core.utils import encrypt_data
from ..core.config import AgentConfig

class UniversalAgent:
    def __init__(self, config: Dict = None):
        self.platform = platform.system().lower()
        self.config = config or AgentConfig().load()
        self.logger = logging.getLogger(__name__)
        self.collectors = self._init_collectors()
        self.running = False
        self.event_queue = queue.Queue()
        self.executor = ThreadPoolExecutor(max_workers=4)
        self.collection_interval = self.config.get('collection_interval', 60)
        
    def shutdown(self):
        """Gracefully shutdown the agent"""
        self.logger.info("Shutting down agent...")
        self.running = False
        self.executor.shutdown(wait=True)
        self.logger.info("Agent shutdown complete")

    def _init_collectors(self) -> Dict:
        """Initialize platform-specific collectors"""
        collectors = {
            'syslog': self._collect_syslog,
            'eventlog': self._collect_eventlog,
            'security': self._collect_security_events,
            'network': self._collect_network_events,
            'process': self._collect_process_events,
            'file': self._collect_file_events
        }
        
        if self.platform == 'windows':
            try:
                self.wmi = wmi.WMI()
            except Exception as e:
                self.logger.error(f"Failed to initialize WMI: {str(e)}")
                self.wmi = None
        return collectors

    def start_monitoring(self):
        """Start continuous monitoring"""
        self.logger.info(f"Starting agent on {self.platform} platform")
        self.running = True
        
        # Start collector threads
        collector_threads = []
        for collector_name, collector_func in self.collectors.items():
            if self.config.get('collectors', {}).get(collector_name, True):
                thread = threading.Thread(
                    target=self._collector_thread,
                    args=(collector_name, collector_func),
                    daemon=True
                )
                thread.start()
                collector_threads.append(thread)
        
        # Start event processor
        processor_thread = threading.Thread(
            target=self._event_processor,
            daemon=True
        )
        processor_thread.start()
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.shutdown()
            
    def _collector_thread(self, name: str, collector_func):
        """Run collector in a separate thread"""
        while self.running:
            try:
                events = collector_func()
                if events:
                    for event in events:
                        event['collector'] = name
                        event['timestamp'] = datetime.now().isoformat()
                        self.event_queue.put(event)
            except Exception as e:
                self.logger.error(f"Error in collector {name}: {str(e)}")
            time.sleep(self.collection_interval)
            
    def _event_processor(self):
        """Process events from the queue"""
        while self.running:
            try:
                events = []
                while not self.event_queue.empty() and len(events) < 100:
                    events.append(self.event_queue.get_nowait())
                
                if events:
                    self._process_and_forward_events(events)
            except Exception as e:
                self.logger.error(f"Error processing events: {str(e)}")
            time.sleep(1)

    def collect_all_events(self) -> List[Dict]:
        """Collect all relevant events based on platform"""
        events = []
        for collector in self.collectors.values():
            try:
                events.extend(collector())
            except Exception as e:
                self.logger.error(f"Collection error: {str(e)}")
        return events

    def _collect_syslog(self) -> List[Dict]:
        """Collect system logs"""
        if self.platform in ['linux', 'darwin']:
            # Implementation for Linux/MacOS syslog
            pass
        return []

    def _collect_eventlog(self) -> List[Dict]:
        """Collect Windows Event Logs"""
        if self.platform == 'windows':
            # Windows Event Log collection
            pass
        return []

    def _collect_security_events(self) -> List[Dict]:
        """Collect security-specific events"""
        events = []
        if self.platform == 'windows':
            # Windows Security Events
            security_events = self.wmi.Win32_NTLogEvent(LogFile='Security')
            for event in security_events:
                events.append({
                    'EventCode': event.EventCode,
                    'SourceName': event.SourceName,
                    'TimeGenerated': str(event.TimeGenerated),
                    'Message': event.Message
                })
        else:
            # Linux/MacOS Security Events
            auth_log = '/var/log/auth.log'
            if os.path.exists(auth_log):
                # Parse auth.log
                pass
        return events

    def _collect_network_events(self) -> List[Dict]:
        """Collect network-related events"""
        events = []
        net_connections = psutil.net_connections()
        for conn in net_connections:
            events.append({
                'local_address': conn.laddr,
                'remote_address': conn.raddr,
                'status': conn.status,
                'pid': conn.pid
            })
        return events

    def _collect_process_events(self) -> List[Dict]:
        """Collect process-related events"""
        events = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
            events.append(proc.info)
        return events

    def _collect_file_events(self) -> List[Dict]:
        """Monitor file system events"""
        # Implement using watchdog for cross-platform file system monitoring
        return []

    def _process_and_forward_events(self, events: List[Dict]):
        """Process and forward events to SIEM server"""
        if events:
            encrypted_events = encrypt_data(events)
            # Forward to SIEM server
            pass
