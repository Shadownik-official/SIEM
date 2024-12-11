import platform
import os
import sys
import logging
import threading
import queue
import time
import json
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Any
import psutil
import wmi  # for Windows
import distro  # for Linux
from datetime import datetime, timedelta
import pythoncom  # for Windows COM interfaces

from ..core.utils import SecurityUtils, SystemUtils, DataProcessor
from ..core.config import SIEMConfig
from ..models import EventLog
from ..intelligence.threat_intelligence import ThreatIntelligenceEnhanced

class UniversalAgent:
    def __init__(self, config: Optional[SIEMConfig] = None):
        """
        Initialize Universal Agent with enhanced capabilities
        
        :param config: SIEM configuration object
        """
        self.agent_id = str(uuid.uuid4())
        self.platform = platform.system().lower()
        
        # Use provided config or load default
        self.config = config or SIEMConfig()
        
        # Configure logging
        self.logger = logging.getLogger(__name__)
        self.logger.info(f"Initializing Universal Agent: {self.agent_id}")
        
        # Threat Intelligence Integration
        self.threat_intelligence = ThreatIntelligenceEnhanced(self.config)
        
        # Initialize collectors and other components
        self.collectors = self._init_collectors()
        
        # Agent state management
        self.running = False
        self.event_queue = queue.Queue(maxsize=self.config.max_queue_size)
        
        # Thread pool for parallel processing
        self.executor = ThreadPoolExecutor(
            max_workers=min(8, os.cpu_count() or 1)
        )
        
        # Collection interval from config
        self.collection_interval = self.config.agent_collection_interval
        
        # Performance tracking
        self.performance_metrics = {
            'total_events_collected': 0,
            'total_events_processed': 0,
            'last_collection_duration': 0,
            'start_time': datetime.utcnow()
        }
    
    def _init_collectors(self) -> List[str]:
        """
        Initialize system collectors based on platform
        
        :return: List of active collectors
        """
        default_collectors = ['system_logs', 'network_traffic', 'process_monitor']
        
        platform_specific_collectors = {
            'windows': ['windows_event_logs', 'windows_registry'],
            'linux': ['syslog', 'kernel_logs'],
            'darwin': ['macos_logs', 'system_profiler']
        }
        
        collectors = default_collectors + platform_specific_collectors.get(self.platform, [])
        self.logger.info(f"Initialized collectors: {collectors}")
        return collectors
    
    def _collect_system_metrics(self) -> Dict[str, Any]:
        """
        Collect comprehensive system metrics
        
        :return: Dictionary of system metrics
        """
        try:
            system_info = SystemUtils.get_system_info()
            
            # Extend system info with additional metrics
            system_info.update({
                'network_interfaces': self._get_network_interfaces(),
                'running_processes': self._get_running_processes(),
                'logged_in_users': self._get_logged_in_users()
            })
            
            return system_info
        except Exception as e:
            self.logger.error(f"Error collecting system metrics: {e}")
            return {}
    
    def _get_network_interfaces(self) -> List[Dict[str, Any]]:
        """
        Get detailed network interface information
        
        :return: List of network interface details
        """
        try:
            interfaces = []
            for interface, addrs in psutil.net_if_addrs().items():
                interface_info = {
                    'name': interface,
                    'addresses': [
                        {'family': addr.family, 'address': addr.address} 
                        for addr in addrs
                    ]
                }
                interfaces.append(interface_info)
            return interfaces
        except Exception as e:
            self.logger.warning(f"Could not retrieve network interfaces: {e}")
            return []
    
    def _get_running_processes(self) -> List[Dict[str, Any]]:
        """
        Get list of running processes with key details
        
        :return: List of process details
        """
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'username', 'status']):
                try:
                    process_info = {
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'username': proc.info['username'],
                        'status': proc.info['status']
                    }
                    processes.append(process_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            return processes
        except Exception as e:
            self.logger.warning(f"Could not retrieve running processes: {e}")
            return []
    
    def _get_logged_in_users(self) -> List[str]:
        """
        Get list of currently logged-in users
        
        :return: List of usernames
        """
        try:
            return list(set(user.name for user in psutil.users()))
        except Exception as e:
            self.logger.warning(f"Could not retrieve logged-in users: {e}")
            return []
    
    def _process_event(self, event_data: Dict[str, Any]) -> bool:
        """
        Process and analyze collected event
        
        :param event_data: Event data dictionary
        :return: Whether event was successfully processed
        """
        try:
            # Sanitize input
            sanitized_event = {
                k: DataProcessor.sanitize_input(str(v)) 
                for k, v in event_data.items()
            }
            
            # Encrypt sensitive data
            key, _ = SecurityUtils.generate_encryption_key(self.agent_id)
            encrypted_event = SecurityUtils.encrypt_data(sanitized_event, key)
            
            # Threat intelligence analysis
            threat_score = self.threat_intelligence.analyze_event(sanitized_event)
            
            # Create event log
            event_log = {
                'source_ip': sanitized_event.get('source_ip', ''),
                'destination_ip': sanitized_event.get('destination_ip', ''),
                'event_type': sanitized_event.get('type', 'unknown'),
                'severity': threat_score,
                'details': encrypted_event
            }
            
            # Log event
            with self.database.get_session() as session:
                EventLog.log_event(session, event_log)
            
            self.performance_metrics['total_events_processed'] += 1
            return True
        
        except Exception as e:
            self.logger.error(f"Event processing error: {e}")
            return False
    
    def collect_events(self) -> List[Dict[str, Any]]:
        """
        Collect events from various system sources
        
        :return: List of collected events
        """
        events = []
        
        # Parallel event collection
        with ThreadPoolExecutor(max_workers=len(self.collectors)) as executor:
            futures = {
                executor.submit(self._collect_events_from_source, source): source 
                for source in self.collectors
            }
            
            for future in as_completed(futures):
                source = futures[future]
                try:
                    source_events = future.result()
                    events.extend(source_events)
                except Exception as e:
                    self.logger.error(f"Error collecting events from {source}: {e}")
        
        return events
    
    def _collect_events_from_source(self, source: str) -> List[Dict[str, Any]]:
        """
        Collect events from a specific source
        
        :param source: Event source name
        :return: List of events from the source
        """
        try:
            # Placeholder for source-specific event collection
            if source == 'system_logs':
                return self._collect_system_logs()
            elif source == 'network_traffic':
                return self._collect_network_traffic()
            elif source == 'process_monitor':
                return self._collect_process_events()
            # Add more source-specific collectors
            return []
        except Exception as e:
            self.logger.error(f"Error in {source} event collection: {e}")
            return []
    
    def _collect_system_logs(self) -> List[Dict[str, Any]]:
        """
        Collect system logs
        
        :return: List of system log events
        """
        # Platform-specific log collection
        if self.platform == 'windows':
            return self._collect_windows_logs()
        elif self.platform == 'linux':
            return self._collect_linux_logs()
        elif self.platform == 'darwin':
            return self._collect_macos_logs()
        return []
    
    def _collect_windows_logs(self) -> List[Dict[str, Any]]:
        """
        Collect Windows system logs
        
        :return: List of Windows log events
        """
        try:
            pythoncom.CoInitialize()  # Initialize COM for threading
            w = wmi.WMI()
            
            # Collect system event logs
            events = []
            for log in w.Win32_NTLogEvent(EventCode='!0'):
                event = {
                    'type': 'windows_system_log',
                    'source': log.SourceName,
                    'event_code': log.EventCode,
                    'message': log.Message,
                    'timestamp': log.TimeGenerated
                }
                events.append(event)
            
            return events
        except Exception as e:
            self.logger.error(f"Windows log collection error: {e}")
            return []
        finally:
            pythoncom.CoUninitialize()
    
    def _collect_linux_logs(self) -> List[Dict[str, Any]]:
        """
        Collect Linux system logs
        
        :return: List of Linux log events
        """
        try:
            # Placeholder for Linux log collection
            # Typically would use journalctl or parse /var/log files
            return []
        except Exception as e:
            self.logger.error(f"Linux log collection error: {e}")
            return []
    
    def _collect_macos_logs(self) -> List[Dict[str, Any]]:
        """
        Collect macOS system logs
        
        :return: List of macOS log events
        """
        try:
            # Placeholder for macOS log collection
            # Would use log show or parse system logs
            return []
        except Exception as e:
            self.logger.error(f"macOS log collection error: {e}")
            return []
    
    def _collect_network_traffic(self) -> List[Dict[str, Any]]:
        """
        Collect network traffic events
        
        :return: List of network traffic events
        """
        try:
            # Use psutil or platform-specific tools to collect network connections
            connections = psutil.net_connections()
            events = []
            
            for conn in connections:
                event = {
                    'type': 'network_connection',
                    'source_ip': conn.laddr.ip,
                    'source_port': conn.laddr.port,
                    'destination_ip': conn.raddr.ip if conn.raddr else '',
                    'destination_port': conn.raddr.port if conn.raddr else 0,
                    'protocol': conn.type,
                    'status': conn.status
                }
                events.append(event)
            
            return events
        except Exception as e:
            self.logger.error(f"Network traffic collection error: {e}")
            return []
    
    def _collect_process_events(self) -> List[Dict[str, Any]]:
        """
        Collect process-related events
        
        :return: List of process events
        """
        try:
            # Collect process creation, termination events
            events = []
            for proc in psutil.process_iter(['pid', 'name', 'create_time', 'status']):
                try:
                    event = {
                        'type': 'process_event',
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'create_time': proc.info['create_time'],
                        'status': proc.info['status']
                    }
                    events.append(event)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            return events
        except Exception as e:
            self.logger.error(f"Process event collection error: {e}")
            return []
    
    def run(self):
        """
        Main agent run method with enhanced event processing
        """
        self.running = True
        self.logger.info(f"Universal Agent {self.agent_id} started")
        
        try:
            while self.running:
                start_time = time.time()
                
                # Collect system metrics
                system_metrics = self._collect_system_metrics()
                
                # Collect events
                events = self.collect_events()
                
                # Process events
                for event in events:
                    try:
                        self._process_event(event)
                    except Exception as e:
                        self.logger.error(f"Event processing error: {e}")
                
                # Update performance metrics
                collection_duration = time.time() - start_time
                self.performance_metrics.update({
                    'total_events_collected': len(events),
                    'last_collection_duration': collection_duration
                })
                
                # Sleep for configured interval
                time.sleep(self.collection_interval)
        
        except Exception as e:
            self.logger.critical(f"Agent runtime error: {e}")
        
        finally:
            self.shutdown()
    
    def shutdown(self):
        """
        Graceful agent shutdown
        """
        self.running = False
        self.executor.shutdown(wait=True)
        
        # Log final performance metrics
        self.logger.info(f"Agent {self.agent_id} Performance Metrics:")
        for metric, value in self.performance_metrics.items():
            self.logger.info(f"{metric}: {value}")
        
        self.logger.info("Universal Agent shutdown complete")
