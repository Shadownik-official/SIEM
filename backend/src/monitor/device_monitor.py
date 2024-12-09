"""
Advanced Device Monitoring System for Enterprise SIEM
"""
import logging
import json
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime
import uuid
import psutil
import wmi
import winreg
from .core import BaseMonitor
from ..core.utils import encrypt_data, decrypt_data
from ..core.database import Database

@dataclass
class Device:
    """Represents a monitored device."""
    id: str
    hostname: str
    ip_address: str
    mac_address: str
    type: str
    os: str
    version: str
    status: str
    last_seen: datetime
    services: List[str]
    vulnerabilities: List[str]
    
@dataclass
class DeviceMetrics:
    """Represents device performance metrics."""
    device_id: str
    timestamp: datetime
    cpu_usage: float
    memory_usage: float
    disk_usage: Dict
    network_usage: Dict
    process_count: int
    service_status: Dict
    
class DeviceMonitor(BaseMonitor):
    """Advanced device monitoring system with comprehensive metrics."""
    
    def __init__(self, config_path: str = None):
        super().__init__(config_path)
        self.logger = logging.getLogger(__name__)
        self.db = Database()
        self.wmi = wmi.WMI()
        self._initialize_monitoring()
        
    def _initialize_monitoring(self) -> None:
        """Initialize device monitoring."""
        try:
            # Set up WMI connections
            self.wmi_os = self.wmi.Win32_OperatingSystem()[0]
            self.wmi_cpu = self.wmi.Win32_Processor()[0]
            self.wmi_memory = self.wmi.Win32_PhysicalMemory()
            self.wmi_network = self.wmi.Win32_NetworkAdapter()
            
            # Initialize performance counters
            self._initialize_counters()
            
        except Exception as e:
            self.logger.error(f"Error initializing monitoring: {str(e)}")
            
    def discover_devices(self) -> List[Device]:
        """Discover devices in the network."""
        try:
            devices = []
            
            # Discover using multiple methods
            devices.extend(self._discover_network_devices())
            devices.extend(self._discover_usb_devices())
            devices.extend(self._discover_bluetooth_devices())
            
            # Update device database
            self._update_device_database(devices)
            
            return devices
            
        except Exception as e:
            self.logger.error(f"Error discovering devices: {str(e)}")
            return []
            
    def monitor_device(self, device: Device) -> DeviceMetrics:
        """Monitor a device and collect metrics."""
        try:
            metrics = DeviceMetrics(
                device_id=device.id,
                timestamp=datetime.now(),
                cpu_usage=self._get_cpu_usage(device),
                memory_usage=self._get_memory_usage(device),
                disk_usage=self._get_disk_usage(device),
                network_usage=self._get_network_usage(device),
                process_count=self._get_process_count(device),
                service_status=self._get_service_status(device)
            )
            
            # Store metrics
            self._store_metrics(metrics)
            
            return metrics
            
        except Exception as e:
            self.logger.error(f"Error monitoring device: {str(e)}")
            return None
            
    def _get_cpu_usage(self, device: Device) -> float:
        """Get CPU usage metrics."""
        try:
            if device.type == 'windows':
                return psutil.cpu_percent(interval=1)
            elif device.type == 'linux':
                return self._get_linux_cpu_usage(device)
            elif device.type == 'mac':
                return self._get_mac_cpu_usage(device)
                
        except Exception as e:
            self.logger.error(f"Error getting CPU usage: {str(e)}")
            return 0.0
            
    def _get_memory_usage(self, device: Device) -> float:
        """Get memory usage metrics."""
        try:
            if device.type == 'windows':
                memory = psutil.virtual_memory()
                return memory.percent
            elif device.type == 'linux':
                return self._get_linux_memory_usage(device)
            elif device.type == 'mac':
                return self._get_mac_memory_usage(device)
                
        except Exception as e:
            self.logger.error(f"Error getting memory usage: {str(e)}")
            return 0.0
            
    def analyze_device_health(self, device: Device, metrics: List[DeviceMetrics]) -> Dict:
        """Analyze device health based on metrics."""
        try:
            analysis = {
                'device_id': device.id,
                'timestamp': datetime.now(),
                'health_score': self._calculate_health_score(metrics),
                'performance_issues': self._identify_performance_issues(metrics),
                'security_issues': self._identify_security_issues(device),
                'recommendations': self._generate_recommendations(device, metrics)
            }
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error analyzing device health: {str(e)}")
            return {}
            
    def _calculate_health_score(self, metrics: List[DeviceMetrics]) -> float:
        """Calculate device health score."""
        try:
            scores = []
            
            # CPU health
            cpu_score = self._calculate_cpu_health(metrics)
            scores.append(cpu_score)
            
            # Memory health
            memory_score = self._calculate_memory_health(metrics)
            scores.append(memory_score)
            
            # Disk health
            disk_score = self._calculate_disk_health(metrics)
            scores.append(disk_score)
            
            # Network health
            network_score = self._calculate_network_health(metrics)
            scores.append(network_score)
            
            # Calculate overall score
            return sum(scores) / len(scores)
            
        except Exception as e:
            self.logger.error(f"Error calculating health score: {str(e)}")
            return 0.0
            
    def monitor_device_changes(self, device: Device) -> Dict:
        """Monitor device configuration changes."""
        try:
            changes = {
                'device_id': device.id,
                'timestamp': datetime.now(),
                'registry_changes': self._monitor_registry_changes(device),
                'file_changes': self._monitor_file_changes(device),
                'service_changes': self._monitor_service_changes(device),
                'software_changes': self._monitor_software_changes(device),
                'hardware_changes': self._monitor_hardware_changes(device)
            }
            
            return changes
            
        except Exception as e:
            self.logger.error(f"Error monitoring changes: {str(e)}")
            return {}
            
    def generate_device_report(self, device: Device, metrics: List[DeviceMetrics], changes: Dict) -> Dict:
        """Generate comprehensive device report."""
        try:
            report = {
                'device_info': self._format_device_info(device),
                'health_analysis': self._analyze_device_health(device, metrics),
                'performance_metrics': self._summarize_metrics(metrics),
                'configuration_changes': self._summarize_changes(changes),
                'security_posture': self._assess_security_posture(device),
                'recommendations': self._generate_device_recommendations(device, metrics, changes)
            }
            
            return report
            
        except Exception as e:
            self.logger.error(f"Error generating report: {str(e)}")
            return {}
            
    def get_device_dashboard(self) -> Dict:
        """Get device monitoring dashboard data."""
        try:
            dashboard = {
                'total_devices': self._get_total_devices(),
                'device_status': self._get_device_status(),
                'performance_metrics': self._get_performance_metrics(),
                'health_overview': self._get_health_overview(),
                'recent_changes': self._get_recent_changes(),
                'alerts': self._get_device_alerts()
            }
            
            return dashboard
            
        except Exception as e:
            self.logger.error(f"Error getting dashboard: {str(e)}")
            return {}
