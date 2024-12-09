"""
Advanced Network Detection and Device Monitoring System
Integrates active and passive scanning with real-time monitoring
"""
import logging
import json
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import uuid
import nmap
import scapy.all as scapy
from scapy.layers.l2 import ARP, Ether
from netaddr import IPNetwork, IPAddress
import netifaces
from .core import BaseMonitor
from ..core.utils import encrypt_data, decrypt_data
from ..core.database import Database

@dataclass
class NetworkDevice:
    """Represents a detected network device."""
    id: str
    ip_address: str
    mac_address: str
    hostname: Optional[str]
    vendor: Optional[str]
    device_type: str
    open_ports: List[int]
    services: Dict[int, str]
    first_seen: datetime
    last_seen: datetime
    status: str
    risk_score: float
    vulnerabilities: List[Dict]

@dataclass
class NetworkTopology:
    """Represents network topology information."""
    devices: List[NetworkDevice]
    connections: List[Tuple[str, str]]  # (source_id, target_id)
    subnets: List[str]
    gateways: List[str]
    timestamp: datetime

class NetworkDetection(BaseMonitor):
    """Advanced network detection and monitoring system."""
    
    def __init__(self, config_path: str = None):
        super().__init__(config_path)
        self.logger = logging.getLogger(__name__)
        self.db = Database()
        self.nmap = nmap.PortScanner()
        self._initialize_detection()
        
    def _initialize_detection(self) -> None:
        """Initialize network detection components."""
        try:
            # Initialize network interfaces
            self.interfaces = netifaces.interfaces()
            
            # Start passive scanning
            self._start_passive_scanning()
            
            # Initialize device tracking
            self._initialize_device_tracking()
            
        except Exception as e:
            self.logger.error(f"Error initializing network detection: {str(e)}")
            
    def active_scan_network(self, target_range: str) -> List[NetworkDevice]:
        """Perform active network scan using nmap."""
        try:
            devices = []
            
            # Perform comprehensive nmap scan
            self.nmap.scan(hosts=target_range, arguments='-sS -sV -O -A')
            
            for host in self.nmap.all_hosts():
                device = self._process_nmap_host(host)
                if device:
                    devices.append(device)
                    self._update_device_database(device)
            
            return devices
            
        except Exception as e:
            self.logger.error(f"Error during active network scan: {str(e)}")
            return []
            
    def passive_network_monitoring(self) -> List[NetworkDevice]:
        """Perform passive network monitoring using packet capture."""
        try:
            devices = []
            
            # Capture and analyze network traffic
            packets = scapy.sniff(timeout=60)
            
            for packet in packets:
                if ARP in packet:
                    device = self._process_arp_packet(packet)
                    if device:
                        devices.append(device)
                        self._update_device_database(device)
            
            return devices
            
        except Exception as e:
            self.logger.error(f"Error during passive monitoring: {str(e)}")
            return []
            
    def map_network_topology(self) -> NetworkTopology:
        """Generate network topology map."""
        try:
            # Get all known devices
            devices = self._get_all_devices()
            
            # Map connections between devices
            connections = self._map_device_connections()
            
            # Identify subnets and gateways
            subnets = self._identify_subnets()
            gateways = self._identify_gateways()
            
            topology = NetworkTopology(
                devices=devices,
                connections=connections,
                subnets=subnets,
                gateways=gateways,
                timestamp=datetime.now()
            )
            
            return topology
            
        except Exception as e:
            self.logger.error(f"Error mapping network topology: {str(e)}")
            return None
            
    def detect_unauthorized_devices(self) -> List[NetworkDevice]:
        """Detect unauthorized or suspicious devices."""
        try:
            unauthorized = []
            
            # Get all current devices
            current_devices = self._get_all_devices()
            
            for device in current_devices:
                if self._is_unauthorized(device):
                    unauthorized.append(device)
                    self._trigger_alert(device, "Unauthorized Device Detected")
            
            return unauthorized
            
        except Exception as e:
            self.logger.error(f"Error detecting unauthorized devices: {str(e)}")
            return []
            
    def analyze_device_behavior(self, device: NetworkDevice) -> Dict:
        """Analyze device behavior for anomalies."""
        try:
            analysis = {
                'device_id': device.id,
                'timestamp': datetime.now(),
                'traffic_patterns': self._analyze_traffic_patterns(device),
                'port_usage': self._analyze_port_usage(device),
                'connection_attempts': self._analyze_connections(device),
                'protocol_analysis': self._analyze_protocols(device),
                'risk_assessment': self._assess_device_risk(device)
            }
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error analyzing device behavior: {str(e)}")
            return {}
            
    def generate_network_report(self) -> Dict:
        """Generate comprehensive network analysis report."""
        try:
            report = {
                'timestamp': datetime.now(),
                'topology': self.map_network_topology(),
                'device_inventory': self._get_device_inventory(),
                'security_posture': self._assess_network_security(),
                'vulnerabilities': self._scan_network_vulnerabilities(),
                'recommendations': self._generate_security_recommendations(),
                'compliance_status': self._check_compliance_status()
            }
            
            return report
            
        except Exception as e:
            self.logger.error(f"Error generating network report: {str(e)}")
            return {}
            
    def _process_nmap_host(self, host: str) -> NetworkDevice:
        """Process nmap scan results for a host."""
        try:
            host_info = self.nmap[host]
            
            device = NetworkDevice(
                id=str(uuid.uuid4()),
                ip_address=host,
                mac_address=self._get_mac_address(host),
                hostname=host_info.hostname() if 'hostname' in dir(host_info) else None,
                vendor=self._get_vendor_info(host),
                device_type=self._determine_device_type(host_info),
                open_ports=list(host_info.all_tcp()),
                services=self._get_services(host_info),
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                status='active',
                risk_score=self._calculate_risk_score(host_info),
                vulnerabilities=self._check_vulnerabilities(host_info)
            )
            
            return device
            
        except Exception as e:
            self.logger.error(f"Error processing nmap host: {str(e)}")
            return None
            
    def _assess_network_security(self) -> Dict:
        """Assess overall network security posture."""
        try:
            assessment = {
                'risk_level': self._calculate_network_risk(),
                'vulnerable_devices': self._identify_vulnerable_devices(),
                'security_gaps': self._identify_security_gaps(),
                'mitigation_strategies': self._generate_mitigation_strategies(),
                'compliance_issues': self._check_compliance_issues()
            }
            
            return assessment
            
        except Exception as e:
            self.logger.error(f"Error assessing network security: {str(e)}")
            return {}
            
    def get_network_dashboard(self) -> Dict:
        """Get network monitoring dashboard data."""
        try:
            dashboard = {
                'active_devices': self._get_active_devices(),
                'network_topology': self.map_network_topology(),
                'security_alerts': self._get_security_alerts(),
                'performance_metrics': self._get_network_metrics(),
                'threat_indicators': self._get_threat_indicators(),
                'compliance_status': self._get_compliance_status()
            }
            
            return dashboard
            
        except Exception as e:
            self.logger.error(f"Error getting network dashboard: {str(e)}")
            return {}
