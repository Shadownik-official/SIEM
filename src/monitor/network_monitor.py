"""
Advanced Network Monitoring Engine for Enterprise SIEM
"""
import logging
import json
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime
import uuid
import pyshark
import nmap
import netifaces
from scapy.all import *
from .core import BaseMonitor
from ..core.utils import encrypt_data, decrypt_data
from ..core.database import Database
import threading
import time
from netaddr import IPNetwork, IPAddress

@dataclass
class NetworkDevice:
    """Represents a detected network device."""
    id: str
    mac_address: str
    ip_address: Optional[str]
    hostname: Optional[str]
    device_type: str
    vendor: Optional[str]
    first_seen: datetime
    last_seen: datetime
    ports: List[Dict]
    services: List[Dict]
    os_info: Optional[Dict]
    status: str
    risk_score: float
    tags: List[str]

@dataclass
class NetworkActivity:
    """Represents network activity."""
    id: str
    timestamp: datetime
    source_ip: str
    destination_ip: str
    protocol: str
    source_port: int
    destination_port: int
    bytes_sent: int
    bytes_received: int
    duration: float
    flags: Dict
    payload_type: Optional[str]
    risk_score: float

@dataclass
class NetworkFlow:
    """Represents a network traffic flow."""
    id: str
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    bytes_sent: int
    bytes_received: int
    start_time: datetime
    end_time: datetime
    status: str

class NetworkMonitor(BaseMonitor):
    """Advanced network monitoring engine with active and passive capabilities."""
    
    def __init__(self, config_path: str = None):
        super().__init__(config_path)
        self.logger = logging.getLogger(__name__)
        self.db = Database()
        self.nm = nmap.PortScanner()
        self.capture = None
        self.known_devices = self._load_known_devices()
        self.detection_rules = self._load_detection_rules()
        self.behavior_thread = None
        self.device_inventory = {}
        self.flow_cache = {}
        
    def start_monitoring(self, interface: str = None) -> None:
        """Start network monitoring."""
        try:
            if not interface:
                interface = self._get_default_interface()
                
            # Start packet capture
            self.capture = pyshark.LiveCapture(interface=interface)
            
            # Start monitoring threads
            self._start_passive_monitoring()
            self._start_active_scanning()
            self._start_service_detection()
            self._start_behavioral_analysis()
            
            self.logger.info(f"Network monitoring started on interface {interface}")
            
        except Exception as e:
            self.logger.error(f"Error starting network monitoring: {str(e)}")
            
    def stop_monitoring(self) -> None:
        """Stop network monitoring."""
        try:
            if self.capture:
                self.capture.close()
                
            # Stop monitoring threads
            self._stop_monitoring_threads()
            
            self.logger.info("Network monitoring stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping network monitoring: {str(e)}")
            
    def _start_passive_monitoring(self) -> None:
        """Start passive network monitoring."""
        try:
            def packet_callback(packet):
                try:
                    # Process packet
                    activity = self._process_packet(packet)
                    
                    # Check for threats
                    if activity:
                        self._check_activity_threats(activity)
                        
                    # Store activity
                    self._store_activity(activity)
                    
                except Exception as e:
                    self.logger.error(f"Error processing packet: {str(e)}")
                    
            # Start capture with callback
            self.capture.apply_on_packets(packet_callback)
            
        except Exception as e:
            self.logger.error(f"Error in passive monitoring: {str(e)}")
            
    def _start_active_scanning(self) -> None:
        """Start active network scanning."""
        try:
            while not self.stop_flag.is_set():
                # Scan network for devices
                devices = self._scan_network()
                
                # Process discovered devices
                for device in devices:
                    self._process_device(device)
                    
                # Wait for next scan interval
                time.sleep(self.config['scan_interval'])
                
        except Exception as e:
            self.logger.error(f"Error in active scanning: {str(e)}")
            
    def _scan_network(self) -> List[NetworkDevice]:
        """Perform network scan."""
        devices = []
        try:
            # Get network range
            network = self._get_network_range()
            
            # Perform Nmap scan
            self.nm.scan(network, arguments='-sn')
            
            # Process results
            for host in self.nm.all_hosts():
                try:
                    device = self._create_device(host)
                    if device:
                        devices.append(device)
                except Exception as e:
                    self.logger.error(f"Error processing host {host}: {str(e)}")
                    
            return devices
            
        except Exception as e:
            self.logger.error(f"Error scanning network: {str(e)}")
            return []
            
    def _process_device(self, device: NetworkDevice) -> None:
        """Process a discovered device."""
        try:
            # Check if device is known
            known_device = self._get_known_device(device.mac_address)
            
            if known_device:
                # Update existing device
                self._update_device(known_device, device)
            else:
                # New device detected
                self._handle_new_device(device)
                
            # Perform detailed device analysis
            self._analyze_device(device)
            
            # Store device information
            self._store_device(device)
            
        except Exception as e:
            self.logger.error(f"Error processing device: {str(e)}")
            
    def _analyze_device(self, device: NetworkDevice) -> None:
        """Perform detailed device analysis."""
        try:
            # OS detection
            os_info = self._detect_os(device.ip_address)
            device.os_info = os_info
            
            # Service detection
            services = self._detect_services(device.ip_address)
            device.services = services
            
            # Vulnerability scan
            vulnerabilities = self._scan_vulnerabilities(device)
            
            # Calculate risk score
            device.risk_score = self._calculate_device_risk(device, vulnerabilities)
            
            # Check compliance
            compliance = self._check_device_compliance(device)
            
            # Store analysis results
            self._store_device_analysis(device, vulnerabilities, compliance)
            
        except Exception as e:
            self.logger.error(f"Error analyzing device: {str(e)}")
            
    def _detect_services(self, ip_address: str) -> List[Dict]:
        """Detect services running on a device."""
        try:
            services = []
            
            # Perform service detection scan
            self.nm.scan(ip_address, arguments='-sV')
            
            # Process results
            if ip_address in self.nm.all_hosts():
                for proto in self.nm[ip_address].all_protocols():
                    ports = self.nm[ip_address][proto].keys()
                    for port in ports:
                        service = self.nm[ip_address][proto][port]
                        services.append({
                            'port': port,
                            'protocol': proto,
                            'name': service.get('name'),
                            'product': service.get('product'),
                            'version': service.get('version'),
                            'extrainfo': service.get('extrainfo')
                        })
                        
            return services
            
        except Exception as e:
            self.logger.error(f"Error detecting services: {str(e)}")
            return []
            
    def _process_packet(self, packet) -> Optional[NetworkActivity]:
        """Process a captured packet."""
        try:
            # Extract packet information
            activity = NetworkActivity(
                id=str(uuid.uuid4()),
                timestamp=datetime.now(),
                source_ip=packet.ip.src,
                destination_ip=packet.ip.dst,
                protocol=packet.highest_layer,
                source_port=int(packet.tcp.srcport) if hasattr(packet, 'tcp') else 0,
                destination_port=int(packet.tcp.dstport) if hasattr(packet, 'tcp') else 0,
                bytes_sent=len(packet),
                bytes_received=0,
                duration=0.0,
                flags=self._extract_flags(packet),
                payload_type=self._detect_payload_type(packet),
                risk_score=0.0
            )
            
            # Calculate risk score
            activity.risk_score = self._calculate_activity_risk(activity)
            
            return activity
            
        except Exception as e:
            self.logger.error(f"Error processing packet: {str(e)}")
            return None
            
    def _check_activity_threats(self, activity: NetworkActivity) -> None:
        """Check network activity for threats."""
        try:
            # Apply detection rules
            for rule in self.detection_rules:
                if rule.matches(activity):
                    # Create threat indicator
                    threat = self._create_threat_indicator(rule, activity)
                    
                    # Store threat
                    self._store_threat(threat)
                    
                    # Trigger response
                    self._trigger_threat_response(threat)
                    
        except Exception as e:
            self.logger.error(f"Error checking activity threats: {str(e)}")
            
    def get_network_topology(self) -> Dict:
        """Get current network topology."""
        try:
            topology = {
                'devices': self._get_active_devices(),
                'connections': self._get_active_connections(),
                'segments': self._get_network_segments(),
                'metrics': self._get_network_metrics()
            }
            return topology
            
        except Exception as e:
            self.logger.error(f"Error getting network topology: {str(e)}")
            return {}
            
    def get_device_details(self, device_id: str) -> Dict:
        """Get detailed information about a device."""
        try:
            # Get device from database
            device = self.db.get_device(device_id)
            if not device:
                return {'error': 'Device not found'}
                
            # Get additional information
            details = {
                'device': device,
                'activities': self._get_device_activities(device_id),
                'vulnerabilities': self._get_device_vulnerabilities(device_id),
                'compliance': self._get_device_compliance(device_id),
                'risks': self._get_device_risks(device_id)
            }
            
            return details
            
        except Exception as e:
            self.logger.error(f"Error getting device details: {str(e)}")
            return {'error': str(e)}
            
    def get_network_metrics(self) -> Dict:
        """Get network performance and security metrics."""
        try:
            metrics = {
                'performance': self._get_performance_metrics(),
                'security': self._get_security_metrics(),
                'availability': self._get_availability_metrics(),
                'compliance': self._get_compliance_metrics()
            }
            return metrics
            
        except Exception as e:
            self.logger.error(f"Error getting network metrics: {str(e)}")
            return {}

    def _start_behavioral_analysis(self) -> None:
        """Start behavioral analysis of network traffic."""
        try:
            def analyze_behavior():
                while self.is_running:
                    # Analyze traffic patterns
                    current_patterns = self._get_traffic_patterns()
                    anomalies = self._detect_anomalies(current_patterns)
                    
                    # Analyze device behavior
                    device_behaviors = self._analyze_device_behaviors()
                    suspicious_devices = self._detect_suspicious_devices(device_behaviors)
                    
                    # Process findings
                    self._process_anomalies(anomalies)
                    self._process_suspicious_devices(suspicious_devices)
                    
                    time.sleep(self.config.behavior_analysis_interval)
                    
            self.behavior_thread = threading.Thread(target=analyze_behavior)
            self.behavior_thread.start()
            
        except Exception as e:
            self.logger.error(f"Error starting behavioral analysis: {str(e)}")
            
    def _detect_anomalies(self, patterns: Dict) -> List[Dict]:
        """Detect network traffic anomalies using ML models."""
        anomalies = []
        try:
            # Apply statistical analysis
            stat_anomalies = self._statistical_anomaly_detection(patterns)
            anomalies.extend(stat_anomalies)
            
            # Apply ML-based detection
            ml_anomalies = self._ml_anomaly_detection(patterns)
            anomalies.extend(ml_anomalies)
            
            # Apply behavioral patterns
            behav_anomalies = self._behavioral_pattern_detection(patterns)
            anomalies.extend(behav_anomalies)
            
            return self._deduplicate_anomalies(anomalies)
            
        except Exception as e:
            self.logger.error(f"Error in anomaly detection: {str(e)}")
            return []
            
    def _analyze_device_behaviors(self) -> Dict[str, Dict]:
        """Analyze behavior patterns of network devices."""
        device_behaviors = {}
        try:
            for device in self.known_devices:
                # Get device traffic patterns
                traffic = self._get_device_traffic(device.id)
                
                # Analyze communication patterns
                comm_patterns = self._analyze_communication_patterns(traffic)
                
                # Analyze service usage
                service_usage = self._analyze_service_usage(traffic)
                
                # Analyze data transfer patterns
                data_patterns = self._analyze_data_patterns(traffic)
                
                # Calculate risk score
                risk_score = self._calculate_device_risk(
                    comm_patterns,
                    service_usage,
                    data_patterns
                )
                
                device_behaviors[device.id] = {
                    'communication_patterns': comm_patterns,
                    'service_usage': service_usage,
                    'data_patterns': data_patterns,
                    'risk_score': risk_score,
                    'timestamp': datetime.now()
                }
                
            return device_behaviors
            
        except Exception as e:
            self.logger.error(f"Error analyzing device behaviors: {str(e)}")
            return {}
            
    def _detect_suspicious_devices(self, behaviors: Dict[str, Dict]) -> List[NetworkDevice]:
        """Identify suspicious devices based on behavioral analysis."""
        suspicious_devices = []
        try:
            for device_id, behavior in behaviors.items():
                device = self._get_device_by_id(device_id)
                if not device:
                    continue
                    
                # Check risk score
                if behavior['risk_score'] > self.config.risk_threshold:
                    suspicious_devices.append(device)
                    continue
                    
                # Check communication patterns
                if self._has_suspicious_communications(behavior['communication_patterns']):
                    suspicious_devices.append(device)
                    continue
                    
                # Check service usage
                if self._has_suspicious_services(behavior['service_usage']):
                    suspicious_devices.append(device)
                    continue
                    
                # Check data patterns
                if self._has_suspicious_data_patterns(behavior['data_patterns']):
                    suspicious_devices.append(device)
                    
            return suspicious_devices
            
        except Exception as e:
            self.logger.error(f"Error detecting suspicious devices: {str(e)}")
            return []
            
    def _process_suspicious_devices(self, devices: List[NetworkDevice]) -> None:
        """Process and respond to suspicious device detections."""
        try:
            for device in devices:
                # Generate alert
                alert = self._generate_device_alert(device)
                
                # Update device status
                self._update_device_status(device, 'suspicious')
                
                # Implement containment measures if configured
                if self.config.auto_containment_enabled:
                    self._contain_suspicious_device(device)
                    
                # Log the detection
                self._log_suspicious_device(device)
                
                # Notify security team
                self._notify_security_team(alert)
                
        except Exception as e:
            self.logger.error(f"Error processing suspicious devices: {str(e)}")
            
    def _contain_suspicious_device(self, device: NetworkDevice) -> None:
        """Implement containment measures for suspicious devices."""
        try:
            # Isolate device network access
            self._isolate_device(device)
            
            # Block suspicious services
            self._block_suspicious_services(device)
            
            # Enable enhanced monitoring
            self._enable_enhanced_monitoring(device)
            
            # Log containment actions
            self._log_containment_actions(device)
            
        except Exception as e:
            self.logger.error(f"Error containing suspicious device: {str(e)}")

    def monitor_network(self) -> Dict:
        """Perform comprehensive network monitoring."""
        try:
            results = {
                'devices': self._detect_devices(),
                'traffic': self._analyze_traffic(),
                'anomalies': self._detect_anomalies(),
                'security_issues': self._check_security(),
                'performance': self._measure_performance()
            }
            
            # Update inventory
            self._update_device_inventory(results['devices'])
            
            # Store monitoring results
            self._store_monitoring_results(results)
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error monitoring network: {str(e)}")
            return {}
            
    def _detect_devices(self) -> List[NetworkDevice]:
        """Detect and profile network devices."""
        try:
            devices = []
            
            # Active scanning
            nmap_results = self._perform_nmap_scan()
            devices.extend(self._process_nmap_results(nmap_results))
            
            # Passive detection
            passive_results = self._passive_device_detection()
            devices.extend(passive_results)
            
            # Device profiling
            for device in devices:
                self._profile_device(device)
                
            return devices
            
        except Exception as e:
            self.logger.error(f"Error detecting devices: {str(e)}")
            return []
            
    def _analyze_traffic(self) -> Dict:
        """Analyze network traffic patterns."""
        try:
            analysis = {
                'flows': self._analyze_network_flows(),
                'protocols': self._analyze_protocols(),
                'bandwidth': self._analyze_bandwidth(),
                'connections': self._analyze_connections(),
                'services': self._analyze_services()
            }
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error analyzing traffic: {str(e)}")
            return {}
            
    def _profile_device(self, device: NetworkDevice) -> None:
        """Profile a network device."""
        try:
            # OS detection
            os_info = self._detect_os(device.ip_address)
            device.os_info = os_info
            
            # Service enumeration
            services = self._enumerate_services(device.ip_address)
            device.services = services
            
            # Vulnerability assessment
            vulnerabilities = self._check_vulnerabilities(device)
            device.risk_score = self._calculate_device_risk(device, vulnerabilities)
            
            # Update device info
            self._update_device_profile(device)
            
        except Exception as e:
            self.logger.error(f"Error profiling device {device.ip_address}: {str(e)}")
            
    def _detect_anomalies(self) -> List[Dict]:
        """Detect network anomalies."""
        try:
            anomalies = []
            
            # Traffic pattern anomalies
            traffic_anomalies = self._detect_traffic_anomalies()
            anomalies.extend(traffic_anomalies)
            
            # Protocol anomalies
            protocol_anomalies = self._detect_protocol_anomalies()
            anomalies.extend(protocol_anomalies)
            
            # Behavioral anomalies
            behavioral_anomalies = self._detect_behavioral_anomalies()
            anomalies.extend(behavioral_anomalies)
            
            return anomalies
            
        except Exception as e:
            self.logger.error(f"Error detecting anomalies: {str(e)}")
            return []
            
    def _check_security(self) -> Dict:
        """Check network security posture."""
        try:
            security_checks = {
                'unauthorized_devices': self._detect_unauthorized_devices(),
                'vulnerable_services': self._detect_vulnerable_services(),
                'misconfigurations': self._detect_misconfigurations(),
                'compliance_issues': self._check_compliance(),
                'exposure_analysis': self._analyze_exposure()
            }
            
            return security_checks
            
        except Exception as e:
            self.logger.error(f"Error checking security: {str(e)}")
            return {}
            
    def _analyze_network_flows(self) -> List[NetworkFlow]:
        """Analyze network traffic flows."""
        try:
            flows = []
            
            # Process packets
            for packet in self.capture.sniff_continuously():
                flow = self._process_packet(packet)
                
                if flow:
                    # Check for existing flow
                    if flow.id in self.flow_cache:
                        self._update_flow(flow)
                    else:
                        self._create_new_flow(flow)
                        
                    flows.append(flow)
                    
            return flows
            
        except Exception as e:
            self.logger.error(f"Error analyzing network flows: {str(e)}")
            return []
            
    def _detect_unauthorized_devices(self) -> List[Dict]:
        """Detect unauthorized network devices."""
        try:
            unauthorized = []
            
            for device in self.device_inventory.values():
                # Check against whitelist
                if not self._is_device_authorized(device):
                    unauthorized.append({
                        'device': device,
                        'reason': 'Not in whitelist',
                        'risk_level': 'high'
                    })
                    
                # Check for suspicious characteristics
                if self._has_suspicious_characteristics(device):
                    unauthorized.append({
                        'device': device,
                        'reason': 'Suspicious characteristics',
                        'risk_level': 'medium'
                    })
                    
            return unauthorized
            
        except Exception as e:
            self.logger.error(f"Error detecting unauthorized devices: {str(e)}")
            return []
