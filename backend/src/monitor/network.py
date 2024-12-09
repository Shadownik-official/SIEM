"""
Network Device Monitoring Module for Enterprise SIEM
Handles device discovery, monitoring, and behavior analysis
"""
import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
import yaml
import netaddr
import pyshark
from scapy.all import *
from elasticsearch import Elasticsearch
from redis import Redis

logger = logging.getLogger(__name__)

@dataclass
class DeviceInfo:
    ip: str
    mac: str
    hostname: Optional[str]
    vendor: Optional[str]
    device_type: Optional[str]
    first_seen: datetime
    last_seen: datetime
    open_ports: List[int]
    services: Dict[str, str]
    os_info: Optional[str]
    tags: List[str]

class NetworkMonitor:
    def __init__(self, es_client: Elasticsearch, redis_client: Redis):
        self.es = es_client
        self.redis = redis_client
        self.known_devices: Dict[str, DeviceInfo] = {}
        self.load_monitoring_config()
        
    def load_monitoring_config(self):
        """Load network monitoring configuration"""
        try:
            with open('config/network_monitoring.yaml', 'r') as f:
                self.config = yaml.safe_load(f)
            logger.info("Loaded network monitoring configuration")
        except Exception as e:
            logger.error(f"Failed to load monitoring config: {e}")
            self.config = {
                'scan_interval': 300,  # 5 minutes
                'retention_period': 90,  # 90 days
                'alert_thresholds': {
                    'new_device': True,
                    'port_change': True,
                    'service_change': True,
                    'unusual_traffic': True
                }
            }

    def start_monitoring(self):
        """Start network monitoring"""
        try:
            # Start passive monitoring
            self._start_passive_monitoring()
            
            # Start active scanning
            self._start_active_scanning()
            
            logger.info("Network monitoring started successfully")
        except Exception as e:
            logger.error(f"Failed to start monitoring: {e}")

    def _start_passive_monitoring(self):
        """Start passive network monitoring"""
        try:
            # Start packet capture
            capture = pyshark.LiveCapture(interface=self.config.get('interface', 'eth0'))
            capture.apply_on_packets(self._process_packet)
        except Exception as e:
            logger.error(f"Failed to start passive monitoring: {e}")

    def _start_active_scanning(self):
        """Start active network scanning"""
        try:
            networks = self.config.get('networks', ['192.168.1.0/24'])
            for network in networks:
                self._scan_network(network)
        except Exception as e:
            logger.error(f"Failed to start active scanning: {e}")

    def _process_packet(self, packet):
        """Process captured network packet"""
        try:
            # Extract device information
            if hasattr(packet, 'ip'):
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                
                # Update device information
                self._update_device_info(src_ip, packet)
                self._update_device_info(dst_ip, packet)
                
                # Analyze traffic patterns
                self._analyze_traffic_pattern(packet)
        except Exception as e:
            logger.error(f"Failed to process packet: {e}")

    def _update_device_info(self, ip: str, packet) -> None:
        """Update device information from packet"""
        try:
            now = datetime.now()
            
            if ip not in self.known_devices:
                # New device discovered
                device = DeviceInfo(
                    ip=ip,
                    mac=self._get_mac_address(ip),
                    hostname=self._resolve_hostname(ip),
                    vendor=self._get_vendor_info(ip),
                    device_type=self._detect_device_type(packet),
                    first_seen=now,
                    last_seen=now,
                    open_ports=[],
                    services={},
                    os_info=None,
                    tags=[]
                )
                self.known_devices[ip] = device
                
                # Alert on new device
                if self.config['alert_thresholds']['new_device']:
                    self._alert_new_device(device)
            else:
                # Update existing device
                device = self.known_devices[ip]
                device.last_seen = now
                
                # Update services if new information available
                if hasattr(packet, 'tcp') or hasattr(packet, 'udp'):
                    self._update_device_services(device, packet)
        except Exception as e:
            logger.error(f"Failed to update device info: {e}")

    def _get_mac_address(self, ip: str) -> Optional[str]:
        """Get MAC address for IP"""
        try:
            # Check ARP cache first
            arp_response = sr1(ARP(pdst=ip), timeout=2, verbose=False)
            if arp_response:
                return arp_response.hwsrc
        except Exception as e:
            logger.error(f"Failed to get MAC address: {e}")
        return None

    def _resolve_hostname(self, ip: str) -> Optional[str]:
        """Resolve hostname for IP"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None

    def _get_vendor_info(self, ip: str) -> Optional[str]:
        """Get vendor information from MAC address"""
        try:
            mac = self._get_mac_address(ip)
            if mac:
                # Query MAC vendor database
                # Implementation depends on available database
                pass
        except Exception as e:
            logger.error(f"Failed to get vendor info: {e}")
        return None

    def _detect_device_type(self, packet) -> Optional[str]:
        """Detect device type from network behavior"""
        try:
            # Implement device type detection logic
            # Based on traffic patterns, ports, protocols
            return None
        except Exception as e:
            logger.error(f"Failed to detect device type: {e}")
        return None

    def _update_device_services(self, device: DeviceInfo, packet) -> None:
        """Update device services information"""
        try:
            if hasattr(packet, 'tcp'):
                port = int(packet.tcp.port)
                if port not in device.open_ports:
                    device.open_ports.append(port)
                    if self.config['alert_thresholds']['port_change']:
                        self._alert_port_change(device, port)
                
                # Try to identify service
                service = self._identify_service(port)
                if service and service not in device.services.values():
                    device.services[str(port)] = service
                    if self.config['alert_thresholds']['service_change']:
                        self._alert_service_change(device, port, service)
        except Exception as e:
            logger.error(f"Failed to update device services: {e}")

    def _identify_service(self, port: int) -> Optional[str]:
        """Identify service running on port"""
        common_ports = {
            80: 'HTTP',
            443: 'HTTPS',
            22: 'SSH',
            21: 'FTP',
            3389: 'RDP',
            445: 'SMB'
            # Add more common ports
        }
        return common_ports.get(port)

    def _analyze_traffic_pattern(self, packet) -> None:
        """Analyze network traffic patterns"""
        try:
            if hasattr(packet, 'ip'):
                # Extract flow information
                flow = {
                    'src_ip': packet.ip.src,
                    'dst_ip': packet.ip.dst,
                    'protocol': packet.transport_layer if hasattr(packet, 'transport_layer') else 'Unknown',
                    'length': packet.length,
                    'timestamp': datetime.now().isoformat()
                }
                
                # Store flow data
                self._store_flow_data(flow)
                
                # Check for unusual patterns
                if self.config['alert_thresholds']['unusual_traffic']:
                    self._check_unusual_pattern(flow)
        except Exception as e:
            logger.error(f"Failed to analyze traffic pattern: {e}")

    def _store_flow_data(self, flow: Dict) -> None:
        """Store network flow data"""
        try:
            self.es.index(
                index='siem-network-flows',
                body=flow
            )
        except Exception as e:
            logger.error(f"Failed to store flow data: {e}")

    def _check_unusual_pattern(self, flow: Dict) -> None:
        """Check for unusual traffic patterns"""
        try:
            # Implement anomaly detection logic
            # Based on historical traffic patterns
            pass
        except Exception as e:
            logger.error(f"Failed to check unusual pattern: {e}")

    def _alert_new_device(self, device: DeviceInfo) -> None:
        """Generate alert for new device"""
        alert = {
            'type': 'new_device',
            'severity': 'medium',
            'device': device.__dict__,
            'timestamp': datetime.now().isoformat(),
            'message': f"New device detected: {device.ip} ({device.hostname or 'Unknown'})"
        }
        self._send_alert(alert)

    def _alert_port_change(self, device: DeviceInfo, port: int) -> None:
        """Generate alert for port change"""
        alert = {
            'type': 'port_change',
            'severity': 'medium',
            'device': device.__dict__,
            'port': port,
            'timestamp': datetime.now().isoformat(),
            'message': f"New port {port} detected on device {device.ip}"
        }
        self._send_alert(alert)

    def _alert_service_change(self, device: DeviceInfo, port: int, service: str) -> None:
        """Generate alert for service change"""
        alert = {
            'type': 'service_change',
            'severity': 'medium',
            'device': device.__dict__,
            'port': port,
            'service': service,
            'timestamp': datetime.now().isoformat(),
            'message': f"New service {service} detected on device {device.ip}:{port}"
        }
        self._send_alert(alert)

    def _send_alert(self, alert: Dict) -> None:
        """Send alert to alert management system"""
        try:
            self.es.index(
                index='siem-alerts',
                body=alert
            )
        except Exception as e:
            logger.error(f"Failed to send alert: {e}")

    def generate_network_map(self) -> Dict:
        """Generate network topology map"""
        try:
            topology = {
                'nodes': [],
                'links': [],
                'timestamp': datetime.now().isoformat()
            }
            
            # Add nodes (devices)
            for device in self.known_devices.values():
                topology['nodes'].append({
                    'id': device.ip,
                    'type': device.device_type or 'unknown',
                    'hostname': device.hostname,
                    'vendor': device.vendor,
                    'services': device.services
                })
            
            # Add links (connections)
            # Implementation depends on stored flow data
            
            # Store topology
            self.es.index(
                index='siem-network-topology',
                body=topology
            )
            
            return topology
        except Exception as e:
            logger.error(f"Failed to generate network map: {e}")
            return {}
