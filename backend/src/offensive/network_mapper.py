import nmap
import socket
import struct
import threading
import time
from typing import Dict, List, Optional, Set
import logging
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import netifaces
import scapy.all as scapy
from scapy.layers.l2 import ARP, Ether
import json

@dataclass
class NetworkDevice:
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    os: Optional[str] = None
    open_ports: List[Dict] = None
    services: List[Dict] = None
    last_seen: float = None
    first_seen: float = None
    device_type: Optional[str] = None
    risk_score: float = 0.0
    vulnerabilities: List[Dict] = None

class NetworkMapper:
    def __init__(self, interface: str = None):
        self.interface = interface or self._get_default_interface()
        self.devices: Dict[str, NetworkDevice] = {}
        self.logger = logging.getLogger(__name__)
        self.nm = nmap.PortScanner()
        self._stop_scan = False
        
    def start_network_discovery(self, passive: bool = False):
        """Start network device discovery"""
        try:
            if passive:
                self._start_passive_discovery()
            else:
                self._start_active_discovery()
        except Exception as e:
            self.logger.error(f"Error during network discovery: {str(e)}")
            raise
            
    def stop_network_discovery(self):
        """Stop network discovery process"""
        self._stop_scan = True
        
    def get_network_topology(self) -> Dict:
        """Get current network topology"""
        topology = {
            "nodes": [],
            "edges": [],
            "stats": self._generate_network_stats()
        }
        
        # Add devices as nodes
        for device in self.devices.values():
            node = {
                "id": device.ip_address,
                "label": device.hostname or device.ip_address,
                "type": device.device_type or "unknown",
                "data": {
                    "mac": device.mac_address,
                    "vendor": device.vendor,
                    "os": device.os,
                    "risk_score": device.risk_score
                }
            }
            topology["nodes"].append(node)
            
        # Add network connections as edges
        topology["edges"] = self._map_network_connections()
        
        return topology
        
    def scan_device(self, ip_address: str, ports: str = "1-1024") -> Dict:
        """Perform detailed scan of a specific device"""
        try:
            # Run Nmap scan
            self.nm.scan(ip_address, ports, arguments="-sV -O -sC")
            
            if ip_address not in self.nm.all_hosts():
                raise ValueError(f"No device found at {ip_address}")
                
            device_info = self.nm[ip_address]
            
            # Update device information
            if ip_address in self.devices:
                device = self.devices[ip_address]
            else:
                device = NetworkDevice(ip_address=ip_address)
                
            # Update device details
            device.os = self._get_os_details(device_info)
            device.open_ports = self._get_port_details(device_info)
            device.services = self._get_service_details(device_info)
            device.risk_score = self._calculate_risk_score(device)
            device.vulnerabilities = self._check_vulnerabilities(device)
            
            self.devices[ip_address] = device
            
            return self._format_device_report(device)
            
        except Exception as e:
            self.logger.error(f"Error scanning device {ip_address}: {str(e)}")
            raise
            
    def _start_passive_discovery(self):
        """Start passive network discovery using packet sniffing"""
        self.logger.info("Starting passive network discovery")
        self._stop_scan = False
        
        try:
            scapy.sniff(
                iface=self.interface,
                prn=self._packet_handler,
                store=False,
                stop_filter=lambda _: self._stop_scan
            )
        except Exception as e:
            self.logger.error(f"Error in passive discovery: {str(e)}")
            raise
            
    def _start_active_discovery(self):
        """Start active network discovery using ARP scanning"""
        self.logger.info("Starting active network discovery")
        
        # Get network range
        network = self._get_network_range()
        
        try:
            # Create and send ARP requests
            arp = ARP(pdst=network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            result = scapy.srp(packet, timeout=3, verbose=0)[0]
            
            for sent, received in result:
                ip_address = received.psrc
                mac_address = received.hwsrc
                
                if ip_address not in self.devices:
                    device = NetworkDevice(
                        ip_address=ip_address,
                        mac_address=mac_address,
                        first_seen=time.time(),
                        last_seen=time.time()
                    )
                    self.devices[ip_address] = device
                    
                    # Start detailed scan in separate thread
                    with ThreadPoolExecutor() as executor:
                        executor.submit(self.scan_device, ip_address)
                        
        except Exception as e:
            self.logger.error(f"Error in active discovery: {str(e)}")
            raise
            
    def _packet_handler(self, packet):
        """Handle captured network packets"""
        try:
            if ARP in packet and packet[ARP].op in (1, 2):  # ARP request or reply
                self._process_arp_packet(packet)
            elif IP in packet:
                self._process_ip_packet(packet)
        except Exception as e:
            self.logger.error(f"Error processing packet: {str(e)}")
            
    def _process_arp_packet(self, packet):
        """Process ARP packet information"""
        ip_address = packet[ARP].psrc
        mac_address = packet[ARP].hwsrc
        current_time = time.time()
        
        if ip_address not in self.devices:
            device = NetworkDevice(
                ip_address=ip_address,
                mac_address=mac_address,
                first_seen=current_time,
                last_seen=current_time
            )
            self.devices[ip_address] = device
        else:
            self.devices[ip_address].last_seen = current_time
            
    def _calculate_risk_score(self, device: NetworkDevice) -> float:
        """Calculate risk score for a device"""
        score = 0.0
        
        # Check for open high-risk ports
        high_risk_ports = {21, 22, 23, 445, 3389}  # FTP, SSH, Telnet, SMB, RDP
        device_ports = {port["port"] for port in (device.open_ports or [])}
        if high_risk_ports & device_ports:
            score += 2.0
            
        # Check for vulnerable services
        if device.vulnerabilities:
            score += len(device.vulnerabilities)
            
        # Check for outdated OS
        if device.os and "windows xp" in device.os.lower():
            score += 3.0
            
        # Normalize score to 0-10 range
        return min(10.0, score)
        
    def _check_vulnerabilities(self, device: NetworkDevice) -> List[Dict]:
        """Check for common vulnerabilities"""
        vulnerabilities = []
        
        # Check for open ports with known vulnerabilities
        port_vulns = {
            21: {"name": "FTP Exposed", "severity": "high", "cve": "Multiple"},
            23: {"name": "Telnet Exposed", "severity": "critical", "cve": "Multiple"},
            445: {"name": "SMB Exposed", "severity": "high", "cve": "Multiple"}
        }
        
        for port in (device.open_ports or []):
            if port["port"] in port_vulns:
                vulnerabilities.append(port_vulns[port["port"]])
                
        return vulnerabilities
        
    def _get_network_range(self) -> str:
        """Get the network range for the interface"""
        addrs = netifaces.ifaddresses(self.interface)
        ipv4_addr = addrs[netifaces.AF_INET][0]
        
        ip = ipv4_addr['addr']
        netmask = ipv4_addr['netmask']
        
        # Calculate network address
        ip_int = struct.unpack('!L', socket.inet_aton(ip))[0]
        mask_int = struct.unpack('!L', socket.inet_aton(netmask))[0]
        network_int = ip_int & mask_int
        network = socket.inet_ntoa(struct.pack('!L', network_int))
        
        return f"{network}/{bin(mask_int).count('1')}"
        
    def _get_default_interface(self) -> str:
        """Get the default network interface"""
        gateways = netifaces.gateways()
        if 'default' in gateways and netifaces.AF_INET in gateways['default']:
            return gateways['default'][netifaces.AF_INET][1]
        return netifaces.interfaces()[0]
        
    def generate_report(self) -> Dict:
        """Generate a comprehensive network report"""
        return {
            "timestamp": time.time(),
            "network_info": {
                "interface": self.interface,
                "network_range": self._get_network_range()
            },
            "devices": [self._format_device_report(device) 
                       for device in self.devices.values()],
            "statistics": self._generate_network_stats(),
            "risk_assessment": self._generate_risk_assessment(),
            "recommendations": self._generate_recommendations()
        }
        
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        # Check for high-risk devices
        high_risk_devices = [d for d in self.devices.values() if d.risk_score >= 7.0]
        if high_risk_devices:
            recommendations.append(
                f"Address {len(high_risk_devices)} high-risk devices immediately"
            )
            
        # Check for exposed services
        exposed_services = set()
        for device in self.devices.values():
            if device.services:
                exposed_services.update(s["name"] for s in device.services)
                
        if "telnet" in exposed_services:
            recommendations.append("Disable Telnet and use SSH instead")
        if "ftp" in exposed_services:
            recommendations.append("Secure FTP services or migrate to SFTP")
            
        return recommendations
