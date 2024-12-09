import nmap
import scapy.all as scapy
import netifaces
import netaddr
import threading
import time
from datetime import datetime
import logging
from typing import Dict, List, Optional, Set
import yaml
import json

from ..utils.database import Database
from ..utils.encryption import encrypt_data
from ..utils.logging import setup_logger

class NetworkDeviceMonitor:
    """Advanced network device monitoring and detection system."""
    
    def __init__(self, config_path: str):
        self.logger = setup_logger("NetworkDeviceMonitor")
        self.load_config(config_path)
        self.db = Database()
        self.known_devices: Dict[str, dict] = {}
        self.lock = threading.Lock()
        self.running = False
        
        # Initialize scanning tools
        self.nmap_scanner = nmap.PortScanner()
        
    def load_config(self, config_path: str) -> None:
        """Load monitoring configuration from YAML file."""
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.scan_interval = self.config['network_monitoring']['device_discovery']['interval']
        self.retention_days = self.config['network_monitoring']['asset_tracking']['history_retention']
        
    def start_monitoring(self) -> None:
        """Start continuous network monitoring."""
        self.running = True
        
        # Start different monitoring threads
        threading.Thread(target=self._active_scanning_loop, daemon=True).start()
        threading.Thread(target=self._passive_monitoring_loop, daemon=True).start()
        threading.Thread(target=self._behavioral_analysis_loop, daemon=True).start()
        
        self.logger.info("Network device monitoring started")
        
    def stop_monitoring(self) -> None:
        """Stop all monitoring activities."""
        self.running = False
        self.logger.info("Network device monitoring stopped")
        
    def _active_scanning_loop(self) -> None:
        """Continuous active network scanning."""
        while self.running:
            try:
                networks = self._get_local_networks()
                for network in networks:
                    self._scan_network(str(network))
                time.sleep(self.scan_interval)
            except Exception as e:
                self.logger.error(f"Active scanning error: {str(e)}")
                
    def _passive_monitoring_loop(self) -> None:
        """Passive network monitoring using packet capture."""
        while self.running:
            try:
                scapy.sniff(prn=self._packet_callback, store=0, timeout=60)
            except Exception as e:
                self.logger.error(f"Passive monitoring error: {str(e)}")
                
    def _behavioral_analysis_loop(self) -> None:
        """Analyze device behavior patterns."""
        while self.running:
            try:
                self._analyze_device_behaviors()
                time.sleep(300)  # Analysis interval
            except Exception as e:
                self.logger.error(f"Behavioral analysis error: {str(e)}")
                
    def _scan_network(self, network: str) -> None:
        """Perform detailed network scan."""
        try:
            # Basic host discovery
            self.nmap_scanner.scan(hosts=network, arguments='-sn')
            
            # Detailed scan for discovered hosts
            for host in self.nmap_scanner.all_hosts():
                if self.nmap_scanner[host].state() == 'up':
                    # Detailed port and service scan
                    self.nmap_scanner.scan(host, arguments='-sV -O --version-intensity 5')
                    
                    device_info = {
                        'ip_address': host,
                        'mac_address': self._get_mac_address(host),
                        'hostname': self.nmap_scanner[host].hostname(),
                        'os': self._parse_os_info(self.nmap_scanner[host]),
                        'open_ports': self._parse_ports(self.nmap_scanner[host]),
                        'services': self._parse_services(self.nmap_scanner[host]),
                        'last_seen': datetime.now().isoformat(),
                        'discovery_method': 'active_scan'
                    }
                    
                    self._process_device(device_info)
                    
        except Exception as e:
            self.logger.error(f"Network scan error for {network}: {str(e)}")
            
    def _packet_callback(self, packet) -> None:
        """Process captured network packets."""
        try:
            if packet.haslayer(scapy.IP):
                ip_src = packet[scapy.IP].src
                ip_dst = packet[scapy.IP].dst
                
                # Process source device
                if ip_src not in self.known_devices:
                    device_info = {
                        'ip_address': ip_src,
                        'mac_address': self._get_mac_address(ip_src),
                        'last_seen': datetime.now().isoformat(),
                        'discovery_method': 'passive_monitoring'
                    }
                    self._process_device(device_info)
                    
        except Exception as e:
            self.logger.error(f"Packet processing error: {str(e)}")
            
    def _analyze_device_behaviors(self) -> None:
        """Analyze and detect abnormal device behaviors."""
        try:
            for device_id, device in self.known_devices.items():
                # Get historical behavior
                historical_data = self.db.get_device_history(device_id)
                
                # Analyze patterns
                anomalies = self._detect_anomalies(device, historical_data)
                
                if anomalies:
                    self._report_anomalies(device_id, anomalies)
                    
        except Exception as e:
            self.logger.error(f"Behavioral analysis error: {str(e)}")
            
    def _process_device(self, device_info: dict) -> None:
        """Process and store device information."""
        with self.lock:
            device_id = device_info['mac_address'] or device_info['ip_address']
            
            if device_id in self.known_devices:
                # Update existing device
                changes = self._detect_changes(self.known_devices[device_id], device_info)
                if changes:
                    self._report_changes(device_id, changes)
            else:
                # New device detected
                self._report_new_device(device_info)
                
            # Update database
            self.known_devices[device_id] = device_info
            self.db.update_device(device_id, encrypt_data(device_info))
            
    def _detect_changes(self, old_info: dict, new_info: dict) -> List[str]:
        """Detect changes in device information."""
        changes = []
        
        # Compare relevant fields
        fields_to_check = ['os', 'open_ports', 'services', 'hostname']
        for field in fields_to_check:
            if field in old_info and field in new_info:
                if old_info[field] != new_info[field]:
                    changes.append(f"{field}_change")
                    
        return changes
        
    def _report_new_device(self, device_info: dict) -> None:
        """Report detection of new device."""
        alert = {
            'type': 'new_device',
            'severity': 'medium',
            'device_info': device_info,
            'timestamp': datetime.now().isoformat()
        }
        self._send_alert(alert)
        
    def _report_changes(self, device_id: str, changes: List[str]) -> None:
        """Report detected changes in device."""
        alert = {
            'type': 'device_change',
            'severity': 'medium',
            'device_id': device_id,
            'changes': changes,
            'timestamp': datetime.now().isoformat()
        }
        self._send_alert(alert)
        
    def _report_anomalies(self, device_id: str, anomalies: List[str]) -> None:
        """Report detected behavioral anomalies."""
        alert = {
            'type': 'behavioral_anomaly',
            'severity': 'high',
            'device_id': device_id,
            'anomalies': anomalies,
            'timestamp': datetime.now().isoformat()
        }
        self._send_alert(alert)
        
    def _send_alert(self, alert: dict) -> None:
        """Send alert to the incident response system."""
        try:
            # Store alert in database
            self.db.store_alert(alert)
            
            # Forward to incident response system
            # Implementation depends on your incident response system
            pass
            
        except Exception as e:
            self.logger.error(f"Alert sending error: {str(e)}")
            
    @staticmethod
    def _get_mac_address(ip: str) -> Optional[str]:
        """Get MAC address for an IP address."""
        try:
            ans, _ = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=ip),
                              timeout=2, verbose=False)
            if ans:
                return ans[0][1].hwsrc
        except Exception:
            pass
        return None
        
    @staticmethod
    def _get_local_networks() -> List[netaddr.IPNetwork]:
        """Get list of local networks to scan."""
        networks = []
        for interface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    if 'addr' in addr and 'netmask' in addr:
                        cidr = netaddr.IPNetwork(f"{addr['addr']}/{addr['netmask']}")
                        networks.append(cidr)
        return networks
        
    @staticmethod
    def _parse_os_info(host) -> dict:
        """Parse OS information from nmap scan."""
        os_info = {'name': 'unknown', 'version': 'unknown', 'accuracy': 0}
        if 'osmatch' in host:
            matches = host['osmatch']
            if matches:
                best_match = matches[0]
                os_info['name'] = best_match['name']
                os_info['accuracy'] = int(best_match['accuracy'])
        return os_info
        
    @staticmethod
    def _parse_ports(host) -> List[dict]:
        """Parse port information from nmap scan."""
        ports = []
        if 'tcp' in host:
            for port_num, port_info in host['tcp'].items():
                ports.append({
                    'number': port_num,
                    'state': port_info['state'],
                    'protocol': 'tcp'
                })
        return ports
        
    @staticmethod
    def _parse_services(host) -> List[dict]:
        """Parse service information from nmap scan."""
        services = []
        if 'tcp' in host:
            for port_num, port_info in host['tcp'].items():
                services.append({
                    'port': port_num,
                    'name': port_info.get('name', 'unknown'),
                    'product': port_info.get('product', ''),
                    'version': port_info.get('version', ''),
                    'protocol': 'tcp'
                })
        return services
