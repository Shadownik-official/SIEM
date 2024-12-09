import scapy.all as scapy
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt
import threading
import time
import logging
from typing import Dict, List, Set, Optional
import json
import yaml
from pathlib import Path
import subprocess
from datetime import datetime

from ..utils.logging import setup_logger
from ..utils.encryption import encrypt_data, decrypt_data
from ..utils.database import Database

class WirelessAnalyzer:
    """Advanced wireless network security assessment and monitoring toolkit."""
    
    def __init__(self, config_path: str):
        self.logger = setup_logger("WirelessAnalyzer")
        self.load_config(config_path)
        self.db = Database()
        self.networks = {}
        self.clients = {}
        self.running = False
        self.lock = threading.Lock()
        
    def load_config(self, config_path: str) -> None:
        """Load analyzer configuration."""
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
            
        self.wireless_config = self.config['wireless_security']
        
    def start_monitoring(self, interface: str) -> None:
        """Start wireless network monitoring."""
        try:
            # Set interface to monitor mode
            self._set_monitor_mode(interface)
            
            self.running = True
            
            # Start monitoring threads
            threading.Thread(
                target=self._packet_capture_worker,
                args=(interface,),
                daemon=True
            ).start()
            
            threading.Thread(
                target=self._analysis_worker,
                daemon=True
            ).start()
            
            self.logger.info(f"Started wireless monitoring on {interface}")
            
        except Exception as e:
            self.logger.error(f"Error starting wireless monitoring: {str(e)}")
            raise
            
    def stop_monitoring(self) -> None:
        """Stop wireless network monitoring."""
        self.running = False
        self.logger.info("Stopped wireless monitoring")
        
    def get_detected_networks(self) -> List[dict]:
        """Get list of detected wireless networks."""
        with self.lock:
            return list(self.networks.values())
            
    def get_detected_clients(self) -> List[dict]:
        """Get list of detected wireless clients."""
        with self.lock:
            return list(self.clients.values())
            
    def perform_security_audit(self, target_bssid: str) -> dict:
        """Perform comprehensive security audit of a wireless network."""
        try:
            network = self.networks.get(target_bssid)
            if not network:
                raise ValueError(f"Network not found: {target_bssid}")
                
            audit_results = {
                'bssid': target_bssid,
                'ssid': network['ssid'],
                'encryption': self._analyze_encryption(network),
                'vulnerabilities': self._check_vulnerabilities(network),
                'clients': self._get_network_clients(target_bssid),
                'recommendations': self._generate_recommendations(network)
            }
            
            # Store audit results
            self.db.store_wireless_audit(target_bssid, encrypt_data(audit_results))
            
            return audit_results
            
        except Exception as e:
            self.logger.error(f"Error performing security audit: {str(e)}")
            raise
            
    def _packet_capture_worker(self, interface: str) -> None:
        """Worker thread for capturing wireless packets."""
        try:
            scapy.sniff(
                iface=interface,
                prn=self._process_packet,
                store=0,
                stop_filter=lambda _: not self.running
            )
            
        except Exception as e:
            self.logger.error(f"Packet capture error: {str(e)}")
            
    def _process_packet(self, packet) -> None:
        """Process captured wireless packets."""
        try:
            if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
                self._process_beacon(packet)
            elif packet.haslayer(Dot11):
                self._process_data_packet(packet)
                
        except Exception as e:
            self.logger.error(f"Error processing packet: {str(e)}")
            
    def _process_beacon(self, packet) -> None:
        """Process beacon frames to detect networks."""
        try:
            bssid = packet[Dot11].addr2
            if not bssid:
                return
                
            # Extract network information
            ssid = self._get_ssid(packet)
            encryption = self._get_encryption_type(packet)
            channel = self._get_channel(packet)
            signal_strength = -(256-ord(packet.notdecoded[-4:-3]))
            
            with self.lock:
                if bssid not in self.networks:
                    self.networks[bssid] = {
                        'bssid': bssid,
                        'ssid': ssid,
                        'encryption': encryption,
                        'channel': channel,
                        'signal_strength': signal_strength,
                        'first_seen': datetime.now().isoformat(),
                        'last_seen': datetime.now().isoformat(),
                        'clients': set()
                    }
                else:
                    self.networks[bssid].update({
                        'signal_strength': signal_strength,
                        'last_seen': datetime.now().isoformat()
                    })
                    
        except Exception as e:
            self.logger.error(f"Error processing beacon: {str(e)}")
            
    def _process_data_packet(self, packet) -> None:
        """Process data packets to detect clients."""
        try:
            # Extract addresses
            bssid = packet[Dot11].addr1
            client_mac = packet[Dot11].addr2
            
            if not (bssid and client_mac):
                return
                
            with self.lock:
                if bssid in self.networks:
                    self.networks[bssid]['clients'].add(client_mac)
                    
                if client_mac not in self.clients:
                    self.clients[client_mac] = {
                        'mac_address': client_mac,
                        'associated_networks': {bssid},
                        'first_seen': datetime.now().isoformat(),
                        'last_seen': datetime.now().isoformat()
                    }
                else:
                    self.clients[client_mac]['associated_networks'].add(bssid)
                    self.clients[client_mac]['last_seen'] = datetime.now().isoformat()
                    
        except Exception as e:
            self.logger.error(f"Error processing data packet: {str(e)}")
            
    def _analysis_worker(self) -> None:
        """Worker thread for analyzing wireless security."""
        while self.running:
            try:
                self._analyze_networks()
                self._detect_attacks()
                time.sleep(self.wireless_config['analysis_interval'])
                
            except Exception as e:
                self.logger.error(f"Analysis error: {str(e)}")
                
    def _analyze_networks(self) -> None:
        """Analyze security of detected networks."""
        with self.lock:
            for bssid, network in self.networks.items():
                try:
                    # Check for common vulnerabilities
                    vulnerabilities = self._check_vulnerabilities(network)
                    if vulnerabilities:
                        self._report_vulnerabilities(bssid, vulnerabilities)
                        
                    # Check for suspicious clients
                    suspicious = self._detect_suspicious_clients(network)
                    if suspicious:
                        self._report_suspicious_activity(bssid, suspicious)
                        
                except Exception as e:
                    self.logger.error(f"Network analysis error: {str(e)}")
                    
    def _detect_attacks(self) -> None:
        """Detect common wireless attacks."""
        attacks = {
            'deauth': self._detect_deauth_attacks(),
            'evil_twin': self._detect_evil_twin(),
            'karma': self._detect_karma_attacks(),
            'krack': self._detect_krack_vulnerability()
        }
        
        for attack_type, detected in attacks.items():
            if detected:
                self._report_attack(attack_type, detected)
                
    @staticmethod
    def _get_ssid(packet) -> Optional[str]:
        """Extract SSID from packet."""
        try:
            return packet[Dot11Elt].info.decode()
        except:
            return None
            
    @staticmethod
    def _get_encryption_type(packet) -> List[str]:
        """Determine encryption type from packet."""
        encryption_types = []
        
        try:
            # Check for WPA/WPA2
            for item in packet[Dot11Elt:]:
                if item.ID == 48:  # RSN (WPA2) element
                    encryption_types.append("WPA2")
                elif item.ID == 221 and item.info.startswith(b'\x00P\xf2\x01\x01\x00'):
                    encryption_types.append("WPA")
                    
            # Check for WEP
            capability = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
            if 'privacy' in capability and not encryption_types:
                encryption_types.append("WEP")
                
            if not encryption_types:
                encryption_types.append("Open")
                
        except Exception:
            encryption_types.append("Unknown")
            
        return encryption_types
        
    @staticmethod
    def _get_channel(packet) -> Optional[int]:
        """Extract channel number from packet."""
        try:
            for item in packet[Dot11Elt:]:
                if item.ID == 3:
                    return ord(item.info)
        except:
            return None
            
    @staticmethod
    def _set_monitor_mode(interface: str) -> None:
        """Set wireless interface to monitor mode."""
        try:
            subprocess.run(['airmon-ng', 'start', interface], check=True)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to set monitor mode: {str(e)}")
            
    def _check_vulnerabilities(self, network: dict) -> List[dict]:
        """Check for common wireless vulnerabilities."""
        vulnerabilities = []
        
        # Check encryption
        if "Open" in network['encryption']:
            vulnerabilities.append({
                'type': 'open_network',
                'severity': 'high',
                'description': 'Network is operating without encryption'
            })
        elif "WEP" in network['encryption']:
            vulnerabilities.append({
                'type': 'weak_encryption',
                'severity': 'high',
                'description': 'WEP encryption is cryptographically broken'
            })
            
        # Check for weak signal
        if network['signal_strength'] < -70:
            vulnerabilities.append({
                'type': 'weak_signal',
                'severity': 'medium',
                'description': 'Weak signal strength may lead to connection issues'
            })
            
        return vulnerabilities
        
    def _detect_suspicious_clients(self, network: dict) -> List[dict]:
        """Detect suspicious client behavior."""
        suspicious = []
        
        for client_mac in network['clients']:
            client = self.clients.get(client_mac)
            if client:
                # Check for multiple network associations
                if len(client['associated_networks']) > 1:
                    suspicious.append({
                        'client_mac': client_mac,
                        'type': 'multiple_networks',
                        'details': {
                            'networks': list(client['associated_networks'])
                        }
                    })
                    
        return suspicious
        
    def _detect_deauth_attacks(self) -> List[dict]:
        """Detect deauthentication attacks."""
        # Implementation depends on packet analysis
        return []
        
    def _detect_evil_twin(self) -> List[dict]:
        """Detect evil twin attacks."""
        # Implementation depends on SSID and BSSID analysis
        return []
        
    def _detect_karma_attacks(self) -> List[dict]:
        """Detect KARMA attacks."""
        # Implementation depends on probe response analysis
        return []
        
    def _detect_krack_vulnerability(self) -> List[dict]:
        """Detect KRACK vulnerability."""
        # Implementation depends on WPA handshake analysis
        return []
        
    def _report_vulnerabilities(self, bssid: str, vulnerabilities: List[dict]) -> None:
        """Report detected vulnerabilities."""
        try:
            report = {
                'timestamp': datetime.now().isoformat(),
                'bssid': bssid,
                'vulnerabilities': vulnerabilities
            }
            
            self.db.store_vulnerability_report(bssid, encrypt_data(report))
            self.logger.warning(f"Vulnerabilities detected for {bssid}: {vulnerabilities}")
            
        except Exception as e:
            self.logger.error(f"Error reporting vulnerabilities: {str(e)}")
            
    def _report_suspicious_activity(self, bssid: str, suspicious: List[dict]) -> None:
        """Report suspicious activity."""
        try:
            report = {
                'timestamp': datetime.now().isoformat(),
                'bssid': bssid,
                'suspicious_activity': suspicious
            }
            
            self.db.store_suspicious_activity(bssid, encrypt_data(report))
            self.logger.warning(f"Suspicious activity detected for {bssid}: {suspicious}")
            
        except Exception as e:
            self.logger.error(f"Error reporting suspicious activity: {str(e)}")
            
    def _report_attack(self, attack_type: str, details: List[dict]) -> None:
        """Report detected attacks."""
        try:
            report = {
                'timestamp': datetime.now().isoformat(),
                'attack_type': attack_type,
                'details': details
            }
            
            self.db.store_attack_report(attack_type, encrypt_data(report))
            self.logger.warning(f"{attack_type} attack detected: {details}")
            
        except Exception as e:
            self.logger.error(f"Error reporting attack: {str(e)}")
            
    def _generate_recommendations(self, network: dict) -> List[dict]:
        """Generate security recommendations."""
        recommendations = []
        
        # Check encryption
        if "Open" in network['encryption']:
            recommendations.append({
                'category': 'encryption',
                'severity': 'high',
                'description': 'Implement WPA3 encryption',
                'details': 'Open networks are vulnerable to eavesdropping and attacks'
            })
        elif "WEP" in network['encryption']:
            recommendations.append({
                'category': 'encryption',
                'severity': 'high',
                'description': 'Upgrade to WPA3 encryption',
                'details': 'WEP encryption can be broken in minutes'
            })
        elif "WPA" in network['encryption'] and "WPA2" not in network['encryption']:
            recommendations.append({
                'category': 'encryption',
                'severity': 'medium',
                'description': 'Upgrade to WPA3 encryption',
                'details': 'WPA has known vulnerabilities'
            })
            
        # Signal strength recommendations
        if network['signal_strength'] < -70:
            recommendations.append({
                'category': 'signal',
                'severity': 'medium',
                'description': 'Improve signal strength',
                'details': 'Consider adding access points or adjusting antenna placement'
            })
            
        return recommendations
