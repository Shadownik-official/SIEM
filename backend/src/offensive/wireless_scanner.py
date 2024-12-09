import scapy.all as scapy
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
import threading
import time
from typing import Dict, List, Optional
import logging
from dataclasses import dataclass
import os
import re

@dataclass
class WirelessNetwork:
    bssid: str
    ssid: str
    channel: int
    encryption: str
    signal_strength: int
    clients: List[str]
    first_seen: float
    last_seen: float
    vendor: Optional[str] = None
    capabilities: Optional[Dict[str, bool]] = None
    beacon_interval: Optional[int] = None
    hidden: bool = False
    suspicious_activity: List[str] = None

class WirelessScanner:
    def __init__(self, interface: str = "wlan0"):
        self.interface = interface
        self.networks: Dict[str, WirelessNetwork] = {}
        self.running = False
        self.logger = logging.getLogger(__name__)
        self.known_networks = set()  # For evil twin detection
        self.rogue_aps = []  # For rogue AP tracking
        self.deauth_detection = False  # For deauth attack detection

    def start_scan(self, channel_hop: bool = True):
        """Start wireless network scanning"""
        self.running = True
        
        # Start channel hopping in a separate thread if enabled
        if channel_hop:
            hop_thread = threading.Thread(target=self._channel_hopper)
            hop_thread.daemon = True
            hop_thread.start()
            
        try:
            self.logger.info(f"Starting wireless scan on interface {self.interface}")
            scapy.sniff(iface=self.interface, prn=self._packet_handler, 
                       store=False, stop_filter=lambda _: not self.running)
        except Exception as e:
            self.logger.error(f"Error during wireless scan: {str(e)}")
            self.stop_scan()

    def stop_scan(self):
        """Stop the wireless network scan"""
        self.running = False

    def _channel_hopper(self):
        """Hop through wireless channels to capture more networks"""
        while self.running:
            for channel in range(1, 15):  # Standard 2.4GHz channels
                try:
                    # Set wireless interface to the current channel
                    os.system(f"iwconfig {self.interface} channel {channel}")
                    time.sleep(0.5)  # Dwell time per channel
                except Exception as e:
                    self.logger.error(f"Error during channel hop: {str(e)}")
                    
                if not self.running:
                    break

    def _packet_handler(self, pkt):
        """Handle captured wireless packets"""
        if not pkt.haslayer(Dot11Beacon):
            return
            
        # Extract network information
        try:
            bssid = pkt[Dot11].addr2
            if not bssid:
                return
                
            # Get the SSID
            ssid = None
            for element in pkt[Dot11Elt]:
                if element.ID == 0:  # SSID element
                    ssid = element.info.decode('utf-8', errors='ignore')
                    break
                    
            if not ssid:
                return
                
            # Get encryption type
            encryption = self._get_encryption_type(pkt)
            
            # Get channel
            channel = self._get_channel(pkt)
            
            # Calculate signal strength
            signal_strength = -(256-ord(pkt.notdecoded[-4:-3]))
            
            current_time = time.time()
            
            if bssid not in self.networks:
                # New network discovered
                self.networks[bssid] = WirelessNetwork(
                    bssid=bssid,
                    ssid=ssid,
                    channel=channel,
                    encryption=encryption,
                    signal_strength=signal_strength,
                    clients=[],
                    first_seen=current_time,
                    last_seen=current_time
                )
                self.logger.info(f"Discovered new network: {ssid} ({bssid})")
            else:
                # Update existing network
                network = self.networks[bssid]
                network.signal_strength = signal_strength
                network.last_seen = current_time
                
        except Exception as e:
            self.logger.error(f"Error processing packet: {str(e)}")

    def _get_encryption_type(self, pkt) -> str:
        """Determine the encryption type of a wireless network"""
        cap = pkt[Dot11Beacon].cap
        encryption = []
        
        if cap.privacy:
            # Check for WPA/WPA2/WPA3
            for element in pkt[Dot11Elt]:
                if element.ID == 48:  # RSN (WPA2/WPA3) element
                    rsn_info = element.info
                    if b'\x00\x0f\xac\x08' in rsn_info:  # SAE authentication
                        encryption.append("WPA3")
                    if b'\x00\x0f\xac\x02' in rsn_info:  # CCMP encryption
                        encryption.append("WPA2")
                elif element.ID == 221 and element.info.startswith(b'\x00P\xf2\x01\x01\x00'):
                    encryption.append("WPA")
                    
            if not encryption:  # No WPA/WPA2/WPA3, must be WEP
                encryption.append("WEP")
        else:
            encryption.append("Open")
            
        return "+".join(encryption)

    def detect_evil_twins(self) -> List[Dict]:
        """Detect potential evil twin attacks"""
        evil_twins = []
        ssid_groups = {}
        
        # Group networks by SSID
        for network in self.networks.values():
            if network.ssid not in ssid_groups:
                ssid_groups[network.ssid] = []
            ssid_groups[network.ssid].append(network)
        
        # Analyze each group for potential evil twins
        for ssid, networks in ssid_groups.items():
            if len(networks) > 1:
                # Compare network characteristics
                for i in range(len(networks)):
                    for j in range(i + 1, len(networks)):
                        if self._is_potential_evil_twin(networks[i], networks[j]):
                            evil_twins.append({
                                "ssid": ssid,
                                "legitimate": {
                                    "bssid": networks[i].bssid,
                                    "encryption": networks[i].encryption,
                                    "signal_strength": networks[i].signal_strength
                                },
                                "suspicious": {
                                    "bssid": networks[j].bssid,
                                    "encryption": networks[j].encryption,
                                    "signal_strength": networks[j].signal_strength
                                }
                            })
        
        return evil_twins

    def _is_potential_evil_twin(self, net1: WirelessNetwork, net2: WirelessNetwork) -> bool:
        """Determine if two networks might be involved in an evil twin attack"""
        # Different encryption types might indicate an evil twin
        if net1.encryption != net2.encryption:
            return True
            
        # Significant signal strength difference might indicate an evil twin
        if abs(net1.signal_strength - net2.signal_strength) > 20:
            return True
            
        # If one network is missing vendor info
        if bool(net1.vendor) != bool(net2.vendor):
            return True
            
        return False

    def detect_rogue_aps(self) -> List[Dict]:
        """Detect potential rogue access points"""
        rogue_aps = []
        
        for network in self.networks.values():
            suspicious_traits = []
            
            # Check for suspicious SSIDs
            if self._has_suspicious_ssid(network.ssid):
                suspicious_traits.append("Suspicious SSID pattern")
            
            # Check for unusual encryption configurations
            if "WPA" in network.encryption and "Open" in network.encryption:
                suspicious_traits.append("Inconsistent encryption")
            
            # Check for unusually high signal strength
            if network.signal_strength > -30:
                suspicious_traits.append("Abnormally high signal strength")
            
            # Check for rapid beacon interval changes
            if network.beacon_interval and network.beacon_interval < 10:
                suspicious_traits.append("Unusual beacon interval")
            
            if suspicious_traits:
                rogue_aps.append({
                    "bssid": network.bssid,
                    "ssid": network.ssid,
                    "suspicious_traits": suspicious_traits,
                    "risk_level": self._calculate_risk_level(suspicious_traits)
                })
        
        return rogue_aps

    def _has_suspicious_ssid(self, ssid: str) -> bool:
        """Check if SSID matches known suspicious patterns"""
        suspicious_patterns = [
            r"default",
            r"test",
            r"free.*wifi",
            r"public.*wifi",
            r"^$",  # Empty SSID
            r"linksys",
            r"netgear",
            r"guest"
        ]
        
        return any(re.search(pattern, ssid.lower()) for pattern in suspicious_patterns)

    def _calculate_risk_level(self, suspicious_traits: List[str]) -> str:
        """Calculate risk level based on suspicious traits"""
        if len(suspicious_traits) >= 3:
            return "High"
        elif len(suspicious_traits) == 2:
            return "Medium"
        else:
            return "Low"

    def get_vulnerable_networks(self) -> List[Dict]:
        """Identify potentially vulnerable networks"""
        vulnerable = []
        for net in self.networks.values():
            vulnerabilities = []
            
            # Check for open networks
            if "Open" in net.encryption:
                vulnerabilities.append("No encryption")
                
            # Check for WEP
            if "WEP" in net.encryption:
                vulnerabilities.append("WEP encryption (broken)")
                
            # Check for old WPA
            if "WPA" in net.encryption and "WPA2" not in net.encryption:
                vulnerabilities.append("WPA1 encryption (outdated)")
                
            # Check for missing WPA3
            if "WPA2" in net.encryption and "WPA3" not in net.encryption:
                vulnerabilities.append("WPA3 not enabled")
                
            # Check for hidden SSIDs
            if net.hidden:
                vulnerabilities.append("Hidden SSID (security by obscurity)")
                
            if vulnerabilities:
                vulnerable.append({
                    "ssid": net.ssid,
                    "bssid": net.bssid,
                    "encryption": net.encryption,
                    "vulnerabilities": vulnerabilities,
                    "risk_level": self._calculate_vulnerability_risk(vulnerabilities),
                    "recommendation": self._get_security_recommendations(vulnerabilities)
                })
                
        return vulnerable

    def _calculate_vulnerability_risk(self, vulnerabilities: List[str]) -> str:
        """Calculate risk level based on vulnerability types"""
        risk_scores = {
            "No encryption": 5,
            "WEP encryption (broken)": 5,
            "WPA1 encryption (outdated)": 4,
            "WPA3 not enabled": 2,
            "Hidden SSID (security by obscurity)": 1
        }
        
        total_score = sum(risk_scores.get(vuln, 0) for vuln in vulnerabilities)
        
        if total_score >= 5:
            return "Critical"
        elif total_score >= 3:
            return "High"
        elif total_score >= 2:
            return "Medium"
        else:
            return "Low"

    def _get_security_recommendations(self, vulnerabilities: List[str]) -> List[str]:
        """Generate security recommendations based on vulnerabilities"""
        recommendations = []
        
        if "No encryption" in vulnerabilities:
            recommendations.extend([
                "Enable WPA2/WPA3 encryption immediately",
                "Use a strong pre-shared key (PSK)",
                "Consider implementing 802.1X authentication"
            ])
            
        if "WEP encryption (broken)" in vulnerabilities:
            recommendations.extend([
                "Upgrade to WPA2/WPA3 encryption immediately",
                "Replace legacy devices that only support WEP",
                "Implement network segmentation for legacy devices"
            ])
            
        if "WPA1 encryption (outdated)" in vulnerabilities:
            recommendations.extend([
                "Upgrade to WPA2/WPA3 encryption",
                "Ensure all devices support newer encryption standards",
                "Use strong, unique passwords"
            ])
            
        if "WPA3 not enabled" in vulnerabilities:
            recommendations.extend([
                "Enable WPA3 encryption",
                "Ensure all devices support WPA3 encryption",
                "Use strong, unique passwords"
            ])
            
        if "Hidden SSID (security by obscurity)" in vulnerabilities:
            recommendations.extend([
                "Broadcast the SSID",
                "Use strong, unique passwords",
                "Consider implementing 802.1X authentication"
            ])
            
        return recommendations

    def get_network_summary(self) -> List[Dict]:
        """Get a summary of all discovered networks"""
        return [
            {
                "bssid": net.bssid,
                "ssid": net.ssid,
                "channel": net.channel,
                "encryption": net.encryption,
                "signal_strength": net.signal_strength,
                "clients": len(net.clients),
                "first_seen": net.first_seen,
                "last_seen": net.last_seen,
                "vendor": net.vendor
            }
            for net in self.networks.values()
        ]
