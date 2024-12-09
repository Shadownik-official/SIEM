"""
Feature extraction module for ML-based threat detection
Handles extraction and preprocessing of network traffic features
"""
import numpy as np
import pandas as pd
from typing import Dict, List, Union, Optional
from scipy.stats import entropy
import ipaddress
from scapy.all import IP, TCP, UDP, ICMP, DNS, HTTP
import json
import logging
from datetime import datetime

class FeatureExtractor:
    """Extracts and processes features from network traffic data."""
    
    def __init__(self, config_path: str = None):
        self.logger = logging.getLogger(__name__)
        self.config = self._load_config(config_path)
        self.feature_cache = {}
        self.encoders = self._initialize_encoders()
        
    def extract_features(self, packet_data: Union[Dict, List[Dict]]) -> pd.DataFrame:
        """Extract features from packet data."""
        try:
            if isinstance(packet_data, dict):
                packet_data = [packet_data]
                
            features = []
            for packet in packet_data:
                feature_dict = {
                    **self._extract_basic_features(packet),
                    **self._extract_protocol_features(packet),
                    **self._extract_entropy_features(packet),
                    **self._extract_temporal_features(packet),
                    **self._extract_behavioral_features(packet),
                    **self._extract_signature_features(packet)
                }
                features.append(feature_dict)
                
            return pd.DataFrame(features)
            
        except Exception as e:
            self.logger.error(f"Error extracting features: {str(e)}")
            return pd.DataFrame()
            
    def _extract_basic_features(self, packet: Dict) -> Dict:
        """Extract basic network features."""
        try:
            return {
                'bytes_transferred': packet.get('length', 0),
                'packet_count': 1,
                'connection_duration': packet.get('duration', 0),
                'source_port': packet.get('sport', 0),
                'destination_port': packet.get('dport', 0)
            }
        except Exception as e:
            self.logger.error(f"Error extracting basic features: {str(e)}")
            return {}
            
    def _extract_protocol_features(self, packet: Dict) -> Dict:
        """Extract protocol-specific features."""
        try:
            features = {
                'protocol': packet.get('proto', 'unknown'),
                'tcp_flags': self._extract_tcp_flags(packet),
                'http_method': packet.get('http_method', ''),
                'http_status': packet.get('http_status', 0),
                'ssl_version': packet.get('ssl_version', ''),
                'dns_query_type': packet.get('dns_qtype', '')
            }
            
            # Encode categorical features
            for feature in ['protocol', 'tcp_flags', 'http_method', 'ssl_version', 'dns_query_type']:
                if feature in self.encoders:
                    features[f'{feature}_encoded'] = self.encoders[feature].transform([features[feature]])[0]
                    
            return features
            
        except Exception as e:
            self.logger.error(f"Error extracting protocol features: {str(e)}")
            return {}
            
    def _extract_entropy_features(self, packet: Dict) -> Dict:
        """Extract entropy-based features."""
        try:
            return {
                'source_ip_entropy': self._calculate_ip_entropy(packet.get('src', '')),
                'destination_ip_entropy': self._calculate_ip_entropy(packet.get('dst', '')),
                'payload_entropy': self._calculate_payload_entropy(packet.get('payload', b''))
            }
        except Exception as e:
            self.logger.error(f"Error extracting entropy features: {str(e)}")
            return {}
            
    def _extract_temporal_features(self, packet: Dict) -> Dict:
        """Extract time-based features."""
        try:
            timestamp = packet.get('timestamp', datetime.now())
            return {
                'time_of_day': timestamp.hour + timestamp.minute/60,
                'day_of_week': timestamp.weekday(),
                'is_weekend': int(timestamp.weekday() >= 5)
            }
        except Exception as e:
            self.logger.error(f"Error extracting temporal features: {str(e)}")
            return {}
            
    def _extract_behavioral_features(self, packet: Dict) -> Dict:
        """Extract behavioral features."""
        try:
            flow_key = f"{packet.get('src', '')}:{packet.get('sport', '')}-{packet.get('dst', '')}:{packet.get('dport', '')}"
            
            if flow_key not in self.feature_cache:
                self.feature_cache[flow_key] = {
                    'packet_count': 0,
                    'byte_count': 0,
                    'start_time': datetime.now(),
                    'last_seen': datetime.now()
                }
                
            cache = self.feature_cache[flow_key]
            cache['packet_count'] += 1
            cache['byte_count'] += packet.get('length', 0)
            cache['last_seen'] = datetime.now()
            
            return {
                'flow_duration': (cache['last_seen'] - cache['start_time']).total_seconds(),
                'packets_per_second': cache['packet_count'] / max(1, (cache['last_seen'] - cache['start_time']).total_seconds()),
                'bytes_per_second': cache['byte_count'] / max(1, (cache['last_seen'] - cache['start_time']).total_seconds())
            }
            
        except Exception as e:
            self.logger.error(f"Error extracting behavioral features: {str(e)}")
            return {}
            
    def _extract_signature_features(self, packet: Dict) -> Dict:
        """Extract signature-based features."""
        try:
            return {
                'payload_signature': self._calculate_payload_signature(packet.get('payload', b'')),
                'header_signature': self._calculate_header_signature(packet),
                'flow_signature': self._calculate_flow_signature(packet)
            }
        except Exception as e:
            self.logger.error(f"Error extracting signature features: {str(e)}")
            return {}
            
    def _calculate_ip_entropy(self, ip: str) -> float:
        """Calculate entropy of an IP address."""
        try:
            if not ip:
                return 0.0
                
            # Convert IP to binary representation
            ip_obj = ipaddress.ip_address(ip)
            ip_bytes = ip_obj.packed
            
            # Calculate entropy
            _, counts = np.unique(list(ip_bytes), return_counts=True)
            return entropy(counts)
            
        except Exception as e:
            self.logger.error(f"Error calculating IP entropy: {str(e)}")
            return 0.0
            
    def _calculate_payload_entropy(self, payload: bytes) -> float:
        """Calculate entropy of packet payload."""
        try:
            if not payload:
                return 0.0
                
            # Calculate byte frequency
            _, counts = np.unique(list(payload), return_counts=True)
            return entropy(counts)
            
        except Exception as e:
            self.logger.error(f"Error calculating payload entropy: {str(e)}")
            return 0.0
            
    def _calculate_payload_signature(self, payload: bytes) -> str:
        """Generate signature from packet payload."""
        try:
            if not payload:
                return ""
                
            # Simple rolling hash
            signature = 0
            for byte in payload[:64]:  # Use first 64 bytes
                signature = ((signature << 4) + byte) & 0xFFFFFFFF
                
            return hex(signature)[2:]
            
        except Exception as e:
            self.logger.error(f"Error calculating payload signature: {str(e)}")
            return ""
            
    def _calculate_header_signature(self, packet: Dict) -> str:
        """Generate signature from packet headers."""
        try:
            header_fields = [
                packet.get('proto', ''),
                packet.get('sport', ''),
                packet.get('dport', ''),
                packet.get('flags', ''),
                packet.get('window', '')
            ]
            
            # Create hash from header fields
            header_str = "|".join(str(field) for field in header_fields)
            return hex(hash(header_str) & 0xFFFFFFFF)[2:]
            
        except Exception as e:
            self.logger.error(f"Error calculating header signature: {str(e)}")
            return ""
            
    def _calculate_flow_signature(self, packet: Dict) -> str:
        """Generate signature for the flow."""
        try:
            flow_fields = [
                packet.get('src', ''),
                packet.get('dst', ''),
                packet.get('sport', ''),
                packet.get('dport', ''),
                packet.get('proto', '')
            ]
            
            # Create hash from flow fields
            flow_str = "|".join(str(field) for field in flow_fields)
            return hex(hash(flow_str) & 0xFFFFFFFF)[2:]
            
        except Exception as e:
            self.logger.error(f"Error calculating flow signature: {str(e)}")
            return ""
            
    def _extract_tcp_flags(self, packet: Dict) -> str:
        """Extract TCP flags from packet."""
        try:
            flags = []
            if packet.get('flags'):
                flag_map = {
                    'F': 'FIN',
                    'S': 'SYN',
                    'R': 'RST',
                    'P': 'PSH',
                    'A': 'ACK',
                    'U': 'URG'
                }
                
                for flag, name in flag_map.items():
                    if flag in packet['flags']:
                        flags.append(name)
                        
            return "|".join(flags) if flags else "NONE"
            
        except Exception as e:
            self.logger.error(f"Error extracting TCP flags: {str(e)}")
            return "NONE"
            
    def _load_config(self, config_path: str) -> Dict:
        """Load feature extractor configuration."""
        try:
            if not config_path:
                config_path = "config/ml_detector_config.json"
                
            with open(config_path, 'r') as f:
                return json.load(f)
                
        except Exception as e:
            self.logger.error(f"Error loading config: {str(e)}")
            return {}
            
    def _initialize_encoders(self) -> Dict:
        """Initialize encoders for categorical features."""
        try:
            from sklearn.preprocessing import LabelEncoder
            
            encoders = {}
            categorical_features = [
                'protocol',
                'tcp_flags',
                'http_method',
                'ssl_version',
                'dns_query_type'
            ]
            
            for feature in categorical_features:
                encoders[feature] = LabelEncoder()
                
            return encoders
            
        except Exception as e:
            self.logger.error(f"Error initializing encoders: {str(e)}")
            return {}
