"""
Feature Extraction for Security Events
"""
import numpy as np
from collections import defaultdict
from datetime import datetime, timedelta
import ipaddress

class SecurityFeatureExtractor:
    def __init__(self):
        self.ip_history = defaultdict(list)
        self.user_history = defaultdict(list)
        self.resource_history = defaultdict(list)
        
    def extract_time_features(self, timestamp):
        """Extract temporal features from timestamp"""
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        return {
            'hour': dt.hour,
            'day_of_week': dt.weekday(),
            'is_weekend': 1 if dt.weekday() >= 5 else 0,
            'is_business_hours': 1 if 9 <= dt.hour <= 17 else 0
        }
    
    def extract_ip_features(self, ip_address):
        """Extract features from IP address"""
        try:
            ip = ipaddress.ip_address(ip_address)
            return {
                'is_private': int(ip.is_private),
                'is_global': int(ip.is_global),
                'is_multicast': int(ip.is_multicast),
                'ip_version': int(ip.version)
            }
        except ValueError:
            return {
                'is_private': 0,
                'is_global': 0,
                'is_multicast': 0,
                'ip_version': 0
            }
    
    def extract_user_features(self, user, timestamp):
        """Extract user behavior features"""
        self.user_history[user].append(timestamp)
        recent_activity = [t for t in self.user_history[user] 
                         if timestamp - timedelta(hours=24) <= t <= timestamp]
        
        return {
            'user_activity_count_24h': len(recent_activity),
            'user_activity_frequency': len(recent_activity) / 24.0 if recent_activity else 0,
            'user_first_activity': int(len(self.user_history[user]) == 1)
        }
    
    def extract_resource_features(self, resource, timestamp):
        """Extract resource access features"""
        self.resource_history[resource].append(timestamp)
        recent_access = [t for t in self.resource_history[resource]
                        if timestamp - timedelta(hours=24) <= t <= timestamp]
        
        return {
            'resource_access_count_24h': len(recent_access),
            'resource_access_frequency': len(recent_access) / 24.0 if recent_access else 0,
            'resource_first_access': int(len(self.resource_history[resource]) == 1)
        }
    
    def extract_event_features(self, event):
        """Extract features from security event"""
        features = {}
        
        # Time-based features
        features.update(self.extract_time_features(event['timestamp']))
        
        # IP-based features
        if 'source_ip' in event:
            features.update({
                f'source_{k}': v 
                for k, v in self.extract_ip_features(event['source_ip']).items()
            })
        if 'destination_ip' in event:
            features.update({
                f'destination_{k}': v 
                for k, v in self.extract_ip_features(event['destination_ip']).items()
            })
        
        # User features
        if 'user' in event:
            features.update(self.extract_user_features(
                event['user'],
                datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
            ))
        
        # Resource features
        if 'resource' in event:
            features.update(self.extract_resource_features(
                event['resource'],
                datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
            ))
        
        # Event type and severity
        features.update({
            'event_type': hash(event.get('event_type', '')) % 100,  # Hash for categorical
            'severity': int(event.get('severity', 0))
        })
        
        return features
    
    def extract_sequence_features(self, events, window_size=10):
        """Extract sequential features from a series of events"""
        sequence_features = []
        
        for i in range(len(events) - window_size + 1):
            window = events[i:i + window_size]
            
            # Calculate statistical features over the window
            severities = [e.get('severity', 0) for e in window]
            event_types = [hash(e.get('event_type', '')) % 100 for e in window]
            
            sequence_features.append({
                'mean_severity': np.mean(severities),
                'max_severity': np.max(severities),
                'severity_std': np.std(severities),
                'unique_event_types': len(set(event_types)),
                'event_type_entropy': self._calculate_entropy(event_types)
            })
        
        return sequence_features
    
    def _calculate_entropy(self, values):
        """Calculate Shannon entropy of a sequence"""
        value_counts = defaultdict(int)
        for value in values:
            value_counts[value] += 1
        
        total = len(values)
        entropy = 0
        
        for count in value_counts.values():
            probability = count / total
            entropy -= probability * np.log2(probability)
            
        return entropy
