"""
Machine Learning-based Threat Detection Module for Enterprise SIEM
Handles anomaly detection, behavior analysis, and threat classification
"""
import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import tensorflow as tf
from elasticsearch import Elasticsearch
from redis import Redis

logger = logging.getLogger(__name__)

class ThreatDetector:
    def __init__(self, es_client: Elasticsearch, redis_client: Redis):
        self.es = es_client
        self.redis = redis_client
        self.load_models()
        
    def load_models(self):
        """Load trained ML models"""
        try:
            # Load anomaly detection model
            self.anomaly_detector = IsolationForest(
                contamination=0.1,
                random_state=42
            )
            
            # Load behavior analysis model (LSTM)
            self.behavior_model = tf.keras.models.load_model(
                'models/behavior_lstm.h5'
            )
            
            # Load threat classification model
            self.threat_classifier = RandomForestClassifier(
                n_estimators=100,
                random_state=42
            )
            
            # Load feature scalers
            self.anomaly_scaler = StandardScaler()
            self.behavior_scaler = StandardScaler()
            self.threat_scaler = StandardScaler()
            
            logger.info("Successfully loaded ML models")
        except Exception as e:
            logger.error(f"Failed to load ML models: {e}")

    def detect_threats(self, events: List[Dict]) -> List[Dict]:
        """Detect threats using multiple ML models"""
        try:
            results = []
            
            # Convert events to features
            features = self._extract_features(events)
            
            # Run anomaly detection
            anomalies = self._detect_anomalies(features)
            
            # Analyze behavior patterns
            behaviors = self._analyze_behavior(features)
            
            # Classify threats
            classifications = self._classify_threats(features)
            
            # Combine results
            for i, event in enumerate(events):
                threat = {
                    'event': event,
                    'anomaly_score': float(anomalies[i]),
                    'behavior_pattern': behaviors[i],
                    'threat_class': classifications[i],
                    'timestamp': datetime.now().isoformat()
                }
                
                # Calculate overall threat score
                threat['threat_score'] = self._calculate_threat_score(threat)
                
                results.append(threat)
                
                # Store threat detection result
                self._store_threat_result(threat)
            
            return results
        except Exception as e:
            logger.error(f"Threat detection failed: {e}")
            return []

    def _extract_features(self, events: List[Dict]) -> np.ndarray:
        """Extract features from events for ML models"""
        try:
            features = []
            
            for event in events:
                # Extract numerical features
                numerical = self._extract_numerical_features(event)
                
                # Extract categorical features
                categorical = self._extract_categorical_features(event)
                
                # Extract temporal features
                temporal = self._extract_temporal_features(event)
                
                # Combine features
                combined = np.concatenate([numerical, categorical, temporal])
                features.append(combined)
            
            return np.array(features)
        except Exception as e:
            logger.error(f"Feature extraction failed: {e}")
            return np.array([])

    def _extract_numerical_features(self, event: Dict) -> np.ndarray:
        """Extract numerical features from event"""
        features = []
        
        try:
            # Extract basic numerical features
            features.extend([
                event.get('bytes_in', 0),
                event.get('bytes_out', 0),
                event.get('packets_in', 0),
                event.get('packets_out', 0),
                event.get('duration', 0)
            ])
            
            # Extract statistical features
            if 'statistics' in event:
                stats = event['statistics']
                features.extend([
                    stats.get('mean', 0),
                    stats.get('std', 0),
                    stats.get('min', 0),
                    stats.get('max', 0)
                ])
        except Exception as e:
            logger.error(f"Numerical feature extraction failed: {e}")
        
        return np.array(features)

    def _extract_categorical_features(self, event: Dict) -> np.ndarray:
        """Extract categorical features from event"""
        features = []
        
        try:
            # One-hot encode protocol
            protocol = event.get('protocol', 'unknown')
            protocols = ['tcp', 'udp', 'icmp', 'unknown']
            features.extend([1 if p == protocol else 0 for p in protocols])
            
            # One-hot encode event type
            event_type = event.get('type', 'unknown')
            event_types = ['connection', 'alert', 'dns', 'http', 'unknown']
            features.extend([1 if t == event_type else 0 for t in event_types])
        except Exception as e:
            logger.error(f"Categorical feature extraction failed: {e}")
        
        return np.array(features)

    def _extract_temporal_features(self, event: Dict) -> np.ndarray:
        """Extract temporal features from event"""
        features = []
        
        try:
            timestamp = datetime.fromisoformat(event.get('timestamp', datetime.now().isoformat()))
            
            # Extract time-based features
            features.extend([
                timestamp.hour,
                timestamp.minute,
                timestamp.weekday(),
                1 if timestamp.hour in range(9, 17) else 0  # business hours
            ])
            
            # Calculate time-based statistics
            recent_events = self._get_recent_events(
                event.get('source_ip'),
                timestamp,
                minutes=5
            )
            
            if recent_events:
                features.extend([
                    len(recent_events),  # event frequency
                    np.mean([e.get('bytes_in', 0) for e in recent_events]),
                    np.std([e.get('bytes_out', 0) for e in recent_events])
                ])
            else:
                features.extend([0, 0, 0])
        except Exception as e:
            logger.error(f"Temporal feature extraction failed: {e}")
        
        return np.array(features)

    def _get_recent_events(self, source_ip: str, timestamp: datetime, minutes: int) -> List[Dict]:
        """Get recent events for source IP"""
        try:
            query = {
                'query': {
                    'bool': {
                        'must': [
                            {'term': {'source_ip': source_ip}},
                            {'range': {
                                'timestamp': {
                                    'gte': (timestamp - timedelta(minutes=minutes)).isoformat(),
                                    'lt': timestamp.isoformat()
                                }
                            }}
                        ]
                    }
                }
            }
            
            results = self.es.search(
                index='siem-events-*',
                body=query,
                size=1000
            )
            
            return [hit['_source'] for hit in results['hits']['hits']]
        except Exception as e:
            logger.error(f"Failed to get recent events: {e}")
            return []

    def _detect_anomalies(self, features: np.ndarray) -> np.ndarray:
        """Detect anomalies using Isolation Forest"""
        try:
            # Scale features
            scaled_features = self.anomaly_scaler.transform(features)
            
            # Predict anomalies
            # -1 for anomalies, 1 for normal
            predictions = self.anomaly_detector.predict(scaled_features)
            
            # Convert to anomaly scores (0 to 1)
            scores = self.anomaly_detector.score_samples(scaled_features)
            normalized_scores = (scores - scores.min()) / (scores.max() - scores.min())
            
            return normalized_scores
        except Exception as e:
            logger.error(f"Anomaly detection failed: {e}")
            return np.zeros(len(features))

    def _analyze_behavior(self, features: np.ndarray) -> List[Dict]:
        """Analyze behavior patterns using LSTM"""
        try:
            # Scale features
            scaled_features = self.behavior_scaler.transform(features)
            
            # Reshape for LSTM (samples, timesteps, features)
            reshaped = scaled_features.reshape((scaled_features.shape[0], 1, -1))
            
            # Predict behavior patterns
            predictions = self.behavior_model.predict(reshaped)
            
            # Convert predictions to behavior patterns
            patterns = []
            for pred in predictions:
                pattern = {
                    'normal': float(pred[0]),
                    'suspicious': float(pred[1]),
                    'malicious': float(pred[2])
                }
                patterns.append(pattern)
            
            return patterns
        except Exception as e:
            logger.error(f"Behavior analysis failed: {e}")
            return [{'normal': 1.0, 'suspicious': 0.0, 'malicious': 0.0}] * len(features)

    def _classify_threats(self, features: np.ndarray) -> List[str]:
        """Classify threats using Random Forest"""
        try:
            # Scale features
            scaled_features = self.threat_scaler.transform(features)
            
            # Predict threat classes
            predictions = self.threat_classifier.predict(scaled_features)
            probabilities = self.threat_classifier.predict_proba(scaled_features)
            
            # Convert predictions to threat classifications
            classifications = []
            for pred, prob in zip(predictions, probabilities):
                classification = {
                    'class': str(pred),
                    'confidence': float(max(prob)),
                    'probabilities': {
                        'benign': float(prob[0]),
                        'ddos': float(prob[1]),
                        'injection': float(prob[2]),
                        'malware': float(prob[3])
                    }
                }
                classifications.append(classification)
            
            return classifications
        except Exception as e:
            logger.error(f"Threat classification failed: {e}")
            return [{'class': 'unknown', 'confidence': 0.0}] * len(features)

    def _calculate_threat_score(self, threat: Dict) -> float:
        """Calculate overall threat score"""
        try:
            # Weights for different components
            weights = {
                'anomaly': 0.3,
                'behavior': 0.3,
                'classification': 0.4
            }
            
            # Calculate component scores
            anomaly_score = threat['anomaly_score']
            
            behavior_score = (
                threat['behavior_pattern']['suspicious'] * 0.5 +
                threat['behavior_pattern']['malicious'] * 1.0
            )
            
            classification_score = threat['threat_class']['confidence']
            if threat['threat_class']['class'] == 'benign':
                classification_score = 1.0 - classification_score
            
            # Calculate weighted sum
            total_score = (
                weights['anomaly'] * anomaly_score +
                weights['behavior'] * behavior_score +
                weights['classification'] * classification_score
            )
            
            return min(max(total_score, 0.0), 1.0)  # Ensure score is between 0 and 1
        except Exception as e:
            logger.error(f"Threat score calculation failed: {e}")
            return 0.0

    def _store_threat_result(self, threat: Dict):
        """Store threat detection result"""
        try:
            self.es.index(
                index='siem-threats',
                body=threat
            )
        except Exception as e:
            logger.error(f"Failed to store threat result: {e}")

    def update_models(self, training_data: pd.DataFrame):
        """Update ML models with new training data"""
        try:
            # Update anomaly detection model
            self._update_anomaly_detector(training_data)
            
            # Update behavior analysis model
            self._update_behavior_model(training_data)
            
            # Update threat classification model
            self._update_threat_classifier(training_data)
            
            logger.info("Successfully updated ML models")
        except Exception as e:
            logger.error(f"Failed to update models: {e}")

    def _update_anomaly_detector(self, data: pd.DataFrame):
        """Update anomaly detection model"""
        try:
            # Extract features
            features = self._extract_training_features(data)
            
            # Update scaler
            self.anomaly_scaler.fit(features)
            scaled_features = self.anomaly_scaler.transform(features)
            
            # Retrain model
            self.anomaly_detector.fit(scaled_features)
        except Exception as e:
            logger.error(f"Failed to update anomaly detector: {e}")

    def _update_behavior_model(self, data: pd.DataFrame):
        """Update behavior analysis model"""
        try:
            # Extract features and labels
            features = self._extract_training_features(data)
            labels = data['behavior_label'].values
            
            # Update scaler
            self.behavior_scaler.fit(features)
            scaled_features = self.behavior_scaler.transform(features)
            
            # Reshape for LSTM
            reshaped = scaled_features.reshape((scaled_features.shape[0], 1, -1))
            
            # Retrain model
            self.behavior_model.fit(
                reshaped,
                labels,
                epochs=10,
                batch_size=32,
                verbose=0
            )
        except Exception as e:
            logger.error(f"Failed to update behavior model: {e}")

    def _update_threat_classifier(self, data: pd.DataFrame):
        """Update threat classification model"""
        try:
            # Extract features and labels
            features = self._extract_training_features(data)
            labels = data['threat_label'].values
            
            # Update scaler
            self.threat_scaler.fit(features)
            scaled_features = self.threat_scaler.transform(features)
            
            # Retrain model
            self.threat_classifier.fit(scaled_features, labels)
        except Exception as e:
            logger.error(f"Failed to update threat classifier: {e}")

    def _extract_training_features(self, data: pd.DataFrame) -> np.ndarray:
        """Extract features from training data"""
        try:
            events = data.to_dict('records')
            return self._extract_features(events)
        except Exception as e:
            logger.error(f"Failed to extract training features: {e}")
            return np.array([])
