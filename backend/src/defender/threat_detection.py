"""
Advanced Threat Detection Engine for Enterprise SIEM
"""
import logging
import json
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime
import numpy as np
from sklearn.ensemble import IsolationForest
import tensorflow as tf
from .core import BaseDefender
from ..core.utils import encrypt_data, decrypt_data
from ..core.database import Database

@dataclass
class ThreatIndicator:
    """Represents a detected threat indicator."""
    id: str
    type: str
    severity: str
    confidence: float
    description: str
    source: str
    timestamp: datetime
    affected_assets: List[str]
    indicators: Dict[str, str]
    mitigations: List[str]

class ThreatDetectionEngine(BaseDefender):
    """Advanced threat detection engine using ML/AI."""
    
    def __init__(self, config_path: str = None):
        super().__init__(config_path)
        self.logger = logging.getLogger(__name__)
        self.db = Database()
        self.ml_models = self._initialize_ml_models()
        self.threat_patterns = self._load_threat_patterns()
        self.mitigation_strategies = self._load_mitigation_strategies()
        
    def _initialize_ml_models(self) -> Dict:
        """Initialize machine learning models for threat detection."""
        try:
            models = {
                'anomaly_detector': IsolationForest(
                    contamination=0.1,
                    random_state=42
                ),
                'behavior_analyzer': self._create_behavior_model(),
                'threat_classifier': self._create_threat_classifier()
            }
            return models
        except Exception as e:
            self.logger.error(f"Error initializing ML models: {str(e)}")
            return {}
            
    def _create_behavior_model(self) -> tf.keras.Model:
        """Create deep learning model for behavior analysis."""
        try:
            model = tf.keras.Sequential([
                tf.keras.layers.LSTM(128, return_sequences=True),
                tf.keras.layers.LSTM(64),
                tf.keras.layers.Dense(32, activation='relu'),
                tf.keras.layers.Dense(16, activation='relu'),
                tf.keras.layers.Dense(1, activation='sigmoid')
            ])
            model.compile(
                optimizer='adam',
                loss='binary_crossentropy',
                metrics=['accuracy']
            )
            return model
        except Exception as e:
            self.logger.error(f"Error creating behavior model: {str(e)}")
            return None
            
    def _create_threat_classifier(self) -> tf.keras.Model:
        """Create deep learning model for threat classification."""
        try:
            model = tf.keras.Sequential([
                tf.keras.layers.Dense(64, activation='relu'),
                tf.keras.layers.Dropout(0.3),
                tf.keras.layers.Dense(32, activation='relu'),
                tf.keras.layers.Dropout(0.2),
                tf.keras.layers.Dense(16, activation='relu'),
                tf.keras.layers.Dense(8, activation='softmax')
            ])
            model.compile(
                optimizer='adam',
                loss='categorical_crossentropy',
                metrics=['accuracy']
            )
            return model
        except Exception as e:
            self.logger.error(f"Error creating threat classifier: {str(e)}")
            return None
            
    def detect_threats(self, events: List[Dict]) -> List[ThreatIndicator]:
        """Detect threats from incoming events using multiple detection methods."""
        try:
            threats = []
            
            # 1. Rule-based detection
            rule_threats = self._apply_detection_rules(events)
            threats.extend(rule_threats)
            
            # 2. ML-based anomaly detection
            anomaly_threats = self._detect_anomalies(events)
            threats.extend(anomaly_threats)
            
            # 3. Behavior analysis
            behavior_threats = self._analyze_behavior(events)
            threats.extend(behavior_threats)
            
            # 4. Pattern matching
            pattern_threats = self._match_threat_patterns(events)
            threats.extend(pattern_threats)
            
            # 5. Correlation analysis
            correlated_threats = self._correlate_events(events)
            threats.extend(correlated_threats)
            
            # Deduplicate and enrich threats
            unique_threats = self._deduplicate_threats(threats)
            enriched_threats = self._enrich_threats(unique_threats)
            
            # Store threats in database
            self._store_threats(enriched_threats)
            
            return enriched_threats
            
        except Exception as e:
            self.logger.error(f"Error in threat detection: {str(e)}")
            return []
            
    def _apply_detection_rules(self, events: List[Dict]) -> List[ThreatIndicator]:
        """Apply predefined detection rules to events."""
        threats = []
        try:
            for event in events:
                # Apply each detection rule
                for rule in self.detection_rules:
                    if rule.matches(event):
                        threat = ThreatIndicator(
                            id=str(uuid.uuid4()),
                            type=rule.threat_type,
                            severity=rule.severity,
                            confidence=rule.confidence,
                            description=rule.description,
                            source='rule_based',
                            timestamp=datetime.now(),
                            affected_assets=[event.get('source')],
                            indicators=rule.extract_indicators(event),
                            mitigations=rule.get_mitigations()
                        )
                        threats.append(threat)
            return threats
        except Exception as e:
            self.logger.error(f"Error in rule-based detection: {str(e)}")
            return []
            
    def _detect_anomalies(self, events: List[Dict]) -> List[ThreatIndicator]:
        """Detect anomalies using machine learning."""
        threats = []
        try:
            # Extract features for anomaly detection
            features = self._extract_features(events)
            
            # Run anomaly detection
            predictions = self.ml_models['anomaly_detector'].predict(features)
            
            # Process anomalies
            for idx, pred in enumerate(predictions):
                if pred == -1:  # Anomaly detected
                    event = events[idx]
                    threat = ThreatIndicator(
                        id=str(uuid.uuid4()),
                        type='anomaly',
                        severity='medium',
                        confidence=0.8,
                        description='Anomalous behavior detected',
                        source='ml_anomaly',
                        timestamp=datetime.now(),
                        affected_assets=[event.get('source')],
                        indicators=self._extract_anomaly_indicators(event),
                        mitigations=self._get_anomaly_mitigations(event)
                    )
                    threats.append(threat)
            return threats
        except Exception as e:
            self.logger.error(f"Error in anomaly detection: {str(e)}")
            return []
            
    def _analyze_behavior(self, events: List[Dict]) -> List[ThreatIndicator]:
        """Analyze behavior patterns for threats."""
        threats = []
        try:
            # Extract behavioral features
            features = self._extract_behavior_features(events)
            
            # Analyze behavior using deep learning model
            predictions = self.ml_models['behavior_analyzer'].predict(features)
            
            # Process behavior analysis results
            for idx, pred in enumerate(predictions):
                if pred > 0.8:  # High probability of malicious behavior
                    event = events[idx]
                    threat = ThreatIndicator(
                        id=str(uuid.uuid4()),
                        type='malicious_behavior',
                        severity='high',
                        confidence=float(pred),
                        description='Suspicious behavior pattern detected',
                        source='behavior_analysis',
                        timestamp=datetime.now(),
                        affected_assets=[event.get('source')],
                        indicators=self._extract_behavior_indicators(event),
                        mitigations=self._get_behavior_mitigations(event)
                    )
                    threats.append(threat)
            return threats
        except Exception as e:
            self.logger.error(f"Error in behavior analysis: {str(e)}")
            return []
            
    def _match_threat_patterns(self, events: List[Dict]) -> List[ThreatIndicator]:
        """Match events against known threat patterns."""
        threats = []
        try:
            for pattern in self.threat_patterns:
                matches = pattern.match(events)
                for match in matches:
                    threat = ThreatIndicator(
                        id=str(uuid.uuid4()),
                        type=pattern.type,
                        severity=pattern.severity,
                        confidence=pattern.confidence,
                        description=pattern.description,
                        source='pattern_matching',
                        timestamp=datetime.now(),
                        affected_assets=match.get('affected_assets', []),
                        indicators=match.get('indicators', {}),
                        mitigations=pattern.mitigations
                    )
                    threats.append(threat)
            return threats
        except Exception as e:
            self.logger.error(f"Error in pattern matching: {str(e)}")
            return []
            
    def _correlate_events(self, events: List[Dict]) -> List[ThreatIndicator]:
        """Correlate events to identify complex threats."""
        threats = []
        try:
            # Group related events
            event_groups = self._group_related_events(events)
            
            # Analyze each group for threat patterns
            for group in event_groups:
                correlated_threats = self._analyze_event_group(group)
                threats.extend(correlated_threats)
                
            return threats
        except Exception as e:
            self.logger.error(f"Error in event correlation: {str(e)}")
            return []
            
    def _deduplicate_threats(self, threats: List[ThreatIndicator]) -> List[ThreatIndicator]:
        """Remove duplicate threat detections."""
        try:
            unique_threats = {}
            for threat in threats:
                key = (threat.type, tuple(sorted(threat.affected_assets)))
                if key not in unique_threats or threat.confidence > unique_threats[key].confidence:
                    unique_threats[key] = threat
            return list(unique_threats.values())
        except Exception as e:
            self.logger.error(f"Error in threat deduplication: {str(e)}")
            return threats
            
    def _enrich_threats(self, threats: List[ThreatIndicator]) -> List[ThreatIndicator]:
        """Enrich threats with additional context and intelligence."""
        try:
            for threat in threats:
                # Add threat intelligence
                threat = self._add_threat_intelligence(threat)
                
                # Add asset context
                threat = self._add_asset_context(threat)
                
                # Add historical context
                threat = self._add_historical_context(threat)
                
                # Update mitigation strategies
                threat = self._update_mitigations(threat)
                
            return threats
        except Exception as e:
            self.logger.error(f"Error in threat enrichment: {str(e)}")
            return threats
            
    def _store_threats(self, threats: List[ThreatIndicator]) -> None:
        """Store detected threats in the database."""
        try:
            for threat in threats:
                # Encrypt sensitive data
                encrypted_threat = encrypt_data(threat.__dict__)
                
                # Store in database
                self.db.store_threat(encrypted_threat)
                
        except Exception as e:
            self.logger.error(f"Error storing threats: {str(e)}")
            
    def get_mitigations(self, threat: ThreatIndicator) -> List[Dict]:
        """Get detailed mitigation strategies for a threat."""
        try:
            mitigations = []
            
            # Get base mitigations for threat type
            base_mitigations = self.mitigation_strategies.get(threat.type, [])
            mitigations.extend(base_mitigations)
            
            # Get specific mitigations based on indicators
            specific_mitigations = self._get_specific_mitigations(threat)
            mitigations.extend(specific_mitigations)
            
            # Prioritize and deduplicate mitigations
            unique_mitigations = self._prioritize_mitigations(mitigations)
            
            return unique_mitigations
            
        except Exception as e:
            self.logger.error(f"Error getting mitigations: {str(e)}")
            return []
