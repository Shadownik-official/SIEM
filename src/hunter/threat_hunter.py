"""
Advanced Threat Hunting Module for Enterprise SIEM
Provides sophisticated threat hunting capabilities with ML-powered analytics
"""
import logging
from typing import Dict, List, Optional, Union
from dataclasses import dataclass
from datetime import datetime
import uuid
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import tensorflow as tf
from ..core.utils import encrypt_data, decrypt_data
from ..core.database import Database
from ..intelligence.threat_intelligence import ThreatIntelligence
from ..monitor.network_monitor import NetworkMonitor

@dataclass
class HuntingRule:
    """Represents a threat hunting rule."""
    id: str
    name: str
    description: str
    tactics: List[str]  # MITRE ATT&CK tactics
    techniques: List[str]  # MITRE ATT&CK techniques
    data_sources: List[str]
    query: str
    severity: str
    author: str
    created: datetime
    updated: datetime
    enabled: bool
    tags: List[str]

@dataclass
class HuntingResult:
    """Represents the result of a threat hunt."""
    id: str
    rule_id: str
    timestamp: datetime
    severity: str
    confidence: float
    affected_assets: List[str]
    evidence: Dict
    context: Dict
    recommendations: List[str]
    status: str

class ThreatHunter:
    """Advanced threat hunting system with ML-powered detection."""
    
    def __init__(self, config: Dict = None):
        self.logger = logging.getLogger(__name__)
        self.db = Database()
        self.config = config or self._load_default_config()
        self.ti = ThreatIntelligence()
        self.network_monitor = NetworkMonitor()
        self._initialize_ml_models()
        
    def hunt_threats(self, data_sources: List[str], timeframe: str) -> List[HuntingResult]:
        """Execute threat hunting across specified data sources."""
        try:
            results = []
            
            # Load hunting rules
            rules = self._load_hunting_rules()
            
            # Collect data for analysis
            data = self._collect_hunting_data(data_sources, timeframe)
            
            # Apply ML-based anomaly detection
            anomalies = self._detect_anomalies(data)
            
            # Apply hunting rules
            for rule in rules:
                if not rule.enabled:
                    continue
                    
                # Execute rule
                rule_results = self._execute_hunting_rule(rule, data)
                results.extend(rule_results)
                
            # Correlate results with threat intelligence
            enriched_results = self._enrich_results(results)
            
            # Store results
            self._store_hunting_results(enriched_results)
            
            return enriched_results
            
        except Exception as e:
            self.logger.error(f"Error in threat hunting: {str(e)}")
            return []
            
    def create_hunting_rule(self, rule_data: Dict) -> HuntingRule:
        """Create a new threat hunting rule."""
        try:
            rule = HuntingRule(
                id=str(uuid.uuid4()),
                name=rule_data['name'],
                description=rule_data['description'],
                tactics=rule_data['tactics'],
                techniques=rule_data['techniques'],
                data_sources=rule_data['data_sources'],
                query=rule_data['query'],
                severity=rule_data['severity'],
                author=rule_data.get('author', 'system'),
                created=datetime.now(),
                updated=datetime.now(),
                enabled=True,
                tags=rule_data.get('tags', [])
            )
            
            # Validate rule
            self._validate_hunting_rule(rule)
            
            # Store rule
            self._store_hunting_rule(rule)
            
            return rule
            
        except Exception as e:
            self.logger.error(f"Error creating hunting rule: {str(e)}")
            return None
            
    def analyze_behavior(self, asset_id: str, timeframe: str) -> Dict:
        """Analyze asset behavior for potential threats."""
        try:
            analysis = {
                'asset_id': asset_id,
                'timestamp': datetime.now(),
                'behavioral_patterns': [],
                'anomalies': [],
                'risk_score': 0.0,
                'recommendations': []
            }
            
            # Collect asset data
            asset_data = self._collect_asset_data(asset_id, timeframe)
            
            # Analyze behavioral patterns
            patterns = self._analyze_patterns(asset_data)
            analysis['behavioral_patterns'] = patterns
            
            # Detect anomalies
            anomalies = self._detect_asset_anomalies(asset_data)
            analysis['anomalies'] = anomalies
            
            # Calculate risk score
            risk_score = self._calculate_risk_score(patterns, anomalies)
            analysis['risk_score'] = risk_score
            
            # Generate recommendations
            recommendations = self._generate_recommendations(patterns, anomalies)
            analysis['recommendations'] = recommendations
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error analyzing behavior: {str(e)}")
            return None
            
    def _initialize_ml_models(self) -> None:
        """Initialize machine learning models for threat detection."""
        try:
            # Initialize anomaly detection model
            self.anomaly_detector = IsolationForest(
                n_estimators=100,
                contamination=0.1,
                random_state=42
            )
            
            # Initialize behavior analysis model
            self.behavior_model = tf.keras.Sequential([
                tf.keras.layers.Dense(64, activation='relu'),
                tf.keras.layers.Dropout(0.2),
                tf.keras.layers.Dense(32, activation='relu'),
                tf.keras.layers.Dense(16, activation='relu'),
                tf.keras.layers.Dense(1, activation='sigmoid')
            ])
            
            # Load pre-trained weights if available
            self._load_model_weights()
            
        except Exception as e:
            self.logger.error(f"Error initializing ML models: {str(e)}")
            
    def _detect_anomalies(self, data: Dict) -> List[Dict]:
        """Detect anomalies using ML models."""
        try:
            anomalies = []
            
            # Prepare data
            X = self._prepare_data_for_ml(data)
            
            # Scale features
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)
            
            # Detect anomalies
            predictions = self.anomaly_detector.fit_predict(X_scaled)
            
            # Process anomalies
            for i, pred in enumerate(predictions):
                if pred == -1:  # Anomaly detected
                    anomaly = {
                        'timestamp': data['timestamps'][i],
                        'features': data['features'][i],
                        'score': float(self.anomaly_detector.score_samples([X_scaled[i]])[0]),
                        'context': self._get_anomaly_context(data, i)
                    }
                    anomalies.append(anomaly)
                    
            return anomalies
            
        except Exception as e:
            self.logger.error(f"Error detecting anomalies: {str(e)}")
            return []
            
    def _analyze_patterns(self, data: Dict) -> List[Dict]:
        """Analyze behavioral patterns in data."""
        try:
            patterns = []
            
            # Time-based pattern analysis
            time_patterns = self._analyze_time_patterns(data)
            patterns.extend(time_patterns)
            
            # Flow-based pattern analysis
            flow_patterns = self._analyze_flow_patterns(data)
            patterns.extend(flow_patterns)
            
            # Protocol-based pattern analysis
            protocol_patterns = self._analyze_protocol_patterns(data)
            patterns.extend(protocol_patterns)
            
            return patterns
            
        except Exception as e:
            self.logger.error(f"Error analyzing patterns: {str(e)}")
            return []
            
    def _calculate_risk_score(self, patterns: List[Dict], 
                            anomalies: List[Dict]) -> float:
        """Calculate risk score based on patterns and anomalies."""
        try:
            risk_score = 0.0
            
            # Base risk from patterns
            pattern_risk = self._calculate_pattern_risk(patterns)
            
            # Risk from anomalies
            anomaly_risk = self._calculate_anomaly_risk(anomalies)
            
            # Combine risks with weights
            risk_score = (0.4 * pattern_risk) + (0.6 * anomaly_risk)
            
            # Normalize to 0-100 scale
            risk_score = min(max(risk_score * 100, 0), 100)
            
            return risk_score
            
        except Exception as e:
            self.logger.error(f"Error calculating risk score: {str(e)}")
            return 0.0
            
    def _generate_recommendations(self, patterns: List[Dict], 
                                anomalies: List[Dict]) -> List[str]:
        """Generate security recommendations based on findings."""
        try:
            recommendations = []
            
            # Pattern-based recommendations
            for pattern in patterns:
                if pattern['risk_level'] >= 0.7:
                    rec = self._get_pattern_recommendation(pattern)
                    if rec:
                        recommendations.append(rec)
                        
            # Anomaly-based recommendations
            for anomaly in anomalies:
                if anomaly['score'] <= -0.8:
                    rec = self._get_anomaly_recommendation(anomaly)
                    if rec:
                        recommendations.append(rec)
                        
            # Deduplicate and prioritize
            recommendations = list(set(recommendations))
            recommendations.sort(key=lambda x: self._get_recommendation_priority(x))
            
            return recommendations
            
        except Exception as e:
            self.logger.error(f"Error generating recommendations: {str(e)}")
            return []
