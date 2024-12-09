"""
Advanced Threat Intelligence Module for Enterprise SIEM
Integrates multiple threat feeds and provides comprehensive threat analysis
"""
import logging
import json
from typing import Dict, List, Optional, Union, Tuple
from dataclasses import dataclass
from datetime import datetime
import uuid
import requests
import stix2
from stix2 import Filter
from taxii2client.v20 import Server
from ..core.utils import encrypt_data, decrypt_data
from ..core.database import Database
import numpy as np
import threading
import time
from functools import lru_cache
import os

@dataclass
class ThreatIndicator:
    """Represents a threat indicator."""
    id: str
    type: str
    value: str
    confidence: float
    severity: str
    source: str
    first_seen: datetime
    last_seen: datetime
    tags: List[str]
    related_indicators: List[str]
    context: Dict

@dataclass
class ThreatActor:
    """Represents a threat actor profile."""
    id: str
    name: str
    aliases: List[str]
    description: str
    motivation: List[str]
    sophistication: str
    ttps: List[str]
    indicators: List[str]
    campaigns: List[str]
    first_seen: datetime
    last_seen: datetime

class ThreatIntelligence:
    """Advanced threat intelligence system with comprehensive analysis capabilities."""
    
    def __init__(self, config: Dict = None):
        self.logger = logging.getLogger(__name__)
        self.db = Database()
        self.config = config or self._load_default_config()
        self.feeds = self._initialize_feeds()
        self.stix_server = self._initialize_stix_server()
        self.indicator_cache = {}
        self.actor_cache = {}
        self.running = False
        self.update_thread = None
        self._initialize_ml_components()
        self._start_feed_updates()
        
    def _initialize_ml_components(self):
        """Initialize machine learning components"""
        try:
            model_path = self.config.get('ml_config', {}).get('model_path')
            if model_path and os.path.exists(model_path):
                self.ml_model = self._load_ml_model(model_path)
                self.feature_extractor = self._load_feature_extractor()
            else:
                self.logger.warning("ML model path not found, ML features disabled")
                self.ml_model = None
                self.feature_extractor = None
        except Exception as e:
            self.logger.error(f"Error initializing ML components: {str(e)}")
            self.ml_model = None
            self.feature_extractor = None
            
    def shutdown(self):
        """Gracefully shutdown the threat intelligence system"""
        self.logger.info("Shutting down threat intelligence system...")
        self.running = False
        if self.update_thread:
            self.update_thread.join()
        self.db.close()
        self.logger.info("Threat intelligence system shutdown complete")
        
    def _start_feed_updates(self):
        """Start background thread for feed updates"""
        self.running = True
        self.update_thread = threading.Thread(
            target=self._feed_update_loop,
            daemon=True
        )
        self.update_thread.start()
        
    def _feed_update_loop(self):
        """Background loop for updating threat feeds"""
        update_interval = self.config.get('update_interval', 3600)
        while self.running:
            try:
                self._update_feeds()
                time.sleep(update_interval)
            except Exception as e:
                self.logger.error(f"Error updating feeds: {str(e)}")
                time.sleep(60)  # Wait before retry
                
    @lru_cache(maxsize=1000)
    def _get_cached_indicator(self, indicator_id: str) -> Optional[ThreatIndicator]:
        """Get cached threat indicator"""
        return self.indicator_cache.get(indicator_id)
        
    @lru_cache(maxsize=1000)
    def _get_cached_actor(self, actor_id: str) -> Optional[ThreatActor]:
        """Get cached threat actor"""
        return self.actor_cache.get(actor_id)
        
    def analyze_threat(self, data: Dict) -> Dict:
        """Perform comprehensive threat analysis."""
        try:
            # Start with basic analysis
            analysis = {
                'id': str(uuid.uuid4()),
                'timestamp': datetime.now().isoformat(),
                'source_data': data,
                'status': 'in_progress'
            }
            
            try:
                # Find matching indicators
                analysis['indicators'] = self._find_matching_indicators(data)
            except Exception as e:
                self.logger.error(f"Error finding indicators: {str(e)}")
                analysis['indicators'] = []
                
            try:
                # Identify threat actors
                analysis['actors'] = self._identify_threat_actors(data)
            except Exception as e:
                self.logger.error(f"Error identifying actors: {str(e)}")
                analysis['actors'] = []
                
            try:
                # Calculate risk score
                analysis['risk_score'] = self._calculate_risk_score(data)
            except Exception as e:
                self.logger.error(f"Error calculating risk: {str(e)}")
                analysis['risk_score'] = 0.0
                
            # Add additional context and recommendations
            analysis.update({
                'context': self._gather_threat_context(data),
                'mitre_mapping': self._map_to_mitre_attack(data),
                'historical_context': self._get_historical_context(data),
                'recommendations': self._generate_recommendations(data),
                'response_actions': self._suggest_response_actions(analysis),
                'status': 'completed'
            })
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error in threat analysis: {str(e)}")
            return {
                'id': str(uuid.uuid4()),
                'timestamp': datetime.now().isoformat(),
                'status': 'error',
                'error': str(e),
                'source_data': data
            }
            
    def _find_matching_indicators(self, data: Dict) -> List[ThreatIndicator]:
        """Find matching threat indicators in the data."""
        try:
            matches = []
            
            # Check IP addresses
            ip_matches = self._check_ip_indicators(data)
            matches.extend(ip_matches)
            
            # Check domains
            domain_matches = self._check_domain_indicators(data)
            matches.extend(domain_matches)
            
            # Check file hashes
            hash_matches = self._check_hash_indicators(data)
            matches.extend(hash_matches)
            
            # Check URLs
            url_matches = self._check_url_indicators(data)
            matches.extend(url_matches)
            
            return self._deduplicate_indicators(matches)
            
        except Exception as e:
            self.logger.error(f"Error finding matching indicators: {str(e)}")
            return []
            
    def _identify_threat_actors(self, data: Dict) -> List[ThreatActor]:
        """Identify potential threat actors based on TTPs and indicators."""
        try:
            potential_actors = []
            
            # Match based on indicators
            indicator_matches = self._match_actors_by_indicators(data)
            potential_actors.extend(indicator_matches)
            
            # Match based on TTPs
            ttp_matches = self._match_actors_by_ttps(data)
            potential_actors.extend(ttp_matches)
            
            # Score and rank actors
            scored_actors = self._score_actor_matches(potential_actors, data)
            
            return sorted(scored_actors, key=lambda x: x['score'], reverse=True)
            
        except Exception as e:
            self.logger.error(f"Error identifying threat actors: {str(e)}")
            return []
            
    def _calculate_risk_score(self, data: Dict) -> float:
        """Calculate comprehensive risk score."""
        try:
            weights = self.config.risk_weights
            score_components = {
                'indicator_score': self._calculate_indicator_score(data) * weights['indicators'],
                'actor_score': self._calculate_actor_score(data) * weights['actors'],
                'context_score': self._calculate_context_score(data) * weights['context'],
                'impact_score': self._calculate_impact_score(data) * weights['impact']
            }
            
            total_score = sum(score_components.values())
            normalized_score = min(max(total_score, 0), 100)
            
            return normalized_score
            
        except Exception as e:
            self.logger.error(f"Error calculating risk score: {str(e)}")
            return 0.0
            
    def _map_to_mitre_attack(self, data: Dict) -> Dict:
        """Map threat data to MITRE ATT&CK framework."""
        try:
            mapping = {
                'tactics': self._identify_tactics(data),
                'techniques': self._identify_techniques(data),
                'procedures': self._identify_procedures(data),
                'mitigations': self._get_mitre_mitigations(data)
            }
            
            return mapping
            
        except Exception as e:
            self.logger.error(f"Error mapping to MITRE ATT&CK: {str(e)}")
            return {}
            
    def _suggest_response_actions(self, analysis: Dict) -> List[Dict]:
        """Generate suggested response actions based on threat analysis."""
        try:
            actions = []
            
            # Add containment actions
            containment = self._generate_containment_actions(analysis)
            actions.extend(containment)
            
            # Add investigation actions
            investigation = self._generate_investigation_actions(analysis)
            actions.extend(investigation)
            
            # Add mitigation actions
            mitigation = self._generate_mitigation_actions(analysis)
            actions.extend(mitigation)
            
            # Prioritize actions
            return self._prioritize_actions(actions, analysis)
            
        except Exception as e:
            self.logger.error(f"Error suggesting response actions: {str(e)}")
            return []
            
    def collect_threat_intelligence(self) -> Dict:
        """Collect threat intelligence from all configured sources."""
        try:
            intelligence = {
                'timestamp': datetime.now(),
                'indicators': self._collect_indicators(),
                'actors': self._collect_threat_actors(),
                'campaigns': self._collect_campaigns(),
                'ttps': self._collect_ttps(),
                'vulnerabilities': self._collect_vulnerabilities()
            }
            
            # Update intelligence database
            self._update_intelligence_database(intelligence)
            
            return intelligence
            
        except Exception as e:
            self.logger.error(f"Error collecting threat intelligence: {str(e)}")
            return {}
            
    def analyze_indicators(self, indicators: List[ThreatIndicator]) -> Dict:
        """Analyze threat indicators for patterns and relationships."""
        try:
            analysis = {
                'timestamp': datetime.now(),
                'patterns': self._identify_patterns(indicators),
                'relationships': self._map_relationships(indicators),
                'trends': self._analyze_trends(indicators),
                'risk_assessment': self._assess_indicator_risk(indicators),
                'recommendations': self._generate_recommendations(indicators)
            }
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error analyzing indicators: {str(e)}")
            return {}
            
    def profile_threat_actor(self, actor: ThreatActor) -> Dict:
        """Generate comprehensive threat actor profile."""
        try:
            profile = {
                'actor_id': actor.id,
                'timestamp': datetime.now(),
                'capabilities': self._assess_capabilities(actor),
                'infrastructure': self._map_infrastructure(actor),
                'techniques': self._analyze_techniques(actor),
                'targets': self._identify_targets(actor),
                'historical_activities': self._get_historical_activities(actor),
                'prediction': self._predict_future_activities(actor)
            }
            
            return profile
            
        except Exception as e:
            self.logger.error(f"Error profiling threat actor: {str(e)}")
            return {}
            
    def enrich_indicator(self, indicator: ThreatIndicator) -> ThreatIndicator:
        """Enrich threat indicator with additional context."""
        try:
            # Query multiple enrichment sources
            whois_data = self._query_whois(indicator)
            reputation_data = self._query_reputation(indicator)
            malware_data = self._query_malware_analysis(indicator)
            
            # Combine enrichment data
            enriched_context = {
                **indicator.context,
                'whois': whois_data,
                'reputation': reputation_data,
                'malware_analysis': malware_data
            }
            
            # Create enriched indicator
            enriched_indicator = ThreatIndicator(
                **{**indicator.__dict__, 'context': enriched_context}
            )
            
            return enriched_indicator
            
        except Exception as e:
            self.logger.error(f"Error enriching indicator: {str(e)}")
            return indicator
            
    def search_intelligence(self, query: Dict) -> Dict:
        """Search threat intelligence database."""
        try:
            results = {
                'timestamp': datetime.now(),
                'indicators': self._search_indicators(query),
                'actors': self._search_actors(query),
                'campaigns': self._search_campaigns(query),
                'ttps': self._search_ttps(query),
                'context': self._get_search_context(query)
            }
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error searching intelligence: {str(e)}")
            return {}
            
    def generate_intelligence_report(self) -> Dict:
        """Generate comprehensive threat intelligence report."""
        try:
            report = {
                'timestamp': datetime.now(),
                'summary': self._generate_summary(),
                'indicators': self._summarize_indicators(),
                'actors': self._summarize_actors(),
                'campaigns': self._summarize_campaigns(),
                'emerging_threats': self._identify_emerging_threats(),
                'recommendations': self._generate_intel_recommendations()
            }
            
            return report
            
        except Exception as e:
            self.logger.error(f"Error generating intelligence report: {str(e)}")
            return {}
            
    def _identify_emerging_threats(self) -> List[Dict]:
        """Identify emerging threats and trends."""
        try:
            threats = []
            
            # Analyze recent intelligence
            recent_intel = self._get_recent_intelligence()
            
            # Identify new patterns
            new_patterns = self._identify_new_patterns(recent_intel)
            
            # Analyze threat evolution
            evolving_threats = self._analyze_threat_evolution()
            
            # Predict emerging threats
            predicted_threats = self._predict_threats()
            
            threats.extend(new_patterns)
            threats.extend(evolving_threats)
            threats.extend(predicted_threats)
            
            return threats
            
        except Exception as e:
            self.logger.error(f"Error identifying emerging threats: {str(e)}")
            return []
            
    def get_intelligence_dashboard(self) -> Dict:
        """Get threat intelligence dashboard data."""
        try:
            dashboard = {
                'recent_indicators': self._get_recent_indicators(),
                'active_threats': self._get_active_threats(),
                'threat_trends': self._get_threat_trends(),
                'intel_metrics': self._get_intelligence_metrics(),
                'coverage_analysis': self._get_coverage_analysis(),
                'feed_status': self._get_feed_status()
            }
            
            return dashboard
            
        except Exception as e:
            self.logger.error(f"Error getting intelligence dashboard: {str(e)}")
            return {}
            
    def analyze_threat_pattern(self, events: List[Dict]) -> Dict:
        """
        Advanced threat pattern analysis using ML/AI
        """
        analysis_result = {
            'risk_score': 0.0,
            'anomalies': [],
            'patterns': [],
            'recommendations': []
        }

        # Feature extraction
        event_features = self._extract_features(events)
        
        # ML-based anomaly detection
        anomalies = self.ml_model.detect_anomalies(event_features)
        if anomalies:
            analysis_result['anomalies'] = anomalies
            analysis_result['risk_score'] = self._calculate_risk_score(anomalies)

        # Pattern recognition
        patterns = self.pattern_analyzer.find_patterns(events)
        if patterns:
            analysis_result['patterns'] = patterns
            
        # Generate recommendations
        analysis_result['recommendations'] = self._generate_recommendations(
            anomalies, patterns
        )

        return analysis_result

    def _extract_features(self, events: List[Dict]) -> np.ndarray:
        """Extract features for ML analysis"""
        features = []
        for event in events:
            event_vector = self.feature_extractor.transform(event)
            features.append(event_vector)
        return np.array(features)

    def _calculate_risk_score(self, anomalies: List[Dict]) -> float:
        """Calculate risk score based on detected anomalies"""
        base_score = 0.0
        for anomaly in anomalies:
            severity = anomaly.get('severity', 'low')
            confidence = anomaly.get('confidence', 0.5)
            
            # Weight by severity
            severity_weights = {
                'critical': 1.0,
                'high': 0.8,
                'medium': 0.5,
                'low': 0.2
            }
            
            base_score += severity_weights.get(severity, 0.1) * confidence
            
        return min(base_score, 1.0) * 10  # Scale to 0-10
