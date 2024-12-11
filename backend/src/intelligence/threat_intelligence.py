"""
Advanced Threat Intelligence Module for Enterprise SIEM
Integrates multiple threat feeds and provides comprehensive threat analysis
"""
import logging
import json
from typing import Dict, Any, List, Optional, Union, Tuple, Set, FrozenSet, Type, TypeVar, Callable, Iterator, Generator, overload, Literal, Protocol, runtime_checkable
from dataclasses import dataclass
from datetime import datetime
import uuid
import requests
import stix2
from stix2 import Filter
from taxii2client.v20 import Server
from ..core.utils import SecurityUtils, encrypt_data, decrypt_data
from ..core.database import Database
import numpy as np
import threading
import time
from functools import lru_cache
import os
from ..core.config import SIEMConfig
from ..models.base import Base, BaseModel
import joblib
from src.core.error_handler import error_handler, ErrorSeverity
from src.core.performance import performance_monitor

# Wrapper functions to maintain backwards compatibility
def encrypt_data(data, key=None):
    """
    Wrapper function for data encryption
    """
    if key is None:
        key, _ = SecurityUtils.generate_encryption_key("default_threat_key")
    
    return SecurityUtils.encrypt_data(data, key)

def decrypt_data(encrypted_data, key=None):
    """
    Wrapper function for data decryption
    """
    if key is None:
        key, _ = SecurityUtils.generate_encryption_key("default_threat_key")
    
    return SecurityUtils.decrypt_data(encrypted_data, key)

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

class ThreatIntelligenceEnhanced:
    """
    Advanced Threat Intelligence Module with Multi-Source Analysis
    """
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.threat_feeds = []
        self.ml_models = {}
        
        # Initialize threat intelligence components
        self._load_threat_feeds()
        self._load_ml_models()
    
    @performance_monitor.track_performance
    def _load_threat_feeds(self):
        """
        Load threat intelligence feeds from configuration
        """
        try:
            # Get threat feeds configuration
            feeds_config = self.config.get('threat_intelligence', {}).get('feeds', [])
            
            # Filter and load enabled feeds
            self.threat_feeds = [
                feed for feed in feeds_config 
                if feed.get('enabled', False)
            ]
            
            self.logger.info(f"Loaded {len(self.threat_feeds)} threat feeds")
            
            # Log feed details
            for feed in self.threat_feeds:
                self.logger.info(f"Enabled Feed: {feed['name']} (Type: {feed['type']})")
        
        except Exception as e:
            self.logger.error(f"Error loading threat feeds: {e}")
            self.threat_feeds = []
    
    @performance_monitor.track_performance
    def _load_ml_models(self):
        """
        Load multiple machine learning models for threat detection
        """
        try:
            # Get ML model configuration
            ml_config = self.config.get('threat_intelligence', {}).get('ml_models', {})
            default_model_path = ml_config.get('default_path', '')
            
            # Check if model path exists
            if not os.path.exists(default_model_path):
                self.logger.warning(f"ML model path not found: {default_model_path}")
                return {}
            
            # Load default anomaly detection model
            default_model = joblib.load(default_model_path)
            
            # Configure model parameters
            anomaly_config = ml_config.get('anomaly_detection', {})
            default_model.contamination = anomaly_config.get('contamination', 0.1)
            
            # Store models
            self.ml_models = {
                'anomaly_detection': default_model
            }
            
            self.logger.info(f"Loaded {len(self.ml_models)} ML models successfully")
        except Exception as e:
            self.logger.error(f"Error loading ML models: {e}")
            self.ml_models = {}
    
    def analyze_threat(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Comprehensive threat analysis using multiple models and feeds
        
        :param event_data: Event data to analyze
        :return: Threat analysis results
        """
        try:
            threat_scores = {}
            
            # Analyze using threat feeds
            for feed in self.threat_feeds:
                feed_score = self._evaluate_feed(feed, event_data)
                threat_scores[feed.get('name', 'Unknown Feed')] = feed_score
            
            # Analyze using ML models
            for model_name, model in self.ml_models.items():
                ml_score = self._evaluate_ml_model(model, event_data)
                threat_scores[model_name] = ml_score
            
            # Aggregate threat scores
            total_threat_score = self._aggregate_threat_scores(threat_scores)
            
            return {
                'threat_scores': threat_scores,
                'total_threat_score': total_threat_score,
                'is_threat': total_threat_score > 0.7  # Configurable threshold
            }
        except Exception as e:
            error_handler.handle_error(
                'ThreatIntelligence', 
                e, 
                ErrorSeverity.MEDIUM
            )
            return {'error': str(e)}
    
    def _evaluate_feed(self, feed: Dict[str, Any], event_data: Dict[str, Any]) -> float:
        """
        Evaluate threat based on feed rules
        
        :param feed: Threat feed data
        :param event_data: Event to evaluate
        :return: Threat score
        """
        # Implement feed-specific threat evaluation logic
        return 0.0
    
    def _evaluate_ml_model(self, model, event_data: Dict[str, Any]) -> float:
        """
        Evaluate threat using ML model
        
        :param model: ML model
        :param event_data: Event to evaluate
        :return: Threat probability
        """
        try:
            # Preprocess event data
            processed_data = self._preprocess_event_data(event_data)
            
            # Predict threat probability
            threat_probability = model.predict_proba([processed_data])[0][1]
            return float(threat_probability)
        except Exception as e:
            error_handler.handle_error(
                'MLThreatEvaluation', 
                e, 
                ErrorSeverity.LOW
            )
            return 0.0
    
    def _preprocess_event_data(self, event_data: Dict[str, Any]) -> np.ndarray:
        """
        Preprocess event data for ML models
        
        :param event_data: Raw event data
        :return: Preprocessed numpy array
        """
        # Implement data preprocessing logic
        return np.array([0.0])  # Placeholder
    
    def _aggregate_threat_scores(self, threat_scores: Dict[str, float]) -> float:
        """
        Aggregate threat scores from multiple sources
        
        :param threat_scores: Dictionary of threat scores
        :return: Aggregated threat score
        """
        if not threat_scores:
            return 0.0
        
        # Weighted average of threat scores
        scores = list(threat_scores.values())
        return np.mean(scores)
    
    def generate_threat_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive threat intelligence report
        
        :return: Threat report
        """
        try:
            return {
                'total_feeds': len(self.threat_feeds),
                'total_models': len(self.ml_models),
                'last_updated': str(datetime.now())
            }
        except Exception as e:
            error_handler.handle_error(
                'ThreatReport', 
                e, 
                ErrorSeverity.LOW
            )
            return {}

class ThreatIntelligence:
    """Advanced threat intelligence system with comprehensive analysis capabilities."""
    
    def __init__(self, config: Optional[SIEMConfig] = None):
        """
        Initialize threat intelligence system
        
        :param config: SIEM configuration object
        """
        self.logger = logging.getLogger(__name__)
        
        # Use provided config or load default
        self.config = config or SIEMConfig()
        
        # Initialize database with config
        db_path = self.config.database.get('path')
        self.db = Database(db_path)
        
        # Threat intelligence components
        self.threat_feeds = []
        self.ml_models = {}
        
        # Initialize components
        self._initialize_ml_components()
        self._initialize_threat_feeds()

    def _initialize_ml_components(self):
        """
        Initialize machine learning components for threat detection
        """
        try:
            # Get ML model configuration
            ml_config = self.config.threat_intelligence.get('ml_models', {})
            default_model_path = ml_config.get('default_path', '')
            
            # Check if model path exists
            if not os.path.exists(default_model_path):
                self.logger.warning(f"ML model path not found: {default_model_path}")
                return
            
            # Load default anomaly detection model
            default_model = joblib.load(default_model_path)
            
            # Configure model parameters
            anomaly_config = ml_config.get('anomaly_detection', {})
            default_model.contamination = anomaly_config.get('contamination', 0.1)
            
            # Store models
            self.ml_models = {
                'anomaly_detection': default_model
            }
            
            self.logger.info(f"Loaded {len(self.ml_models)} ML models successfully")
        except Exception as e:
            self.logger.error(f"Error initializing ML components: {e}")
            self.ml_models = {}

    def _initialize_threat_feeds(self):
        """
        Initialize threat intelligence feeds from configuration
        """
        try:
            # Get threat feeds configuration
            feeds_config = self.config.threat_intelligence.get('feeds', [])
            
            # Filter and load enabled feeds
            self.threat_feeds = [
                feed for feed in feeds_config 
                if feed.get('enabled', False)
            ]
            
            self.logger.info(f"Loaded {len(self.threat_feeds)} threat feeds")
            
            # Log feed details
            for feed in self.threat_feeds:
                self.logger.info(f"Enabled Feed: {feed['name']} (Type: {feed['type']})")
    
        except Exception as e:
            self.logger.error(f"Error loading threat feeds: {e}")
            self.threat_feeds = []

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

    def _initialize_feeds(self) -> List[Dict]:
        """
        Initialize threat intelligence feeds.
        
        :return: List of configured threat feeds
        """
        default_feeds = [
            {
                'name': 'AlienVault OTX',
                'type': 'otx',
                'url': 'https://otx.alienvault.com/api/v1/indicators',
                'enabled': True
            },
            {
                'name': 'VirusTotal',
                'type': 'virustotal',
                'url': 'https://www.virustotal.com/api/v3/indicators',
                'enabled': False  # Requires API key
            },
            {
                'name': 'MISP',
                'type': 'misp',
                'url': 'https://misp.example.com/feeds',
                'enabled': False
            }
        ]
        
        # Override with config if provided
        configured_feeds = self.config.get('threat_feeds', default_feeds)
        
        # Filter enabled feeds
        return [feed for feed in configured_feeds if feed.get('enabled', False)]

    def _initialize_stix_server(self) -> Optional[Server]:
        """
        Initialize STIX threat intelligence server.
        
        :return: TAXII2 Server instance or None
        """
        try:
            stix_config = self.config.get('stix_config', {})
            if not stix_config.get('enabled', False):
                return None
            
            server_url = stix_config.get('server_url')
            if not server_url:
                self.logger.warning("No STIX server URL configured")
                return None
            
            return Server(server_url)
        except Exception as e:
            self.logger.error(f"Error initializing STIX server: {e}")
            return None

    def _update_feeds(self):
        """
        Update threat intelligence feeds.
        """
        for feed in self.feeds:
            try:
                if feed['type'] == 'otx':
                    self._update_otx_feed(feed)
                elif feed['type'] == 'virustotal':
                    self._update_virustotal_feed(feed)
                elif feed['type'] == 'misp':
                    self._update_misp_feed(feed)
            except Exception as e:
                self.logger.error(f"Error updating feed {feed['name']}: {e}")

    def _update_otx_feed(self, feed: Dict):
        """
        Update OTX threat feed.
        
        :param feed: Feed configuration
        """
        # Placeholder for OTX feed update logic
        pass

    def _update_virustotal_feed(self, feed: Dict):
        """
        Update VirusTotal threat feed.
        
        :param feed: Feed configuration
        """
        # Placeholder for VirusTotal feed update logic
        pass

    def _update_misp_feed(self, feed: Dict):
        """
        Update MISP threat feed.
        
        :param feed: Feed configuration
        """
        # Placeholder for MISP feed update logic
        pass
