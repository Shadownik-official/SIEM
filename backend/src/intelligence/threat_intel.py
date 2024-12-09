"""
Advanced Threat Intelligence Engine for Enterprise SIEM
"""
import logging
import json
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime
import uuid
import requests
import stix2
from stix2 import Filter
from taxii2client.v20 import Server
from .core import BaseIntelligence
from ..core.utils import encrypt_data, decrypt_data
from ..core.database import Database

@dataclass
class ThreatIndicator:
    """Represents a threat indicator."""
    id: str
    type: str
    value: str
    confidence: float
    severity: str
    tags: List[str]
    source: str
    first_seen: datetime
    last_seen: datetime
    context: Dict
    related_indicators: List[str]
    
@dataclass
class ThreatActor:
    """Represents a threat actor."""
    id: str
    name: str
    aliases: List[str]
    description: str
    motivation: str
    sophistication: str
    first_seen: datetime
    last_seen: datetime
    ttps: List[str]
    indicators: List[str]
    campaigns: List[str]
    
class ThreatIntelligence(BaseIntelligence):
    """Advanced threat intelligence engine with STIX/TAXII integration."""
    
    def __init__(self, config_path: str = None):
        super().__init__(config_path)
        self.logger = logging.getLogger(__name__)
        self.db = Database()
        self.sources = self._initialize_sources()
        self.stix_objects = {}
        self._initialize_taxii()
        
    def _initialize_sources(self) -> Dict:
        """Initialize threat intelligence sources."""
        try:
            sources = {}
            
            # Load source configurations
            for source in self.config['sources']:
                source_type = source['type']
                
                if source_type == 'taxii':
                    sources[source['name']] = self._setup_taxii_source(source)
                elif source_type == 'api':
                    sources[source['name']] = self._setup_api_source(source)
                elif source_type == 'file':
                    sources[source['name']] = self._setup_file_source(source)
                    
            return sources
            
        except Exception as e:
            self.logger.error(f"Error initializing sources: {str(e)}")
            return {}
            
    def _initialize_taxii(self) -> None:
        """Initialize TAXII server connections."""
        try:
            for source in self.config['sources']:
                if source['type'] == 'taxii':
                    server = Server(
                        source['url'],
                        user=source.get('username'),
                        password=source.get('password')
                    )
                    
                    # Store server instance
                    self.sources[source['name']]['server'] = server
                    
                    # Initialize collections
                    self._initialize_collections(source['name'], server)
                    
        except Exception as e:
            self.logger.error(f"Error initializing TAXII: {str(e)}")
            
    def update_intelligence(self) -> Dict:
        """Update threat intelligence from all sources."""
        try:
            results = {
                'new_indicators': 0,
                'updated_indicators': 0,
                'new_actors': 0,
                'updated_actors': 0,
                'errors': []
            }
            
            # Update from each source
            for source_name, source in self.sources.items():
                try:
                    if source['type'] == 'taxii':
                        source_results = self._update_from_taxii(source)
                    elif source['type'] == 'api':
                        source_results = self._update_from_api(source)
                    elif source['type'] == 'file':
                        source_results = self._update_from_file(source)
                        
                    # Aggregate results
                    results['new_indicators'] += source_results['new_indicators']
                    results['updated_indicators'] += source_results['updated_indicators']
                    results['new_actors'] += source_results['new_actors']
                    results['updated_actors'] += source_results['updated_actors']
                    
                except Exception as e:
                    error = f"Error updating from {source_name}: {str(e)}"
                    results['errors'].append(error)
                    self.logger.error(error)
                    
            return results
            
        except Exception as e:
            self.logger.error(f"Error updating intelligence: {str(e)}")
            return {'error': str(e)}
            
    def _update_from_taxii(self, source: Dict) -> Dict:
        """Update intelligence from TAXII source."""
        try:
            results = {
                'new_indicators': 0,
                'updated_indicators': 0,
                'new_actors': 0,
                'updated_actors': 0
            }
            
            # Get STIX bundles from collections
            for collection in source['collections']:
                # Get STIX objects
                objects = collection.get_objects()
                
                # Process objects
                for obj in objects:
                    if obj['type'] == 'indicator':
                        indicator = self._process_stix_indicator(obj)
                        if self._store_indicator(indicator):
                            results['new_indicators'] += 1
                        else:
                            results['updated_indicators'] += 1
                            
                    elif obj['type'] == 'threat-actor':
                        actor = self._process_stix_actor(obj)
                        if self._store_actor(actor):
                            results['new_actors'] += 1
                        else:
                            results['updated_actors'] += 1
                            
            return results
            
        except Exception as e:
            self.logger.error(f"Error updating from TAXII: {str(e)}")
            return {}
            
    def _process_stix_indicator(self, stix_obj: Dict) -> ThreatIndicator:
        """Process STIX indicator object."""
        try:
            return ThreatIndicator(
                id=stix_obj['id'],
                type=stix_obj['pattern_type'],
                value=stix_obj['pattern'],
                confidence=float(stix_obj.get('confidence', 0)),
                severity=self._determine_severity(stix_obj),
                tags=stix_obj.get('labels', []),
                source=stix_obj.get('created_by_ref', ''),
                first_seen=datetime.fromisoformat(stix_obj['valid_from']),
                last_seen=datetime.fromisoformat(stix_obj['valid_until']),
                context=self._extract_context(stix_obj),
                related_indicators=self._get_related_indicators(stix_obj)
            )
            
        except Exception as e:
            self.logger.error(f"Error processing STIX indicator: {str(e)}")
            return None
            
    def enrich_indicator(self, indicator: ThreatIndicator) -> Dict:
        """Enrich indicator with additional context."""
        try:
            enrichment = {
                'reputation': self._get_reputation(indicator),
                'relationships': self._get_relationships(indicator),
                'additional_context': {},
                'analysis': {}
            }
            
            # Enrich from various sources
            for source_name, source in self.sources.items():
                try:
                    if source['type'] == 'api':
                        source_data = self._enrich_from_api(source, indicator)
                        enrichment['additional_context'].update(source_data)
                        
                except Exception as e:
                    self.logger.error(f"Error enriching from {source_name}: {str(e)}")
                    
            # Perform analysis
            enrichment['analysis'] = self._analyze_indicator(indicator, enrichment)
            
            return enrichment
            
        except Exception as e:
            self.logger.error(f"Error enriching indicator: {str(e)}")
            return {}
            
    def search_indicators(self, query: Dict) -> List[ThreatIndicator]:
        """Search for threat indicators."""
        try:
            # Create STIX filter
            filter_obj = Filter(
                query.get('type'),
                query.get('property'),
                query.get('operator'),
                query.get('value')
            )
            
            # Search local database
            local_results = self._search_local_indicators(filter_obj)
            
            # Search external sources if needed
            if query.get('include_external', False):
                external_results = self._search_external_indicators(filter_obj)
                local_results.extend(external_results)
                
            return local_results
            
        except Exception as e:
            self.logger.error(f"Error searching indicators: {str(e)}")
            return []
            
    def get_actor_profile(self, actor_id: str) -> Dict:
        """Get detailed profile of a threat actor."""
        try:
            # Get basic actor information
            actor = self.db.get_actor(actor_id)
            if not actor:
                return None
                
            # Enrich with additional information
            profile = {
                'actor': actor,
                'indicators': self._get_actor_indicators(actor_id),
                'campaigns': self._get_actor_campaigns(actor_id),
                'ttps': self._get_actor_ttps(actor_id),
                'victims': self._get_actor_victims(actor_id),
                'infrastructure': self._get_actor_infrastructure(actor_id),
                'analysis': self._analyze_actor(actor)
            }
            
            return profile
            
        except Exception as e:
            self.logger.error(f"Error getting actor profile: {str(e)}")
            return None
            
    def generate_intel_report(self, indicators: List[ThreatIndicator], timeframe: Dict) -> Dict:
        """Generate comprehensive threat intelligence report."""
        try:
            report = {
                'summary': self._generate_summary(indicators, timeframe),
                'trends': self._analyze_trends(indicators, timeframe),
                'actor_analysis': self._analyze_actors(indicators),
                'infrastructure': self._analyze_infrastructure(indicators),
                'recommendations': self._generate_recommendations(indicators),
                'iocs': self._extract_iocs(indicators)
            }
            
            return report
            
        except Exception as e:
            self.logger.error(f"Error generating report: {str(e)}")
            return {}
