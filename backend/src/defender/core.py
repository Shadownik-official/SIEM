"""
Core Defensive Module for Enterprise SIEM
Handles threat detection, response, and mitigation
"""
import logging
import json
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass
import yaml
import requests
from elasticsearch import Elasticsearch
from redis import Redis

logger = logging.getLogger(__name__)

@dataclass
class ThreatInfo:
    severity: str
    category: str
    description: str
    mitigation_steps: List[str]
    ttps: List[str]  # Tactics, Techniques, and Procedures
    mitre_ids: List[str]
    indicators: Dict[str, str]

class DefenseCore:
    def __init__(self, es_client: Elasticsearch, redis_client: Redis):
        self.es = es_client
        self.redis = redis_client
        self.load_detection_rules()
        self.load_response_playbooks()
        
    def load_detection_rules(self):
        """Load detection rules from configuration"""
        try:
            with open('config/detection_rules.yaml', 'r') as f:
                self.rules = yaml.safe_load(f)
            logger.info(f"Loaded {len(self.rules)} detection rules")
        except Exception as e:
            logger.error(f"Failed to load detection rules: {e}")
            self.rules = []

    def load_response_playbooks(self):
        """Load incident response playbooks"""
        try:
            with open('config/response_playbooks.yaml', 'r') as f:
                self.playbooks = yaml.safe_load(f)
            logger.info(f"Loaded {len(self.playbooks)} response playbooks")
        except Exception as e:
            logger.error(f"Failed to load response playbooks: {e}")
            self.playbooks = []

    def analyze_event(self, event: Dict) -> List[ThreatInfo]:
        """Analyze event for potential threats"""
        threats = []
        
        # Apply detection rules
        for rule in self.rules:
            if self._matches_rule(event, rule):
                threat = self._create_threat_info(rule, event)
                threats.append(threat)
                
                # Cache threat detection for real-time correlation
                self._cache_threat_detection(threat, event)
        
        return threats

    def _matches_rule(self, event: Dict, rule: Dict) -> bool:
        """Check if event matches detection rule"""
        try:
            conditions = rule['conditions']
            for condition in conditions:
                field = condition['field']
                operator = condition['operator']
                value = condition['value']
                
                if field not in event:
                    return False
                
                if operator == 'equals':
                    if event[field] != value:
                        return False
                elif operator == 'contains':
                    if value not in event[field]:
                        return False
                elif operator == 'regex':
                    if not re.match(value, event[field]):
                        return False
                elif operator == 'greater_than':
                    if not event[field] > value:
                        return False
                elif operator == 'less_than':
                    if not event[field] < value:
                        return False
            
            return True
        except Exception as e:
            logger.error(f"Error matching rule: {e}")
            return False

    def _create_threat_info(self, rule: Dict, event: Dict) -> ThreatInfo:
        """Create threat information from matched rule"""
        return ThreatInfo(
            severity=rule['severity'],
            category=rule['category'],
            description=rule['description'],
            mitigation_steps=rule['mitigation_steps'],
            ttps=rule.get('ttps', []),
            mitre_ids=rule.get('mitre_ids', []),
            indicators=self._extract_indicators(event, rule)
        )

    def _extract_indicators(self, event: Dict, rule: Dict) -> Dict[str, str]:
        """Extract indicators of compromise from event"""
        indicators = {}
        for indicator_type in ['ip', 'domain', 'hash', 'url']:
            if indicator_type in event:
                indicators[indicator_type] = event[indicator_type]
        return indicators

    def _cache_threat_detection(self, threat: ThreatInfo, event: Dict):
        """Cache threat detection for correlation"""
        cache_key = f"threat:{event.get('source_ip', '')}:{event.get('timestamp', '')}"
        self.redis.setex(
            cache_key,
            3600,  # Cache for 1 hour
            json.dumps({
                'threat': threat.__dict__,
                'event': event
            })
        )

    def get_mitigation_steps(self, threat: ThreatInfo) -> List[str]:
        """Get detailed mitigation steps for a threat"""
        steps = []
        
        # Add immediate mitigation steps
        steps.extend(threat.mitigation_steps)
        
        # Add MITRE ATT&CK framework mitigations
        for mitre_id in threat.mitre_ids:
            mitigations = self._get_mitre_mitigations(mitre_id)
            steps.extend(mitigations)
        
        return steps

    def _get_mitre_mitigations(self, technique_id: str) -> List[str]:
        """Fetch mitigations from MITRE ATT&CK framework"""
        try:
            # Cache check
            cache_key = f"mitre:mitigation:{technique_id}"
            cached = self.redis.get(cache_key)
            if cached:
                return json.loads(cached)
            
            # Fetch from MITRE API
            url = f"https://attack.mitre.org/api/v1/techniques/{technique_id}/mitigations"
            response = requests.get(url)
            mitigations = response.json()
            
            # Extract mitigation steps
            steps = [m['description'] for m in mitigations]
            
            # Cache results
            self.redis.setex(cache_key, 86400, json.dumps(steps))  # Cache for 24 hours
            
            return steps
        except Exception as e:
            logger.error(f"Failed to fetch MITRE mitigations: {e}")
            return []

    def execute_response_playbook(self, threat: ThreatInfo, event: Dict) -> bool:
        """Execute automated response playbook for threat"""
        try:
            # Find matching playbook
            playbook = self._find_matching_playbook(threat)
            if not playbook:
                logger.warning("No matching playbook found for threat")
                return False
            
            # Execute playbook steps
            for step in playbook['steps']:
                self._execute_playbook_step(step, threat, event)
            
            # Log response actions
            self._log_response_actions(threat, playbook, event)
            
            return True
        except Exception as e:
            logger.error(f"Failed to execute response playbook: {e}")
            return False

    def _find_matching_playbook(self, threat: ThreatInfo) -> Optional[Dict]:
        """Find appropriate response playbook for threat"""
        for playbook in self.playbooks:
            if (playbook['severity'] == threat.severity and 
                playbook['category'] == threat.category):
                return playbook
        return None

    def _execute_playbook_step(self, step: Dict, threat: ThreatInfo, event: Dict):
        """Execute a single step in response playbook"""
        action = step['action']
        
        if action == 'block_ip':
            self._block_ip(event.get('source_ip'))
        elif action == 'isolate_host':
            self._isolate_host(event.get('hostname'))
        elif action == 'disable_user':
            self._disable_user(event.get('username'))
        elif action == 'create_ticket':
            self._create_incident_ticket(threat, event)
        elif action == 'notify_team':
            self._send_notification(threat, event)

    def _block_ip(self, ip: str):
        """Block malicious IP address"""
        # Implementation depends on firewall/network infrastructure
        pass

    def _isolate_host(self, hostname: str):
        """Isolate compromised host"""
        # Implementation depends on endpoint protection solution
        pass

    def _disable_user(self, username: str):
        """Disable compromised user account"""
        # Implementation depends on identity management system
        pass

    def _create_incident_ticket(self, threat: ThreatInfo, event: Dict):
        """Create incident ticket in ticketing system"""
        # Implementation depends on ticketing system (e.g., JIRA, ServiceNow)
        pass

    def _send_notification(self, threat: ThreatInfo, event: Dict):
        """Send notification to security team"""
        # Implementation depends on notification system
        pass

    def _log_response_actions(self, threat: ThreatInfo, playbook: Dict, event: Dict):
        """Log automated response actions"""
        doc = {
            'timestamp': datetime.now().isoformat(),
            'threat': threat.__dict__,
            'playbook': playbook,
            'event': event,
            'status': 'completed'
        }
        
        self.es.index(
            index='siem-response-actions',
            body=doc
        )
