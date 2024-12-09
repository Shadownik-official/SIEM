from sqlalchemy.orm import Session
from typing import List, Dict, Any, Optional

from ..models.threat_intelligence import ThreatIntelligence, ThreatType, ThreatSeverity
from ..repositories.threat_intelligence_repository import ThreatIntelligenceRepository
from ..services.base import BaseService
from ..core.exceptions import ThreatIntelligenceError

class ThreatIntelligenceService(BaseService[ThreatIntelligenceRepository]):
    """
    Service layer for advanced threat intelligence management and processing.
    """
    def __init__(self, db_session: Session):
        threat_intel_repository = ThreatIntelligenceRepository(db_session)
        super().__init__(threat_intel_repository, db_session)

    def create_threat_intelligence(
        self, 
        threat_id: str,
        name: str,
        threat_type: ThreatType,
        severity: ThreatSeverity = ThreatSeverity.LOW,
        description: Optional[str] = None,
        source: Optional[str] = None,
        ioc_data: Optional[Dict[str, Any]] = None,
        mitre_attack_techniques: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        expiration_days: int = 30
    ) -> ThreatIntelligence:
        """
        Create and persist new threat intelligence.
        
        :param threat_id: Unique threat identifier
        :param name: Threat name
        :param threat_type: Type of threat
        :param severity: Threat severity
        :param description: Detailed threat description
        :param source: Source of threat intelligence
        :param ioc_data: Indicators of Compromise
        :param mitre_attack_techniques: MITRE ATT&CK Techniques
        :param tags: Additional tags
        :param expiration_days: Days until threat intelligence expires
        :return: Created ThreatIntelligence
        """
        try:
            # Check for existing threat intelligence
            existing_threat = self.repository.get_by_threat_id(threat_id)
            if existing_threat:
                raise ThreatIntelligenceError(f"Threat with ID {threat_id} already exists")
            
            threat_intel = ThreatIntelligence.create_threat_intelligence(
                threat_id=threat_id,
                name=name,
                threat_type=threat_type,
                severity=severity,
                description=description,
                source=source,
                ioc_data=ioc_data,
                mitre_attack_techniques=mitre_attack_techniques,
                tags=tags,
                expiration_days=expiration_days
            )
            
            return self.repository.create(threat_intel)
        
        except Exception as e:
            self.rollback_transaction()
            raise ThreatIntelligenceError(f"Failed to create threat intelligence: {e}")

    def update_threat_intelligence(
        self, 
        threat_id: str, 
        **kwargs
    ) -> ThreatIntelligence:
        """
        Update existing threat intelligence.
        
        :param threat_id: Unique threat identifier
        :param kwargs: Fields to update
        :return: Updated ThreatIntelligence
        """
        try:
            threat_intel = self.repository.get_by_threat_id(threat_id)
            
            if not threat_intel:
                raise ThreatIntelligenceError(f"Threat with ID {threat_id} not found")
            
            # Update fields dynamically
            for key, value in kwargs.items():
                if hasattr(threat_intel, key):
                    setattr(threat_intel, key, value)
            
            return self.repository.update(threat_intel)
        
        except Exception as e:
            self.rollback_transaction()
            raise ThreatIntelligenceError(f"Failed to update threat intelligence: {e}")

    def analyze_threat_landscape(
        self, 
        time_window_days: int = 30
    ) -> Dict[str, Any]:
        """
        Perform comprehensive threat landscape analysis.
        
        :param time_window_days: Time window for analysis
        :return: Threat landscape analysis results
        """
        try:
            # Get threat intelligence statistics
            stats = self.repository.get_threat_intelligence_statistics()
            
            # Advanced threat analysis
            threat_landscape = {
                'total_threats': stats.get('total_threats', 0),
                'active_threats': stats.get('active_threats', 0),
                'expired_threats': stats.get('expired_threats', 0),
                'threats_by_type': stats.get('threats_by_type', {}),
                'threats_by_severity': stats.get('threats_by_severity', {}),
                'threat_trends': self._analyze_threat_trends(time_window_days),
                'high_severity_threats': self._get_high_severity_threats()
            }
            
            return threat_landscape
        
        except Exception as e:
            raise ThreatIntelligenceError(f"Threat landscape analysis failed: {e}")

    def _analyze_threat_trends(self, time_window_days: int) -> Dict[str, Any]:
        """
        Analyze threat trends within a specified time window.
        
        :param time_window_days: Time window for trend analysis
        :return: Threat trend analysis
        """
        # Placeholder for trend analysis logic
        # In a real-world scenario, this would involve more complex trend detection
        trends = {
            'increasing_threat_types': [],
            'emerging_threat_sources': []
        }
        
        return trends

    def _get_high_severity_threats(self, top_n: int = 5) -> List[Dict[str, Any]]:
        """
        Retrieve top high-severity threats.
        
        :param top_n: Number of top threats to return
        :return: List of high-severity threats
        """
        high_severity_filters = {
            'severities': [ThreatSeverity.HIGH, ThreatSeverity.CRITICAL]
        }
        
        high_severity_threats = self.repository.search_threat_intelligence(
            filters=high_severity_filters, 
            limit=top_n
        )
        
        return [threat.to_dict() for threat in high_severity_threats]

    def cleanup_expired_threat_intelligence(self) -> int:
        """
        Remove expired threat intelligence entries.
        
        :return: Number of entries removed
        """
        try:
            expired_threats = self.repository.get_expired_threat_intelligence()
            
            removed_count = 0
            for threat in expired_threats:
                self.repository.delete(threat)
                removed_count += 1
            
            return removed_count
        
        except Exception as e:
            self.rollback_transaction()
            raise ThreatIntelligenceError(f"Failed to cleanup expired threat intelligence: {e}")

    def generate_threat_report(self) -> Dict[str, Any]:
        """
        Generate a comprehensive threat intelligence report.
        
        :return: Detailed threat report
        """
        try:
            threat_landscape = self.analyze_threat_landscape()
            
            threat_report = {
                'summary': {
                    'total_threats': threat_landscape.get('total_threats', 0),
                    'active_threats': threat_landscape.get('active_threats', 0),
                    'expired_threats': threat_landscape.get('expired_threats', 0)
                },
                'threat_distribution': {
                    'by_type': threat_landscape.get('threats_by_type', {}),
                    'by_severity': threat_landscape.get('threats_by_severity', {})
                },
                'high_severity_threats': threat_landscape.get('high_severity_threats', []),
                'recommended_actions': self._generate_recommended_actions(threat_landscape)
            }
            
            return threat_report
        
        except Exception as e:
            raise ThreatIntelligenceError(f"Threat report generation failed: {e}")

    def _generate_recommended_actions(self, threat_landscape: Dict[str, Any]) -> List[str]:
        """
        Generate recommended actions based on threat landscape.
        
        :param threat_landscape: Threat landscape analysis results
        :return: List of recommended actions
        """
        actions = []
        
        # High-severity threat recommendations
        if threat_landscape.get('threats_by_severity', {}).get('high', 0) > 10:
            actions.append("Immediate security review and mitigation required")
        
        # Threat type specific recommendations
        if threat_landscape.get('threats_by_type', {}).get('malware', 0) > 5:
            actions.append("Update and strengthen anti-malware defenses")
        
        if threat_landscape.get('threats_by_type', {}).get('phishing', 0) > 3:
            actions.append("Enhance email filtering and user awareness training")
        
        return actions or ["No immediate actions required"]
