from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_
from typing import List, Optional, Dict, Any

from ..models.threat_intelligence import ThreatIntelligence, ThreatType, ThreatSeverity
from .base import BaseRepository

class ThreatIntelligenceRepository(BaseRepository[ThreatIntelligence]):
    """
    Specialized repository for managing threat intelligence with advanced querying capabilities.
    """
    def __init__(self, db_session: Session):
        super().__init__(db_session, ThreatIntelligence)

    def get_by_threat_id(self, threat_id: str) -> Optional[ThreatIntelligence]:
        """
        Retrieve threat intelligence by its unique threat ID.
        
        :param threat_id: Unique threat identifier
        :return: ThreatIntelligence instance or None
        """
        return self.session.query(ThreatIntelligence).filter(
            ThreatIntelligence.threat_id == threat_id
        ).first()

    def get_threats_by_type(
        self, 
        threat_type: ThreatType, 
        skip: int = 0, 
        limit: int = 100
    ) -> List[ThreatIntelligence]:
        """
        Retrieve threat intelligence by specific threat type.
        
        :param threat_type: Threat type to filter
        :param skip: Number of entries to skip
        :param limit: Maximum number of entries to return
        :return: List of threat intelligence entries
        """
        return (
            self.session.query(ThreatIntelligence)
            .filter(ThreatIntelligence.threat_type == threat_type)
            .filter(ThreatIntelligence.is_active == True)
            .offset(skip)
            .limit(limit)
            .all()
        )

    def get_threats_by_severity(
        self, 
        severity: ThreatSeverity, 
        skip: int = 0, 
        limit: int = 100
    ) -> List[ThreatIntelligence]:
        """
        Retrieve threat intelligence by severity level.
        
        :param severity: Threat severity to filter
        :param skip: Number of entries to skip
        :param limit: Maximum number of entries to return
        :return: List of threat intelligence entries
        """
        return (
            self.session.query(ThreatIntelligence)
            .filter(ThreatIntelligence.severity == severity)
            .filter(ThreatIntelligence.is_active == True)
            .offset(skip)
            .limit(limit)
            .all()
        )

    def search_threat_intelligence(
        self, 
        filters: Optional[Dict[str, Any]] = None, 
        skip: int = 0, 
        limit: int = 100
    ) -> List[ThreatIntelligence]:
        """
        Advanced search for threat intelligence with multiple filter options.
        
        :param filters: Dictionary of filter conditions
        :param skip: Number of entries to skip
        :param limit: Maximum number of entries to return
        :return: List of matching threat intelligence entries
        """
        query = self.session.query(ThreatIntelligence)
        
        if filters:
            conditions = [ThreatIntelligence.is_active == True]
            
            # Threat type filter
            if 'threat_types' in filters:
                conditions.append(ThreatIntelligence.threat_type.in_(filters['threat_types']))
            
            # Severity filter
            if 'severities' in filters:
                conditions.append(ThreatIntelligence.severity.in_(filters['severities']))
            
            # Source filter
            if 'source' in filters:
                conditions.append(ThreatIntelligence.source.like(f"%{filters['source']}%"))
            
            # Tags filter
            if 'tags' in filters:
                conditions.append(
                    or_(*[ThreatIntelligence.tags.contains(tag) for tag in filters['tags']]
                ))
            
            # Apply all conditions
            query = query.filter(and_(*conditions))
        
        return query.offset(skip).limit(limit).all()

    def get_expired_threat_intelligence(self) -> List[ThreatIntelligence]:
        """
        Retrieve expired threat intelligence entries.
        
        :return: List of expired threat intelligence entries
        """
        return (
            self.session.query(ThreatIntelligence)
            .filter(
                or_(
                    ThreatIntelligence.is_active == False,
                    ThreatIntelligence.expiration_date < func.now()
                )
            )
            .all()
        )

    def get_threat_intelligence_statistics(self) -> Dict[str, Any]:
        """
        Generate comprehensive threat intelligence statistics.
        
        :return: Dictionary of threat intelligence statistics
        """
        stats = {
            'total_threats': 0,
            'threats_by_type': {},
            'threats_by_severity': {},
            'active_threats': 0,
            'expired_threats': 0
        }
        
        # Total threats
        stats['total_threats'] = self.count()
        
        # Threat type statistics
        for threat_type in ThreatType:
            stats['threats_by_type'][threat_type.value] = (
                self.session.query(func.count(ThreatIntelligence.id))
                .filter(ThreatIntelligence.threat_type == threat_type)
                .scalar() or 0
            )
        
        # Threat severity statistics
        for severity in ThreatSeverity:
            stats['threats_by_severity'][severity.value] = (
                self.session.query(func.count(ThreatIntelligence.id))
                .filter(ThreatIntelligence.severity == severity)
                .scalar() or 0
            )
        
        # Active threats
        stats['active_threats'] = (
            self.session.query(func.count(ThreatIntelligence.id))
            .filter(ThreatIntelligence.is_active == True)
            .filter(ThreatIntelligence.expiration_date > func.now())
            .scalar() or 0
        )
        
        # Expired threats
        stats['expired_threats'] = (
            self.session.query(func.count(ThreatIntelligence.id))
            .filter(
                or_(
                    ThreatIntelligence.is_active == False,
                    ThreatIntelligence.expiration_date <= func.now()
                )
            )
            .scalar() or 0
        )
        
        return stats
