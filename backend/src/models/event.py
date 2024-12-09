from sqlalchemy import Column, String, Integer, JSON, Enum, ForeignKey, Boolean, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime
import enum
from typing import Dict, Any, Optional

from .base import BaseModel
from ..core.exceptions import EventProcessingError

class EventCategory(enum.Enum):
    """
    Comprehensive event categorization for Offensive/Defensive SIEM.
    """
    # Defensive Event Categories
    SYSTEM_ANOMALY = "system_anomaly"
    NETWORK_INTRUSION = "network_intrusion"
    ACCESS_VIOLATION = "access_violation"
    MALWARE_DETECTION = "malware_detection"
    COMPLIANCE_VIOLATION = "compliance_violation"
    
    # Offensive Event Categories
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"

class EventThreatLevel(enum.Enum):
    """
    Threat level classification for events.
    """
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class EventStatus(enum.Enum):
    """
    Event processing and investigation status.
    """
    NEW = "new"
    INVESTIGATING = "investigating"
    MITIGATED = "mitigated"
    ESCALATED = "escalated"
    FALSE_POSITIVE = "false_positive"

class Event(BaseModel):
    """
    Advanced Event model for Offensive/Defensive SIEM.
    """
    __tablename__ = 'events'

    # Core Event Identification
    source_ip = Column(String(45), nullable=True)  # IPv4/IPv6 support
    destination_ip = Column(String(45), nullable=True)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    protocol = Column(String(20), nullable=True)

    # Event Classification
    category = Column(Enum(EventCategory), nullable=False)
    threat_level = Column(Enum(EventThreatLevel), nullable=False, default=EventThreatLevel.INFORMATIONAL)
    status = Column(Enum(EventStatus), nullable=False, default=EventStatus.NEW)

    # Detailed Event Information
    description = Column(String(1000), nullable=True)
    raw_event_data = Column(JSON, nullable=True)
    
    # Forensic and Tracking Details
    timestamp = Column(DateTime, default=datetime.utcnow)
    is_correlated = Column(Boolean, default=False)
    confidence_score = Column(Integer, default=0)  # 0-100 confidence

    # Optional Relationships
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    # user = relationship("User", back_populates="events")

    @classmethod
    def create_event(
        cls, 
        category: EventCategory, 
        threat_level: EventThreatLevel = EventThreatLevel.INFORMATIONAL,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        description: Optional[str] = None,
        raw_event_data: Optional[Dict[str, Any]] = None
    ) -> 'Event':
        """
        Factory method to create a standardized event.
        
        :param category: Event category
        :param threat_level: Threat level of the event
        :param source_ip: Source IP address
        :param destination_ip: Destination IP address
        :param description: Event description
        :param raw_event_data: Raw event data dictionary
        :return: Event instance
        """
        try:
            return cls(
                category=category,
                threat_level=threat_level,
                source_ip=source_ip,
                destination_ip=destination_ip,
                description=description or "",
                raw_event_data=raw_event_data or {},
                status=EventStatus.NEW,
                confidence_score=cls._calculate_confidence(category, threat_level)
            )
        except Exception as e:
            raise EventProcessingError(f"Failed to create event: {e}")

    @staticmethod
    def _calculate_confidence(
        category: EventCategory, 
        threat_level: EventThreatLevel
    ) -> int:
        """
        Calculate confidence score based on category and threat level.
        
        :param category: Event category
        :param threat_level: Event threat level
        :return: Confidence score (0-100)
        """
        base_scores = {
            EventCategory.NETWORK_INTRUSION: 80,
            EventCategory.MALWARE_DETECTION: 90,
            EventCategory.INITIAL_ACCESS: 75,
            EventCategory.PRIVILEGE_ESCALATION: 85,
            EventCategory.LATERAL_MOVEMENT: 70
        }

        threat_multipliers = {
            EventThreatLevel.INFORMATIONAL: 0.2,
            EventThreatLevel.LOW: 0.4,
            EventThreatLevel.MEDIUM: 0.6,
            EventThreatLevel.HIGH: 0.8,
            EventThreatLevel.CRITICAL: 1.0
        }

        base_score = base_scores.get(category, 50)
        multiplier = threat_multipliers.get(threat_level, 0.5)

        return min(int(base_score * multiplier), 100)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert event to a comprehensive dictionary representation.
        
        :return: Dictionary representation of the event
        """
        base_dict = super().to_dict()
        base_dict.update({
            'category': self.category.value,
            'threat_level': self.threat_level.value,
            'status': self.status.value,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        })
        return base_dict

    def __repr__(self):
        return f"<Event {self.category.value} - {self.threat_level.value}>"
