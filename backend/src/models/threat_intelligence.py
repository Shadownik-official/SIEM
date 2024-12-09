from sqlalchemy import Column, String, Integer, DateTime, JSON, Boolean, Enum
from sqlalchemy.sql import func
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import enum

from .base import BaseModel

class ThreatType(enum.Enum):
    """
    Comprehensive threat type classification.
    """
    # Offensive Threat Types
    MALWARE = "malware"
    EXPLOIT = "exploit"
    PHISHING = "phishing"
    RANSOMWARE = "ransomware"
    COMMAND_AND_CONTROL = "command_and_control"
    
    # Defensive Threat Types
    VULNERABILITY = "vulnerability"
    SUSPICIOUS_IP = "suspicious_ip"
    WEAK_CREDENTIAL = "weak_credential"
    ANOMALOUS_BEHAVIOR = "anomalous_behavior"

class ThreatSeverity(enum.Enum):
    """
    Threat severity classification.
    """
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ThreatIntelligence(BaseModel):
    """
    Advanced Threat Intelligence model for tracking and analyzing threats.
    """
    __tablename__ = 'threat_intelligence'

    # Threat Identification
    threat_id = Column(String(100), unique=True, nullable=False, index=True)
    name = Column(String(200), nullable=False)
    description = Column(String(1000))
    
    # Classification
    threat_type = Column(Enum(ThreatType), nullable=False)
    severity = Column(Enum(ThreatSeverity), nullable=False, default=ThreatSeverity.LOW)
    
    # Metadata
    source = Column(String(200))  # Source of threat intelligence
    tags = Column(JSON, default=list)  # Additional tags for categorization
    
    # Threat Details
    ioc_data = Column(JSON, default=dict)  # Indicators of Compromise
    mitre_attack_techniques = Column(JSON, default=list)  # MITRE ATT&CK Techniques
    
    # Status and Tracking
    is_active = Column(Boolean, default=True)
    first_seen = Column(DateTime, default=func.now())
    last_updated = Column(DateTime, default=func.now(), onupdate=func.now())
    expiration_date = Column(DateTime)

    @classmethod
    def create_threat_intelligence(
        cls,
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
    ) -> 'ThreatIntelligence':
        """
        Factory method to create threat intelligence entry.
        
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
        :return: ThreatIntelligence instance
        """
        return cls(
            threat_id=threat_id,
            name=name,
            threat_type=threat_type,
            severity=severity,
            description=description or "",
            source=source or "Unknown",
            ioc_data=ioc_data or {},
            mitre_attack_techniques=mitre_attack_techniques or [],
            tags=tags or [],
            expiration_date=datetime.utcnow() + timedelta(days=expiration_days)
        )

    def is_expired(self) -> bool:
        """
        Check if threat intelligence has expired.
        
        :return: True if expired, False otherwise
        """
        return datetime.utcnow() > self.expiration_date

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert threat intelligence to a comprehensive dictionary.
        
        :return: Dictionary representation
        """
        base_dict = super().to_dict()
        base_dict.update({
            'threat_type': self.threat_type.value,
            'severity': self.severity.value,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_updated': self.last_updated.isoformat() if self.last_updated else None,
            'expiration_date': self.expiration_date.isoformat() if self.expiration_date else None
        })
        return base_dict

    def __repr__(self):
        return f"<ThreatIntelligence {self.name} - {self.threat_type.value}>"
