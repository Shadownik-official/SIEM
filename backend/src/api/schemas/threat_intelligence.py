from pydantic import BaseModel, Field, validator
from typing import List, Dict, Any, Optional
from datetime import datetime

from ...models.threat_intelligence import ThreatType, ThreatSeverity

class ThreatIntelligenceBase(BaseModel):
    """
    Base schema for threat intelligence
    """
    threat_id: str = Field(..., min_length=1, max_length=100, description="Unique threat identifier")
    name: str = Field(..., min_length=1, max_length=200, description="Name of the threat")
    description: Optional[str] = Field(None, max_length=1000, description="Detailed threat description")
    
    threat_type: ThreatType = Field(..., description="Type of threat")
    severity: ThreatSeverity = Field(default=ThreatSeverity.LOW, description="Threat severity")
    
    source: Optional[str] = Field(None, max_length=200, description="Source of threat intelligence")
    tags: Optional[List[str]] = Field(default_factory=list, description="Additional tags")
    
    @validator('tags')
    def validate_tags(cls, tags):
        """
        Validate tags to ensure they are unique and not empty
        """
        if tags:
            tags = list(set(tag.strip() for tag in tags if tag.strip()))
        return tags

class ThreatIntelligenceCreate(ThreatIntelligenceBase):
    """
    Schema for creating threat intelligence
    """
    ioc_data: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Indicators of Compromise")
    mitre_attack_techniques: Optional[List[str]] = Field(default_factory=list, description="MITRE ATT&CK Techniques")
    expiration_days: int = Field(default=30, ge=1, le=365, description="Days until threat intelligence expires")

class ThreatIntelligenceResponse(ThreatIntelligenceBase):
    """
    Schema for threat intelligence response
    """
    id: int
    ioc_data: Optional[Dict[str, Any]] = Field(default_factory=dict)
    mitre_attack_techniques: Optional[List[str]] = Field(default_factory=list)
    
    is_active: bool
    first_seen: datetime
    last_updated: datetime
    expiration_date: datetime
    
    class Config:
        """
        Pydantic configuration for ORM compatibility
        """
        orm_mode = True

class ThreatIntelligenceUpdateSchema(BaseModel):
    """
    Schema for updating threat intelligence
    """
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=1000)
    threat_type: Optional[ThreatType] = None
    severity: Optional[ThreatSeverity] = None
    source: Optional[str] = Field(None, max_length=200)
    tags: Optional[List[str]] = None
    ioc_data: Optional[Dict[str, Any]] = None
    mitre_attack_techniques: Optional[List[str]] = None
    is_active: Optional[bool] = None

class ThreatIntelligenceStatisticsSchema(BaseModel):
    """
    Schema for threat intelligence statistics
    """
    total_threats: int
    active_threats: int
    expired_threats: int
    threats_by_type: Dict[str, int]
    threats_by_severity: Dict[str, int]

class ThreatReportSchema(BaseModel):
    """
    Comprehensive threat report schema
    """
    summary: Dict[str, int]
    threat_distribution: Dict[str, Dict[str, int]]
    high_severity_threats: List[Dict[str, Any]]
    recommended_actions: List[str]
