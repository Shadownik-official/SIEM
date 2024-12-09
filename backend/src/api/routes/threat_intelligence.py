from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional

from ...core.database import get_db
from ...services.threat_intelligence_service import ThreatIntelligenceService
from ...models.threat_intelligence import ThreatType, ThreatSeverity
from ..schemas.threat_intelligence import (
    ThreatIntelligenceCreate,
    ThreatIntelligenceResponse,
    ThreatIntelligenceUpdateSchema,
    ThreatIntelligenceStatisticsSchema,
    ThreatReportSchema
)
from ...core.exceptions import ThreatIntelligenceError

router = APIRouter(prefix="/threat-intelligence", tags=["Threat Intelligence"])

@router.post("/", response_model=ThreatIntelligenceResponse)
def create_threat_intelligence(
    threat_intel: ThreatIntelligenceCreate,
    db: Session = Depends(get_db)
):
    """
    Create a new threat intelligence entry
    """
    try:
        service = ThreatIntelligenceService(db)
        created_threat = service.create_threat_intelligence(
            threat_id=threat_intel.threat_id,
            name=threat_intel.name,
            threat_type=threat_intel.threat_type,
            severity=threat_intel.severity,
            description=threat_intel.description,
            source=threat_intel.source,
            ioc_data=threat_intel.ioc_data,
            mitre_attack_techniques=threat_intel.mitre_attack_techniques,
            tags=threat_intel.tags,
            expiration_days=threat_intel.expiration_days
        )
        return created_threat
    except ThreatIntelligenceError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/", response_model=List[ThreatIntelligenceResponse])
def search_threat_intelligence(
    threat_types: Optional[List[ThreatType]] = Query(None),
    severities: Optional[List[ThreatSeverity]] = Query(None),
    source: Optional[str] = Query(None),
    tags: Optional[List[str]] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db)
):
    """
    Search threat intelligence with advanced filtering
    """
    try:
        service = ThreatIntelligenceService(db)
        
        filters = {}
        if threat_types:
            filters['threat_types'] = threat_types
        if severities:
            filters['severities'] = severities
        if source:
            filters['source'] = source
        if tags:
            filters['tags'] = tags
        
        results = service.repository.search_threat_intelligence(
            filters=filters, 
            skip=skip, 
            limit=limit
        )
        
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/{threat_id}", response_model=ThreatIntelligenceResponse)
def update_threat_intelligence(
    threat_id: str,
    update_data: ThreatIntelligenceUpdateSchema,
    db: Session = Depends(get_db)
):
    """
    Update an existing threat intelligence entry
    """
    try:
        service = ThreatIntelligenceService(db)
        
        # Convert update_data to dictionary, removing None values
        update_dict = {
            k: v for k, v in update_data.dict().items() 
            if v is not None
        }
        
        updated_threat = service.update_threat_intelligence(
            threat_id=threat_id,
            **update_dict
        )
        
        return updated_threat
    except ThreatIntelligenceError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.get("/statistics", response_model=ThreatIntelligenceStatisticsSchema)
def get_threat_intelligence_statistics(
    db: Session = Depends(get_db)
):
    """
    Get comprehensive threat intelligence statistics
    """
    try:
        service = ThreatIntelligenceService(db)
        stats = service.repository.get_threat_intelligence_statistics()
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/report", response_model=ThreatReportSchema)
def generate_threat_report(
    db: Session = Depends(get_db)
):
    """
    Generate a comprehensive threat intelligence report
    """
    try:
        service = ThreatIntelligenceService(db)
        report = service.generate_threat_report()
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/cleanup", response_model=dict)
def cleanup_expired_threat_intelligence(
    db: Session = Depends(get_db)
):
    """
    Remove expired threat intelligence entries
    """
    try:
        service = ThreatIntelligenceService(db)
        removed_count = service.cleanup_expired_threat_intelligence()
        return {"removed_threats": removed_count}
    except ThreatIntelligenceError as e:
        raise HTTPException(status_code=500, detail=str(e))
