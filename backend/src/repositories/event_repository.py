from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_
from typing import List, Optional, Dict, Any

from ..models.event import Event, EventCategory, EventThreatLevel, EventStatus
from .base import BaseRepository

class EventRepository(BaseRepository[Event]):
    """
    Specialized repository for managing SIEM events with advanced querying capabilities.
    """
    def __init__(self, db_session: Session):
        super().__init__(db_session, Event)

    def get_events_by_category(
        self, 
        category: EventCategory, 
        skip: int = 0, 
        limit: int = 100
    ) -> List[Event]:
        """
        Retrieve events by specific category.
        
        :param category: Event category to filter
        :param skip: Number of events to skip
        :param limit: Maximum number of events to return
        :return: List of events
        """
        return (
            self.session.query(Event)
            .filter(Event.category == category)
            .offset(skip)
            .limit(limit)
            .all()
        )

    def get_events_by_threat_level(
        self, 
        threat_level: EventThreatLevel, 
        skip: int = 0, 
        limit: int = 100
    ) -> List[Event]:
        """
        Retrieve events by threat level.
        
        :param threat_level: Threat level to filter
        :param skip: Number of events to skip
        :param limit: Maximum number of events to return
        :return: List of events
        """
        return (
            self.session.query(Event)
            .filter(Event.threat_level == threat_level)
            .offset(skip)
            .limit(limit)
            .all()
        )

    def get_high_confidence_events(
        self, 
        confidence_threshold: int = 70, 
        skip: int = 0, 
        limit: int = 100
    ) -> List[Event]:
        """
        Retrieve high-confidence events.
        
        :param confidence_threshold: Minimum confidence score
        :param skip: Number of events to skip
        :param limit: Maximum number of events to return
        :return: List of high-confidence events
        """
        return (
            self.session.query(Event)
            .filter(Event.confidence_score >= confidence_threshold)
            .offset(skip)
            .limit(limit)
            .all()
        )

    def get_correlated_events(
        self, 
        source_ip: Optional[str] = None, 
        destination_ip: Optional[str] = None,
        time_window_minutes: int = 60
    ) -> List[Event]:
        """
        Find correlated events within a time window.
        
        :param source_ip: Source IP to correlate
        :param destination_ip: Destination IP to correlate
        :param time_window_minutes: Time window for correlation
        :return: List of correlated events
        """
        time_threshold = func.now() - func.interval(f'{time_window_minutes} minutes')
        
        correlation_conditions = []
        if source_ip:
            correlation_conditions.append(Event.source_ip == source_ip)
        if destination_ip:
            correlation_conditions.append(Event.destination_ip == destination_ip)
        
        return (
            self.session.query(Event)
            .filter(
                and_(
                    *correlation_conditions,
                    Event.timestamp >= time_threshold
                )
            )
            .order_by(Event.timestamp)
            .all()
        )

    def advanced_event_search(
        self, 
        filters: Optional[Dict[str, Any]] = None, 
        skip: int = 0, 
        limit: int = 100
    ) -> List[Event]:
        """
        Advanced event search with multiple filter options.
        
        :param filters: Dictionary of filter conditions
        :param skip: Number of events to skip
        :param limit: Maximum number of events to return
        :return: List of matching events
        """
        query = self.session.query(Event)
        
        if filters:
            conditions = []
            
            # Category filter
            if 'categories' in filters:
                conditions.append(Event.category.in_(filters['categories']))
            
            # Threat level filter
            if 'threat_levels' in filters:
                conditions.append(Event.threat_level.in_(filters['threat_levels']))
            
            # Status filter
            if 'statuses' in filters:
                conditions.append(Event.status.in_(filters['statuses']))
            
            # IP filters
            if 'source_ip' in filters:
                conditions.append(Event.source_ip == filters['source_ip'])
            
            if 'destination_ip' in filters:
                conditions.append(Event.destination_ip == filters['destination_ip'])
            
            # Confidence score filter
            if 'min_confidence' in filters:
                conditions.append(Event.confidence_score >= filters['min_confidence'])
            
            # Apply all conditions
            if conditions:
                query = query.filter(and_(*conditions))
        
        return query.offset(skip).limit(limit).all()

    def get_event_statistics(self) -> Dict[str, Any]:
        """
        Generate comprehensive event statistics.
        
        :return: Dictionary of event statistics
        """
        stats = {
            'total_events': self.count(),
            'events_by_category': {},
            'events_by_threat_level': {},
            'events_by_status': {}
        }
        
        # Category statistics
        for category in EventCategory:
            stats['events_by_category'][category.value] = (
                self.session.query(func.count(Event.id))
                .filter(Event.category == category)
                .scalar()
            )
        
        # Threat level statistics
        for threat_level in EventThreatLevel:
            stats['events_by_threat_level'][threat_level.value] = (
                self.session.query(func.count(Event.id))
                .filter(Event.threat_level == threat_level)
                .scalar()
            )
        
        # Status statistics
        for status in EventStatus:
            stats['events_by_status'][status.value] = (
                self.session.query(func.count(Event.id))
                .filter(Event.status == status)
                .scalar()
            )
        
        return stats
