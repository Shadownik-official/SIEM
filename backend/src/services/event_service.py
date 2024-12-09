from sqlalchemy.orm import Session
from typing import List, Dict, Any, Optional

from ..models.event import Event, EventCategory, EventThreatLevel, EventStatus
from ..repositories.event_repository import EventRepository
from ..services.base import BaseService
from ..core.exceptions import EventProcessingError

class EventService(BaseService[EventRepository]):
    """
    Service layer for advanced event processing and management.
    """
    def __init__(self, db_session: Session):
        event_repository = EventRepository(db_session)
        super().__init__(event_repository, db_session)

    def create_event(
        self, 
        category: EventCategory, 
        threat_level: EventThreatLevel = EventThreatLevel.INFORMATIONAL,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        description: Optional[str] = None,
        raw_event_data: Optional[Dict[str, Any]] = None
    ) -> Event:
        """
        Create and persist a new event with advanced processing.
        
        :param category: Event category
        :param threat_level: Event threat level
        :param source_ip: Source IP address
        :param destination_ip: Destination IP address
        :param description: Event description
        :param raw_event_data: Raw event data
        :return: Created event
        """
        try:
            event = Event.create_event(
                category=category,
                threat_level=threat_level,
                source_ip=source_ip,
                destination_ip=destination_ip,
                description=description,
                raw_event_data=raw_event_data
            )
            
            # Correlate with existing events
            correlated_events = self.repository.get_correlated_events(
                source_ip=source_ip, 
                destination_ip=destination_ip
            )
            
            event.is_correlated = bool(correlated_events)
            
            # Persist event
            return self.repository.create(event)
        
        except Exception as e:
            self.rollback_transaction()
            raise EventProcessingError(f"Failed to create event: {e}")

    def update_event_status(
        self, 
        event_id: int, 
        new_status: EventStatus, 
        description: Optional[str] = None
    ) -> Event:
        """
        Update the status of an existing event.
        
        :param event_id: ID of the event to update
        :param new_status: New event status
        :param description: Optional updated description
        :return: Updated event
        """
        try:
            event = self.repository.get(event_id)
            
            if not event:
                raise EventProcessingError(f"Event with ID {event_id} not found")
            
            event.status = new_status
            
            if description:
                event.description = description
            
            return self.repository.update(event)
        
        except Exception as e:
            self.rollback_transaction()
            raise EventProcessingError(f"Failed to update event status: {e}")

    def analyze_event_patterns(
        self, 
        categories: Optional[List[EventCategory]] = None, 
        time_window_hours: int = 24
    ) -> Dict[str, Any]:
        """
        Perform advanced event pattern analysis.
        
        :param categories: Categories to analyze
        :param time_window_hours: Time window for analysis
        :return: Event pattern analysis results
        """
        try:
            filters = {
                'categories': categories or list(EventCategory),
                'time_window_hours': time_window_hours
            }
            
            # Retrieve events within time window
            events = self.repository.advanced_event_search(filters)
            
            # Pattern analysis
            pattern_analysis = {
                'total_events': len(events),
                'event_distribution': {},
                'threat_escalation_patterns': {},
                'ip_activity_map': {}
            }
            
            # Analyze event distribution
            for event in events:
                category = event.category.value
                pattern_analysis['event_distribution'][category] = (
                    pattern_analysis['event_distribution'].get(category, 0) + 1
                )
                
                # Track IP activity
                if event.source_ip:
                    pattern_analysis['ip_activity_map'][event.source_ip] = (
                        pattern_analysis['ip_activity_map'].get(event.source_ip, 0) + 1
                    )
            
            return pattern_analysis
        
        except Exception as e:
            raise EventProcessingError(f"Event pattern analysis failed: {e}")

    def generate_threat_report(self) -> Dict[str, Any]:
        """
        Generate a comprehensive threat report.
        
        :return: Detailed threat report
        """
        try:
            # Get event statistics
            stats = self.repository.get_event_statistics()
            
            # High-confidence events
            high_confidence_events = self.repository.get_high_confidence_events(confidence_threshold=70)
            
            threat_report = {
                'total_events': stats['total_events'],
                'events_by_category': stats['events_by_category'],
                'events_by_threat_level': stats['events_by_threat_level'],
                'high_confidence_events': len(high_confidence_events),
                'top_threat_categories': self._get_top_threat_categories(stats),
                'recommended_actions': self._generate_recommended_actions(stats)
            }
            
            return threat_report
        
        except Exception as e:
            raise EventProcessingError(f"Threat report generation failed: {e}")

    def _get_top_threat_categories(self, stats: Dict[str, Any], top_n: int = 3) -> List[str]:
        """
        Identify top threat categories.
        
        :param stats: Event statistics
        :param top_n: Number of top categories to return
        :return: List of top threat categories
        """
        category_counts = stats['events_by_category']
        return sorted(category_counts, key=category_counts.get, reverse=True)[:top_n]

    def _generate_recommended_actions(self, stats: Dict[str, Any]) -> List[str]:
        """
        Generate recommended actions based on event statistics.
        
        :param stats: Event statistics
        :return: List of recommended actions
        """
        actions = []
        
        # High-threat level recommendations
        if stats['events_by_threat_level']['high'] > 10:
            actions.append("Immediate security review required")
        
        # Specific category recommendations
        if stats['events_by_category']['network_intrusion'] > 5:
            actions.append("Enhance network segmentation and firewall rules")
        
        if stats['events_by_category']['privilege_escalation'] > 3:
            actions.append("Review and tighten access control policies")
        
        return actions or ["No immediate actions required"]
