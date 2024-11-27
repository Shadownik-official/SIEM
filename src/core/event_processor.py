from typing import List, Dict, Any, Optional
import json
import logging
from datetime import datetime
from elasticsearch import Elasticsearch
from kafka import KafkaConsumer, KafkaProducer
import redis
from concurrent.futures import ThreadPoolExecutor
import threading
import queue

class EventProcessor:
    """Core event processing engine for SIEM system"""
    
    def __init__(
        self,
        elasticsearch_hosts: List[str],
        kafka_brokers: List[str],
        redis_host: str,
        redis_port: int
    ):
        self.logger = logging.getLogger(__name__)
        self.event_queue = queue.Queue()
        self.executor = ThreadPoolExecutor(max_workers=10)
        
        # Initialize connections
        self._init_elasticsearch(elasticsearch_hosts)
        self._init_kafka(kafka_brokers)
        self._init_redis(redis_host, redis_port)
        
        # Start processing threads
        self._start_processing_threads()
    
    def _init_elasticsearch(self, hosts: List[str]):
        """Initialize Elasticsearch connection"""
        try:
            self.es = Elasticsearch(hosts)
            self.logger.info("Successfully connected to Elasticsearch")
        except Exception as e:
            self.logger.error(f"Failed to connect to Elasticsearch: {str(e)}")
            raise
    
    def _init_kafka(self, brokers: List[str]):
        """Initialize Kafka producer and consumer"""
        try:
            self.producer = KafkaProducer(
                bootstrap_servers=brokers,
                value_serializer=lambda v: json.dumps(v).encode('utf-8')
            )
            self.consumer = KafkaConsumer(
                'siem_events',
                bootstrap_servers=brokers,
                value_deserializer=lambda v: json.loads(v.decode('utf-8'))
            )
            self.logger.info("Successfully connected to Kafka")
        except Exception as e:
            self.logger.error(f"Failed to connect to Kafka: {str(e)}")
            raise
    
    def _init_redis(self, host: str, port: int):
        """Initialize Redis connection"""
        try:
            self.redis = redis.Redis(host=host, port=port)
            self.logger.info("Successfully connected to Redis")
        except Exception as e:
            self.logger.error(f"Failed to connect to Redis: {str(e)}")
            raise
    
    def _start_processing_threads(self):
        """Start background processing threads"""
        self.processing_thread = threading.Thread(
            target=self._process_events_queue,
            daemon=True
        )
        self.processing_thread.start()
        
        self.kafka_consumer_thread = threading.Thread(
            target=self._consume_kafka_events,
            daemon=True
        )
        self.kafka_consumer_thread.start()
    
    def process_event(self, event: Dict[str, Any]):
        """Process a single event"""
        try:
            # Enrich event with additional context
            enriched_event = self._enrich_event(event)
            
            # Normalize event format
            normalized_event = self._normalize_event(enriched_event)
            
            # Store event in Elasticsearch
            self._store_event(normalized_event)
            
            # Check for alerts
            self._check_alerts(normalized_event)
            
            # Update statistics
            self._update_stats(normalized_event)
            
            return True
        except Exception as e:
            self.logger.error(f"Error processing event: {str(e)}")
            return False
    
    def _enrich_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich event with additional context and information"""
        enriched = event.copy()
        
        # Add timestamp if not present
        if 'timestamp' not in enriched:
            enriched['timestamp'] = datetime.utcnow().isoformat()
        
        # Add source metadata
        enriched['metadata'] = {
            'processed_time': datetime.utcnow().isoformat(),
            'siem_version': '1.0.0'
        }
        
        # Add threat intelligence data
        enriched['threat_intel'] = self._get_threat_intel(event)
        
        return enriched
    
    def _normalize_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize event format to standard schema"""
        normalized = {
            'timestamp': event.get('timestamp'),
            'source': event.get('source'),
            'type': event.get('type'),
            'severity': event.get('severity', 'low'),
            'description': event.get('description'),
            'raw_data': event.get('raw_data'),
            'metadata': event.get('metadata'),
            'threat_intel': event.get('threat_intel')
        }
        return normalized
    
    def _store_event(self, event: Dict[str, Any]):
        """Store event in Elasticsearch"""
        try:
            self.es.index(
                index=f"siem-events-{datetime.utcnow().strftime('%Y-%m')}",
                document=event
            )
        except Exception as e:
            self.logger.error(f"Failed to store event in Elasticsearch: {str(e)}")
            raise
    
    def _check_alerts(self, event: Dict[str, Any]):
        """Check if event triggers any alerts"""
        # Implement alert checking logic here
        pass
    
    def _update_stats(self, event: Dict[str, Any]):
        """Update statistics in Redis"""
        try:
            # Update event count
            self.redis.incr('total_events')
            
            # Update severity counts
            severity = event.get('severity', 'low')
            self.redis.incr(f'severity_{severity}_count')
            
            # Update source counts
            source = event.get('source', 'unknown')
            self.redis.hincrby('source_counts', source, 1)
        except Exception as e:
            self.logger.error(f"Failed to update statistics: {str(e)}")
    
    def _get_threat_intel(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Get threat intelligence data for event"""
        # Implement threat intelligence lookup logic here
        return {}
    
    def _process_events_queue(self):
        """Process events from the queue"""
        while True:
            try:
                event = self.event_queue.get()
                self.process_event(event)
            except Exception as e:
                self.logger.error(f"Error processing event from queue: {str(e)}")
            finally:
                self.event_queue.task_done()
    
    def _consume_kafka_events(self):
        """Consume events from Kafka"""
        for message in self.consumer:
            try:
                event = message.value
                self.event_queue.put(event)
            except Exception as e:
                self.logger.error(f"Error consuming Kafka message: {str(e)}")
    
    def submit_event(self, event: Dict[str, Any]):
        """Submit event for processing"""
        self.event_queue.put(event)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get current statistics"""
        try:
            return {
                'total_events': int(self.redis.get('total_events') or 0),
                'severity_counts': {
                    'low': int(self.redis.get('severity_low_count') or 0),
                    'medium': int(self.redis.get('severity_medium_count') or 0),
                    'high': int(self.redis.get('severity_high_count') or 0),
                    'critical': int(self.redis.get('severity_critical_count') or 0)
                },
                'source_counts': self.redis.hgetall('source_counts')
            }
        except Exception as e:
            self.logger.error(f"Failed to get statistics: {str(e)}")
            return {}
