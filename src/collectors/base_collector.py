from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
import logging
import json
from datetime import datetime
from kafka import KafkaProducer
import threading
import queue

class BaseCollector(ABC):
    """Base class for all log collectors"""
    
    def __init__(
        self,
        kafka_brokers: List[str],
        topic: str = 'siem_events',
        batch_size: int = 100,
        batch_timeout: int = 5
    ):
        self.logger = logging.getLogger(__name__)
        self.topic = topic
        self.batch_size = batch_size
        self.batch_timeout = batch_timeout
        self.event_queue = queue.Queue()
        
        # Initialize Kafka producer
        self._init_kafka(kafka_brokers)
        
        # Start batch processing thread
        self._start_processor()
    
    def _init_kafka(self, brokers: List[str]):
        """Initialize Kafka producer"""
        try:
            self.producer = KafkaProducer(
                bootstrap_servers=brokers,
                value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                compression_type='gzip',
                batch_size=16384,
                linger_ms=100,
                buffer_memory=33554432
            )
            self.logger.info("Successfully connected to Kafka")
        except Exception as e:
            self.logger.error(f"Failed to connect to Kafka: {str(e)}")
            raise
    
    def _start_processor(self):
        """Start batch processing thread"""
        self.processor_thread = threading.Thread(
            target=self._process_batch,
            daemon=True
        )
        self.processor_thread.start()
    
    def _process_batch(self):
        """Process events in batches"""
        batch = []
        last_flush = datetime.now()
        
        while True:
            try:
                # Try to get an event with timeout
                try:
                    event = self.event_queue.get(timeout=1.0)
                    batch.append(event)
                except queue.Empty:
                    pass
                
                # Check if we should flush the batch
                if len(batch) >= self.batch_size or \
                   (batch and (datetime.now() - last_flush).seconds >= self.batch_timeout):
                    self._send_batch(batch)
                    batch = []
                    last_flush = datetime.now()
            
            except Exception as e:
                self.logger.error(f"Error in batch processing: {str(e)}")
                if batch:
                    self._send_batch(batch)
                    batch = []
    
    def _send_batch(self, batch: List[Dict[str, Any]]):
        """Send batch of events to Kafka"""
        if not batch:
            return
        
        try:
            for event in batch:
                self.producer.send(self.topic, event)
            self.producer.flush()
            self.logger.debug(f"Sent batch of {len(batch)} events to Kafka")
        except Exception as e:
            self.logger.error(f"Failed to send batch to Kafka: {str(e)}")
    
    def submit_event(self, event: Dict[str, Any]):
        """Submit event for processing"""
        try:
            # Enrich event with collector metadata
            enriched_event = self._enrich_event(event)
            
            # Add to processing queue
            self.event_queue.put(enriched_event)
        except Exception as e:
            self.logger.error(f"Failed to submit event: {str(e)}")
    
    def _enrich_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich event with collector metadata"""
        enriched = event.copy()
        
        # Add timestamp if not present
        if 'timestamp' not in enriched:
            enriched['timestamp'] = datetime.utcnow().isoformat()
        
        # Add collector metadata
        enriched['collector'] = {
            'type': self.__class__.__name__,
            'version': '1.0.0',
            'collection_time': datetime.utcnow().isoformat()
        }
        
        return enriched
    
    @abstractmethod
    def start(self):
        """Start collecting logs"""
        pass
    
    @abstractmethod
    def stop(self):
        """Stop collecting logs"""
        pass
    
    @abstractmethod
    def get_status(self) -> Dict[str, Any]:
        """Get collector status"""
        pass
