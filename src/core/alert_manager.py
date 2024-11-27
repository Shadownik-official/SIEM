from typing import List, Dict, Any, Optional
import json
import logging
from datetime import datetime
import threading
import queue
from elasticsearch import Elasticsearch
import redis
from kafka import KafkaProducer
import requests
import yaml
import os

class AlertManager:
    """Alert management system for SIEM"""
    
    def __init__(
        self,
        elasticsearch_hosts: List[str],
        kafka_brokers: List[str],
        redis_host: str,
        redis_port: int,
        rules_directory: str
    ):
        self.logger = logging.getLogger(__name__)
        self.alert_queue = queue.Queue()
        self.rules = {}
        self.rules_directory = rules_directory
        
        # Initialize connections
        self._init_elasticsearch(elasticsearch_hosts)
        self._init_kafka(kafka_brokers)
        self._init_redis(redis_host, redis_port)
        
        # Load alert rules
        self._load_rules()
        
        # Start alert processing thread
        self._start_alert_processor()
    
    def _init_elasticsearch(self, hosts: List[str]):
        """Initialize Elasticsearch connection"""
        try:
            self.es = Elasticsearch(hosts)
            self.logger.info("Successfully connected to Elasticsearch")
        except Exception as e:
            self.logger.error(f"Failed to connect to Elasticsearch: {str(e)}")
            raise
    
    def _init_kafka(self, brokers: List[str]):
        """Initialize Kafka producer"""
        try:
            self.producer = KafkaProducer(
                bootstrap_servers=brokers,
                value_serializer=lambda v: json.dumps(v).encode('utf-8')
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
    
    def _load_rules(self):
        """Load alert rules from yaml files"""
        try:
            for filename in os.listdir(self.rules_directory):
                if filename.endswith('.yaml') or filename.endswith('.yml'):
                    with open(os.path.join(self.rules_directory, filename)) as f:
                        rules = yaml.safe_load(f)
                        for rule in rules:
                            self.rules[rule['id']] = rule
            self.logger.info(f"Loaded {len(self.rules)} alert rules")
        except Exception as e:
            self.logger.error(f"Failed to load rules: {str(e)}")
            raise
    
    def _start_alert_processor(self):
        """Start alert processing thread"""
        self.alert_thread = threading.Thread(
            target=self._process_alerts,
            daemon=True
        )
        self.alert_thread.start()
    
    def check_event(self, event: Dict[str, Any]):
        """Check if event triggers any alerts"""
        for rule_id, rule in self.rules.items():
            if self._evaluate_rule(event, rule):
                alert = self._create_alert(event, rule)
                self.alert_queue.put(alert)
    
    def _evaluate_rule(self, event: Dict[str, Any], rule: Dict[str, Any]) -> bool:
        """Evaluate if event matches rule conditions"""
        try:
            # Basic field matching
            for field, pattern in rule.get('match', {}).items():
                if field not in event or event[field] != pattern:
                    return False
            
            # Regex matching
            for field, pattern in rule.get('regex_match', {}).items():
                if field not in event or not re.match(pattern, str(event[field])):
                    return False
            
            # Threshold checking
            if 'threshold' in rule:
                return self._check_threshold(event, rule)
            
            return True
        except Exception as e:
            self.logger.error(f"Error evaluating rule {rule['id']}: {str(e)}")
            return False
    
    def _check_threshold(self, event: Dict[str, Any], rule: Dict[str, Any]) -> bool:
        """Check if event exceeds threshold conditions"""
        try:
            threshold = rule['threshold']
            key = f"threshold:{rule['id']}:{event.get('source', 'unknown')}"
            
            # Increment counter
            count = self.redis.incr(key)
            
            # Set expiry if first occurrence
            if count == 1:
                self.redis.expire(key, threshold.get('timeframe', 3600))
            
            return count >= threshold.get('count', 1)
        except Exception as e:
            self.logger.error(f"Error checking threshold: {str(e)}")
            return False
    
    def _create_alert(self, event: Dict[str, Any], rule: Dict[str, Any]) -> Dict[str, Any]:
        """Create alert from event and rule"""
        return {
            'id': f"alert-{datetime.utcnow().timestamp()}",
            'timestamp': datetime.utcnow().isoformat(),
            'rule_id': rule['id'],
            'rule_name': rule.get('name', 'Unknown Rule'),
            'severity': rule.get('severity', 'medium'),
            'description': rule.get('description', ''),
            'event': event,
            'status': 'new'
        }
    
    def _process_alerts(self):
        """Process alerts from queue"""
        while True:
            try:
                alert = self.alert_queue.get()
                self._handle_alert(alert)
            except Exception as e:
                self.logger.error(f"Error processing alert: {str(e)}")
            finally:
                self.alert_queue.task_done()
    
    def _handle_alert(self, alert: Dict[str, Any]):
        """Handle a single alert"""
        try:
            # Store alert in Elasticsearch
            self._store_alert(alert)
            
            # Send alert to Kafka
            self._send_alert(alert)
            
            # Execute response actions
            self._execute_actions(alert)
            
            # Update statistics
            self._update_stats(alert)
        except Exception as e:
            self.logger.error(f"Error handling alert: {str(e)}")
    
    def _store_alert(self, alert: Dict[str, Any]):
        """Store alert in Elasticsearch"""
        try:
            self.es.index(
                index=f"siem-alerts-{datetime.utcnow().strftime('%Y-%m')}",
                document=alert
            )
        except Exception as e:
            self.logger.error(f"Failed to store alert: {str(e)}")
            raise
    
    def _send_alert(self, alert: Dict[str, Any]):
        """Send alert to Kafka topic"""
        try:
            self.producer.send('siem_alerts', alert)
        except Exception as e:
            self.logger.error(f"Failed to send alert to Kafka: {str(e)}")
    
    def _execute_actions(self, alert: Dict[str, Any]):
        """Execute response actions for alert"""
        rule = self.rules.get(alert['rule_id'])
        if not rule or 'actions' not in rule:
            return
        
        for action in rule['actions']:
            try:
                if action['type'] == 'email':
                    self._send_email(alert, action)
                elif action['type'] == 'webhook':
                    self._send_webhook(alert, action)
                elif action['type'] == 'block_ip':
                    self._block_ip(alert, action)
            except Exception as e:
                self.logger.error(f"Failed to execute action {action['type']}: {str(e)}")
    
    def _send_email(self, alert: Dict[str, Any], action: Dict[str, Any]):
        """Send email notification"""
        # Implement email sending logic here
        pass
    
    def _send_webhook(self, alert: Dict[str, Any], action: Dict[str, Any]):
        """Send webhook notification"""
        try:
            requests.post(
                action['url'],
                json=alert,
                headers={'Content-Type': 'application/json'},
                timeout=5
            )
        except Exception as e:
            self.logger.error(f"Failed to send webhook: {str(e)}")
    
    def _block_ip(self, alert: Dict[str, Any], action: Dict[str, Any]):
        """Block IP address"""
        # Implement IP blocking logic here
        pass
    
    def _update_stats(self, alert: Dict[str, Any]):
        """Update alert statistics"""
        try:
            # Update total alerts count
            self.redis.incr('total_alerts')
            
            # Update severity counts
            severity = alert.get('severity', 'medium')
            self.redis.incr(f'alert_severity_{severity}_count')
            
            # Update rule counts
            rule_id = alert.get('rule_id', 'unknown')
            self.redis.hincrby('rule_alert_counts', rule_id, 1)
        except Exception as e:
            self.logger.error(f"Failed to update alert statistics: {str(e)}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get alert statistics"""
        try:
            return {
                'total_alerts': int(self.redis.get('total_alerts') or 0),
                'severity_counts': {
                    'low': int(self.redis.get('alert_severity_low_count') or 0),
                    'medium': int(self.redis.get('alert_severity_medium_count') or 0),
                    'high': int(self.redis.get('alert_severity_high_count') or 0),
                    'critical': int(self.redis.get('alert_severity_critical_count') or 0)
                },
                'rule_counts': self.redis.hgetall('rule_alert_counts')
            }
        except Exception as e:
            self.logger.error(f"Failed to get alert statistics: {str(e)}")
            return {}
