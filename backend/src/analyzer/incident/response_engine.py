import threading
import queue
import logging
import json
from typing import Dict, List, Optional, Callable
from datetime import datetime
import sqlite3
from pathlib import Path
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class IncidentResponseEngine:
    """Advanced incident response and automation engine."""
    
    def __init__(self, config_path: str = None):
        self.logger = logging.getLogger(__name__)
        self.config = self._load_config(config_path)
        self.incident_queue = queue.PriorityQueue()
        self.response_handlers = {}
        self.stop_flag = threading.Event()
        self.db_path = Path("incidents.db")
        self._initialize_database()
        self._register_default_handlers()
        
    def _load_config(self, config_path: Optional[str]) -> Dict:
        """Load configuration settings."""
        default_config = {
            "severity_levels": {
                "critical": 1,
                "high": 2,
                "medium": 3,
                "low": 4
            },
            "notification": {
                "email": {
                    "smtp_server": "smtp.gmail.com",
                    "smtp_port": 587,
                    "username": "",
                    "password": "",
                    "from_address": ""
                },
                "slack": {
                    "webhook_url": ""
                }
            },
            "automation": {
                "enabled": True,
                "max_severity_auto_response": "medium"
            },
            "response_timeout": 300  # seconds
        }
        
        if config_path:
            try:
                with open(config_path, 'r') as f:
                    return {**default_config, **json.load(f)}
            except Exception as e:
                self.logger.warning(f"Error loading config: {str(e)}. Using defaults.")
                return default_config
        return default_config
        
    def _initialize_database(self):
        """Initialize SQLite database for incident tracking."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            # Create tables
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP,
                    severity TEXT,
                    type TEXT,
                    source TEXT,
                    description TEXT,
                    status TEXT,
                    resolution TEXT,
                    resolution_time TIMESTAMP
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS incident_actions (
                    incident_id INTEGER,
                    timestamp TIMESTAMP,
                    action_type TEXT,
                    details TEXT,
                    success BOOLEAN,
                    FOREIGN KEY (incident_id) REFERENCES incidents(id)
                )
            ''')
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Database initialization error: {str(e)}")
            raise
            
    def _register_default_handlers(self):
        """Register default incident response handlers."""
        self.register_handler("malware_detected", self._handle_malware)
        self.register_handler("brute_force_attempt", self._handle_brute_force)
        self.register_handler("data_exfiltration", self._handle_data_exfiltration)
        self.register_handler("unauthorized_access", self._handle_unauthorized_access)
        
    def start(self):
        """Start the incident response engine."""
        try:
            # Start incident processing thread
            self.process_thread = threading.Thread(
                target=self._incident_processing_worker)
            self.process_thread.start()
            
            self.logger.info("Incident response engine started successfully")
            
        except Exception as e:
            self.logger.error(f"Error starting incident response engine: {str(e)}")
            raise
            
    def stop(self):
        """Stop the incident response engine."""
        self.stop_flag.set()
        self.process_thread.join()
        self.logger.info("Incident response engine stopped")
        
    def register_handler(self, incident_type: str, 
                        handler: Callable[[Dict], None]):
        """Register a custom incident handler."""
        self.response_handlers[incident_type] = handler
        
    def report_incident(self, incident: Dict):
        """Report a new security incident."""
        try:
            # Validate incident data
            required_fields = ['type', 'severity', 'source', 'description']
            if not all(field in incident for field in required_fields):
                raise ValueError("Missing required incident fields")
                
            # Add timestamp and status
            incident['timestamp'] = datetime.now()
            incident['status'] = 'new'
            
            # Store incident in database
            incident_id = self._store_incident(incident)
            
            # Add to processing queue with priority based on severity
            priority = self.config['severity_levels'].get(
                incident['severity'].lower(), 999)
            self.incident_queue.put((priority, incident_id, incident))
            
            # Immediate notification for critical incidents
            if incident['severity'].lower() == 'critical':
                self._send_notifications(incident)
                
            return incident_id
            
        except Exception as e:
            self.logger.error(f"Error reporting incident: {str(e)}")
            raise
            
    def _store_incident(self, incident: Dict) -> int:
        """Store incident in database and return incident ID."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO incidents 
                (timestamp, severity, type, source, description, status)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (incident['timestamp'], incident['severity'],
                  incident['type'], incident['source'],
                  incident['description'], incident['status']))
            
            incident_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            return incident_id
            
        except Exception as e:
            self.logger.error(f"Error storing incident: {str(e)}")
            raise
            
    def _incident_processing_worker(self):
        """Worker thread for processing incidents."""
        while not self.stop_flag.is_set():
            try:
                # Get incident from queue with timeout
                try:
                    priority, incident_id, incident = \
                        self.incident_queue.get(timeout=1)
                except queue.Empty:
                    continue
                
                # Process incident
                self._process_incident(incident_id, incident)
                
            except Exception as e:
                self.logger.error(f"Error in incident processing: {str(e)}")
                
    def _process_incident(self, incident_id: int, incident: Dict):
        """Process a single incident."""
        try:
            # Get appropriate handler
            handler = self.response_handlers.get(incident['type'])
            if handler:
                # Execute handler
                response = handler(incident)
                
                # Log response action
                self._log_response_action(
                    incident_id,
                    "automated_response",
                    json.dumps(response),
                    True
                )
                
                # Update incident status
                self._update_incident_status(
                    incident_id,
                    "resolved" if response.get('success', False) else "pending"
                )
                
            else:
                self.logger.warning(
                    f"No handler found for incident type: {incident['type']}")
                
        except Exception as e:
            self.logger.error(f"Error processing incident: {str(e)}")
            self._log_response_action(
                incident_id,
                "automated_response",
                str(e),
                False
            )
            
    def _handle_malware(self, incident: Dict) -> Dict:
        """Handle malware detection incidents."""
        try:
            # Implement malware response actions
            # Example: Isolate infected system, scan for malware, etc.
            return {
                "success": True,
                "actions": ["system_isolated", "malware_scan_initiated"]
            }
        except Exception as e:
            self.logger.error(f"Error handling malware incident: {str(e)}")
            return {"success": False, "error": str(e)}
            
    def _handle_brute_force(self, incident: Dict) -> Dict:
        """Handle brute force attack attempts."""
        try:
            # Implement brute force response actions
            # Example: Block IP, increase authentication requirements
            return {
                "success": True,
                "actions": ["ip_blocked", "account_locked"]
            }
        except Exception as e:
            self.logger.error(f"Error handling brute force incident: {str(e)}")
            return {"success": False, "error": str(e)}
            
    def _handle_data_exfiltration(self, incident: Dict) -> Dict:
        """Handle data exfiltration incidents."""
        try:
            # Implement data exfiltration response actions
            # Example: Block outbound connections, alert security team
            return {
                "success": True,
                "actions": ["connections_blocked", "team_alerted"]
            }
        except Exception as e:
            self.logger.error(f"Error handling data exfiltration: {str(e)}")
            return {"success": False, "error": str(e)}
            
    def _handle_unauthorized_access(self, incident: Dict) -> Dict:
        """Handle unauthorized access attempts."""
        try:
            # Implement unauthorized access response actions
            # Example: Terminate sessions, reset credentials
            return {
                "success": True,
                "actions": ["sessions_terminated", "credentials_reset"]
            }
        except Exception as e:
            self.logger.error(f"Error handling unauthorized access: {str(e)}")
            return {"success": False, "error": str(e)}
            
    def _send_notifications(self, incident: Dict):
        """Send notifications about critical incidents."""
        try:
            # Email notification
            if self.config['notification']['email']['smtp_server']:
                self._send_email_notification(incident)
                
            # Slack notification
            if self.config['notification']['slack']['webhook_url']:
                self._send_slack_notification(incident)
                
        except Exception as e:
            self.logger.error(f"Error sending notifications: {str(e)}")
            
    def _send_email_notification(self, incident: Dict):
        """Send email notification about incident."""
        try:
            config = self.config['notification']['email']
            
            msg = MIMEMultipart()
            msg['From'] = config['from_address']
            msg['To'] = config['to_address']
            msg['Subject'] = f"Security Incident: {incident['type']}"
            
            body = f"""
            Security Incident Report
            
            Type: {incident['type']}
            Severity: {incident['severity']}
            Source: {incident['source']}
            Time: {incident['timestamp']}
            
            Description:
            {incident['description']}
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            with smtplib.SMTP(config['smtp_server'], config['smtp_port']) as server:
                server.starttls()
                server.login(config['username'], config['password'])
                server.send_message(msg)
                
        except Exception as e:
            self.logger.error(f"Error sending email notification: {str(e)}")
            
    def _send_slack_notification(self, incident: Dict):
        """Send Slack notification about incident."""
        try:
            webhook_url = self.config['notification']['slack']['webhook_url']
            
            message = {
                "text": "Security Incident Alert",
                "attachments": [{
                    "color": "danger",
                    "fields": [
                        {"title": "Type", "value": incident['type']},
                        {"title": "Severity", "value": incident['severity']},
                        {"title": "Source", "value": incident['source']},
                        {"title": "Description", "value": incident['description']}
                    ]
                }]
            }
            
            requests.post(webhook_url, json=message)
            
        except Exception as e:
            self.logger.error(f"Error sending Slack notification: {str(e)}")
            
    def get_incident_status(self, incident_id: int) -> Dict:
        """Get current status of an incident."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute(
                "SELECT * FROM incidents WHERE id = ?", 
                (incident_id,)
            )
            incident = cursor.fetchone()
            
            if incident:
                # Get associated actions
                cursor.execute(
                    "SELECT * FROM incident_actions WHERE incident_id = ?",
                    (incident_id,)
                )
                actions = cursor.fetchall()
                
                conn.close()
                
                return {
                    'id': incident[0],
                    'timestamp': incident[1],
                    'severity': incident[2],
                    'type': incident[3],
                    'source': incident[4],
                    'description': incident[5],
                    'status': incident[6],
                    'resolution': incident[7],
                    'resolution_time': incident[8],
                    'actions': [
                        {
                            'timestamp': action[1],
                            'type': action[2],
                            'details': action[3],
                            'success': action[4]
                        }
                        for action in actions
                    ]
                }
            
            conn.close()
            return None
            
        except Exception as e:
            self.logger.error(f"Error getting incident status: {str(e)}")
            return None
            
    def _update_incident_status(self, incident_id: int, status: str):
        """Update the status of an incident."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE incidents 
                SET status = ?,
                    resolution_time = CASE 
                        WHEN ? = 'resolved' THEN datetime('now')
                        ELSE resolution_time 
                    END
                WHERE id = ?
            ''', (status, status, incident_id))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Error updating incident status: {str(e)}")
            
    def _log_response_action(self, incident_id: int, action_type: str,
                           details: str, success: bool):
        """Log an automated response action."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO incident_actions 
                (incident_id, timestamp, action_type, details, success)
                VALUES (?, datetime('now'), ?, ?, ?)
            ''', (incident_id, action_type, details, success))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Error logging response action: {str(e)}")
            
    def get_active_incidents(self) -> List[Dict]:
        """Get list of active incidents."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM incidents 
                WHERE status != 'resolved'
                ORDER BY severity ASC, timestamp DESC
            ''')
            
            incidents = []
            for row in cursor.fetchall():
                incidents.append({
                    'id': row[0],
                    'timestamp': row[1],
                    'severity': row[2],
                    'type': row[3],
                    'source': row[4],
                    'description': row[5],
                    'status': row[6]
                })
                
            conn.close()
            return incidents
            
        except Exception as e:
            self.logger.error(f"Error getting active incidents: {str(e)}")
            return []
