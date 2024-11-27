import logging
import json
from typing import Dict, List, Optional
from datetime import datetime
import sqlite3
from pathlib import Path
import yaml
import re
import requests
from dataclasses import dataclass
import threading
import queue

@dataclass
class ComplianceRule:
    """Represents a single compliance rule."""
    id: str
    framework: str
    category: str
    description: str
    severity: str
    check_function: str
    remediation_steps: List[str]
    references: List[str]

@dataclass
class ComplianceCheck:
    """Results of a compliance check."""
    rule_id: str
    timestamp: datetime
    status: str  # 'pass', 'fail', 'error'
    details: str
    evidence: Dict
    remediation_applied: bool = False

class ComplianceEngine:
    """Advanced compliance monitoring and enforcement engine."""
    
    def __init__(self, config_path: str = None):
        self.logger = logging.getLogger(__name__)
        self.config = self._load_config(config_path)
        self.rules = {}
        self.check_queue = queue.Queue()
        self.stop_flag = threading.Event()
        self.db_path = Path("compliance.db")
        self._initialize_database()
        self._load_compliance_rules()
        
    def _load_config(self, config_path: Optional[str]) -> Dict:
        """Load configuration settings."""
        default_config = {
            "frameworks": ["PCI-DSS", "HIPAA", "GDPR", "ISO27001"],
            "scan_interval": 3600,  # seconds
            "report_retention": 90,  # days
            "auto_remediation": False,
            "notification": {
                "email": True,
                "slack": True,
                "threshold_severity": "high"
            }
        }
        
        if config_path:
            try:
                with open(config_path, 'r') as f:
                    return {**default_config, **yaml.safe_load(f)}
            except Exception as e:
                self.logger.warning(f"Error loading config: {str(e)}. Using defaults.")
                return default_config
        return default_config
        
    def _initialize_database(self):
        """Initialize SQLite database for compliance tracking."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            # Create tables
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS compliance_checks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id TEXT,
                    timestamp TIMESTAMP,
                    status TEXT,
                    details TEXT,
                    evidence TEXT,
                    remediation_applied BOOLEAN
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS remediation_history (
                    check_id INTEGER,
                    timestamp TIMESTAMP,
                    action TEXT,
                    result TEXT,
                    FOREIGN KEY (check_id) REFERENCES compliance_checks(id)
                )
            ''')
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Database initialization error: {str(e)}")
            raise
            
    def _load_compliance_rules(self):
        """Load compliance rules from various frameworks."""
        try:
            rules_dir = Path(__file__).parent / "rules"
            
            for framework in self.config["frameworks"]:
                rule_file = rules_dir / f"{framework.lower()}_rules.yaml"
                
                if rule_file.exists():
                    with open(rule_file, 'r') as f:
                        rules = yaml.safe_load(f)
                        
                    for rule in rules:
                        self.rules[rule['id']] = ComplianceRule(
                            id=rule['id'],
                            framework=framework,
                            category=rule['category'],
                            description=rule['description'],
                            severity=rule['severity'],
                            check_function=rule['check_function'],
                            remediation_steps=rule['remediation_steps'],
                            references=rule.get('references', [])
                        )
                        
        except Exception as e:
            self.logger.error(f"Error loading compliance rules: {str(e)}")
            raise
            
    def start_monitoring(self):
        """Start compliance monitoring."""
        try:
            # Start compliance check thread
            self.check_thread = threading.Thread(
                target=self._compliance_check_worker)
            self.check_thread.start()
            
            self.logger.info("Compliance monitoring started successfully")
            
        except Exception as e:
            self.logger.error(f"Error starting compliance monitoring: {str(e)}")
            raise
            
    def stop_monitoring(self):
        """Stop compliance monitoring."""
        self.stop_flag.set()
        self.check_thread.join()
        self.logger.info("Compliance monitoring stopped")
        
    def _compliance_check_worker(self):
        """Worker thread for running compliance checks."""
        while not self.stop_flag.is_set():
            try:
                rule_id = self.check_queue.get(timeout=1)
                self._run_compliance_check(rule_id)
                
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error in compliance check worker: {str(e)}")
                
    def _run_compliance_check(self, rule_id: str):
        """Run a single compliance check."""
        try:
            rule = self.rules.get(rule_id)
            if not rule:
                raise ValueError(f"Unknown rule ID: {rule_id}")
                
            # Get the check function
            check_func = getattr(self, rule.check_function, None)
            if not check_func:
                raise ValueError(f"Check function not found: {rule.check_function}")
                
            # Run the check
            result = check_func()
            
            # Create check record
            check = ComplianceCheck(
                rule_id=rule_id,
                timestamp=datetime.now(),
                status=result['status'],
                details=result['details'],
                evidence=result['evidence']
            )
            
            # Store check results
            self._store_check_result(check)
            
            # Handle failures
            if check.status == 'fail':
                self._handle_compliance_failure(rule, check)
                
        except Exception as e:
            self.logger.error(f"Error running compliance check: {str(e)}")
            
    def _store_check_result(self, check: ComplianceCheck):
        """Store compliance check results in database."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO compliance_checks 
                (rule_id, timestamp, status, details, evidence, remediation_applied)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (check.rule_id, check.timestamp, check.status,
                  check.details, json.dumps(check.evidence),
                  check.remediation_applied))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Error storing check result: {str(e)}")
            
    def _handle_compliance_failure(self, rule: ComplianceRule, 
                                 check: ComplianceCheck):
        """Handle compliance check failures."""
        try:
            # Send notifications if severity meets threshold
            if self._should_notify(rule.severity):
                self._send_notifications(rule, check)
                
            # Attempt auto-remediation if enabled
            if self.config['auto_remediation']:
                self._attempt_remediation(rule, check)
                
        except Exception as e:
            self.logger.error(f"Error handling compliance failure: {str(e)}")
            
    def _should_notify(self, severity: str) -> bool:
        """Determine if notification should be sent based on severity."""
        severity_levels = {
            'critical': 1,
            'high': 2,
            'medium': 3,
            'low': 4
        }
        
        threshold = severity_levels.get(
            self.config['notification']['threshold_severity'], 4)
        current = severity_levels.get(severity.lower(), 4)
        
        return current <= threshold
        
    def _attempt_remediation(self, rule: ComplianceRule, 
                           check: ComplianceCheck):
        """Attempt to automatically remediate compliance failure."""
        try:
            # Get remediation function
            remediation_func = getattr(
                self, f"remediate_{rule.check_function}", None)
            
            if remediation_func:
                # Attempt remediation
                result = remediation_func(check.evidence)
                
                # Log remediation attempt
                self._log_remediation(check.rule_id, result)
                
                # Update check status if successful
                if result.get('success'):
                    self._update_check_status(
                        check.rule_id, 'pass', 'Auto-remediated')
                    
        except Exception as e:
            self.logger.error(f"Error attempting remediation: {str(e)}")
            
    def _log_remediation(self, check_id: int, result: Dict):
        """Log remediation attempt."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO remediation_history 
                (check_id, timestamp, action, result)
                VALUES (?, datetime('now'), ?, ?)
            ''', (check_id, result.get('action', ''),
                  json.dumps(result)))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Error logging remediation: {str(e)}")
            
    def _update_check_status(self, rule_id: str, status: str, 
                           details: str):
        """Update the status of a compliance check."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE compliance_checks 
                SET status = ?, details = ?
                WHERE rule_id = ?
                AND id = (
                    SELECT id FROM compliance_checks 
                    WHERE rule_id = ? 
                    ORDER BY timestamp DESC 
                    LIMIT 1
                )
            ''', (status, details, rule_id, rule_id))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Error updating check status: {str(e)}")
            
    def get_compliance_status(self, framework: Optional[str] = None) -> Dict:
        """Get current compliance status."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            if framework:
                # Get status for specific framework
                cursor.execute('''
                    SELECT c.rule_id, c.status, c.timestamp
                    FROM compliance_checks c
                    JOIN (
                        SELECT rule_id, MAX(timestamp) as max_time
                        FROM compliance_checks
                        GROUP BY rule_id
                    ) latest
                    ON c.rule_id = latest.rule_id 
                    AND c.timestamp = latest.max_time
                    WHERE c.rule_id LIKE ?
                ''', (f"{framework}%",))
            else:
                # Get status for all frameworks
                cursor.execute('''
                    SELECT c.rule_id, c.status, c.timestamp
                    FROM compliance_checks c
                    JOIN (
                        SELECT rule_id, MAX(timestamp) as max_time
                        FROM compliance_checks
                        GROUP BY rule_id
                    ) latest
                    ON c.rule_id = latest.rule_id 
                    AND c.timestamp = latest.max_time
                ''')
                
            results = cursor.fetchall()
            conn.close()
            
            # Calculate compliance metrics
            total = len(results)
            passed = sum(1 for r in results if r[1] == 'pass')
            
            return {
                'total_rules': total,
                'passed_rules': passed,
                'compliance_rate': (passed / total * 100) if total > 0 else 0,
                'checks': [
                    {
                        'rule_id': r[0],
                        'status': r[1],
                        'last_check': r[2]
                    }
                    for r in results
                ]
            }
            
        except Exception as e:
            self.logger.error(f"Error getting compliance status: {str(e)}")
            return {
                'total_rules': 0,
                'passed_rules': 0,
                'compliance_rate': 0,
                'checks': []
            }
            
    def generate_compliance_report(self, framework: Optional[str] = None,
                                 start_date: Optional[datetime] = None,
                                 end_date: Optional[datetime] = None) -> Dict:
        """Generate detailed compliance report."""
        try:
            status = self.get_compliance_status(framework)
            
            # Add detailed check information
            for check in status['checks']:
                rule = self.rules.get(check['rule_id'])
                if rule:
                    check['details'] = {
                        'description': rule.description,
                        'category': rule.category,
                        'severity': rule.severity,
                        'remediation_steps': rule.remediation_steps,
                        'references': rule.references
                    }
                    
            # Add historical trend data
            status['trends'] = self._get_compliance_trends(
                framework, start_date, end_date)
            
            return status
            
        except Exception as e:
            self.logger.error(f"Error generating compliance report: {str(e)}")
            return {}
            
    def _get_compliance_trends(self, framework: Optional[str],
                             start_date: Optional[datetime],
                             end_date: Optional[datetime]) -> List[Dict]:
        """Get historical compliance trend data."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            query = '''
                SELECT date(timestamp) as check_date,
                       COUNT(*) as total_checks,
                       SUM(CASE WHEN status = 'pass' THEN 1 ELSE 0 END) as passed_checks
                FROM compliance_checks
                WHERE 1=1
            '''
            
            params = []
            
            if framework:
                query += " AND rule_id LIKE ?"
                params.append(f"{framework}%")
                
            if start_date:
                query += " AND timestamp >= ?"
                params.append(start_date)
                
            if end_date:
                query += " AND timestamp <= ?"
                params.append(end_date)
                
            query += " GROUP BY date(timestamp) ORDER BY check_date"
            
            cursor.execute(query, params)
            results = cursor.fetchall()
            conn.close()
            
            return [
                {
                    'date': r[0],
                    'compliance_rate': (r[2] / r[1] * 100) if r[1] > 0 else 0,
                    'total_checks': r[1],
                    'passed_checks': r[2]
                }
                for r in results
            ]
            
        except Exception as e:
            self.logger.error(f"Error getting compliance trends: {str(e)}")
            return []
