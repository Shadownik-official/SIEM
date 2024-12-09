"""
Compliance and Audit Module for Enterprise SIEM
Handles compliance reporting, auditing, and security posture assessment
"""
import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from dataclasses import dataclass
import yaml
from elasticsearch import Elasticsearch
from redis import Redis

logger = logging.getLogger(__name__)

@dataclass
class ComplianceFramework:
    name: str
    version: str
    controls: List[Dict]
    requirements: List[Dict]
    audit_frequency: int  # days
    last_audit: Optional[datetime]

@dataclass
class AuditResult:
    framework: str
    control_id: str
    status: str  # passed, failed, warning
    evidence: List[str]
    remediation: Optional[str]
    timestamp: datetime

class ComplianceAuditor:
    def __init__(self, es_client: Elasticsearch, redis_client: Redis):
        self.es = es_client
        self.redis = redis_client
        self.load_compliance_frameworks()
        
    def load_compliance_frameworks(self):
        """Load compliance framework definitions"""
        try:
            with open('config/compliance_frameworks.yaml', 'r') as f:
                frameworks = yaml.safe_load(f)
                
            self.frameworks = {}
            for fw in frameworks:
                self.frameworks[fw['name']] = ComplianceFramework(
                    name=fw['name'],
                    version=fw['version'],
                    controls=fw['controls'],
                    requirements=fw['requirements'],
                    audit_frequency=fw.get('audit_frequency', 90),
                    last_audit=None
                )
            
            logger.info(f"Loaded {len(self.frameworks)} compliance frameworks")
        except Exception as e:
            logger.error(f"Failed to load compliance frameworks: {e}")
            self.frameworks = {}

    def perform_compliance_audit(self, framework_name: str) -> List[AuditResult]:
        """Perform compliance audit for specified framework"""
        try:
            if framework_name not in self.frameworks:
                raise ValueError(f"Unknown framework: {framework_name}")
            
            framework = self.frameworks[framework_name]
            results = []
            
            # Audit each control
            for control in framework.controls:
                result = self._audit_control(framework_name, control)
                results.append(result)
                
                # Store result immediately
                self._store_audit_result(result)
            
            # Update last audit time
            framework.last_audit = datetime.now()
            
            # Generate and store audit report
            self._generate_audit_report(framework_name, results)
            
            return results
        except Exception as e:
            logger.error(f"Compliance audit failed: {e}")
            return []

    def _audit_control(self, framework: str, control: Dict) -> AuditResult:
        """Audit individual compliance control"""
        try:
            # Get evidence for control
            evidence = self._gather_control_evidence(control)
            
            # Evaluate control
            status = self._evaluate_control(control, evidence)
            
            # Generate remediation if needed
            remediation = None
            if status != 'passed':
                remediation = self._generate_remediation(control, evidence)
            
            return AuditResult(
                framework=framework,
                control_id=control['id'],
                status=status,
                evidence=evidence,
                remediation=remediation,
                timestamp=datetime.now()
            )
        except Exception as e:
            logger.error(f"Control audit failed: {e}")
            return AuditResult(
                framework=framework,
                control_id=control['id'],
                status='error',
                evidence=[f"Audit error: {str(e)}"],
                remediation=None,
                timestamp=datetime.now()
            )

    def _gather_control_evidence(self, control: Dict) -> List[str]:
        """Gather evidence for compliance control"""
        evidence = []
        
        try:
            # Query relevant data sources based on control type
            if control.get('type') == 'configuration':
                evidence.extend(self._check_configurations(control))
            elif control.get('type') == 'log_analysis':
                evidence.extend(self._analyze_logs(control))
            elif control.get('type') == 'policy':
                evidence.extend(self._check_policies(control))
            elif control.get('type') == 'technical':
                evidence.extend(self._perform_technical_checks(control))
        except Exception as e:
            logger.error(f"Failed to gather evidence: {e}")
            evidence.append(f"Evidence gathering error: {str(e)}")
        
        return evidence

    def _check_configurations(self, control: Dict) -> List[str]:
        """Check system configurations"""
        evidence = []
        
        # Query configuration management system
        # Implementation depends on available systems
        
        return evidence

    def _analyze_logs(self, control: Dict) -> List[str]:
        """Analyze logs for compliance evidence"""
        evidence = []
        
        try:
            # Query Elasticsearch for relevant logs
            query = self._build_log_query(control)
            results = self.es.search(
                index='siem-logs-*',
                body=query,
                size=1000
            )
            
            # Process results
            for hit in results['hits']['hits']:
                evidence.append(self._format_log_evidence(hit))
        except Exception as e:
            logger.error(f"Log analysis failed: {e}")
        
        return evidence

    def _check_policies(self, control: Dict) -> List[str]:
        """Check policy compliance"""
        evidence = []
        
        # Query policy management system
        # Implementation depends on available systems
        
        return evidence

    def _perform_technical_checks(self, control: Dict) -> List[str]:
        """Perform technical compliance checks"""
        evidence = []
        
        try:
            if control.get('check_type') == 'network':
                evidence.extend(self._check_network_compliance(control))
            elif control.get('check_type') == 'system':
                evidence.extend(self._check_system_compliance(control))
            elif control.get('check_type') == 'application':
                evidence.extend(self._check_application_compliance(control))
        except Exception as e:
            logger.error(f"Technical check failed: {e}")
        
        return evidence

    def _evaluate_control(self, control: Dict, evidence: List[str]) -> str:
        """Evaluate control based on evidence"""
        try:
            if not evidence:
                return 'failed'
            
            # Count evidence types
            failures = sum(1 for e in evidence if 'failure' in e.lower())
            warnings = sum(1 for e in evidence if 'warning' in e.lower())
            
            # Evaluate based on thresholds
            if failures > 0:
                return 'failed'
            elif warnings > 0:
                return 'warning'
            return 'passed'
        except Exception as e:
            logger.error(f"Control evaluation failed: {e}")
            return 'error'

    def _generate_remediation(self, control: Dict, evidence: List[str]) -> str:
        """Generate remediation steps for failed control"""
        try:
            remediation = "Recommended remediation steps:\n"
            
            # Add control-specific remediation steps
            if 'remediation_steps' in control:
                remediation += "\n".join(control['remediation_steps'])
            
            # Add evidence-based recommendations
            remediation += "\nBased on evidence:\n"
            for e in evidence:
                if 'failure' in e.lower():
                    remediation += f"- Address: {e}\n"
            
            return remediation
        except Exception as e:
            logger.error(f"Remediation generation failed: {e}")
            return "Remediation generation failed"

    def _store_audit_result(self, result: AuditResult):
        """Store audit result"""
        try:
            doc = {
                'framework': result.framework,
                'control_id': result.control_id,
                'status': result.status,
                'evidence': result.evidence,
                'remediation': result.remediation,
                'timestamp': result.timestamp.isoformat()
            }
            
            self.es.index(
                index='siem-compliance-audits',
                body=doc
            )
        except Exception as e:
            logger.error(f"Failed to store audit result: {e}")

    def _generate_audit_report(self, framework: str, results: List[AuditResult]) -> Dict:
        """Generate comprehensive audit report"""
        try:
            report = {
                'framework': framework,
                'timestamp': datetime.now().isoformat(),
                'summary': {
                    'total_controls': len(results),
                    'passed': sum(1 for r in results if r.status == 'passed'),
                    'failed': sum(1 for r in results if r.status == 'failed'),
                    'warnings': sum(1 for r in results if r.status == 'warning'),
                    'errors': sum(1 for r in results if r.status == 'error')
                },
                'results': [self._format_result_for_report(r) for r in results],
                'recommendations': self._generate_report_recommendations(results)
            }
            
            # Store report
            self.es.index(
                index='siem-compliance-reports',
                body=report
            )
            
            return report
        except Exception as e:
            logger.error(f"Failed to generate audit report: {e}")
            return {}

    def _format_result_for_report(self, result: AuditResult) -> Dict:
        """Format audit result for report"""
        return {
            'control_id': result.control_id,
            'status': result.status,
            'evidence_count': len(result.evidence),
            'evidence_summary': self._summarize_evidence(result.evidence),
            'remediation': result.remediation
        }

    def _summarize_evidence(self, evidence: List[str]) -> str:
        """Create summary of evidence"""
        if not evidence:
            return "No evidence collected"
        
        summary = []
        for e in evidence:
            if len(e) > 100:
                summary.append(e[:97] + "...")
            else:
                summary.append(e)
        
        return "\n".join(summary)

    def _generate_report_recommendations(self, results: List[AuditResult]) -> List[str]:
        """Generate overall recommendations based on audit results"""
        recommendations = []
        
        # Analyze patterns in failures
        failed_controls = [r for r in results if r.status == 'failed']
        if failed_controls:
            recommendations.append(
                f"Priority: Address {len(failed_controls)} failed controls immediately"
            )
        
        # Analyze warning patterns
        warning_controls = [r for r in results if r.status == 'warning']
        if warning_controls:
            recommendations.append(
                f"Review {len(warning_controls)} controls with warnings"
            )
        
        # Add framework-specific recommendations
        # Implementation depends on framework requirements
        
        return recommendations

    def get_compliance_status(self) -> Dict:
        """Get overall compliance status"""
        try:
            status = {
                'frameworks': {},
                'overall_compliance': 0.0,
                'last_updated': datetime.now().isoformat()
            }
            
            for name, framework in self.frameworks.items():
                # Get latest audit results
                results = self._get_latest_audit_results(name)
                
                if results:
                    # Calculate compliance score
                    total = len(results)
                    passed = sum(1 for r in results if r.status == 'passed')
                    score = (passed / total) * 100 if total > 0 else 0
                    
                    status['frameworks'][name] = {
                        'compliance_score': score,
                        'last_audit': framework.last_audit.isoformat() if framework.last_audit else None,
                        'controls_passed': passed,
                        'controls_total': total
                    }
            
            # Calculate overall compliance
            if status['frameworks']:
                scores = [fw['compliance_score'] for fw in status['frameworks'].values()]
                status['overall_compliance'] = sum(scores) / len(scores)
            
            return status
        except Exception as e:
            logger.error(f"Failed to get compliance status: {e}")
            return {}

    def _get_latest_audit_results(self, framework: str) -> List[AuditResult]:
        """Get latest audit results for framework"""
        try:
            query = {
                'query': {
                    'bool': {
                        'must': [
                            {'term': {'framework': framework}},
                            {'range': {
                                'timestamp': {
                                    'gte': 'now-30d'
                                }
                            }}
                        ]
                    }
                },
                'sort': [{'timestamp': 'desc'}],
                'size': 1000
            }
            
            results = self.es.search(
                index='siem-compliance-audits',
                body=query
            )
            
            return [self._convert_hit_to_result(hit) for hit in results['hits']['hits']]
        except Exception as e:
            logger.error(f"Failed to get latest audit results: {e}")
            return []

    def _convert_hit_to_result(self, hit: Dict) -> AuditResult:
        """Convert Elasticsearch hit to AuditResult"""
        source = hit['_source']
        return AuditResult(
            framework=source['framework'],
            control_id=source['control_id'],
            status=source['status'],
            evidence=source['evidence'],
            remediation=source.get('remediation'),
            timestamp=datetime.fromisoformat(source['timestamp'])
        )
