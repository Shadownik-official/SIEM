import logging
import smtplib
import dns.resolver
import requests
import json
import yaml
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Dict, Optional
from datetime import datetime
import random
import string
from pathlib import Path

from ..utils.logging import setup_logger
from ..utils.encryption import encrypt_data, decrypt_data
from ..utils.database import Database

class SocialEngineeringToolkit:
    """Advanced social engineering assessment and simulation toolkit."""
    
    def __init__(self, config_path: str):
        self.logger = setup_logger("SocialEngineeringToolkit")
        self.load_config(config_path)
        self.db = Database()
        
    def load_config(self, config_path: str) -> None:
        """Load toolkit configuration."""
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
            
        # Email configuration
        self.email_config = self.config['social_engineering']['email']
        
    def create_phishing_campaign(self, campaign_config: dict) -> str:
        """Create and configure a new phishing assessment campaign."""
        try:
            campaign_id = self._generate_campaign_id()
            
            campaign_data = {
                'id': campaign_id,
                'name': campaign_config['name'],
                'type': campaign_config['type'],
                'start_date': campaign_config.get('start_date', datetime.now().isoformat()),
                'end_date': campaign_config.get('end_date'),
                'targets': self._validate_targets(campaign_config['targets']),
                'template': campaign_config['template'],
                'tracking_enabled': campaign_config.get('tracking_enabled', True),
                'status': 'configured',
                'results': {
                    'sent': 0,
                    'opened': 0,
                    'clicked': 0,
                    'reported': 0
                }
            }
            
            # Store campaign data
            self.db.store_campaign(campaign_id, encrypt_data(campaign_data))
            
            self.logger.info(f"Created phishing campaign: {campaign_id}")
            return campaign_id
            
        except Exception as e:
            self.logger.error(f"Error creating phishing campaign: {str(e)}")
            raise
            
    def start_campaign(self, campaign_id: str) -> None:
        """Start a configured phishing campaign."""
        try:
            campaign_data = self._get_campaign(campaign_id)
            if not campaign_data:
                raise ValueError(f"Campaign not found: {campaign_id}")
                
            if campaign_data['status'] != 'configured':
                raise ValueError(f"Campaign {campaign_id} is not in configured state")
                
            # Update campaign status
            campaign_data['status'] = 'running'
            campaign_data['start_time'] = datetime.now().isoformat()
            
            # Send phishing emails
            for target in campaign_data['targets']:
                self._send_phishing_email(campaign_id, target, campaign_data['template'])
                campaign_data['results']['sent'] += 1
                
            # Update campaign data
            self.db.update_campaign(campaign_id, encrypt_data(campaign_data))
            
            self.logger.info(f"Started phishing campaign: {campaign_id}")
            
        except Exception as e:
            self.logger.error(f"Error starting campaign {campaign_id}: {str(e)}")
            raise
            
    def stop_campaign(self, campaign_id: str) -> None:
        """Stop an active phishing campaign."""
        try:
            campaign_data = self._get_campaign(campaign_id)
            if not campaign_data:
                raise ValueError(f"Campaign not found: {campaign_id}")
                
            if campaign_data['status'] != 'running':
                raise ValueError(f"Campaign {campaign_id} is not running")
                
            # Update campaign status
            campaign_data['status'] = 'completed'
            campaign_data['end_time'] = datetime.now().isoformat()
            
            # Store final results
            self.db.update_campaign(campaign_id, encrypt_data(campaign_data))
            
            self.logger.info(f"Stopped phishing campaign: {campaign_id}")
            
        except Exception as e:
            self.logger.error(f"Error stopping campaign {campaign_id}: {str(e)}")
            raise
            
    def get_campaign_results(self, campaign_id: str) -> dict:
        """Get detailed results of a phishing campaign."""
        try:
            campaign_data = self._get_campaign(campaign_id)
            if not campaign_data:
                raise ValueError(f"Campaign not found: {campaign_id}")
                
            results = {
                'campaign_id': campaign_id,
                'name': campaign_data['name'],
                'status': campaign_data['status'],
                'duration': self._calculate_duration(campaign_data),
                'statistics': campaign_data['results'],
                'success_rate': self._calculate_success_rate(campaign_data['results']),
                'target_breakdown': self._get_target_breakdown(campaign_id)
            }
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error getting campaign results: {str(e)}")
            raise
            
    def generate_report(self, campaign_id: str, format: str = 'pdf') -> str:
        """Generate a detailed campaign report."""
        try:
            results = self.get_campaign_results(campaign_id)
            
            # Generate report based on format
            if format == 'pdf':
                report_path = self._generate_pdf_report(results)
            elif format == 'html':
                report_path = self._generate_html_report(results)
            else:
                raise ValueError(f"Unsupported report format: {format}")
                
            return report_path
            
        except Exception as e:
            self.logger.error(f"Error generating report: {str(e)}")
            raise
            
    def _send_phishing_email(self, campaign_id: str, target: dict, template: dict) -> None:
        """Send a phishing assessment email to a target."""
        try:
            # Prepare email content
            msg = MIMEMultipart('alternative')
            msg['Subject'] = template['subject']
            msg['From'] = self.email_config['from_address']
            msg['To'] = target['email']
            
            # Add tracking pixel and modified links
            html_content = self._prepare_email_content(
                template['content'],
                campaign_id,
                target['email']
            )
            
            msg.attach(MIMEText(html_content, 'html'))
            
            # Send email
            with smtplib.SMTP(self.email_config['smtp_server'], self.email_config['smtp_port']) as server:
                server.starttls()
                server.login(
                    self.email_config['username'],
                    self.email_config['password']
                )
                server.send_message(msg)
                
            self.logger.info(f"Sent phishing email to {target['email']}")
            
        except Exception as e:
            self.logger.error(f"Error sending phishing email: {str(e)}")
            raise
            
    def _prepare_email_content(self, content: str, campaign_id: str, target_email: str) -> str:
        """Prepare email content with tracking elements."""
        try:
            # Add tracking pixel
            tracking_pixel = self._generate_tracking_pixel(campaign_id, target_email)
            content = content.replace('</body>', f'{tracking_pixel}</body>')
            
            # Modify links for click tracking
            content = self._modify_links_for_tracking(content, campaign_id, target_email)
            
            return content
            
        except Exception as e:
            self.logger.error(f"Error preparing email content: {str(e)}")
            raise
            
    def _generate_tracking_pixel(self, campaign_id: str, target_email: str) -> str:
        """Generate HTML for a tracking pixel."""
        tracking_url = self._generate_tracking_url(
            campaign_id, target_email, 'open'
        )
        return f'<img src="{tracking_url}" style="display:none" />'
        
    def _modify_links_for_tracking(self, content: str, campaign_id: str, target_email: str) -> str:
        """Modify links in content to enable click tracking."""
        # Implementation depends on your tracking system
        return content
        
    def _generate_tracking_url(self, campaign_id: str, target_email: str, action: str) -> str:
        """Generate tracking URL for email opens and clicks."""
        # Implementation depends on your tracking system
        return f"https://track.example.com/{campaign_id}/{action}/{target_email}"
        
    def _validate_targets(self, targets: List[dict]) -> List[dict]:
        """Validate and enrich target information."""
        validated_targets = []
        for target in targets:
            if self._is_valid_email(target['email']):
                # Enrich target data
                enriched_target = {
                    **target,
                    'domain': target['email'].split('@')[1],
                    'validated': True
                }
                validated_targets.append(enriched_target)
            else:
                self.logger.warning(f"Invalid email: {target['email']}")
                
        return validated_targets
        
    @staticmethod
    def _is_valid_email(email: str) -> bool:
        """Validate email address format and domain."""
        try:
            # Basic format validation
            if '@' not in email or '.' not in email:
                return False
                
            # Domain validation
            domain = email.split('@')[1]
            dns.resolver.resolve(domain, 'MX')
            
            return True
            
        except Exception:
            return False
            
    @staticmethod
    def _generate_campaign_id() -> str:
        """Generate unique campaign identifier."""
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        random_string = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        return f"PHISH_{timestamp}_{random_string}"
        
    def _get_campaign(self, campaign_id: str) -> Optional[dict]:
        """Retrieve campaign data from database."""
        try:
            encrypted_data = self.db.get_campaign(campaign_id)
            if encrypted_data:
                return decrypt_data(encrypted_data)
            return None
            
        except Exception as e:
            self.logger.error(f"Error retrieving campaign data: {str(e)}")
            return None
            
    @staticmethod
    def _calculate_duration(campaign_data: dict) -> str:
        """Calculate campaign duration."""
        start_time = datetime.fromisoformat(campaign_data['start_time'])
        end_time = datetime.fromisoformat(campaign_data.get('end_time', datetime.now().isoformat()))
        duration = end_time - start_time
        return str(duration)
        
    @staticmethod
    def _calculate_success_rate(results: dict) -> float:
        """Calculate campaign success rate."""
        if results['sent'] == 0:
            return 0.0
        return (results['clicked'] / results['sent']) * 100
        
    def _get_target_breakdown(self, campaign_id: str) -> dict:
        """Get detailed breakdown of target responses."""
        # Implementation depends on your tracking system
        return {
            'total_targets': 0,
            'responded': 0,
            'reported': 0
        }
