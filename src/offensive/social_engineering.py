import random
from typing import List, Dict, Optional
import json
from pathlib import Path
import logging
from datetime import datetime
import requests
from bs4 import BeautifulSoup
import re
import spacy

class SocialEngineeringToolkit:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.nlp = spacy.load("en_core_web_sm")
        self.templates_file = Path(__file__).parent / "data" / "email_templates.json"
        self.personas_file = Path(__file__).parent / "data" / "personas.json"
        
    def generate_phishing_campaign(self, target_info: Dict) -> Dict:
        """Generate a customized phishing campaign based on target information"""
        try:
            # Load email templates and personas
            templates = self._load_json(self.templates_file)
            personas = self._load_json(self.personas_file)
            
            # Analyze target information
            analysis = self._analyze_target(target_info)
            
            # Select appropriate template and persona
            template = self._select_template(templates, analysis)
            persona = self._select_persona(personas, analysis)
            
            # Customize content
            content = self._customize_content(template, persona, target_info)
            
            # Generate campaign details
            campaign = {
                "id": self._generate_campaign_id(),
                "target": target_info,
                "template": template["name"],
                "persona": persona["name"],
                "content": content,
                "recommended_timing": self._suggest_timing(),
                "success_metrics": self._define_success_metrics(),
                "risk_assessment": self._assess_risks(),
                "mitigation_strategies": self._generate_mitigations()
            }
            
            return campaign
            
        except Exception as e:
            self.logger.error(f"Error generating phishing campaign: {str(e)}")
            raise
            
    def analyze_website(self, url: str) -> Dict:
        """Analyze a website for potential social engineering vectors"""
        try:
            response = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'})
            soup = BeautifulSoup(response.text, 'html.parser')
            
            analysis = {
                "url": url,
                "technologies": self._detect_technologies(soup),
                "contact_forms": self._find_contact_forms(soup),
                "social_links": self._find_social_links(soup),
                "email_addresses": self._extract_emails(response.text),
                "potential_vulnerabilities": self._identify_vulnerabilities(soup),
                "trust_indicators": self._analyze_trust_indicators(soup),
                "recommendations": []
            }
            
            # Generate recommendations based on findings
            analysis["recommendations"] = self._generate_recommendations(analysis)
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error analyzing website: {str(e)}")
            raise
            
    def generate_pretexting_scenario(self, target_profile: Dict) -> Dict:
        """Generate a pretexting scenario based on target profile"""
        try:
            scenario = {
                "persona": self._create_persona(),
                "background_story": self._generate_background_story(target_profile),
                "conversation_points": self._generate_conversation_points(target_profile),
                "supporting_documents": self._suggest_supporting_documents(),
                "risk_factors": self._identify_risk_factors(),
                "success_metrics": self._define_pretext_metrics(),
                "abort_conditions": self._define_abort_conditions(),
                "legal_considerations": self._legal_compliance_check()
            }
            
            return scenario
            
        except Exception as e:
            self.logger.error(f"Error generating pretexting scenario: {str(e)}")
            raise
            
    def _analyze_target(self, target_info: Dict) -> Dict:
        """Analyze target information for campaign customization"""
        analysis = {
            "industry": target_info.get("industry"),
            "size": target_info.get("size"),
            "security_posture": self._assess_security_posture(target_info),
            "technical_sophistication": self._assess_technical_sophistication(target_info),
            "potential_vulnerabilities": self._identify_target_vulnerabilities(target_info),
            "recommended_approach": self._determine_approach(target_info)
        }
        
        return analysis
        
    def _select_template(self, templates: List[Dict], analysis: Dict) -> Dict:
        """Select the most appropriate template based on target analysis"""
        scored_templates = []
        
        for template in templates:
            score = 0
            # Score based on industry match
            if template.get("industry") == analysis.get("industry"):
                score += 2
            # Score based on sophistication level
            if template.get("sophistication") == analysis.get("technical_sophistication"):
                score += 2
            # Score based on approach match
            if template.get("approach") == analysis.get("recommended_approach"):
                score += 3
                
            scored_templates.append((score, template))
            
        # Return the template with the highest score
        return max(scored_templates, key=lambda x: x[0])[1]
        
    def _customize_content(self, template: Dict, persona: Dict, target_info: Dict) -> Dict:
        """Customize template content for the target"""
        content = template["content"].copy()
        
        # Replace placeholders with target-specific information
        replacements = {
            "{{company}}": target_info.get("company_name", ""),
            "{{name}}": target_info.get("contact_name", ""),
            "{{position}}": target_info.get("position", ""),
            "{{sender_name}}": persona.get("name", ""),
            "{{sender_position}}": persona.get("position", ""),
            "{{sender_company}}": persona.get("company", "")
        }
        
        for key, value in replacements.items():
            content["subject"] = content["subject"].replace(key, value)
            content["body"] = content["body"].replace(key, value)
            
        return content
        
    def _generate_mitigations(self) -> List[str]:
        """Generate mitigation strategies for the campaign"""
        return [
            "Implement DMARC, SPF, and DKIM email authentication",
            "Train employees on social engineering awareness",
            "Use email filtering and anti-phishing solutions",
            "Implement multi-factor authentication",
            "Regular security awareness training",
            "Establish clear security policies and procedures",
            "Monitor for suspicious email patterns",
            "Regular penetration testing and vulnerability assessments"
        ]
        
    def _detect_technologies(self, soup: BeautifulSoup) -> List[str]:
        """Detect technologies used on the website"""
        technologies = []
        
        # Check for common frameworks and libraries
        if soup.find(string=re.compile(r'jquery|bootstrap|react|angular|vue')):
            technologies.extend(['jQuery', 'Bootstrap', 'React', 'Angular', 'Vue.js'])
            
        # Check meta tags for technology hints
        meta_tags = soup.find_all('meta')
        for tag in meta_tags:
            if tag.get('name') == 'generator':
                technologies.append(tag.get('content'))
                
        return list(set(technologies))
        
    def _generate_recommendations(self, analysis: Dict) -> List[str]:
        """Generate security recommendations based on website analysis"""
        recommendations = []
        
        # Check for missing security headers
        if "security_headers" not in analysis.get("technologies", []):
            recommendations.append("Implement security headers (HSTS, CSP, X-Frame-Options)")
            
        # Check for exposed email addresses
        if analysis.get("email_addresses"):
            recommendations.append("Protect email addresses from harvesting")
            
        # Check for vulnerable contact forms
        if analysis.get("contact_forms"):
            recommendations.append("Implement CAPTCHA and rate limiting on forms")
            
        return recommendations
        
    def _legal_compliance_check(self) -> Dict:
        """Check legal compliance considerations"""
        return {
            "gdpr_compliance": [
                "Ensure data collection is minimal and necessary",
                "Implement proper data handling procedures",
                "Document all data processing activities"
            ],
            "ccpa_compliance": [
                "Provide notice of data collection",
                "Implement data subject access rights",
                "Maintain data inventory"
            ],
            "ethical_considerations": [
                "Avoid targeting vulnerable individuals",
                "Maintain professional boundaries",
                "Document all activities for audit purposes"
            ]
        }
        
    def _load_json(self, file_path: Path) -> Dict:
        """Load and parse JSON file"""
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Error loading JSON file {file_path}: {str(e)}")
            raise
