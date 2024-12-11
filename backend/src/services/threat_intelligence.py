"""
Threat Intelligence Service for SIEM system.
Handles threat detection, analysis, and correlation.
"""
from typing import List, Dict, Any, Optional
from datetime import datetime
import aiohttp
import json
from ..models.event import Event, EventCategory, EventThreatLevel
from ..database import get_db
from ..core.exceptions import ThreatIntelligenceError

class ThreatIntelligence:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get('enabled', False)
        self.feeds = config.get('feeds', [])
        self.cache = {}
        self.ml_config = config.get('ml_models', {})

    async def analyze_event(self, event: Event) -> Dict[str, Any]:
        """Analyze an event for potential threats"""
        if not self.enabled:
            return {"threat_score": 0, "confidence": 0, "tags": []}

        analysis = {
            "threat_score": 0,
            "confidence": 0,
            "tags": [],
            "indicators": [],
            "recommendations": []
        }

        try:
            # Check IoCs against threat feeds
            ioc_matches = await self._check_threat_feeds(event)
            if ioc_matches:
                analysis["indicators"].extend(ioc_matches)
                analysis["threat_score"] += 30
                analysis["tags"].extend([match["type"] for match in ioc_matches])

            # Perform behavioral analysis
            behavior_score = await self._analyze_behavior(event)
            analysis["threat_score"] += behavior_score

            # Correlate with other events
            correlation = await self._correlate_events(event)
            if correlation["related_events"]:
                analysis["threat_score"] += correlation["score"]
                analysis["indicators"].extend(correlation["indicators"])

            # Calculate final confidence score
            analysis["confidence"] = self._calculate_confidence(analysis)

            # Generate recommendations
            analysis["recommendations"] = self._generate_recommendations(analysis)

            return analysis

        except Exception as e:
            raise ThreatIntelligenceError(f"Error analyzing event: {str(e)}")

    async def _check_threat_feeds(self, event: Event) -> List[Dict[str, Any]]:
        """Check event indicators against threat feeds"""
        matches = []
        
        for feed in self.feeds:
            if not feed.get('enabled'):
                continue

            try:
                if feed['type'] == 'otx':
                    matches.extend(await self._check_otx_feed(event, feed))
                elif feed['type'] == 'virustotal':
                    matches.extend(await self._check_virustotal(event, feed))
                # Add more feed types as needed
            except Exception as e:
                continue  # Log error but continue with other feeds

        return matches

    async def _check_otx_feed(self, event: Event, feed_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check indicators against OTX feed"""
        api_key = feed_config.get('api_key')
        if not api_key:
            return []

        matches = []
        indicators = self._extract_indicators(event)

        async with aiohttp.ClientSession() as session:
            for indicator in indicators:
                cache_key = f"otx:{indicator}"
                if cache_key in self.cache:
                    matches.extend(self.cache[cache_key])
                    continue

                url = f"https://otx.alienvault.com/api/v1/indicators/{indicator}/general"
                headers = {'X-OTX-API-KEY': api_key}
                
                try:
                    async with session.get(url, headers=headers) as response:
                        if response.status == 200:
                            data = await response.json()
                            if data.get('pulse_info', {}).get('count', 0) > 0:
                                match = {
                                    "type": "otx",
                                    "indicator": indicator,
                                    "pulses": data['pulse_info']['pulses'],
                                    "timestamp": datetime.utcnow().isoformat()
                                }
                                matches.append(match)
                                self.cache[cache_key] = [match]
                except Exception:
                    continue

        return matches

    async def _analyze_behavior(self, event: Event) -> int:
        """Analyze event behavior patterns"""
        score = 0
        
        # Check event category severity
        if event.category in [EventCategory.PRIVILEGE_ESCALATION, 
                            EventCategory.DEFENSE_EVASION,
                            EventCategory.COMMAND_AND_CONTROL]:
            score += 20

        # Check for suspicious patterns
        patterns = self._check_suspicious_patterns(event)
        score += len(patterns) * 10

        # Check for anomalies using ML models
        if self.ml_config.get('enabled'):
            anomaly_score = await self._check_anomalies(event)
            score += anomaly_score

        return min(score, 100)  # Cap at 100

    async def _correlate_events(self, event: Event) -> Dict[str, Any]:
        """Correlate event with other recent events"""
        db = next(get_db())
        
        # Look for related events in the last hour
        time_window = datetime.utcnow() - datetime.timedelta(hours=1)
        related_events = db.query(Event).filter(
            Event.timestamp >= time_window,
            Event.id != event.id,
            Event.source_ip.in_([event.source_ip, event.destination_ip])
        ).all()

        correlation = {
            "related_events": [],
            "score": 0,
            "indicators": []
        }

        if related_events:
            correlation["related_events"] = [e.id for e in related_events]
            correlation["score"] = min(len(related_events) * 5, 30)
            
            # Look for attack patterns
            if self._check_attack_chain(related_events + [event]):
                correlation["score"] += 20
                correlation["indicators"].append({
                    "type": "attack_chain",
                    "description": "Potential attack chain detected"
                })

        return correlation

    def _check_suspicious_patterns(self, event: Event) -> List[str]:
        """Check for suspicious patterns in event data"""
        patterns = []
        
        if event.raw_event_data:
            # Check for common malware patterns
            if self._check_malware_patterns(event.raw_event_data):
                patterns.append("malware_behavior")

            # Check for suspicious commands
            if self._check_suspicious_commands(event.raw_event_data):
                patterns.append("suspicious_command")

            # Check for data exfiltration patterns
            if self._check_data_exfiltration(event.raw_event_data):
                patterns.append("potential_exfiltration")

        return patterns

    def _calculate_confidence(self, analysis: Dict[str, Any]) -> int:
        """Calculate confidence score for the analysis"""
        confidence = 0
        
        # Base confidence on number of indicators
        indicator_count = len(analysis["indicators"])
        confidence += min(indicator_count * 10, 40)

        # Add confidence based on threat score
        confidence += (analysis["threat_score"] // 10) * 5

        # Add confidence based on tag diversity
        unique_tags = len(set(analysis["tags"]))
        confidence += min(unique_tags * 5, 20)

        return min(confidence, 100)

    def _generate_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []

        if analysis["threat_score"] >= 70:
            recommendations.append("Immediate investigation recommended")
            recommendations.append("Consider blocking source IP")

        if "malware_behavior" in analysis["tags"]:
            recommendations.append("Run malware scan on affected systems")
            recommendations.append("Update antivirus signatures")

        if analysis["threat_score"] >= 50:
            recommendations.append("Review system logs for related activities")
            recommendations.append("Enable enhanced monitoring for affected assets")

        return recommendations

    @staticmethod
    def _extract_indicators(event: Event) -> List[str]:
        """Extract potential indicators from event"""
        indicators = []
        
        if event.source_ip:
            indicators.append(event.source_ip)
        if event.destination_ip:
            indicators.append(event.destination_ip)
            
        # Extract additional indicators from raw event data
        if event.raw_event_data:
            # Add extraction logic based on event data structure
            pass

        return indicators

    @staticmethod
    def _check_attack_chain(events: List[Event]) -> bool:
        """Check if events form a potential attack chain"""
        # Implement MITRE ATT&CK chain detection
        attack_stages = {e.category for e in events}
        
        # Check for progression through attack stages
        progression = [
            EventCategory.RECONNAISSANCE,
            EventCategory.INITIAL_ACCESS,
            EventCategory.EXECUTION,
            EventCategory.PERSISTENCE
        ]
        
        return all(stage in attack_stages for stage in progression)
