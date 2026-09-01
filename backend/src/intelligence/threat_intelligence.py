from typing import List, Dict, Optional
from dataclasses import dataclass
from enum import Enum, auto

class ThreatSeverity(Enum):
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()

@dataclass
class ThreatIndicator:
    type: str
    value: str
    confidence: float
    severity: ThreatSeverity

@dataclass
class ThreatActor:
    name: str
    motivation: str
    techniques: List[str]

class ThreatIntelligence:
    def __init__(self):
        self.indicators: List[ThreatIndicator] = []
        self.actors: List[ThreatActor] = []

    def add_indicator(self, indicator: ThreatIndicator):
        self.indicators.append(indicator)

    def add_actor(self, actor: ThreatActor):
        self.actors.append(actor)

class ThreatIntelligenceEnhanced(ThreatIntelligence):
    def correlate_indicators(self) -> List[Dict]:
        # Enhanced correlation logic
        return [
            {
                "indicator": ind,
                "potential_actor": next((actor for actor in self.actors if ind.type in actor.techniques), None)
            } for ind in self.indicators
        ]

    def detect_advanced_threats(self) -> List[ThreatIndicator]:
        return [
            ind for ind in self.indicators 
            if ind.severity in [ThreatSeverity.HIGH, ThreatSeverity.CRITICAL]
        ]
