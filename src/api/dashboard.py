"""
Dashboard API Module for Enterprise SIEM
Handles all dashboard-related API endpoints and data processing
"""
import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from elasticsearch import Elasticsearch
from redis import Redis

# Initialize FastAPI app
app = FastAPI(
    title="Enterprise SIEM Dashboard API",
    description="API for the Enterprise SIEM Dashboard",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify actual origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize OAuth2
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Initialize logging
logger = logging.getLogger(__name__)

class DashboardAPI:
    def __init__(self, es_client: Elasticsearch, redis_client: Redis):
        self.es = es_client
        self.redis = redis_client

    async def get_overview_stats(self) -> Dict:
        """Get overview statistics for dashboard"""
        try:
            stats = {
                'total_events': await self._get_total_events(),
                'active_threats': await self._get_active_threats(),
                'system_health': await self._get_system_health(),
                'compliance_status': await self._get_compliance_status(),
                'timestamp': datetime.now().isoformat()
            }
            return stats
        except Exception as e:
            logger.error(f"Failed to get overview stats: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    async def _get_total_events(self) -> Dict:
        """Get total event statistics"""
        try:
            # Query for events in different time ranges
            ranges = {
                'last_hour': 'now-1h',
                'last_day': 'now-1d',
                'last_week': 'now-7d',
                'last_month': 'now-30d'
            }
            
            stats = {}
            for period, time_range in ranges.items():
                query = {
                    'query': {
                        'range': {
                            'timestamp': {
                                'gte': time_range
                            }
                        }
                    }
                }
                
                result = await self.es.count(
                    index='siem-events-*',
                    body=query
                )
                
                stats[period] = result['count']
            
            return stats
        except Exception as e:
            logger.error(f"Failed to get total events: {e}")
            return {}

    async def _get_active_threats(self) -> Dict:
        """Get active threat statistics"""
        try:
            query = {
                'query': {
                    'bool': {
                        'must': [
                            {'range': {
                                'timestamp': {
                                    'gte': 'now-24h'
                                }
                            }},
                            {'range': {
                                'threat_score': {
                                    'gt': 0.5
                                }
                            }}
                        ]
                    }
                },
                'aggs': {
                    'severity_counts': {
                        'range': {
                            'field': 'threat_score',
                            'ranges': [
                                {'from': 0.5, 'to': 0.7},
                                {'from': 0.7, 'to': 0.9},
                                {'from': 0.9, 'to': 1.0}
                            ]
                        }
                    },
                    'threat_types': {
                        'terms': {
                            'field': 'threat_class.class'
                        }
                    }
                }
            }
            
            result = await self.es.search(
                index='siem-threats',
                body=query,
                size=0
            )
            
            return {
                'total': result['hits']['total']['value'],
                'severity_distribution': result['aggregations']['severity_counts']['buckets'],
                'threat_types': result['aggregations']['threat_types']['buckets']
            }
        except Exception as e:
            logger.error(f"Failed to get active threats: {e}")
            return {}

    async def _get_system_health(self) -> Dict:
        """Get system health metrics"""
        try:
            # Get various system health metrics
            metrics = {
                'cpu_usage': await self._get_cpu_usage(),
                'memory_usage': await self._get_memory_usage(),
                'disk_usage': await self._get_disk_usage(),
                'service_status': await self._get_service_status()
            }
            
            # Calculate overall health score
            health_score = self._calculate_health_score(metrics)
            metrics['overall_health'] = health_score
            
            return metrics
        except Exception as e:
            logger.error(f"Failed to get system health: {e}")
            return {}

    async def _get_compliance_status(self) -> Dict:
        """Get compliance status summary"""
        try:
            query = {
                'query': {
                    'range': {
                        'timestamp': {
                            'gte': 'now-30d'
                        }
                    }
                },
                'aggs': {
                    'frameworks': {
                        'terms': {
                            'field': 'framework'
                        },
                        'aggs': {
                            'status': {
                                'terms': {
                                    'field': 'status'
                                }
                            }
                        }
                    }
                }
            }
            
            result = await self.es.search(
                index='siem-compliance-audits',
                body=query,
                size=0
            )
            
            return self._process_compliance_results(result)
        except Exception as e:
            logger.error(f"Failed to get compliance status: {e}")
            return {}

    def _process_compliance_results(self, result: Dict) -> Dict:
        """Process compliance aggregation results"""
        try:
            compliance = {}
            
            for framework in result['aggregations']['frameworks']['buckets']:
                name = framework['key']
                total = framework['doc_count']
                status_counts = {
                    bucket['key']: bucket['doc_count']
                    for bucket in framework['status']['buckets']
                }
                
                # Calculate compliance score
                passed = status_counts.get('passed', 0)
                score = (passed / total * 100) if total > 0 else 0
                
                compliance[name] = {
                    'score': score,
                    'total_controls': total,
                    'status_distribution': status_counts
                }
            
            return compliance
        except Exception as e:
            logger.error(f"Failed to process compliance results: {e}")
            return {}

    async def get_threat_timeline(self, time_range: str = "24h") -> List[Dict]:
        """Get threat timeline data"""
        try:
            query = {
                'query': {
                    'range': {
                        'timestamp': {
                            'gte': f'now-{time_range}'
                        }
                    }
                },
                'aggs': {
                    'timeline': {
                        'date_histogram': {
                            'field': 'timestamp',
                            'fixed_interval': '1h'
                        },
                        'aggs': {
                            'severity_stats': {
                                'stats': {
                                    'field': 'threat_score'
                                }
                            },
                            'threat_types': {
                                'terms': {
                                    'field': 'threat_class.class'
                                }
                            }
                        }
                    }
                }
            }
            
            result = await self.es.search(
                index='siem-threats',
                body=query,
                size=0
            )
            
            return self._process_timeline_results(result)
        except Exception as e:
            logger.error(f"Failed to get threat timeline: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    def _process_timeline_results(self, result: Dict) -> List[Dict]:
        """Process threat timeline results"""
        try:
            timeline = []
            
            for bucket in result['aggregations']['timeline']['buckets']:
                point = {
                    'timestamp': bucket['key'],
                    'threat_count': bucket['doc_count'],
                    'avg_severity': bucket['severity_stats']['avg'],
                    'max_severity': bucket['severity_stats']['max'],
                    'threat_types': {
                        item['key']: item['doc_count']
                        for item in bucket['threat_types']['buckets']
                    }
                }
                timeline.append(point)
            
            return timeline
        except Exception as e:
            logger.error(f"Failed to process timeline results: {e}")
            return []

    async def get_network_map(self) -> Dict:
        """Get network topology map data"""
        try:
            # Get latest network topology
            query = {
                'query': {
                    'match_all': {}
                },
                'sort': [
                    {'timestamp': {'order': 'desc'}}
                ],
                'size': 1
            }
            
            result = await self.es.search(
                index='siem-network-topology',
                body=query
            )
            
            if result['hits']['hits']:
                topology = result['hits']['hits'][0]['_source']
                
                # Enrich with threat data
                await self._enrich_topology_with_threats(topology)
                
                return topology
            return {}
        except Exception as e:
            logger.error(f"Failed to get network map: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    async def _enrich_topology_with_threats(self, topology: Dict):
        """Enrich network topology with threat information"""
        try:
            # Get recent threats for each node
            for node in topology['nodes']:
                ip = node['id']
                
                query = {
                    'query': {
                        'bool': {
                            'must': [
                                {'term': {'event.source_ip': ip}},
                                {'range': {
                                    'timestamp': {
                                        'gte': 'now-24h'
                                    }
                                }}
                            ]
                        }
                    }
                }
                
                threats = await self.es.search(
                    index='siem-threats',
                    body=query,
                    size=10
                )
                
                node['threats'] = [
                    hit['_source'] for hit in threats['hits']['hits']
                ]
        except Exception as e:
            logger.error(f"Failed to enrich topology: {e}")

    async def get_compliance_report(self, framework: str) -> Dict:
        """Get detailed compliance report"""
        try:
            # Get latest compliance audit
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
                'sort': [
                    {'timestamp': {'order': 'desc'}}
                ],
                'size': 1000
            }
            
            result = await self.es.search(
                index='siem-compliance-reports',
                body=query
            )
            
            if result['hits']['hits']:
                report = result['hits']['hits'][0]['_source']
                
                # Add trend analysis
                report['trends'] = await self._get_compliance_trends(framework)
                
                return report
            return {}
        except Exception as e:
            logger.error(f"Failed to get compliance report: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    async def _get_compliance_trends(self, framework: str) -> Dict:
        """Get compliance trend analysis"""
        try:
            query = {
                'query': {
                    'bool': {
                        'must': [
                            {'term': {'framework': framework}},
                            {'range': {
                                'timestamp': {
                                    'gte': 'now-90d'
                                }
                            }}
                        ]
                    }
                },
                'aggs': {
                    'trends': {
                        'date_histogram': {
                            'field': 'timestamp',
                            'fixed_interval': '1d'
                        },
                        'aggs': {
                            'status': {
                                'terms': {
                                    'field': 'status'
                                }
                            }
                        }
                    }
                }
            }
            
            result = await self.es.search(
                index='siem-compliance-audits',
                body=query,
                size=0
            )
            
            return self._process_trend_results(result)
        except Exception as e:
            logger.error(f"Failed to get compliance trends: {e}")
            return {}

    def _process_trend_results(self, result: Dict) -> Dict:
        """Process compliance trend results"""
        try:
            trends = []
            
            for bucket in result['aggregations']['trends']['buckets']:
                point = {
                    'timestamp': bucket['key'],
                    'total': bucket['doc_count'],
                    'status_counts': {
                        status['key']: status['doc_count']
                        for status in bucket['status']['buckets']
                    }
                }
                trends.append(point)
            
            return {
                'daily_trends': trends,
                'summary': self._calculate_trend_summary(trends)
            }
        except Exception as e:
            logger.error(f"Failed to process trend results: {e}")
            return {}

    def _calculate_trend_summary(self, trends: List[Dict]) -> Dict:
        """Calculate trend summary statistics"""
        try:
            if not trends:
                return {}
            
            # Calculate compliance score for each day
            scores = []
            for day in trends:
                total = day['total']
                passed = day['status_counts'].get('passed', 0)
                score = (passed / total * 100) if total > 0 else 0
                scores.append(score)
            
            return {
                'avg_score': sum(scores) / len(scores),
                'min_score': min(scores),
                'max_score': max(scores),
                'trend_direction': 'improving' if scores[-1] > scores[0] else 'declining'
            }
        except Exception as e:
            logger.error(f"Failed to calculate trend summary: {e}")
            return {}
