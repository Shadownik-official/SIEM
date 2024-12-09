"""
Advanced Model Evaluation and Monitoring Module for SIEM ML Pipeline
Handles comprehensive model evaluation, performance monitoring, and drift detection.
"""
import logging
import json
from datetime import datetime, timedelta
import numpy as np
from sklearn.metrics import (
    precision_score, recall_score, f1_score,
    confusion_matrix, roc_curve, auc,
    precision_recall_curve, average_precision_score
)
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Dict, List, Optional, Union
import pandas as pd
from .training import ModelTrainingPipeline
from ..core.utils import encrypt_data, decrypt_data

logger = logging.getLogger(__name__)

class ModelEvaluator:
    """Advanced model evaluation and monitoring system."""
    
    def __init__(self, elasticsearch_client, redis_client):
        self.es = elasticsearch_client
        self.redis = redis_client
        self.pipeline = ModelTrainingPipeline(elasticsearch_client, redis_client)
        self.metrics_history = {}
        self.drift_detector = self._initialize_drift_detector()
        
    def evaluate_model_performance(self, model_name: str, X_test: np.ndarray, 
                                 y_test: np.ndarray, detailed: bool = False) -> Dict:
        """
        Comprehensive model evaluation with detailed metrics and performance analysis.
        
        Args:
            model_name: Name of the model to evaluate
            X_test: Test features
            y_test: True labels
            detailed: Whether to include detailed analysis
            
        Returns:
            Dictionary containing evaluation metrics and analysis
        """
        metrics = {}
        
        try:
            # Basic evaluation
            if model_name == 'anomaly_detector':
                metrics = self._evaluate_anomaly_detector(X_test, y_test)
            elif model_name == 'behavior_analyzer':
                metrics = self._evaluate_behavior_analyzer(X_test, y_test)
            elif model_name == 'threat_classifier':
                metrics = self._evaluate_threat_classifier(X_test, y_test)
                
            # Add timestamp
            metrics['timestamp'] = datetime.now()
            metrics['model_name'] = model_name
            
            # Detailed analysis if requested
            if detailed:
                metrics.update(self._perform_detailed_analysis(
                    model_name, X_test, y_test, metrics
                ))
                
            # Check for performance degradation
            if self._detect_performance_degradation(model_name, metrics):
                self._trigger_model_retraining(model_name)
                
            # Store metrics
            self._store_metrics(model_name, metrics)
            
            # Update drift detection
            self._update_drift_detection(model_name, X_test)
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error evaluating model {model_name}: {str(e)}")
            return {'error': str(e)}
            
    def _evaluate_anomaly_detector(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict:
        """Enhanced anomaly detector evaluation with advanced metrics."""
        try:
            scores = self.pipeline.anomaly_detector.decision_function(X_test)
            predictions = self.pipeline.anomaly_detector.predict(X_test)
            
            # Calculate basic metrics
            metrics = {
                'precision': float(precision_score(y_test, predictions)),
                'recall': float(recall_score(y_test, predictions)),
                'f1': float(f1_score(y_test, predictions)),
                'confusion_matrix': confusion_matrix(y_test, predictions).tolist()
            }
            
            # Calculate ROC and AUC
            fpr, tpr, _ = roc_curve(y_test, scores)
            metrics['auc_roc'] = float(auc(fpr, tpr))
            
            # Calculate precision-recall curve
            precision, recall, _ = precision_recall_curve(y_test, scores)
            metrics['avg_precision'] = float(average_precision_score(y_test, scores))
            
            # Calculate threshold metrics
            metrics['optimal_threshold'] = self._find_optimal_threshold(
                y_test, scores
            )
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error evaluating anomaly detector: {str(e)}")
            return {}
            
    def _perform_detailed_analysis(self, model_name: str, X_test: np.ndarray,
                                 y_test: np.ndarray, basic_metrics: Dict) -> Dict:
        """Perform detailed model analysis."""
        try:
            analysis = {
                'feature_importance': self._analyze_feature_importance(model_name, X_test),
                'error_analysis': self._analyze_errors(model_name, X_test, y_test),
                'performance_stability': self._analyze_performance_stability(model_name),
                'prediction_confidence': self._analyze_prediction_confidence(model_name, X_test),
                'model_complexity': self._analyze_model_complexity(model_name)
            }
            
            return {'detailed_analysis': analysis}
            
        except Exception as e:
            logger.error(f"Error in detailed analysis: {str(e)}")
            return {}
            
    def _detect_performance_degradation(self, model_name: str, 
                                      current_metrics: Dict) -> bool:
        """Detect model performance degradation."""
        try:
            if model_name not in self.metrics_history:
                self.metrics_history[model_name] = []
                
            history = self.metrics_history[model_name]
            history.append(current_metrics)
            
            # Keep last 10 evaluations
            if len(history) > 10:
                history.pop(0)
                
            # Check for significant degradation
            if len(history) < 2:
                return False
                
            current_f1 = current_metrics['f1']
            avg_f1 = np.mean([m['f1'] for m in history[:-1]])
            
            return (avg_f1 - current_f1) > self.config.degradation_threshold
            
        except Exception as e:
            logger.error(f"Error detecting performance degradation: {str(e)}")
            return False
            
    def generate_evaluation_report(self, model_name: str, 
                                 metrics: Dict) -> Dict:
        """Generate comprehensive evaluation report."""
        try:
            report = {
                'summary': self._generate_summary(metrics),
                'detailed_metrics': self._format_detailed_metrics(metrics),
                'visualizations': self._generate_visualizations(metrics),
                'recommendations': self._generate_recommendations(model_name, metrics),
                'historical_comparison': self._compare_with_history(model_name, metrics)
            }
            
            return report
            
        except Exception as e:
            logger.error(f"Error generating evaluation report: {str(e)}")
            return {'error': str(e)}
            
    def _evaluate_behavior_analyzer(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict:
        """Evaluate behavior analysis model"""
        X_seq = self.pipeline.behavior_analyzer.prepare_sequences(X_test)
        y_seq = y_test[self.pipeline.behavior_analyzer.sequence_length:]
        
        predictions = self.pipeline.behavior_analyzer.predict(X_seq)
        probabilities = self.pipeline.behavior_analyzer.predict_proba(X_seq)
        
        metrics = {
            'accuracy': float((predictions == y_seq).mean()),
            'precision': float(precision_score(y_seq, predictions)),
            'recall': float(recall_score(y_seq, predictions)),
            'f1': float(f1_score(y_seq, predictions)),
            'auc_roc': float(roc_curve(y_seq, probabilities)[2])
        }
        
        return metrics
    
    def _evaluate_threat_classifier(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict:
        """Evaluate threat classification model"""
        predictions = self.pipeline.threat_classifier.predict(X_test)
        probabilities = self.pipeline.threat_classifier.predict_proba(X_test)[:, 1]
        
        metrics = {
            'accuracy': float((predictions == y_test).mean()),
            'precision': float(precision_score(y_test, predictions)),
            'recall': float(recall_score(y_test, predictions)),
            'f1': float(f1_score(y_test, predictions)),
            'average_precision': float(average_precision_score(y_test, probabilities))
        }
        
        # Generate confusion matrix
        cm = confusion_matrix(y_test, predictions)
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
        plt.title('Confusion Matrix')
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        
        # Save plot to file
        plt.savefig('confusion_matrix.png')
        plt.close()
        
        return metrics
    
    def _store_metrics(self, model_name: str, metrics: Dict) -> None:
        """Store evaluation metrics in Elasticsearch"""
        doc = {
            'model_name': model_name,
            'metrics': metrics,
            'timestamp': datetime.now().isoformat(),
            'model_version': self.redis.get(f'model:{model_name}:version')
        }
        
        self.es.index(
            index='siem-model-metrics',
            body=doc
        )
        
    def monitor_model_drift(self, model_name: str, window_size: int = 7) -> Dict:
        """Monitor model performance drift over time"""
        end_time = datetime.now()
        start_time = end_time - timedelta(days=window_size)
        
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"model_name": model_name}},
                        {"range": {
                            "timestamp": {
                                "gte": start_time.isoformat(),
                                "lte": end_time.isoformat()
                            }
                        }}
                    ]
                }
            },
            "sort": [{"timestamp": "asc"}]
        }
        
        response = self.es.search(
            index='siem-model-metrics',
            body=query,
            size=window_size
        )
        
        metrics_over_time = []
        for hit in response['hits']['hits']:
            metrics_over_time.append({
                'timestamp': hit['_source']['timestamp'],
                'metrics': hit['_source']['metrics']
            })
        
        return self._analyze_drift(metrics_over_time)
    
    def _analyze_drift(self, metrics_over_time: List[Dict]) -> Dict:
        """Analyze performance drift from metrics history"""
        if not metrics_over_time:
            return None
        
        # Calculate drift metrics
        drift_analysis = {}
        metric_keys = metrics_over_time[0]['metrics'].keys()
        
        for key in metric_keys:
            values = [m['metrics'][key] for m in metrics_over_time]
            drift_analysis[key] = {
                'mean': float(np.mean(values)),
                'std': float(np.std(values)),
                'trend': float(np.polyfit(range(len(values)), values, 1)[0])
            }
        
        return drift_analysis
    
    def generate_performance_report(self, model_name: str) -> Dict:
        """Generate comprehensive model performance report"""
        # Get latest metrics
        latest_metrics = self.redis.hgetall(f'model:{model_name}:metrics')
        
        # Get drift analysis
        drift_analysis = self.monitor_model_drift(model_name)
        
        # Get feature importance if available
        feature_importance = self.redis.hgetall(
            f'model:{model_name}:feature_importance'
        )
        
        report = {
            'model_name': model_name,
            'timestamp': datetime.now().isoformat(),
            'current_performance': latest_metrics,
            'performance_drift': drift_analysis,
            'feature_importance': feature_importance
        }
        
        # Store report
        self.es.index(
            index='siem-model-reports',
            body=report
        )
        
        return report
