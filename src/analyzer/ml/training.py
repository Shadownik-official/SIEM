"""
Model Training Pipeline for SIEM
"""
import logging
from datetime import datetime, timedelta
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    precision_score, recall_score, f1_score,
    confusion_matrix, roc_auc_score
)
import tensorflow as tf
from .models import AnomalyDetector, BehaviorAnalyzer, ThreatClassifier
from .feature_extraction import SecurityFeatureExtractor

logger = logging.getLogger(__name__)

class ModelTrainingPipeline:
    def __init__(self, elasticsearch_client, redis_client):
        self.es = elasticsearch_client
        self.redis = redis_client
        self.feature_extractor = SecurityFeatureExtractor()
        
        # Initialize models
        self.anomaly_detector = AnomalyDetector()
        self.behavior_analyzer = BehaviorAnalyzer()
        self.threat_classifier = ThreatClassifier()
        
    def fetch_training_data(self, start_time=None, end_time=None, limit=1000000):
        """Fetch training data from Elasticsearch"""
        if not start_time:
            start_time = datetime.now() - timedelta(days=30)
        if not end_time:
            end_time = datetime.now()
            
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {
                            "timestamp": {
                                "gte": start_time.isoformat(),
                                "lte": end_time.isoformat()
                            }
                        }}
                    ]
                }
            },
            "size": limit
        }
        
        response = self.es.search(index="siem-events", body=query)
        return [hit["_source"] for hit in response["hits"]["hits"]]
    
    def prepare_features(self, events):
        """Prepare features from events"""
        # Extract basic features
        features = [self.feature_extractor.extract_event_features(event) 
                   for event in events]
        
        # Extract sequence features
        sequence_features = self.feature_extractor.extract_sequence_features(events)
        
        # Combine features
        combined_features = []
        for i, basic in enumerate(features):
            if i < len(sequence_features):
                combined = {**basic, **sequence_features[i]}
                combined_features.append(combined)
        
        return np.array([[v for v in f.values()] for f in combined_features])
    
    def prepare_labels(self, events):
        """Prepare labels for supervised learning"""
        return np.array([
            1 if event.get('is_threat', False) else 0
            for event in events
        ])
    
    def train_anomaly_detector(self, X_train):
        """Train the anomaly detection model"""
        logger.info("Training anomaly detection model...")
        self.anomaly_detector.fit(X_train)
        
        # Cache model parameters in Redis
        model_params = {
            'contamination': self.anomaly_detector.isolation_forest.contamination,
            'n_estimators': self.anomaly_detector.isolation_forest.n_estimators
        }
        self.redis.hmset('model:anomaly_detector:params', model_params)
        
        logger.info("Anomaly detection model training completed")
    
    def train_behavior_analyzer(self, X_train, y_train):
        """Train the behavior analysis model"""
        logger.info("Training behavior analysis model...")
        
        # Prepare sequences
        X_seq = self.behavior_analyzer.prepare_sequences(X_train)
        y_seq = y_train[self.behavior_analyzer.sequence_length:]
        
        # Split data
        X_train_seq, X_val_seq, y_train_seq, y_val_seq = train_test_split(
            X_seq, y_seq, test_size=0.2, random_state=42
        )
        
        # Train model
        history = self.behavior_analyzer.fit(
            X_train_seq, y_train_seq,
            validation_data=(X_val_seq, y_val_seq),
            epochs=10,
            batch_size=32
        )
        
        # Save training history
        self.redis.hmset('model:behavior_analyzer:history', {
            'loss': str(history.history['loss']),
            'val_loss': str(history.history['val_loss']),
            'accuracy': str(history.history['accuracy']),
            'val_accuracy': str(history.history['val_accuracy'])
        })
        
        logger.info("Behavior analysis model training completed")
    
    def train_threat_classifier(self, X_train, y_train):
        """Train the threat classification model"""
        logger.info("Training threat classification model...")
        
        # Split data
        X_train_clf, X_val_clf, y_train_clf, y_val_clf = train_test_split(
            X_train, y_train, test_size=0.2, random_state=42
        )
        
        # Train model
        self.threat_classifier.fit(X_train_clf, y_train_clf)
        
        # Evaluate model
        y_pred = self.threat_classifier.predict(X_val_clf)
        y_prob = self.threat_classifier.predict_proba(X_val_clf)[:, 1]
        
        # Calculate metrics
        metrics = {
            'precision': float(precision_score(y_val_clf, y_pred)),
            'recall': float(recall_score(y_val_clf, y_pred)),
            'f1': float(f1_score(y_val_clf, y_pred)),
            'auc_roc': float(roc_auc_score(y_val_clf, y_prob))
        }
        
        # Save metrics to Redis
        self.redis.hmset('model:threat_classifier:metrics', metrics)
        
        # Save feature importance
        feature_importance = {
            f'feature_{i}': float(imp)
            for i, imp in enumerate(self.threat_classifier.feature_importance())
        }
        self.redis.hmset('model:threat_classifier:feature_importance', 
                        feature_importance)
        
        logger.info("Threat classification model training completed")
    
    def train_all_models(self):
        """Train all models in the pipeline"""
        logger.info("Starting model training pipeline...")
        
        # Fetch training data
        events = self.fetch_training_data()
        if not events:
            logger.error("No training data available")
            return
        
        # Prepare features and labels
        X = self.prepare_features(events)
        y = self.prepare_labels(events)
        
        # Train models
        self.train_anomaly_detector(X)
        self.train_behavior_analyzer(X, y)
        self.train_threat_classifier(X, y)
        
        logger.info("Model training pipeline completed successfully")
