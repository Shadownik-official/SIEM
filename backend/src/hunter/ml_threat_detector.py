"""
Advanced Machine Learning-based Threat Detection Module
Implements various ML models for detecting sophisticated threats
"""
import logging
from typing import Dict, List, Optional, Union
from dataclasses import dataclass
from datetime import datetime
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import tensorflow as tf
from tensorflow.keras import layers, models
import torch
import torch.nn as nn
from ..core.utils import encrypt_data, decrypt_data
from ..core.database import Database

@dataclass
class DetectionModel:
    """Represents a machine learning detection model."""
    id: str
    name: str
    type: str  # "anomaly", "classification", "deep_learning"
    framework: str  # "sklearn", "tensorflow", "pytorch"
    features: List[str]
    parameters: Dict
    performance_metrics: Dict
    last_trained: datetime
    last_updated: datetime
    version: str

class MLThreatDetector:
    """Advanced machine learning-based threat detection system."""
    
    def __init__(self, config: Dict = None):
        self.logger = logging.getLogger(__name__)
        self.db = Database()
        self.config = config or self._load_default_config()
        self.models = self._initialize_models()
        self.scaler = StandardScaler()
        self.feature_extractors = self._initialize_feature_extractors()
        
    def detect_threats(self, data: Union[Dict, List[Dict]]) -> Dict:
        """Detect threats using multiple ML models."""
        try:
            # Preprocess data
            processed_data = self._preprocess_data(data)
            
            results = {
                'timestamp': datetime.now(),
                'threats': [],
                'anomalies': [],
                'risk_scores': {},
                'model_confidences': {}
            }
            
            # Run anomaly detection
            anomalies = self._detect_anomalies(processed_data)
            results['anomalies'] = anomalies
            
            # Run classification models
            classifications = self._classify_threats(processed_data)
            results['threats'] = classifications
            
            # Run deep learning models
            dl_results = self._deep_learning_detection(processed_data)
            results['threats'].extend(dl_results)
            
            # Calculate risk scores
            results['risk_scores'] = self._calculate_risk_scores(
                anomalies, classifications, dl_results
            )
            
            # Aggregate model confidences
            results['model_confidences'] = self._aggregate_model_confidences(
                processed_data, results['threats']
            )
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error detecting threats: {str(e)}")
            return {'error': str(e)}
            
    def train_models(self, training_data: List[Dict]) -> Dict:
        """Train or update ML models with new data."""
        try:
            results = {
                'timestamp': datetime.now(),
                'trained_models': [],
                'performance_metrics': {},
                'training_time': {}
            }
            
            # Preprocess training data
            processed_data = self._preprocess_training_data(training_data)
            
            # Train each model type
            for model_type, model in self.models.items():
                try:
                    start_time = datetime.now()
                    
                    # Train model
                    if model_type == 'anomaly':
                        metrics = self._train_anomaly_detector(model, processed_data)
                    elif model_type == 'classification':
                        metrics = self._train_classifier(model, processed_data)
                    else:  # deep learning
                        metrics = self._train_deep_learning(model, processed_data)
                        
                    training_time = (datetime.now() - start_time).total_seconds()
                    
                    results['trained_models'].append(model_type)
                    results['performance_metrics'][model_type] = metrics
                    results['training_time'][model_type] = training_time
                    
                except Exception as e:
                    self.logger.error(f"Error training model {model_type}: {str(e)}")
                    
            # Update model metadata
            self._update_model_metadata(results)
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error training models: {str(e)}")
            return {'error': str(e)}
            
    def evaluate_model_performance(self, test_data: List[Dict]) -> Dict:
        """Evaluate performance of all models."""
        try:
            results = {
                'timestamp': datetime.now(),
                'model_performance': {},
                'overall_metrics': {},
                'recommendations': []
            }
            
            # Preprocess test data
            processed_data = self._preprocess_data(test_data)
            
            # Evaluate each model
            for model_type, model in self.models.items():
                performance = self._evaluate_model(model, processed_data)
                results['model_performance'][model_type] = performance
                
            # Calculate overall metrics
            results['overall_metrics'] = self._calculate_overall_metrics(
                results['model_performance']
            )
            
            # Generate recommendations
            results['recommendations'] = self._generate_model_recommendations(
                results['model_performance']
            )
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error evaluating models: {str(e)}")
            return {'error': str(e)}
            
    def _initialize_models(self) -> Dict:
        """Initialize all ML models."""
        try:
            models = {
                'anomaly': self._create_anomaly_detector(),
                'classification': self._create_classifier(),
                'deep_learning': self._create_deep_learning_model()
            }
            
            # Load saved models if available
            self._load_saved_models(models)
            
            return models
            
        except Exception as e:
            self.logger.error(f"Error initializing models: {str(e)}")
            return {}
            
    def _create_anomaly_detector(self) -> DetectionModel:
        """Create anomaly detection model."""
        try:
            model = DetectionModel(
                id=str(uuid.uuid4()),
                name="IsolationForest",
                type="anomaly",
                framework="sklearn",
                features=self.config['features']['anomaly'],
                parameters={
                    'n_estimators': 100,
                    'contamination': 'auto',
                    'random_state': 42
                },
                performance_metrics={},
                last_trained=None,
                last_updated=datetime.now(),
                version="1.0"
            )
            
            model.model = IsolationForest(**model.parameters)
            return model
            
        except Exception as e:
            self.logger.error(f"Error creating anomaly detector: {str(e)}")
            return None
            
    def _create_classifier(self) -> DetectionModel:
        """Create classification model."""
        try:
            model = DetectionModel(
                id=str(uuid.uuid4()),
                name="RandomForest",
                type="classification",
                framework="sklearn",
                features=self.config['features']['classification'],
                parameters={
                    'n_estimators': 200,
                    'max_depth': 10,
                    'random_state': 42
                },
                performance_metrics={},
                last_trained=None,
                last_updated=datetime.now(),
                version="1.0"
            )
            
            model.model = RandomForestClassifier(**model.parameters)
            return model
            
        except Exception as e:
            self.logger.error(f"Error creating classifier: {str(e)}")
            return None
            
    def _create_deep_learning_model(self) -> DetectionModel:
        """Create deep learning model."""
        try:
            # Create PyTorch model
            class ThreatDetectionNet(nn.Module):
                def __init__(self, input_size):
                    super().__init__()
                    self.layers = nn.Sequential(
                        nn.Linear(input_size, 128),
                        nn.ReLU(),
                        nn.Dropout(0.3),
                        nn.Linear(128, 64),
                        nn.ReLU(),
                        nn.Dropout(0.2),
                        nn.Linear(64, 32),
                        nn.ReLU(),
                        nn.Linear(32, 1),
                        nn.Sigmoid()
                    )
                    
                def forward(self, x):
                    return self.layers(x)
                    
            model = DetectionModel(
                id=str(uuid.uuid4()),
                name="DeepThreatDetector",
                type="deep_learning",
                framework="pytorch",
                features=self.config['features']['deep_learning'],
                parameters={
                    'input_size': len(self.config['features']['deep_learning']),
                    'learning_rate': 0.001,
                    'batch_size': 32,
                    'epochs': 100
                },
                performance_metrics={},
                last_trained=None,
                last_updated=datetime.now(),
                version="1.0"
            )
            
            model.model = ThreatDetectionNet(model.parameters['input_size'])
            return model
            
        except Exception as e:
            self.logger.error(f"Error creating deep learning model: {str(e)}")
            return None
            
    def _preprocess_data(self, data: Union[Dict, List[Dict]]) -> np.ndarray:
        """Preprocess data for ML models."""
        try:
            if isinstance(data, dict):
                data = [data]
                
            # Convert to DataFrame
            df = pd.DataFrame(data)
            
            # Extract features
            features = self._extract_features(df)
            
            # Scale features
            scaled_features = self.scaler.transform(features)
            
            return scaled_features
            
        except Exception as e:
            self.logger.error(f"Error preprocessing data: {str(e)}")
            return None
            
    def _detect_anomalies(self, data: np.ndarray) -> List[Dict]:
        """Detect anomalies using isolation forest."""
        try:
            model = self.models['anomaly']
            predictions = model.model.predict(data)
            
            anomalies = []
            for i, pred in enumerate(predictions):
                if pred == -1:  # Anomaly
                    anomalies.append({
                        'index': i,
                        'confidence': self._calculate_anomaly_score(data[i]),
                        'features': self._get_anomalous_features(data[i])
                    })
                    
            return anomalies
            
        except Exception as e:
            self.logger.error(f"Error detecting anomalies: {str(e)}")
            return []
            
    def _classify_threats(self, data: np.ndarray) -> List[Dict]:
        """Classify threats using random forest."""
        try:
            model = self.models['classification']
            probabilities = model.model.predict_proba(data)
            
            threats = []
            for i, probs in enumerate(probabilities):
                if probs[1] >= self.config['threshold']['classification']:
                    threats.append({
                        'index': i,
                        'probability': float(probs[1]),
                        'type': self._determine_threat_type(data[i]),
                        'features': self._get_important_features(data[i])
                    })
                    
            return threats
            
        except Exception as e:
            self.logger.error(f"Error classifying threats: {str(e)}")
            return []
            
    def _deep_learning_detection(self, data: np.ndarray) -> List[Dict]:
        """Detect threats using deep learning model."""
        try:
            model = self.models['deep_learning']
            
            # Convert to PyTorch tensor
            tensor_data = torch.FloatTensor(data)
            
            # Get predictions
            model.model.eval()
            with torch.no_grad():
                predictions = model.model(tensor_data)
                
            threats = []
            for i, pred in enumerate(predictions):
                confidence = float(pred.item())
                if confidence >= self.config['threshold']['deep_learning']:
                    threats.append({
                        'index': i,
                        'confidence': confidence,
                        'type': 'deep_learning',
                        'features': self._get_dl_feature_importance(data[i])
                    })
                    
            return threats
            
        except Exception as e:
            self.logger.error(f"Error in deep learning detection: {str(e)}")
            return []
