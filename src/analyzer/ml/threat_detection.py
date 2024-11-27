import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
import tensorflow as tf
from typing import Dict, List, Tuple, Optional
import logging
import joblib
from datetime import datetime
import json
from pathlib import Path

class ThreatDetectionEngine:
    """Advanced ML-based threat detection engine with multiple detection methods."""
    
    def __init__(self, config_path: str = None):
        self.logger = logging.getLogger(__name__)
        self.models = {}
        self.scalers = {}
        self.config = self._load_config(config_path)
        self.initialize_models()
        
    def _load_config(self, config_path: Optional[str]) -> Dict:
        """Load configuration from file or use defaults."""
        default_config = {
            "anomaly_detection": {
                "contamination": 0.1,
                "n_estimators": 100,
                "max_samples": "auto"
            },
            "classification": {
                "n_estimators": 200,
                "max_depth": 10,
                "min_samples_split": 5
            },
            "neural_network": {
                "layers": [128, 64, 32],
                "dropout_rate": 0.3,
                "learning_rate": 0.001
            }
        }
        
        if config_path:
            try:
                with open(config_path, 'r') as f:
                    return {**default_config, **json.load(f)}
            except Exception as e:
                self.logger.warning(f"Error loading config: {str(e)}. Using defaults.")
                return default_config
        return default_config
        
    def initialize_models(self):
        """Initialize all detection models."""
        # Anomaly Detection Model
        self.models['anomaly'] = IsolationForest(
            contamination=self.config['anomaly_detection']['contamination'],
            n_estimators=self.config['anomaly_detection']['n_estimators'],
            max_samples=self.config['anomaly_detection']['max_samples']
        )
        
        # Classification Model
        self.models['classifier'] = RandomForestClassifier(
            n_estimators=self.config['classification']['n_estimators'],
            max_depth=self.config['classification']['max_depth'],
            min_samples_split=self.config['classification']['min_samples_split']
        )
        
        # Deep Learning Model
        self.models['deep'] = self._build_neural_network()
        
    def _build_neural_network(self) -> tf.keras.Model:
        """Build and compile neural network for advanced pattern detection."""
        model = tf.keras.Sequential()
        
        # Input layer
        model.add(tf.keras.layers.Dense(
            self.config['neural_network']['layers'][0],
            activation='relu',
            input_shape=(None,)  # Will be set during training
        ))
        model.add(tf.keras.layers.Dropout(self.config['neural_network']['dropout_rate']))
        
        # Hidden layers
        for units in self.config['neural_network']['layers'][1:]:
            model.add(tf.keras.layers.Dense(units, activation='relu'))
            model.add(tf.keras.layers.Dropout(self.config['neural_network']['dropout_rate']))
        
        # Output layer
        model.add(tf.keras.layers.Dense(1, activation='sigmoid'))
        
        model.compile(
            optimizer=tf.keras.optimizers.Adam(
                learning_rate=self.config['neural_network']['learning_rate']
            ),
            loss='binary_crossentropy',
            metrics=['accuracy', tf.keras.metrics.AUC()]
        )
        
        return model
        
    def train(self, data: pd.DataFrame, labels: np.ndarray) -> Dict[str, float]:
        """Train all detection models with provided data."""
        try:
            # Preprocess data
            self.scalers['standard'] = StandardScaler()
            scaled_data = self.scalers['standard'].fit_transform(data)
            
            # Train anomaly detection
            self.models['anomaly'].fit(scaled_data)
            
            # Train classifier
            self.models['classifier'].fit(scaled_data, labels)
            
            # Train neural network
            history = self.models['deep'].fit(
                scaled_data, labels,
                epochs=50,
                batch_size=32,
                validation_split=0.2,
                verbose=0
            )
            
            # Calculate and return performance metrics
            return {
                'classifier_accuracy': self.models['classifier'].score(scaled_data, labels),
                'deep_accuracy': history.history['accuracy'][-1],
                'deep_auc': history.history['auc'][-1]
            }
            
        except Exception as e:
            self.logger.error(f"Error during model training: {str(e)}")
            raise
            
    def detect_threats(self, data: pd.DataFrame) -> Dict[str, np.ndarray]:
        """Detect threats using all available models."""
        try:
            # Preprocess data
            scaled_data = self.scalers['standard'].transform(data)
            
            # Get predictions from all models
            predictions = {
                'anomaly_scores': self.models['anomaly'].score_samples(scaled_data),
                'classifier_predictions': self.models['classifier'].predict_proba(scaled_data)[:, 1],
                'deep_predictions': self.models['deep'].predict(scaled_data).flatten()
            }
            
            # Combine predictions using ensemble method
            predictions['ensemble_score'] = self._ensemble_predictions(predictions)
            
            return predictions
            
        except Exception as e:
            self.logger.error(f"Error during threat detection: {str(e)}")
            raise
            
    def _ensemble_predictions(self, predictions: Dict[str, np.ndarray]) -> np.ndarray:
        """Combine predictions from different models using weighted averaging."""
        weights = {
            'anomaly': 0.3,
            'classifier': 0.3,
            'deep': 0.4
        }
        
        # Normalize anomaly scores to [0, 1] range
        anomaly_scores_norm = (predictions['anomaly_scores'] - 
                             predictions['anomaly_scores'].min()) / \
                            (predictions['anomaly_scores'].max() - 
                             predictions['anomaly_scores'].min())
        
        # Weighted average of all predictions
        ensemble_scores = (
            weights['anomaly'] * anomaly_scores_norm +
            weights['classifier'] * predictions['classifier_predictions'] +
            weights['deep'] * predictions['deep_predictions']
        )
        
        return ensemble_scores
        
    def save_models(self, save_dir: str):
        """Save all models and scalers to disk."""
        save_path = Path(save_dir)
        save_path.mkdir(parents=True, exist_ok=True)
        
        try:
            # Save traditional ML models
            joblib.dump(self.models['anomaly'], 
                       save_path / 'anomaly_model.joblib')
            joblib.dump(self.models['classifier'], 
                       save_path / 'classifier_model.joblib')
            
            # Save neural network
            self.models['deep'].save(save_path / 'deep_model')
            
            # Save scalers
            joblib.dump(self.scalers['standard'], 
                       save_path / 'standard_scaler.joblib')
            
            # Save config
            with open(save_path / 'config.json', 'w') as f:
                json.dump(self.config, f, indent=4)
                
        except Exception as e:
            self.logger.error(f"Error saving models: {str(e)}")
            raise
            
    def load_models(self, load_dir: str):
        """Load all models and scalers from disk."""
        load_path = Path(load_dir)
        
        try:
            # Load traditional ML models
            self.models['anomaly'] = joblib.load(load_path / 'anomaly_model.joblib')
            self.models['classifier'] = joblib.load(load_path / 'classifier_model.joblib')
            
            # Load neural network
            self.models['deep'] = tf.keras.models.load_model(load_path / 'deep_model')
            
            # Load scalers
            self.scalers['standard'] = joblib.load(load_path / 'standard_scaler.joblib')
            
            # Load config
            with open(load_path / 'config.json', 'r') as f:
                self.config = json.load(f)
                
        except Exception as e:
            self.logger.error(f"Error loading models: {str(e)}")
            raise
            
    def get_feature_importance(self) -> Dict[str, np.ndarray]:
        """Get feature importance scores from the classifier model."""
        return {
            'random_forest': self.models['classifier'].feature_importances_
        }
        
    def evaluate_performance(self, test_data: pd.DataFrame, 
                           test_labels: np.ndarray) -> Dict[str, float]:
        """Evaluate performance of all models on test data."""
        try:
            scaled_data = self.scalers['standard'].transform(test_data)
            
            # Get predictions
            predictions = self.detect_threats(test_data)
            
            # Calculate metrics for each model
            from sklearn.metrics import roc_auc_score, precision_score, recall_score
            
            metrics = {}
            for model_name, preds in predictions.items():
                if model_name != 'anomaly_scores':  # Anomaly scores need different metrics
                    metrics[f'{model_name}_auc'] = roc_auc_score(test_labels, preds)
                    metrics[f'{model_name}_precision'] = precision_score(
                        test_labels, preds > 0.5)
                    metrics[f'{model_name}_recall'] = recall_score(
                        test_labels, preds > 0.5)
                    
            return metrics
            
        except Exception as e:
            self.logger.error(f"Error during performance evaluation: {str(e)}")
            raise
