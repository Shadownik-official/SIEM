"""
Advanced Machine Learning Models for Threat Detection
"""
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout

class AnomalyDetector:
    def __init__(self, contamination=0.1):
        self.scaler = StandardScaler()
        self.isolation_forest = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_jobs=-1
        )
        
    def fit(self, X):
        """Train the anomaly detection model"""
        X_scaled = self.scaler.fit_transform(X)
        self.isolation_forest.fit(X_scaled)
        
    def predict(self, X):
        """Predict anomalies (-1 for anomalies, 1 for normal)"""
        X_scaled = self.scaler.transform(X)
        return self.isolation_forest.predict(X_scaled)
    
    def anomaly_score(self, X):
        """Calculate anomaly scores"""
        X_scaled = self.scaler.transform(X)
        return -self.isolation_forest.score_samples(X_scaled)

class BehaviorAnalyzer:
    def __init__(self, sequence_length=10, n_features=20):
        self.sequence_length = sequence_length
        self.n_features = n_features
        self.model = self._build_lstm_model()
        
    def _build_lstm_model(self):
        """Build LSTM model for behavior analysis"""
        model = Sequential([
            LSTM(128, input_shape=(self.sequence_length, self.n_features), return_sequences=True),
            Dropout(0.2),
            LSTM(64, return_sequences=False),
            Dropout(0.2),
            Dense(32, activation='relu'),
            Dense(1, activation='sigmoid')
        ])
        model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
        return model
    
    def prepare_sequences(self, X):
        """Prepare sequences for LSTM"""
        sequences = []
        for i in range(len(X) - self.sequence_length):
            sequences.append(X[i:i + self.sequence_length])
        return np.array(sequences)
    
    def fit(self, X, y, epochs=10, batch_size=32, validation_split=0.2):
        """Train the behavior analysis model"""
        X_seq = self.prepare_sequences(X)
        self.model.fit(
            X_seq, y[self.sequence_length:],
            epochs=epochs,
            batch_size=batch_size,
            validation_split=validation_split
        )
    
    def predict(self, X):
        """Predict behavior anomalies"""
        X_seq = self.prepare_sequences(X)
        return self.model.predict(X_seq)

class ThreatClassifier:
    def __init__(self):
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=None,
            min_samples_split=2,
            min_samples_leaf=1,
            n_jobs=-1,
            random_state=42
        )
        
    def fit(self, X, y):
        """Train the threat classification model"""
        self.model.fit(X, y)
        
    def predict(self, X):
        """Predict threat categories"""
        return self.model.predict(X)
    
    def predict_proba(self, X):
        """Predict threat probabilities"""
        return self.model.predict_proba(X)
    
    def feature_importance(self):
        """Get feature importance scores"""
        return self.model.feature_importances_
