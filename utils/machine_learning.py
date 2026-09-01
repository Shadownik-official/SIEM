import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from typing import Tuple, List, Dict, Any, Union

def train_model(data: pd.DataFrame, target: pd.Series) -> Tuple[StandardScaler, IsolationForest, float]:
    """
    Train an Isolation Forest model for anomaly detection.

    Parameters:
    - data: Input data for training the model. DataFrame where each row represents a sample, and each column represents a feature.
    - target: Target variable for training the model. Series where each value represents the target variable for the corresponding sample.

    Returns:
    - scaler: StandardScaler object used for scaling the data.
    - model: Trained IsolationForest model.
    - accuracy: Accuracy of the model on the test set.
    """
    try:
        scaler = StandardScaler()
        data_scaled = scaler.fit_transform(data)

        X_train, X_test, y_train, y_test = train_test_split(data_scaled, target, test_size=0.2, random_state=42)

        model = IsolationForest(contamination=0.1)
        model.fit(X_train)

        y_pred = model.predict(X_test)
        y_test = y_test.astype(int)

        accuracy = accuracy_score(y_test, y_pred)

        return scaler, model, accuracy

    except Exception as e:
        print(f"Error occurred during model training: {str(e)}")
        return None, None, None

def detect_anomalies(scaler: StandardScaler, model: IsolationForest, data: List[List[float]]) -> List[int]:
    """
    Detect anomalies in new data using a trained Isolation Forest model.

    Parameters:
    - scaler: StandardScaler object used for scaling the data.
    - model: Trained IsolationForest model.
    - data: New data to detect anomalies. List of lists where each inner list represents a data point.

    Returns:
    - anomaly_scores: Anomaly scores for the new data. List of scores where -1 indicates an anomaly and 1 indicates normal.
    """
    try:
        data_scaled = scaler.transform(data)
        anomaly_scores = model.predict(data_scaled)

        return anomaly_scores

    except Exception as e:
        print(f"Error occurred during anomaly detection: {str(e)}")
        return []

# Example usage
if __name__ == "__main__":
    # Sample DataFrame for demonstration
    df = pd.DataFrame({'feature1': [1, 2, 3, 4, 5],
                       'feature2': [5, 4, 3, 2, 1],
                       'target': [0, 0, 1, 0, 0]})

    features = df.drop('target', axis=1)
    target = df['target']

    # Train the model
    scaler, model, accuracy = train_model(features, target)

    if scaler and model and accuracy:
        # Detect anomalies in new data
        new_data = [[6, 1], [2, 4], [3, 3]]  # Assuming new_data is a list of new data points
        anomaly_scores = detect_anomalies(scaler, model, new_data)

        # Find anomalies
        anomalies = [data for data, score in zip(new_data, anomaly_scores) if score == -1]

        print("Anomalies detected:", anomalies)