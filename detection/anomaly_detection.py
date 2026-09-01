import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor

def detect_network_anomalies(data):
    """
    Detect network traffic anomalies using KMeans, Isolation Forest, and Local Outlier Factor algorithms.

    Parameters:
    data (pandas.DataFrame): Network traffic data with columns 'src_ip', 'dst_ip', 'bytes', 'packets', 'duration'.

    Returns:
    pandas.DataFrame: DataFrame with an additional column 'anomaly' indicating whether a row is an anomaly or not.
    """
    # Normalize the data
    data_norm = (data - data.min()) / (data.max() - data.min())

    # KMeans
    kmeans = KMeans(n_clusters=2, random_state=42)
    kmeans.fit(data_norm)
    kmeans_labels = kmeans.labels_

    # Isolation Forest
    ifo = IsolationForest(random_state=42)
    ifo.fit(data_norm)
    ifo_scores = ifo.decision_function(data_norm)
    ifo_labels = np.where(ifo_scores < 0, 1, 0)

    # Local Outlier Factor
    lof = LocalOutlierFactor(n_neighbors=20, contamination='auto')
    lof_labels = lof.fit_predict(data_norm)
    lof_scores = -lof.negative_outlier_factor_

    # Combine the results
    combined_labels = np.where(kmeans_labels == 1, 1, np.where(ifo_labels == 1, 1, np.where(lof_scores > 2, 1, 0)))

    # Add the anomaly column to the original data
    data['anomaly'] = combined_labels

    return data

def detect_user_behavior_anomalies(data):
    """
    Detect user behavior anomalies using KMeans, Isolation Forest, and Local Outlier Factor algorithms.

    Parameters:
    data (pandas.DataFrame): User behavior data with columns 'user_id', 'cpu_usage', 'memory_usage', 'disk_usage'.

    Returns:
    pandas.DataFrame: DataFrame with an additional column 'anomaly' indicating whether a row is an anomaly or not.
    """
    # Normalize the data
    data_norm = (data - data.min()) / (data.max() - data.min())

    # KMeans
    kmeans = KMeans(n_clusters=2, random_state=42)
    kmeans.fit(data_norm)
    kmeans_labels = kmeans.labels_

    # Isolation Forest
    ifo = IsolationForest(random_state=42)
    ifo.fit(data_norm)
    ifo_scores = ifo.decision_function(data_norm)
    ifo_labels = np.where(ifo_scores < 0, 1, 0)

    # Local Outlier Factor
    lof = LocalOutlierFactor(n_neighbors=20, contamination='auto')
    lof_labels = lof.fit_predict(data_norm)
    lof_scores = -lof.negative_outlier_factor_

    # Combine the results
    combined_labels = np.where(kmeans_labels == 1, 1, np.where(ifo_labels == 1, 1, np.where(lof_scores > 2, 1, 0)))

    # Add the anomaly column to the original data
    data['anomaly'] = combined_labels

    return data