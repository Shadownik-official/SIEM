import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import DBSCAN
from utils.logging import get_logger

logger = get_logger(__name__)


class EventCorrelation:
    def __init__(self, vectorizer=TfidfVectorizer(), clustering_algorithm=DBSCAN()):
        self.vectorizer = vectorizer
        self.clustering_algorithm = clustering_algorithm

    def _preprocess_data(self, data):
        """
        Preprocess the input data for feature extraction.
        """
        # Preprocess the data as per the requirement. For example, lowercase the text, remove stop words, etc.
        return data

    def _vectorize_data(self, data):
        """
        Vectorize the input data using a chosen vectorizer.
        """
        return self.vectorizer.fit_transform(data)

    def _cluster_data(self, data):
        """
        Cluster the input data using a chosen clustering algorithm.
        """
        self.clustering_algorithm.fit(data)
        return self.clustering_algorithm.labels_

    def _process_clusters(self, labels):
        """
        Process the clusters obtained from the clustering algorithm.
        """
        unique_labels = set(labels)
        clusters = {}
        for label in unique_labels:
            if label != -1:  # Ignore outliers (if any)
                clusters[label] = []

        for i, label in enumerate(labels):
            if label != -1:  # Ignore outliers (if any)
                clusters[label].append(i)

        return clusters

    def correlate_events(self, events):
        """
        Correlate the input security events using machine learning techniques.
        """
        preprocessed_events = self._preprocess_data(events)
        vectorized_events = self._vectorize_data(preprocessed_events)
        labels = self._cluster_data(vectorized_events)
        clusters = self._process_clusters(labels)

        correlated_events = []
        for label, event_indices in clusters.items():
            correlated_events.append(
                {
                    "correlation_id": label,
                    "events": [events[i] for i in event_indices],
                }
            )

        return correlated_events