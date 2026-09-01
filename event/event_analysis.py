import pandas as pd
import numpy as np
from utils.natural_language_processing import extract_entities
from utils.threat_intelligence import get_threat_info

def analyze_event(event_data):
    """
    Analyze a security event by extracting entities, identifying potential threats, and estimating the impact.

    Parameters:
    event_data (pandas.DataFrame): DataFrame containing information about the security event.

    Returns:
    pandas.DataFrame: DataFrame with additional columns for entities, threat level, and impact.
    """
    # Extract entities from the event description
    entities = extract_entities(event_data['description'].tolist())

    # Add the entities to the event data
    event_data['entities'] = entities

    # Identify potential threats based on the entities
    threat_levels = np.zeros(len(event_data))
    for i, row in event_data.iterrows():
        entities_for_row = row['entities']
        if len(entities_for_row) > 0:
            threat_levels[i] = get_threat_info(entities_for_row)

    event_data['threat_level'] = threat_levels

    # Estimate the impact of the event based on the threat level
    impact_levels = np.zeros(len(event_data))
    for i, row in event_data.iterrows():
        threat_level = row['threat_level']
        if threat_level > 0.5:
            impact_levels[i] = 1
        elif threat_level > 0.2:
            impact_levels[i] = 0.5
        else:
            impact_levels[i] = 0

    event_data['impact'] = impact_levels

    return event_data