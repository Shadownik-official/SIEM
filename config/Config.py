# Network monitoring configuration


# User monitoring configuration
class Config:
    NETWORK_INTERFACE = "eth0"
    MONITOR_PERIOD = 60  # in seconds
    MONITOR_THRESHOLD = 100  # in bytes
    USER_MONITOR_PERIOD = 60  # in seconds
    USER_MONITOR_THRESHOLD = 10  # in events
    THIRD_PARTY_MONITOR_PERIOD = 60  # in seconds
    THIRD_PARTY_MONITOR_THRESHOLD = 5  # in events
# Computing environment monitoring configuration
    COMPUTING_ENVIRONMENT_MONITOR_PERIOD = 60  # in seconds
    COMPUTING_ENVIRONMENT_MONITOR_THRESHOLD = 80  # in percentage

# Security scanning configuration
    SECURITY_SCANNING_PERIOD = 24 * 60 * 60  # in seconds (once per day)
    SECURITY_SCANNING_THRESHOLD = 80  # in percentage

# Logging configuration
    LOGGING_LEVEL = "INFO"
    LOGGING_FILE = "my_siem_tool.log"
    LOGGING_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"

# Machine learning configuration
    ANOMALY_DETECTION_MODEL = "autoencoder"
    ANOMALY_DETECTION_THRESHOLD = 3  # in standard deviations
    EVENT_ANALYSIS_MODEL = "random_forest"
    EVENT_ANALYSIS_THRESHOLD = 0.8  # in probability

# Threat intelligence configuration
    THREAT_INTELLIGENCE_FEED = "https://example.com/threat_intelligence.json"
    THREAT_INTELLIGENCE_THRESHOLD = 5  # in severity

# Database configuration
    DATABASE_URL = "sqlite:///my_siem_tool.db"
    DATABASE_TABLE = "security_events"
    DATABASE_SCHEMA = """
CREATE TABLE security_events (
    id INTEGER PRIMARY KEY,
    timestamp DATETIME,
    severity INTEGER,
    category TEXT,
    description TEXT,
    source TEXT,
    destination TEXT,
    protocol TEXT,
    action TEXT,
    data TEXT
);
"""
