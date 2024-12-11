"""
SIEM System Startup Script
Initializes and starts all SIEM components
"""
import os
import sys
import logging
import logging.handlers
import logging.config
import argparse
import json
from datetime import datetime
from src.agents.cross_platform_agent import UniversalAgent
from src.intelligence.threat_intelligence import ThreatIntelligence
from src.core.config import SIEMConfig, ConfigurationError
from src.utils.database import DatabaseManager
import signal
from typing import Optional
import time
import threading
import queue

# Global variables for cleanup
siem_components = []

# Global event to control the main loop
shutdown_event = threading.Event()

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    logger = logging.getLogger(__name__)
    logger.info("Received shutdown signal. Cleaning up...")
    shutdown_event.set()
    for component in siem_components:
        if hasattr(component, 'shutdown'):
            component.shutdown()
    sys.exit(0)

def setup_logging(config: Optional[SIEMConfig] = None):
    """
    Set up comprehensive logging configuration.
    
    :param config: Optional SIEM configuration object
    """
    # Use default configuration if not provided
    if config is None:
        config = SIEMConfig()
    
    # Ensure logs directory exists
    log_dir = os.path.join(config.base_dir, 'logs')
    os.makedirs(log_dir, exist_ok=True)
    
    # Use configuration's logging configuration
    logging_config = config.get_log_configuration()
    
    # Apply logging configuration
    logging.config.dictConfig(logging_config)
    
    # Create a custom log filter for sensitive data
    class SensitiveDataFilter(logging.Filter):
        def filter(self, record):
            record.msg = config.mask_sensitive_data(str(record.msg))
            return True
    
    # Add sensitive data filter to all loggers
    root_logger = logging.getLogger()
    root_logger.addFilter(SensitiveDataFilter())
    
    return logging.getLogger(__name__)

def start_siem(config: Optional[SIEMConfig] = None):
    """
    Initialize and start SIEM system components
    
    :param config: Optional configuration object
    """
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Setup logging first
    logger = setup_logging(config)
    logger.info("Starting SIEM system...")

    # Ensure config directory exists
    config_dir = os.path.join(os.path.dirname(__file__), 'config')
    os.makedirs(config_dir, exist_ok=True)

    # Improved configuration loading with error handling
    config_files = [
        os.path.join(config_dir, 'base.yml'),
        os.path.join(config_dir, 'development.yml'),
        os.path.join(config_dir, 'production.yml')
    ]
    
    # Create default configuration files if they don't exist
    for config_file in config_files:
        if not os.path.exists(config_file):
            try:
                with open(config_file, 'w') as f:
                    f.write("# Default SIEM Configuration\n")
                logger.info(f"Created default config file: {config_file}")
            except Exception as e:
                logger.warning(f"Could not create default config file {config_file}: {e}")

    # If no config is provided, use default
    if config is None:
        config = SIEMConfig()
    
    logger.info("Configuration initialized successfully")

    # Initialize components
    try:
        # Initialize database
        db_manager = DatabaseManager(config)
        siem_components.append(db_manager)
        logger.info("Database initialized successfully")

        # Initialize Universal Agent
        universal_agent = UniversalAgent(config)
        siem_components.append(universal_agent)
        logger.info("Universal Agent initialized")

        # Initialize Threat Intelligence
        threat_intel = ThreatIntelligence(config)
        siem_components.append(threat_intel)
        logger.info("Threat Intelligence module initialized")

        logger.info("SIEM system started successfully")

        # Main monitoring loop with graceful shutdown
        while not shutdown_event.is_set():
            try:
                # Perform periodic system health checks
                for component in siem_components:
                    if hasattr(component, 'health_check'):
                        component.health_check()
                
                # Sleep to prevent tight loop
                time.sleep(10)  # Check every 10 seconds
            
            except KeyboardInterrupt:
                logger.info("Keyboard interrupt received. Shutting down...")
                break
            except Exception as e:
                logger.error(f"Error in main monitoring loop: {e}")
                time.sleep(5)  # Prevent rapid error looping
        
        # Graceful shutdown
        logger.info("Initiating graceful shutdown...")
        for component in reversed(siem_components):
            if hasattr(component, 'shutdown'):
                try:
                    component.shutdown()
                except Exception as e:
                    logger.error(f"Error during shutdown of {component}: {e}")
        
        logger.info("SIEM system shutdown complete")
    
    except Exception as e:
        logger.error(f"Critical error during SIEM system initialization: {e}")
        # Attempt to shutdown any initialized components
        for component in siem_components:
            if hasattr(component, 'shutdown'):
                try:
                    component.shutdown()
                except Exception:
                    pass
        
        raise  # Re-raise to ensure visibility of the critical error

def main():
    """Main entry point for SIEM system"""
    parser = argparse.ArgumentParser(description="SIEM System Startup")
    parser.add_argument('--log-level', default='INFO', 
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Set the logging level')
    
    args = parser.parse_args()

    try:
        start_siem()
    except Exception as e:
        print(f"Failed to start SIEM system: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
