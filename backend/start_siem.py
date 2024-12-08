"""
SIEM System Startup Script
Initializes and starts all SIEM components
"""
import os
import sys
import logging
import argparse
import json
from datetime import datetime
from src.agents.cross_platform_agent import UniversalAgent
from src.intelligence.threat_intelligence import ThreatIntelligence
import signal

# Global variables for cleanup
siem_components = []

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    logger = logging.getLogger(__name__)
    logger.info("Received shutdown signal. Cleaning up...")
    for component in siem_components:
        if hasattr(component, 'shutdown'):
            component.shutdown()
    sys.exit(0)

def setup_logging(log_level='INFO'):
    """Configure logging"""
    log_dir = 'logs'
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
        
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = os.path.join(log_dir, f'siem_{timestamp}.log')
    
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger(__name__)

def load_config(config_file):
    """Load configuration from file"""
    with open(config_file, 'r') as f:
        return json.load(f)

def start_siem(config_file, log_level='INFO'):
    """Initialize and start SIEM components"""
    logger = setup_logging(log_level)
    logger.info("Starting SIEM system...")
    
    try:
        # Load configuration
        config = load_config(config_file)
        logger.info("Configuration loaded successfully")
        
        # Initialize components
        agent = UniversalAgent(config.get('agent', {}))
        intel = ThreatIntelligence(config.get('intelligence', {}))
        
        # Add components to global list for cleanup
        global siem_components
        siem_components.extend([agent, intel])
        
        logger.info("SIEM components initialized successfully")
        
        # Register signal handlers
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Start monitoring
        logger.info("Starting event monitoring...")
        agent.start_monitoring()
        
    except FileNotFoundError as e:
        logger.error(f"Configuration file not found: {str(e)}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid configuration file format: {str(e)}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error starting SIEM: {str(e)}")
        sys.exit(1)

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='SIEM System Startup')
    parser.add_argument(
        '--config',
        default='config/siem_config.json',
        help='Path to configuration file'
    )
    parser.add_argument(
        '--log-level',
        default='INFO',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        help='Logging level'
    )
    
    args = parser.parse_args()
    start_siem(args.config, args.log_level)

if __name__ == '__main__':
    main()
