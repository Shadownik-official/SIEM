"""
Settings management utilities for SIEM system.
"""
from typing import Dict, Any
import yaml
import os
from pathlib import Path
from ..core.exceptions import ConfigurationError

CONFIG_FILE = Path(__file__).parent.parent.parent / "config" / "base.yml"

async def load_settings() -> Dict[str, Any]:
    """Load current system settings"""
    try:
        with open(CONFIG_FILE, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        raise ConfigurationError(f"Error loading settings: {str(e)}")

async def save_settings(settings: Dict[str, Any]) -> Dict[str, Any]:
    """Save system settings"""
    try:
        # Validate settings before saving
        _validate_settings(settings)
        
        # Create backup of current settings
        if os.path.exists(CONFIG_FILE):
            backup_file = str(CONFIG_FILE) + '.backup'
            with open(CONFIG_FILE, 'r') as src, open(backup_file, 'w') as dst:
                dst.write(src.read())
        
        # Write new settings
        with open(CONFIG_FILE, 'w') as f:
            yaml.safe_dump(settings, f, default_flow_style=False)
        
        return settings
    except Exception as e:
        raise ConfigurationError(f"Error saving settings: {str(e)}")

def _validate_settings(settings: Dict[str, Any]) -> None:
    """Validate settings structure and values"""
    required_keys = [
        'environment',
        'debug',
        'log_level',
        'database',
        'security',
        'collectors',
        'threat_intelligence'
    ]
    
    # Check required keys
    for key in required_keys:
        if key not in settings:
            raise ConfigurationError(f"Missing required setting: {key}")
    
    # Validate database settings
    db_settings = settings.get('database', {})
    required_db_keys = ['host', 'port', 'name', 'user']
    for key in required_db_keys:
        if key not in db_settings:
            raise ConfigurationError(f"Missing required database setting: {key}")
    
    # Validate security settings
    security_settings = settings.get('security', {})
    required_security_keys = ['jwt_algorithm', 'jwt_expiration_minutes']
    for key in required_security_keys:
        if key not in security_settings:
            raise ConfigurationError(f"Missing required security setting: {key}")
    
    # Validate collectors
    collectors = settings.get('collectors', [])
    if not isinstance(collectors, list):
        raise ConfigurationError("Collectors must be a list")
    
    # Validate threat intelligence settings
    ti_settings = settings.get('threat_intelligence', {})
    if not isinstance(ti_settings, dict):
        raise ConfigurationError("Threat intelligence settings must be a dictionary")
    
    if 'enabled' not in ti_settings:
        raise ConfigurationError("Threat intelligence must have 'enabled' field")
