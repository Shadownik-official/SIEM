from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
import os
import json
import yaml
from pathlib import Path

class ConfigurationError(Exception):
    """Exception raised for configuration-related errors."""
    pass

@dataclass
class SIEMConfig:
    """Comprehensive SIEM Configuration Management."""
    
    # Core SIEM Settings
    environment: str = "development"
    debug: bool = False
    log_level: str = "INFO"
    
    # Agent Configuration
    agent_collection_interval: int = 60  # seconds
    max_queue_size: int = 1000
    
    # Database Configuration
    database: Dict[str, Any] = field(default_factory=lambda: {
        "host": "localhost",
        "port": 5432,
        "name": "siem_db",
        "user": "siem_user",
        "password": "",
        "pool_size": 10
    })
    
    # Security Settings
    security: Dict[str, Any] = field(default_factory=lambda: {
        "jwt_secret_key": "",
        "jwt_algorithm": "HS256",
        "jwt_expiration_minutes": 30,
        "password_min_length": 12
    })
    
    # Collectors Configuration
    collectors: List[str] = field(default_factory=list)
    
    # Encryption
    encryption_key: Optional[bytes] = None
    
    @classmethod
    def load_config(cls, config_path: Optional[str] = None) -> "SIEMConfig":
        """
        Load configuration from YAML or JSON file.
        Prioritizes environment-specific configurations.
        
        :param config_path: Optional path to configuration file
        :return: Configured SIEMConfig instance
        """
        # Default config paths
        default_paths = [
            "./config/base.yml",
            "./config/development.yml",
            "./config/production.yml",
            os.path.expanduser("~/.siem/config.yml")
        ]
        
        # Use provided path or search default paths
        paths_to_check = [config_path] + default_paths if config_path else default_paths
        
        for path in paths_to_check:
            if path and os.path.exists(path):
                try:
                    with open(path, 'r') as f:
                        if path.endswith('.json'):
                            config_data = json.load(f)
                        else:
                            config_data = yaml.safe_load(f)
                    
                    # Validate and merge configurations
                    return cls(**config_data)
                except Exception as e:
                    print(f"Error loading config from {path}: {e}")
        
        # Return default configuration if no config found
        return cls()
    
    def save_config(self, config_path: str) -> None:
        """
        Save current configuration to a YAML file.
        
        :param config_path: Path to save configuration
        """
        try:
            config_data = {k: v for k, v in self.__dict__.items() if not k.startswith('_')}
            
            # Ensure parent directory exists
            Path(config_path).parent.mkdir(parents=True, exist_ok=True)
            
            with open(config_path, 'w') as f:
                yaml.dump(config_data, f, default_flow_style=False)
        except Exception as e:
            raise ConfigurationError(f"Failed to save configuration: {e}")
    
    def validate(self) -> bool:
        """
        Validate configuration settings.
        
        :return: True if configuration is valid, False otherwise
        """
        # Add specific validation rules
        if not self.database.get('host'):
            raise ConfigurationError("Database host must be specified")
        
        if not self.security.get('jwt_secret_key'):
            raise ConfigurationError("JWT secret key must be set")
        
        return True
