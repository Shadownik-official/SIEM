"""
Advanced Configuration Management System for Enterprise SIEM
"""
import logging
import yaml
import json
import jsonschema
from typing import Dict, List, Optional, Union
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime
import threading
import hashlib
import uuid
from ..core.utils import encrypt_data, decrypt_data
from ..core.database import Database

@dataclass
class ConfigurationItem:
    """Represents a configuration item."""
    id: str
    path: str
    value: any
    type: str
    description: str
    default: any
    validation: Dict
    last_modified: datetime
    modified_by: str
    version: int
    environment: str
    tags: List[str]
    dependencies: List[str]
    encryption_status: bool
    
class ConfigurationManager:
    """Advanced configuration management system with versioning and validation."""
    
    def __init__(self, config_dir: str = None):
        self.logger = logging.getLogger(__name__)
        self.db = Database()
        self.config_dir = Path(config_dir) if config_dir else Path('config')
        self.config_cache = {}
        self.lock = threading.Lock()
        self.validation_schemas = {}
        self.environment = self._detect_environment()
        self._load_configurations()
        
    def get_configuration(self, path: str, environment: str = None) -> ConfigurationItem:
        """Get configuration value with validation and environment support."""
        try:
            with self.lock:
                # Check cache first
                cache_key = f"{environment or self.environment}:{path}"
                if cache_key in self.config_cache:
                    return self._validate_cached_config(cache_key)
                    
                # Load from storage
                config = self._load_config_item(path, environment)
                
                # Validate configuration
                self._validate_configuration(config)
                
                # Cache the result
                self.config_cache[cache_key] = config
                
                return config
                
        except Exception as e:
            self.logger.error(f"Error getting configuration {path}: {str(e)}")
            return None
            
    def set_configuration(self, path: str, value: any, 
                         environment: str = None) -> bool:
        """Set configuration value with validation and versioning."""
        try:
            with self.lock:
                # Create new configuration item
                config = ConfigurationItem(
                    id=str(uuid.uuid4()),
                    path=path,
                    value=value,
                    type=type(value).__name__,
                    description="",
                    default=None,
                    validation={},
                    last_modified=datetime.now(),
                    modified_by=self._get_current_user(),
                    version=self._get_next_version(path),
                    environment=environment or self.environment,
                    tags=[],
                    dependencies=[],
                    encryption_status=False
                )
                
                # Validate new configuration
                self._validate_configuration(config)
                
                # Check dependencies
                self._check_dependencies(config)
                
                # Encrypt sensitive data
                if self._should_encrypt(config):
                    config.value = encrypt_data(config.value)
                    config.encryption_status = True
                    
                # Store configuration
                self._store_configuration(config)
                
                # Update cache
                cache_key = f"{config.environment}:{path}"
                self.config_cache[cache_key] = config
                
                # Notify subscribers
                self._notify_configuration_change(config)
                
                return True
                
        except Exception as e:
            self.logger.error(f"Error setting configuration {path}: {str(e)}")
            return False
            
    def validate_configurations(self) -> Dict:
        """Validate all configurations against schemas."""
        try:
            results = {
                'valid': [],
                'invalid': [],
                'warnings': [],
                'errors': []
            }
            
            # Load validation schemas
            self._load_validation_schemas()
            
            # Validate each configuration
            for cache_key, config in self.config_cache.items():
                validation_result = self._validate_configuration(config)
                
                if validation_result['valid']:
                    results['valid'].append(config.path)
                else:
                    results['invalid'].append({
                        'path': config.path,
                        'errors': validation_result['errors']
                    })
                    
            return results
            
        except Exception as e:
            self.logger.error(f"Error validating configurations: {str(e)}")
            return {'error': str(e)}
            
    def export_configurations(self, format: str = 'json') -> Union[str, Dict]:
        """Export configurations in specified format."""
        try:
            export_data = {
                'metadata': {
                    'timestamp': datetime.now().isoformat(),
                    'version': '1.0',
                    'environment': self.environment
                },
                'configurations': {}
            }
            
            # Export each configuration
            for cache_key, config in self.config_cache.items():
                if not config.encryption_status:  # Skip encrypted configs
                    export_data['configurations'][config.path] = {
                        'value': config.value,
                        'type': config.type,
                        'version': config.version,
                        'last_modified': config.last_modified.isoformat(),
                        'environment': config.environment
                    }
                    
            # Convert to requested format
            if format.lower() == 'yaml':
                return yaml.dump(export_data, default_flow_style=False)
            elif format.lower() == 'json':
                return json.dumps(export_data, indent=2)
            else:
                return export_data
                
        except Exception as e:
            self.logger.error(f"Error exporting configurations: {str(e)}")
            return None
            
    def import_configurations(self, data: Union[str, Dict], 
                            format: str = 'json') -> bool:
        """Import configurations with validation."""
        try:
            # Parse input data
            if isinstance(data, str):
                if format.lower() == 'yaml':
                    config_data = yaml.safe_load(data)
                else:
                    config_data = json.loads(data)
            else:
                config_data = data
                
            # Validate import data
            if not self._validate_import_data(config_data):
                raise ValueError("Invalid import data format")
                
            # Import configurations
            with self.lock:
                for path, config in config_data['configurations'].items():
                    self.set_configuration(
                        path=path,
                        value=config['value'],
                        environment=config.get('environment', self.environment)
                    )
                    
            return True
            
        except Exception as e:
            self.logger.error(f"Error importing configurations: {str(e)}")
            return False
            
    def _validate_configuration(self, config: ConfigurationItem) -> Dict:
        """Validate configuration against schema."""
        try:
            result = {
                'valid': True,
                'errors': []
            }
            
            # Get schema for config
            schema = self.validation_schemas.get(config.path)
            if not schema:
                return result
                
            # Validate against schema
            try:
                jsonschema.validate(instance=config.value, schema=schema)
            except jsonschema.exceptions.ValidationError as e:
                result['valid'] = False
                result['errors'].append(str(e))
                
            # Additional custom validation
            custom_validation = self._custom_validation(config)
            if not custom_validation['valid']:
                result['valid'] = False
                result['errors'].extend(custom_validation['errors'])
                
            return result
            
        except Exception as e:
            self.logger.error(f"Error validating configuration: {str(e)}")
            return {'valid': False, 'errors': [str(e)]}
            
    def _load_configurations(self) -> None:
        """Load all configuration files."""
        try:
            # Load core configurations
            self._load_core_config()
            
            # Load module configurations
            self._load_module_configs()
            
            # Load environment-specific configurations
            self._load_env_configs()
            
            # Initialize configuration cache
            self._initialize_cache()
            
        except Exception as e:
            self.logger.error(f"Error loading configurations: {str(e)}")
            
    def _load_core_config(self) -> None:
        """Load core system configuration."""
        try:
            core_config_path = self.config_dir / 'core.yaml'
            if core_config_path.exists():
                with open(core_config_path, 'r') as f:
                    config = yaml.safe_load(f)
                    
                # Validate core configuration
                self._validate_core_config(config)
                
                # Store in database
                self._store_config('core', config)
                
        except Exception as e:
            self.logger.error(f"Error loading core config: {str(e)}")
            
    def _load_module_configs(self) -> None:
        """Load module-specific configurations."""
        try:
            module_config_dir = self.config_dir / 'modules'
            if module_config_dir.exists():
                for config_file in module_config_dir.glob('*.yaml'):
                    try:
                        with open(config_file, 'r') as f:
                            config = yaml.safe_load(f)
                            
                        # Validate module configuration
                        self._validate_module_config(config_file.stem, config)
                        
                        # Store in database
                        self._store_config(f"module.{config_file.stem}", config)
                        
                    except Exception as e:
                        self.logger.error(f"Error loading module config {config_file}: {str(e)}")
                        
        except Exception as e:
            self.logger.error(f"Error loading module configs: {str(e)}")
            
    def _validate_config(self, config_type: str, config: Dict) -> bool:
        """Validate configuration against schema."""
        try:
            # Load validation schema
            schema = self._load_validation_schema(config_type)
            
            # Perform validation
            jsonschema.validate(instance=config, schema=schema)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Configuration validation failed: {str(e)}")
            return False
            
    def _store_config(self, config_id: str, config: Dict) -> None:
        """Store configuration in database."""
        try:
            # Create configuration item
            config_item = ConfigurationItem(
                id=config_id,
                path=str(self.config_dir / f"{config_id}.yaml"),
                value=config,
                type='yaml',
                description=config.get('description', ''),
                default=config.get('default', {}),
                validation=config.get('validation', {}),
                last_modified=datetime.now(),
                modified_by='system',
                version=1,
                environment=self.environment,
                tags=[],
                dependencies=[],
                encryption_status=False
            )
            
            # Encrypt sensitive data
            encrypted_config = encrypt_data(config_item.__dict__)
            
            # Store in database
            self.db.store_config(encrypted_config)
            
            # Update cache
            self._update_cache(config_id, config)
            
        except Exception as e:
            self.logger.error(f"Error storing config: {str(e)}")
            
    def get_config(self, config_id: str) -> Optional[Dict]:
        """Get configuration by ID."""
        try:
            # Check cache first
            if config_id in self.config_cache:
                return self.config_cache[config_id]
                
            # Get from database
            config = self.db.get_config(config_id)
            if config:
                # Decrypt configuration
                decrypted_config = decrypt_data(config)
                
                # Update cache
                self._update_cache(config_id, decrypted_config)
                
                return decrypted_config
                
            return None
            
        except Exception as e:
            self.logger.error(f"Error getting config: {str(e)}")
            return None
            
    def update_config(self, config_id: str, updates: Dict, user: str) -> bool:
        """Update configuration values."""
        try:
            with self.lock:
                # Get current config
                current_config = self.get_config(config_id)
                if not current_config:
                    return False
                    
                # Create new version
                new_config = {**current_config, **updates}
                
                # Validate new configuration
                if not self._validate_config(config_id, new_config):
                    return False
                    
                # Create configuration item
                config_item = ConfigurationItem(
                    id=config_id,
                    path=str(self.config_dir / f"{config_id}.yaml"),
                    value=new_config,
                    type='yaml',
                    description=new_config.get('description', ''),
                    default=new_config.get('default', {}),
                    validation=new_config.get('validation', {}),
                    last_modified=datetime.now(),
                    modified_by=user,
                    version=current_config['version'] + 1,
                    environment=self.environment,
                    tags=[],
                    dependencies=[],
                    encryption_status=False
                )
                
                # Store new version
                encrypted_config = encrypt_data(config_item.__dict__)
                self.db.store_config(encrypted_config)
                
                # Update cache
                self._update_cache(config_id, new_config)
                
                # Write to file
                self._write_config_file(config_id, new_config)
                
                return True
                
        except Exception as e:
            self.logger.error(f"Error updating config: {str(e)}")
            return False
            
    def _write_config_file(self, config_id: str, config: Dict) -> None:
        """Write configuration to file."""
        try:
            config_path = self.config_dir / f"{config_id}.yaml"
            with open(config_path, 'w') as f:
                yaml.safe_dump(config, f)
                
        except Exception as e:
            self.logger.error(f"Error writing config file: {str(e)}")
            
    def get_config_history(self, config_id: str) -> List[Dict]:
        """Get configuration version history."""
        try:
            # Get all versions from database
            versions = self.db.get_config_versions(config_id)
            
            # Decrypt and process versions
            history = []
            for version in versions:
                decrypted_version = decrypt_data(version)
                history.append({
                    'version': decrypted_version['version'],
                    'modified_at': decrypted_version['last_modified'],
                    'modified_by': decrypted_version['modified_by'],
                    'changes': self._compute_config_diff(
                        decrypted_version.get('previous_value', {}),
                        decrypted_version['value']
                    )
                })
                
            return history
            
        except Exception as e:
            self.logger.error(f"Error getting config history: {str(e)}")
            return []
            
    def _compute_config_diff(self, old_config: Dict, new_config: Dict) -> Dict:
        """Compute differences between configuration versions."""
        try:
            diff = {
                'added': {},
                'removed': {},
                'modified': {}
            }
            
            # Find added and modified items
            for key, value in new_config.items():
                if key not in old_config:
                    diff['added'][key] = value
                elif old_config[key] != value:
                    diff['modified'][key] = {
                        'old': old_config[key],
                        'new': value
                    }
                    
            # Find removed items
            for key in old_config:
                if key not in new_config:
                    diff['removed'][key] = old_config[key]
                    
            return diff
            
        except Exception as e:
            self.logger.error(f"Error computing config diff: {str(e)}")
            return {}
            
    def validate_all_configs(self) -> Dict:
        """Validate all configurations."""
        try:
            results = {
                'valid': [],
                'invalid': []
            }
            
            # Get all configurations
            configs = self.db.get_all_configs()
            
            # Validate each configuration
            for config in configs:
                decrypted_config = decrypt_data(config)
                if self._validate_config(decrypted_config['id'], decrypted_config['value']):
                    results['valid'].append(decrypted_config['id'])
                else:
                    results['invalid'].append(decrypted_config['id'])
                    
            return results
            
        except Exception as e:
            self.logger.error(f"Error validating configs: {str(e)}")
            return {'error': str(e)}
            
    def export_configs(self, export_path: str) -> bool:
        """Export all configurations to file."""
        try:
            export_dir = Path(export_path)
            export_dir.mkdir(exist_ok=True)
            
            # Get all configurations
            configs = self.db.get_all_configs()
            
            # Export each configuration
            for config in configs:
                decrypted_config = decrypt_data(config)
                config_path = export_dir / f"{decrypted_config['id']}.yaml"
                
                with open(config_path, 'w') as f:
                    yaml.safe_dump(decrypted_config['value'], f)
                    
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting configs: {str(e)}")
            return False
            
    def import_configs(self, import_path: str, user: str) -> Dict:
        """Import configurations from file."""
        try:
            import_dir = Path(import_path)
            results = {
                'imported': [],
                'failed': []
            }
            
            # Import each configuration file
            for config_file in import_dir.glob('*.yaml'):
                try:
                    with open(config_file, 'r') as f:
                        config = yaml.safe_load(f)
                        
                    # Validate configuration
                    if self._validate_config(config_file.stem, config):
                        # Update configuration
                        if self.update_config(config_file.stem, config, user):
                            results['imported'].append(config_file.stem)
                        else:
                            results['failed'].append(config_file.stem)
                            
                except Exception as e:
                    self.logger.error(f"Error importing config {config_file}: {str(e)}")
                    results['failed'].append(config_file.stem)
                    
            return results
            
        except Exception as e:
            self.logger.error(f"Error importing configs: {str(e)}")
            return {'error': str(e)}

    def validate_configuration(self, config_id: str) -> Dict:
        """Validate configuration against schema and business rules."""
        try:
            with self.lock:
                config = self.get_config(config_id)
                if not config:
                    raise ValueError(f"Configuration {config_id} not found")
                    
                validation_results = {
                    'valid': True,
                    'errors': [],
                    'warnings': [],
                    'dependencies': []
                }
                
                # Schema validation
                schema_result = self._validate_schema(config)
                if not schema_result['valid']:
                    validation_results['valid'] = False
                    validation_results['errors'].extend(schema_result['errors'])
                    
                # Business rule validation
                rule_result = self._validate_business_rules(config)
                if not rule_result['valid']:
                    validation_results['valid'] = False
                    validation_results['errors'].extend(rule_result['errors'])
                    
                # Dependency validation
                dep_result = self._validate_dependencies(config)
                validation_results['dependencies'] = dep_result
                
                # Security validation
                sec_result = self._validate_security(config)
                if not sec_result['valid']:
                    validation_results['valid'] = False
                    validation_results['errors'].extend(sec_result['errors'])
                    
                return validation_results
                
        except Exception as e:
            self.logger.error(f"Error validating configuration {config_id}: {str(e)}")
            return {'valid': False, 'errors': [str(e)]}
            
    def _validate_security(self, config: ConfigurationItem) -> Dict:
        """Validate security aspects of configuration."""
        try:
            results = {
                'valid': True,
                'errors': [],
                'warnings': []
            }
            
            # Check for sensitive data exposure
            sensitive_check = self._check_sensitive_data(config)
            if not sensitive_check['valid']:
                results['valid'] = False
                results['errors'].extend(sensitive_check['errors'])
                
            # Validate encryption requirements
            encryption_check = self._validate_encryption(config)
            if not encryption_check['valid']:
                results['valid'] = False
                results['errors'].extend(encryption_check['errors'])
                
            # Check access controls
            access_check = self._validate_access_controls(config)
            if not access_check['valid']:
                results['valid'] = False
                results['errors'].extend(access_check['errors'])
                
            return results
            
        except Exception as e:
            self.logger.error(f"Error in security validation: {str(e)}")
            return {'valid': False, 'errors': [str(e)]}
            
    def apply_configuration_changes(self, changes: List[Dict]) -> Dict:
        """Apply multiple configuration changes atomically."""
        try:
            with self.lock:
                results = {
                    'success': True,
                    'applied_changes': [],
                    'failed_changes': [],
                    'warnings': []
                }
                
                # Validate all changes first
                for change in changes:
                    validation = self.validate_configuration(change['config_id'])
                    if not validation['valid']:
                        results['failed_changes'].append({
                            'config_id': change['config_id'],
                            'errors': validation['errors']
                        })
                        results['success'] = False
                        
                if not results['success']:
                    return results
                    
                # Apply changes
                for change in changes:
                    try:
                        # Create backup
                        self._create_config_backup(change['config_id'])
                        
                        # Apply change
                        self._apply_single_change(change)
                        
                        # Verify change
                        if self._verify_change(change):
                            results['applied_changes'].append(change['config_id'])
                        else:
                            # Rollback on verification failure
                            self._rollback_change(change['config_id'])
                            results['failed_changes'].append({
                                'config_id': change['config_id'],
                                'errors': ['Verification failed']
                            })
                            results['success'] = False
                            
                    except Exception as e:
                        self._rollback_change(change['config_id'])
                        results['failed_changes'].append({
                            'config_id': change['config_id'],
                            'errors': [str(e)]
                        })
                        results['success'] = False
                        
                # Notify subscribers of changes
                if results['applied_changes']:
                    self._notify_configuration_changes(results['applied_changes'])
                    
                return results
                
        except Exception as e:
            self.logger.error(f"Error applying configuration changes: {str(e)}")
            return {
                'success': False,
                'applied_changes': [],
                'failed_changes': [],
                'errors': [str(e)]
            }
            
    def _notify_configuration_changes(self, changed_configs: List[str]) -> None:
        """Notify subscribers of configuration changes."""
        try:
            notifications = []
            for config_id in changed_configs:
                config = self.get_config(config_id)
                if config:
                    notifications.append({
                        'config_id': config_id,
                        'type': 'config_change',
                        'timestamp': datetime.now(),
                        'details': {
                            'path': config.path,
                            'new_version': config.version,
                            'modified_by': config.modified_by
                        }
                    })
                    
            # Send notifications to subscribers
            self._send_notifications(notifications)
            
            # Update monitoring metrics
            self._update_config_metrics(notifications)
            
        except Exception as e:
            self.logger.error(f"Error notifying configuration changes: {str(e)}")
            
    def _load_config_item(self, path: str, environment: str = None) -> ConfigurationItem:
        """Load configuration item from storage."""
        try:
            # Get configuration from database
            config = self.db.get_config(path, environment)
            if not config:
                raise ValueError(f"Configuration {path} not found")
                
            # Decrypt configuration
            decrypted_config = decrypt_data(config)
            
            # Create configuration item
            config_item = ConfigurationItem(
                id=decrypted_config['id'],
                path=decrypted_config['path'],
                value=decrypted_config['value'],
                type=decrypted_config['type'],
                description=decrypted_config['description'],
                default=decrypted_config['default'],
                validation=decrypted_config['validation'],
                last_modified=decrypted_config['last_modified'],
                modified_by=decrypted_config['modified_by'],
                version=decrypted_config['version'],
                environment=decrypted_config['environment'],
                tags=decrypted_config['tags'],
                dependencies=decrypted_config['dependencies'],
                encryption_status=decrypted_config['encryption_status']
            )
            
            return config_item
            
        except Exception as e:
            self.logger.error(f"Error loading configuration {path}: {str(e)}")
            return None
            
    def _validate_cached_config(self, cache_key: str) -> ConfigurationItem:
        """Validate cached configuration."""
        try:
            # Get cached configuration
            config = self.config_cache[cache_key]
            
            # Validate configuration
            validation_result = self._validate_configuration(config)
            
            if not validation_result['valid']:
                # Remove invalid configuration from cache
                del self.config_cache[cache_key]
                raise ValueError(f"Invalid configuration {config.path}")
                
            return config
            
        except Exception as e:
            self.logger.error(f"Error validating cached configuration {cache_key}: {str(e)}")
            return None
            
    def _load_validation_schemas(self) -> None:
        """Load validation schemas from file."""
        try:
            # Load schema file
            schema_path = self.config_dir / 'schemas.yaml'
            if schema_path.exists():
                with open(schema_path, 'r') as f:
                    schemas = yaml.safe_load(f)
                    
                # Store schemas in memory
                self.validation_schemas = schemas
                
        except Exception as e:
            self.logger.error(f"Error loading validation schemas: {str(e)}")
            
    def _validate_import_data(self, data: Dict) -> bool:
        """Validate import data format."""
        try:
            # Check for required fields
            if 'configurations' not in data:
                return False
                
            # Validate each configuration
            for path, config in data['configurations'].items():
                if not isinstance(config, dict):
                    return False
                    
                # Check for required fields
                if 'value' not in config:
                    return False
                    
            return True
            
        except Exception as e:
            self.logger.error(f"Error validating import data: {str(e)}")
            return False
            
    def _get_current_user(self) -> str:
        """Get current user."""
        try:
            # Get current user from environment
            user = os.environ.get('USER', 'system')
            
            return user
            
        except Exception as e:
            self.logger.error(f"Error getting current user: {str(e)}")
            return 'system'
            
    def _get_next_version(self, path: str) -> int:
        """Get next version number for configuration."""
        try:
            # Get current version from database
            version = self.db.get_config_version(path)
            
            # Increment version
            version += 1
            
            return version
            
        except Exception as e:
            self.logger.error(f"Error getting next version: {str(e)}")
            return 1
            
    def _should_encrypt(self, config: ConfigurationItem) -> bool:
        """Check if configuration should be encrypted."""
        try:
            # Check for sensitive data
            if config.value and isinstance(config.value, dict):
                for key, value in config.value.items():
                    if key.startswith('password') or key.startswith('secret'):
                        return True
                        
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking encryption: {str(e)}")
            return False
            
    def _store_configuration(self, config: ConfigurationItem) -> None:
        """Store configuration in database."""
        try:
            # Encrypt configuration
            encrypted_config = encrypt_data(config.__dict__)
            
            # Store in database
            self.db.store_config(encrypted_config)
            
        except Exception as e:
            self.logger.error(f"Error storing configuration: {str(e)}")
            
    def _notify_configuration_change(self, config: ConfigurationItem) -> None:
        """Notify subscribers of configuration change."""
        try:
            # Create notification
            notification = {
                'config_id': config.id,
                'type': 'config_change',
                'timestamp': datetime.now(),
                'details': {
                    'path': config.path,
                    'new_version': config.version,
                    'modified_by': config.modified_by
                }
            }
            
            # Send notification to subscribers
            self._send_notification(notification)
            
        except Exception as e:
            self.logger.error(f"Error notifying configuration change: {str(e)}")
            
    def _send_notification(self, notification: Dict) -> None:
        """Send notification to subscribers."""
        try:
            # Get subscribers
            subscribers = self.db.get_subscribers()
            
            # Send notification to each subscriber
            for subscriber in subscribers:
                # Send notification via email
                self._send_email(subscriber, notification)
                
        except Exception as e:
            self.logger.error(f"Error sending notification: {str(e)}")
            
    def _send_email(self, subscriber: str, notification: Dict) -> None:
        """Send email to subscriber."""
        try:
            # Create email message
            message = f"Configuration {notification['config_id']} changed"
            
            # Send email
            self._send_email_message(subscriber, message)
            
        except Exception as e:
            self.logger.error(f"Error sending email: {str(e)}")
            
    def _send_email_message(self, recipient: str, message: str) -> None:
        """Send email message."""
        try:
            # Get email settings
            email_settings = self.db.get_email_settings()
            
            # Send email
            self._send_email_via_smtp(recipient, message, email_settings)
            
        except Exception as e:
            self.logger.error(f"Error sending email message: {str(e)}")
            
    def _send_email_via_smtp(self, recipient: str, message: str, email_settings: Dict) -> None:
        """Send email via SMTP."""
        try:
            # Import SMTP library
            import smtplib
            from email.mime.text import MIMEText
            
            # Create email message
            msg = MIMEText(message)
            msg['Subject'] = 'Configuration Change'
            msg['From'] = email_settings['from']
            msg['To'] = recipient
            
            # Send email via SMTP
            server = smtplib.SMTP(email_settings['server'], email_settings['port'])
            server.starttls()
            server.login(email_settings['username'], email_settings['password'])
            server.sendmail(email_settings['from'], recipient, msg.as_string())
            server.quit()
            
        except Exception as e:
            self.logger.error(f"Error sending email via SMTP: {str(e)}")
            
    def _detect_environment(self) -> str:
        """Detect environment."""
        try:
            # Get environment from environment variable
            environment = os.environ.get('ENVIRONMENT', 'dev')
            
            return environment
            
        except Exception as e:
            self.logger.error(f"Error detecting environment: {str(e)}")
            return 'dev'
            
    def _custom_validation(self, config: ConfigurationItem) -> Dict:
        """Custom validation for configuration."""
        try:
            # Custom validation logic
            result = {
                'valid': True,
                'errors': []
            }
            
            # Add custom validation logic here
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error in custom validation: {str(e)}")
            return {'valid': False, 'errors': [str(e)]}
