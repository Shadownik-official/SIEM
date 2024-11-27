import hashlib
import itertools
import string
import time
import logging
import threading
import queue
import json
import yaml
from typing import List, Dict, Optional, Set
from pathlib import Path
import subprocess
import re

from ..utils.logging import setup_logger
from ..utils.encryption import encrypt_data, decrypt_data
from ..utils.database import Database

class PasswordAuditor:
    """Advanced password auditing and assessment toolkit."""
    
    def __init__(self, config_path: str):
        self.logger = setup_logger("PasswordAuditor")
        self.load_config(config_path)
        self.db = Database()
        self.running = False
        self.password_queue = queue.Queue()
        self.found_passwords = {}
        self.lock = threading.Lock()
        
    def load_config(self, config_path: str) -> None:
        """Load auditor configuration."""
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
            
        self.audit_config = self.config['password_auditing']
        self.wordlists = self._load_wordlists()
        
    def start_audit(self, target_hashes: Dict[str, str], audit_type: str = 'comprehensive') -> str:
        """Start a password audit job."""
        try:
            audit_id = self._generate_audit_id()
            
            audit_data = {
                'id': audit_id,
                'type': audit_type,
                'status': 'running',
                'start_time': time.time(),
                'target_count': len(target_hashes),
                'cracked_count': 0,
                'progress': 0.0,
                'results': {}
            }
            
            # Store encrypted audit data
            self.db.store_audit(audit_id, encrypt_data(audit_data))
            
            # Start audit threads
            self.running = True
            self._start_audit_threads(audit_id, target_hashes, audit_type)
            
            return audit_id
            
        except Exception as e:
            self.logger.error(f"Error starting password audit: {str(e)}")
            raise
            
    def stop_audit(self, audit_id: str) -> None:
        """Stop an active password audit."""
        try:
            self.running = False
            audit_data = self._get_audit_data(audit_id)
            
            if audit_data:
                audit_data['status'] = 'stopped'
                audit_data['end_time'] = time.time()
                self.db.update_audit(audit_id, encrypt_data(audit_data))
                
            self.logger.info(f"Stopped password audit: {audit_id}")
            
        except Exception as e:
            self.logger.error(f"Error stopping audit: {str(e)}")
            raise
            
    def get_audit_status(self, audit_id: str) -> dict:
        """Get current status of password audit."""
        try:
            audit_data = self._get_audit_data(audit_id)
            if not audit_data:
                raise ValueError(f"Audit not found: {audit_id}")
                
            return {
                'id': audit_id,
                'status': audit_data['status'],
                'progress': audit_data['progress'],
                'cracked_count': audit_data['cracked_count'],
                'elapsed_time': time.time() - audit_data['start_time']
            }
            
        except Exception as e:
            self.logger.error(f"Error getting audit status: {str(e)}")
            raise
            
    def get_audit_results(self, audit_id: str) -> dict:
        """Get complete results of password audit."""
        try:
            audit_data = self._get_audit_data(audit_id)
            if not audit_data:
                raise ValueError(f"Audit not found: {audit_id}")
                
            return {
                'id': audit_id,
                'type': audit_data['type'],
                'duration': time.time() - audit_data['start_time'],
                'total_passwords': audit_data['target_count'],
                'cracked_passwords': audit_data['cracked_count'],
                'success_rate': (audit_data['cracked_count'] / audit_data['target_count']) * 100,
                'results': audit_data['results'],
                'password_analysis': self._analyze_passwords(audit_data['results'])
            }
            
        except Exception as e:
            self.logger.error(f"Error getting audit results: {str(e)}")
            raise
            
    def _start_audit_threads(self, audit_id: str, target_hashes: Dict[str, str], audit_type: str) -> None:
        """Start multiple password cracking threads."""
        try:
            thread_count = self.audit_config['thread_count']
            
            # Dictionary attack thread
            threading.Thread(
                target=self._dictionary_attack_worker,
                args=(audit_id, target_hashes),
                daemon=True
            ).start()
            
            if audit_type == 'comprehensive':
                # Rule-based attack thread
                threading.Thread(
                    target=self._rule_based_attack_worker,
                    args=(audit_id, target_hashes),
                    daemon=True
                ).start()
                
                # Brute force attack threads
                for _ in range(thread_count - 2):
                    threading.Thread(
                        target=self._brute_force_worker,
                        args=(audit_id, target_hashes),
                        daemon=True
                    ).start()
                    
        except Exception as e:
            self.logger.error(f"Error starting audit threads: {str(e)}")
            raise
            
    def _dictionary_attack_worker(self, audit_id: str, target_hashes: Dict[str, str]) -> None:
        """Worker thread for dictionary-based password cracking."""
        try:
            for wordlist in self.wordlists:
                if not self.running:
                    break
                    
                with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                    for word in f:
                        if not self.running:
                            break
                            
                        word = word.strip()
                        self._check_password(audit_id, word, target_hashes)
                        
        except Exception as e:
            self.logger.error(f"Dictionary attack error: {str(e)}")
            
    def _rule_based_attack_worker(self, audit_id: str, target_hashes: Dict[str, str]) -> None:
        """Worker thread for rule-based password mutations."""
        try:
            rules = self._load_password_rules()
            
            for wordlist in self.wordlists:
                if not self.running:
                    break
                    
                with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                    for word in f:
                        if not self.running:
                            break
                            
                        word = word.strip()
                        # Apply each rule to the word
                        for rule in rules:
                            mutated = self._apply_rule(word, rule)
                            self._check_password(audit_id, mutated, target_hashes)
                            
        except Exception as e:
            self.logger.error(f"Rule-based attack error: {str(e)}")
            
    def _brute_force_worker(self, audit_id: str, target_hashes: Dict[str, str]) -> None:
        """Worker thread for brute force password cracking."""
        try:
            charset = string.ascii_letters + string.digits + string.punctuation
            max_length = self.audit_config['max_length']
            
            for length in range(1, max_length + 1):
                if not self.running:
                    break
                    
                for guess in itertools.product(charset, repeat=length):
                    if not self.running:
                        break
                        
                    password = ''.join(guess)
                    self._check_password(audit_id, password, target_hashes)
                    
        except Exception as e:
            self.logger.error(f"Brute force attack error: {str(e)}")
            
    def _check_password(self, audit_id: str, password: str, target_hashes: Dict[str, str]) -> None:
        """Check a password against target hashes."""
        try:
            password_hash = self._hash_password(password)
            
            for username, hash_value in target_hashes.items():
                if hash_value == password_hash:
                    with self.lock:
                        audit_data = self._get_audit_data(audit_id)
                        if audit_data and username not in audit_data['results']:
                            audit_data['results'][username] = password
                            audit_data['cracked_count'] += 1
                            audit_data['progress'] = (audit_data['cracked_count'] / audit_data['target_count']) * 100
                            self.db.update_audit(audit_id, encrypt_data(audit_data))
                            
        except Exception as e:
            self.logger.error(f"Password check error: {str(e)}")
            
    def _analyze_passwords(self, cracked_passwords: Dict[str, str]) -> dict:
        """Analyze cracked passwords for patterns and weaknesses."""
        analysis = {
            'length': {
                'min': float('inf'),
                'max': 0,
                'average': 0
            },
            'character_sets': {
                'lowercase': 0,
                'uppercase': 0,
                'numbers': 0,
                'special': 0
            },
            'common_patterns': [],
            'reused_passwords': []
        }
        
        # Analyze each password
        password_counts = {}
        total_length = 0
        
        for password in cracked_passwords.values():
            # Length statistics
            length = len(password)
            total_length += length
            analysis['length']['min'] = min(analysis['length']['min'], length)
            analysis['length']['max'] = max(analysis['length']['max'], length)
            
            # Character set usage
            if re.search(r'[a-z]', password):
                analysis['character_sets']['lowercase'] += 1
            if re.search(r'[A-Z]', password):
                analysis['character_sets']['uppercase'] += 1
            if re.search(r'[0-9]', password):
                analysis['character_sets']['numbers'] += 1
            if re.search(r'[^a-zA-Z0-9]', password):
                analysis['character_sets']['special'] += 1
                
            # Track password reuse
            password_counts[password] = password_counts.get(password, 0) + 1
            
        # Calculate averages and find patterns
        if cracked_passwords:
            analysis['length']['average'] = total_length / len(cracked_passwords)
            
        # Find reused passwords
        analysis['reused_passwords'] = [
            {'password': pw, 'count': count}
            for pw, count in password_counts.items()
            if count > 1
        ]
        
        # Find common patterns
        analysis['common_patterns'] = self._find_password_patterns(cracked_passwords.values())
        
        return analysis
        
    @staticmethod
    def _find_password_patterns(passwords: List[str]) -> List[dict]:
        """Identify common patterns in passwords."""
        patterns = []
        
        # Common pattern regular expressions
        pattern_checks = [
            (r'\d{4}$', 'Ends with 4 digits'),
            (r'^[A-Z][a-z]+\d+', 'Capitalized word followed by numbers'),
            (r'[a-zA-Z]+123', 'Word followed by 123'),
            (r'[!@#$%^&*()]+$', 'Ends with special characters'),
            (r'([a-zA-Z0-9])\1{2,}', 'Character repeated 3+ times')
        ]
        
        for pattern, description in pattern_checks:
            count = sum(1 for p in passwords if re.search(pattern, p))
            if count > 0:
                patterns.append({
                    'pattern': description,
                    'count': count,
                    'percentage': (count / len(passwords)) * 100
                })
                
        return patterns
        
    @staticmethod
    def _hash_password(password: str) -> str:
        """Hash a password using SHA-256."""
        return hashlib.sha256(password.encode()).hexdigest()
        
    def _load_wordlists(self) -> List[str]:
        """Load configured password wordlists."""
        wordlists = []
        wordlist_dir = Path(self.audit_config['wordlist_directory'])
        
        for wordlist in self.audit_config['wordlists']:
            path = wordlist_dir / wordlist
            if path.exists():
                wordlists.append(str(path))
            else:
                self.logger.warning(f"Wordlist not found: {path}")
                
        return wordlists
        
    def _load_password_rules(self) -> List[dict]:
        """Load password mutation rules."""
        try:
            rules_file = Path(self.audit_config['rules_file'])
            if rules_file.exists():
                with open(rules_file, 'r') as f:
                    return yaml.safe_load(f)
            return []
            
        except Exception as e:
            self.logger.error(f"Error loading password rules: {str(e)}")
            return []
            
    @staticmethod
    def _apply_rule(word: str, rule: dict) -> str:
        """Apply a mutation rule to a word."""
        result = word
        
        if rule.get('capitalize'):
            result = result.capitalize()
        if rule.get('uppercase'):
            result = result.upper()
        if rule.get('leetspeak'):
            for old, new in rule['leetspeak'].items():
                result = result.replace(old, new)
        if rule.get('append'):
            result += str(rule['append'])
        if rule.get('prepend'):
            result = str(rule['prepend']) + result
            
        return result
        
    def _get_audit_data(self, audit_id: str) -> Optional[dict]:
        """Retrieve audit data from database."""
        try:
            encrypted_data = self.db.get_audit(audit_id)
            if encrypted_data:
                return decrypt_data(encrypted_data)
            return None
            
        except Exception as e:
            self.logger.error(f"Error retrieving audit data: {str(e)}")
            return None
            
    @staticmethod
    def _generate_audit_id() -> str:
        """Generate unique audit identifier."""
        timestamp = time.strftime('%Y%m%d%H%M%S')
        return f"PWAUDIT_{timestamp}"
