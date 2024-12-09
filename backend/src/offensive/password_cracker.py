import hashlib
import itertools
import string
from typing import List, Optional, Generator, Dict
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import json

class PasswordCracker:
    def __init__(self, num_threads: int = 4):
        self.num_threads = num_threads
        self.logger = logging.getLogger(__name__)
        self.common_passwords_file = Path(__file__).parent / "data" / "common_passwords.txt"
        self.rules_file = Path(__file__).parent / "data" / "password_rules.json"
        
    def crack_hash(self, hash_value: str, hash_type: str,
                  max_length: int = 8, use_rules: bool = True,
                  use_common: bool = True) -> Optional[str]:
        """
        Attempt to crack a password hash using multiple methods
        """
        self.logger.info(f"Starting password cracking for hash: {hash_value}")
        
        # Try common passwords first
        if use_common:
            result = self._try_common_passwords(hash_value, hash_type)
            if result:
                return result
                
        # Try rule-based mutations of common passwords
        if use_rules:
            result = self._try_rule_based(hash_value, hash_type)
            if result:
                return result
                
        # Try brute force as last resort
        return self._brute_force(hash_value, hash_type, max_length)
        
    def _try_common_passwords(self, hash_value: str, hash_type: str) -> Optional[str]:
        """Try cracking using a list of common passwords"""
        self.logger.info("Trying common passwords...")
        
        try:
            with open(self.common_passwords_file, 'r', encoding='utf-8') as f:
                common_passwords = f.read().splitlines()
                
            with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
                futures = []
                
                for password in common_passwords:
                    future = executor.submit(
                        self._check_password,
                        password,
                        hash_value,
                        hash_type
                    )
                    futures.append(future)
                    
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        return result
                        
        except Exception as e:
            self.logger.error(f"Error during common password check: {str(e)}")
            
        return None
        
    def _try_rule_based(self, hash_value: str, hash_type: str) -> Optional[str]:
        """Apply password mutation rules to common passwords"""
        self.logger.info("Trying rule-based mutations...")
        
        try:
            with open(self.rules_file, 'r') as f:
                rules = json.load(f)
                
            with open(self.common_passwords_file, 'r', encoding='utf-8') as f:
                common_passwords = f.read().splitlines()
                
            with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
                futures = []
                
                for password in common_passwords:
                    for rule in rules:
                        mutated = self._apply_rule(password, rule)
                        future = executor.submit(
                            self._check_password,
                            mutated,
                            hash_value,
                            hash_type
                        )
                        futures.append(future)
                        
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        return result
                        
        except Exception as e:
            self.logger.error(f"Error during rule-based check: {str(e)}")
            
        return None
        
    def _brute_force(self, hash_value: str, hash_type: str,
                     max_length: int) -> Optional[str]:
        """Perform a brute force attack"""
        self.logger.info(f"Starting brute force up to length {max_length}...")
        
        charset = string.ascii_letters + string.digits + string.punctuation
        
        with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            futures = []
            
            for length in range(1, max_length + 1):
                for candidate in self._generate_passwords(charset, length):
                    future = executor.submit(
                        self._check_password,
                        candidate,
                        hash_value,
                        hash_type
                    )
                    futures.append(future)
                    
                    # Check results periodically to avoid memory issues
                    if len(futures) >= self.num_threads * 100:
                        for future in as_completed(futures):
                            result = future.result()
                            if result:
                                return result
                        futures = []
                        
            # Check any remaining futures
            for future in as_completed(futures):
                result = future.result()
                if result:
                    return result
                    
        return None
        
    def _generate_passwords(self, charset: str, length: int) -> Generator[str, None, None]:
        """Generate all possible password combinations of given length"""
        for combination in itertools.product(charset, repeat=length):
            yield ''.join(combination)
            
    def _check_password(self, password: str, hash_value: str,
                       hash_type: str) -> Optional[str]:
        """Check if a password matches the target hash"""
        if self._hash_password(password, hash_type) == hash_value:
            self.logger.info(f"Password found: {password}")
            return password
        return None
        
    def _hash_password(self, password: str, hash_type: str) -> str:
        """Hash a password using the specified algorithm"""
        if hash_type.lower() == 'md5':
            return hashlib.md5(password.encode()).hexdigest()
        elif hash_type.lower() == 'sha1':
            return hashlib.sha1(password.encode()).hexdigest()
        elif hash_type.lower() == 'sha256':
            return hashlib.sha256(password.encode()).hexdigest()
        elif hash_type.lower() == 'sha512':
            return hashlib.sha512(password.encode()).hexdigest()
        else:
            raise ValueError(f"Unsupported hash type: {hash_type}")
            
    def _apply_rule(self, password: str, rule: Dict) -> str:
        """Apply a mutation rule to a password"""
        result = password
        
        if rule.get('capitalize'):
            result = result.capitalize()
            
        if rule.get('uppercase'):
            result = result.upper()
            
        if rule.get('lowercase'):
            result = result.lower()
            
        if rule.get('leetspeak'):
            replacements = {
                'a': '4',
                'e': '3',
                'i': '1',
                'o': '0',
                's': '5',
                't': '7'
            }
            for char, replacement in replacements.items():
                result = result.replace(char, replacement)
                
        if rule.get('append_numbers'):
            result += str(rule['append_numbers'])
            
        if rule.get('prepend_numbers'):
            result = str(rule['prepend_numbers']) + result
            
        if rule.get('append_special'):
            result += rule['append_special']
            
        if rule.get('prepend_special'):
            result = rule['prepend_special'] + result
            
        return result
        
    def generate_password_policy(self) -> Dict:
        """Generate password policy recommendations"""
        return {
            "minimum_length": 12,
            "require_uppercase": True,
            "require_lowercase": True,
            "require_numbers": True,
            "require_special": True,
            "prevent_common_words": True,
            "prevent_keyboard_patterns": True,
            "prevent_repeated_characters": True,
            "password_history": 24,  # Remember last 24 passwords
            "maximum_age_days": 90,  # Force password change every 90 days
            "minimum_age_hours": 24,  # Prevent changing password more than once per day
            "lockout_threshold": 5,  # Lock account after 5 failed attempts
            "lockout_duration_minutes": 30,
            "recommendations": [
                "Use a password manager",
                "Enable two-factor authentication where possible",
                "Use unique passwords for each account",
                "Avoid personal information in passwords",
                "Consider using passphrases instead of passwords"
            ]
        }
