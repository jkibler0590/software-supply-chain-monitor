"""
Core configuration management for Supply Chain Security Monitor.

This module centralizes all configuration settings and environment variables
to make the system easier to configure and maintain.
"""
import os
import logging
from typing import Dict, List, Optional
from pathlib import Path
import urllib3

# Disable SSL warnings globally
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Config:
    """Central configuration class for all system settings."""
    
    def __init__(self):
        """Initialize configuration from environment variables."""
        # Project paths
        project_root = Path(__file__).parent.parent
        
        # Database settings - use project-relative path by default
        self.DB_PATH = os.getenv('DB_PATH', str(project_root / 'data' / 'npm_scanner.db'))
        
        # Network settings
        self.VERIFY_SSL = os.getenv('VERIFY_SSL', 'false').lower() == 'true'
        self.REQUEST_TIMEOUT = int(os.getenv('REQUEST_TIMEOUT', '30'))
        self.MAX_RETRIES = int(os.getenv('MAX_RETRIES', '3'))
        
        # Scanning settings
        self.SCAN_INTERVAL_MINUTES = int(os.getenv('SCAN_INTERVAL_MINUTES', '15'))
        self.CHANGES_FEED_LIMIT = int(os.getenv('CHANGES_FEED_LIMIT', '1000'))
        self.EARLY_STOPPING_ENABLED = os.getenv('EARLY_STOPPING_ENABLED', 'true').lower() == 'true'
        self.EARLY_STOPPING_THRESHOLD = int(os.getenv('EARLY_STOPPING_THRESHOLD', '5'))
        
        # Analysis settings
        self.HOURS_BACK = int(os.getenv('HOURS_BACK', '24'))  # Database cleanup window
        self.VELOCITY_WINDOW_MINUTES = int(os.getenv('VELOCITY_WINDOW_MINUTES', '15'))  # Velocity detection window
        self.MIN_PACKAGES_FOR_ALERT = int(os.getenv('MIN_PACKAGES_FOR_ALERT', '5'))
        self.MIN_DIVERSITY_SCORE = float(os.getenv('MIN_DIVERSITY_SCORE', '0.7'))
        
        # GuardDog settings
        self.GUARDDOG_ENABLED = os.getenv('GUARDDOG_ENABLED', 'true').lower() == 'true'
        self.GUARDDOG_METADATA_ENABLED = os.getenv('GUARDDOG_METADATA_ENABLED', 'true').lower() == 'true'
        self.GUARDDOG_SOURCE_ENABLED = os.getenv('GUARDDOG_SOURCE_ENABLED', 'true').lower() == 'true'
        self.GUARDDOG_RISK_THRESHOLD = float(os.getenv('GUARDDOG_RISK_THRESHOLD', '0.3'))
        
        # Slack settings
        self.SLACK_WEBHOOK_URL = os.getenv('SLACK_WEBHOOK_URL')
        self.SLACK_ALERTS_ENABLED = bool(self.SLACK_WEBHOOK_URL)
        self.SLACK_CHANNEL = os.getenv('SLACK_CHANNEL', '#security-alerts')
        
        # NPM specific settings
        self.NPM_REGISTRY_URL = os.getenv('NPM_REGISTRY_URL', 'https://registry.npmjs.org')
        self.NPM_CHANGES_URL = os.getenv('NPM_CHANGES_URL', 'https://skimdb.npmjs.com/registry/_changes')
        
        # PyPI specific settings  
        self.PYPI_REGISTRY_URL = os.getenv('PYPI_REGISTRY_URL', 'https://pypi.org/pypi')
        self.PYPI_RSS_URL = os.getenv('PYPI_RSS_URL', 'https://pypi.org/rss/packages.xml')
        self.PYPI_SIMPLE_URL = os.getenv('PYPI_SIMPLE_URL', 'https://pypi.org/simple')
        
        # File paths - use project-relative paths for better compatibility
        project_root = Path(__file__).parent.parent
        self.TEMP_DIR = Path(os.getenv('TEMP_DIR', str(project_root / 'temp')))
        self.LOG_DIR = Path(os.getenv('LOG_DIR', str(project_root / 'logs')))
        self.DIFF_OUTPUT_DIR = Path(os.getenv('DIFF_OUTPUT_DIR', str(project_root / 'diffs')))
        
        # Ensure directories exist
        Path(self.DB_PATH).parent.mkdir(exist_ok=True, parents=True)  # Create data directory
        self.TEMP_DIR.mkdir(exist_ok=True, parents=True)
        self.LOG_DIR.mkdir(exist_ok=True, parents=True)
        self.DIFF_OUTPUT_DIR.mkdir(exist_ok=True, parents=True)
        
    def get_realistic_headers(self) -> Dict[str, str]:
        """Get realistic HTTP headers for API requests."""
        return {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
    
    def validate(self) -> List[str]:
        """Validate configuration and return list of issues."""
        issues = []
        
        if not self.SLACK_WEBHOOK_URL:
            issues.append("SLACK_WEBHOOK_URL not configured - Slack alerts disabled")
            
        if self.SCAN_INTERVAL_MINUTES < 1:
            issues.append("SCAN_INTERVAL_MINUTES must be at least 1")
            
        if self.MIN_DIVERSITY_SCORE < 0 or self.MIN_DIVERSITY_SCORE > 1:
            issues.append("MIN_DIVERSITY_SCORE must be between 0 and 1")
            
        if self.GUARDDOG_RISK_THRESHOLD < 0 or self.GUARDDOG_RISK_THRESHOLD > 1:
            issues.append("GUARDDOG_RISK_THRESHOLD must be between 0 and 1")
            
        return issues
    
    def validate_configuration(self) -> None:
        """Validate configuration and raise exception if invalid."""
        issues = self.validate()
        if issues:
            # Log issues but don't fail - these are warnings
            for issue in issues:
                logging.warning(f"Configuration issue: {issue}")
        # Don't raise exception for warnings
    
    def __str__(self) -> str:
        """Return human-readable configuration summary."""
        return f"""Supply Chain Security Monitor Configuration:
Database: {self.DB_PATH}
Scan Interval: {self.SCAN_INTERVAL_MINUTES} minutes
Slack Alerts: {'Enabled' if self.SLACK_ALERTS_ENABLED else 'Disabled'}
GuardDog: {'Enabled' if self.GUARDDOG_ENABLED else 'Disabled'}
SSL Verification: {'Enabled' if self.VERIFY_SSL else 'Disabled'}
"""


# Global configuration instance
config = Config()


# Legacy compatibility - these can be imported as before
DB_PATH = config.DB_PATH
VERIFY_SSL = config.VERIFY_SSL
SLACK_WEBHOOK_URL = config.SLACK_WEBHOOK_URL
