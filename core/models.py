"""
Data models and type definitions for Supply Chain Security Monitor.

This module defines the core data structures used throughout the system
to ensure consistency and type safety.
"""
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from enum import Enum


class RiskLevel(Enum):
    """Risk levels for security analysis."""
    CLEAN = "CLEAN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertPriority(Enum):
    """Priority levels for alerts."""
    LOW = "🔍 LOW PRIORITY"
    MEDIUM = "⚠️ MEDIUM PRIORITY" 
    HIGH = "⚠️⚠️ HIGH PRIORITY"
    CRITICAL = "🚨🚨🚨 CRITICAL PRIORITY"


class PackageEcosystem(Enum):
    """Supported package ecosystems."""
    NPM = "npm"
    PYPI = "pypi"
    GO = "go"  # Future support
    RUST = "rust"  # Future support


@dataclass
class PackageVersion:
    """Represents a package version with metadata."""
    name: str
    version: str
    author: str
    author_email: Optional[str] = None
    published_at: Optional[datetime] = None
    processed_at: Optional[datetime] = None
    description: Optional[str] = None
    keywords: Optional[List[str]] = None
    homepage: Optional[str] = None
    repository_url: Optional[str] = None
    license: Optional[str] = None
    dependencies: Optional[Dict[str, str]] = None
    dev_dependencies: Optional[Dict[str, str]] = None
    maintainers: Optional[List[str]] = None
    file_count: Optional[int] = None
    unpack_size: Optional[int] = None
    tarball_size: Optional[int] = None
    created_at: Optional[str] = None
    is_deprecated: bool = False
    deprecated_reason: Optional[str] = None
    dist_tags: Optional[Dict[str, str]] = None
    shasum: Optional[str] = None
    integrity: Optional[str] = None
    git_head: Optional[str] = None
    ecosystem: PackageEcosystem = PackageEcosystem.NPM


@dataclass
class SecurityFinding:
    """Represents a security finding from analysis."""
    finding_type: str
    severity: RiskLevel
    description: str
    source: str  # e.g., "guarddog_metadata", "velocity_analysis"
    confidence: float = 1.0
    details: Optional[Dict[str, Any]] = None


@dataclass
class GuardDogAnalysis:
    """Represents GuardDog analysis results."""
    package_name: str
    version: str
    ecosystem: PackageEcosystem
    analysis_timestamp: datetime
    metadata_risk_score: float
    source_risk_score: Optional[float] = None
    combined_risk_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.CLEAN
    metadata_findings: List[str] = None
    source_findings: List[str] = None
    guarddog_metadata_results: Optional[Dict[str, Any]] = None
    guarddog_source_results: Optional[Dict[str, Any]] = None
    analysis_error: Optional[str] = None
    
    def __post_init__(self):
        if self.metadata_findings is None:
            self.metadata_findings = []
        if self.source_findings is None:
            self.source_findings = []


@dataclass
class VelocityPattern:
    """Represents a detected velocity-based suspicious pattern."""
    author: str
    packages: List[PackageVersion]
    diversity_score: float
    time_window: int  # hours
    pattern_type: str  # e.g., "velocity_attack", "account_takeover"
    ecosystem: PackageEcosystem
    detected_at: datetime
    risk_level: RiskLevel
    findings: List[SecurityFinding] = None
    
    def __post_init__(self):
        if self.findings is None:
            self.findings = []


@dataclass  
class ThreatDetectionResult:
    """Comprehensive threat detection result combining multiple analyses."""
    package: PackageVersion
    velocity_pattern: Optional[VelocityPattern] = None
    guarddog_analysis: Optional[GuardDogAnalysis] = None
    security_findings: List[SecurityFinding] = None
    combined_risk_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.CLEAN
    alert_priority: AlertPriority = AlertPriority.LOW
    should_alert: bool = False
    
    def __post_init__(self):
        if self.security_findings is None:
            self.security_findings = []


@dataclass
class SlackAlert:
    """Represents a Slack alert message."""
    title: str
    priority: AlertPriority
    color: str  # Slack attachment color
    fields: List[Dict[str, Any]]
    attachments: List[Dict[str, Any]]
    channel: Optional[str] = None
    
    def to_webhook_payload(self) -> Dict[str, Any]:
        """Convert to Slack webhook payload format."""
        return {
            "attachments": self.attachments,
            "channel": self.channel
        }


@dataclass
class ScanningSession:
    """Represents a scanning session with results."""
    ecosystem: PackageEcosystem
    started_at: datetime
    completed_at: Optional[datetime] = None
    packages_discovered: int = 0
    packages_processed: int = 0
    packages_skipped: int = 0
    errors_encountered: int = 0
    suspicious_patterns_found: int = 0
    alerts_sent: int = 0
    database_entries_added: int = 0
    early_stopping_enabled: bool = True
    performance_stats: Optional[Dict[str, Any]] = None


# Type aliases for common usage patterns
PackageDict = Dict[str, Any]  # Raw package data from APIs
AuthorActivities = Dict[str, List[PackageVersion]]  # Author -> their packages
SuspiciousPatterns = List[VelocityPattern]  # List of detected patterns
