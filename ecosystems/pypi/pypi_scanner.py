"""
PyPI-specific scanner implementation.

This module implements the PyPI package scanner using the base scanner architecture,
providing PyPI registry integration, RSS feed monitoring, and threat detection.
"""
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Set
from collections import defaultdict

from core.config import config
from core.database import database
from core.enhanced_guarddog_service import enhanced_guarddog_service
from core.models import PackageVersion, PackageEcosystem, VelocityPattern, ScanningSession
from ecosystems.common.base_scanner import BaseScanner
from ecosystems.pypi.pypi_client import PyPIClient
from notifications.slack_alerts import slack_manager

logger = logging.getLogger(__name__)


class PyPIScanner(BaseScanner):
    """PyPI package ecosystem scanner."""
    
    def __init__(self):
        """Initialize PyPI scanner with PyPI client."""
        client = PyPIClient()
        super().__init__(PackageEcosystem.PYPI, client)
        
        # PyPI-specific configuration
        self.excluded_authors = {
            'pypi-bot', 'dependabot[bot]', 'renovate[bot]', 'github-actions[bot]',
            'automated-release', 'ci-bot', 'release-bot', 'publisher-bot',
            'pypi-publisher', 'automated-publisher', 'ci-publisher'
        }
        
        # PyPI-specific patterns for filtering
        self.test_package_patterns = [
            'test-', 'testing-', 'example-', 'sample-', 'demo-',
            'tutorial-', 'hello-world', 'my-package', 'tmp-'
        ]
    
    def discover_packages(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Discover recent PyPI packages from RSS feed."""
        try:
            logger.info(f"📡 Fetching PyPI package updates (limit: {limit})...")
            
            # Get recent packages from RSS feed
            changes_data = self.client.get_recent_changes(limit=limit)
            
            if not changes_data or 'packages' not in changes_data:
                logger.warning("No package updates found in PyPI RSS feed")
                return []
            
            packages = changes_data['packages']
            logger.info(f"   📊 Successfully discovered {len(packages)} packages")
            
            if self.current_session:
                self.current_session.packages_discovered = len(packages)
            
            return packages
            
        except Exception as e:
            logger.error(f"Error discovering PyPI packages: {e}")
            return []
    
    def filter_packages(self, packages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter packages to reduce noise and focus on legitimate packages."""
        if not packages:
            return []
        
        logger.info(f"🔍 Pre-filtering {len(packages)} PyPI packages...")
        
        filtered_packages = []
        filtered_count = 0
        
        for package in packages:
            package_name = package.get('name', '').lower()
            
            # Skip obvious test packages
            if self._is_test_package(package_name):
                filtered_count += 1
                continue
            
            # Skip packages with suspicious version patterns
            version = package.get('version', '')
            if self._is_suspicious_version(version):
                filtered_count += 1
                continue
            
            # Check if we already have recent data for this package
            if self._has_recent_data(package_name):
                filtered_count += 1
                continue
            
            filtered_packages.append(package)
        
        logger.info(f"   ⚡ Pre-filtering removed {filtered_count} packages ({(filtered_count/len(packages)*100):.1f}% reduction)")
        
        return filtered_packages
    
    def process_package(self, package_data: Dict[str, Any]) -> Optional[PackageVersion]:
        """Process a single PyPI package and extract version information."""
        package_name = package_data.get('name', '')
        
        if not package_name:
            return None
        
        try:
            # Get full package information from JSON API
            full_package_data = self.client.get_package_info(package_name)
            
            if not full_package_data:
                return None
            
            # Extract recent versions
            recent_versions = self.client.extract_recent_versions(
                full_package_data, 
                hours_back=config.HOURS_BACK
            )
            
            if not recent_versions:
                return None
            
            # Store all recent versions in database
            stored_count = database.add_package_versions_bulk(recent_versions)
            
            # Run GuardDog metadata analysis on all stored packages
            if enhanced_guarddog_service.available and recent_versions:
                for version in recent_versions:
                    guarddog_analysis = enhanced_guarddog_service.analyze_package_metadata(version)
                    if guarddog_analysis:
                        database.add_guarddog_analysis(guarddog_analysis)
            
            if self.current_session:
                self.current_session.database_entries_added += stored_count
            
            # Return the latest version for further analysis
            return recent_versions[0] if recent_versions else None
            
        except Exception as e:
            logger.error(f"Error processing PyPI package {package_name}: {e}")
            if self.current_session:
                self.current_session.errors_encountered += 1
            return None
    
    def run_velocity_analysis(self) -> List[VelocityPattern]:
        """Run velocity-based threat detection analysis for PyPI."""
        logger.info("🔍 Starting PyPI velocity pattern analysis...")
        
        # Get recent author activities within velocity detection window (15 minutes)
        author_activities = database.get_velocity_window_activities(
            ecosystem=PackageEcosystem.PYPI,
            minutes_back=config.VELOCITY_WINDOW_MINUTES
        )
        
        # Filter out automated authors
        filtered_activities = {
            author: packages 
            for author, packages in author_activities.items()
            if not self._is_automated_author(author) and len(packages) >= config.MIN_PACKAGES_FOR_ALERT
        }
        
        logger.info(f"   📋 Found {len(filtered_activities)} authors with recent activity")
        
        # Analyze patterns
        patterns = self.analyze_author_patterns(filtered_activities)
        
        if patterns:
            logger.info(f"🚨 Found {len(patterns)} suspicious velocity patterns")
            
            # Run GuardDog static analysis on suspicious packages
            if enhanced_guarddog_service.available:
                for pattern in patterns:
                    logger.info(f"🛡️ Running GuardDog analysis on velocity pattern packages for {pattern.author}")
                    guarddog_analyses = enhanced_guarddog_service.analyze_package_code_with_diff(pattern.packages)
                    
                    for analysis in guarddog_analyses:
                        database.add_guarddog_analysis(analysis)
                        
                        # Log high-risk findings
                        if analysis.risk_score >= 0.7:
                            logger.warning(f"🚨 High-risk GuardDog findings for {analysis.package_name}@{analysis.version} (score: {analysis.risk_score:.2f})")
            
            for pattern in patterns:
                # Check if we've already alerted for this pattern
                if not database.has_alerted_for_pattern(
                    pattern.author, 
                    PackageEcosystem.PYPI, 
                    pattern.detected_at
                ):
                    # Record alert and send notification
                    database.record_suspicious_alert(pattern)
                    slack_manager.send_velocity_pattern_alert(pattern)
                    
                    if self.current_session:
                        self.current_session.alerts_sent += 1
        
        if self.current_session:
            self.current_session.suspicious_patterns_found = len(patterns)
        
        return patterns
    
    def run_enhanced_detection(self, packages: List[PackageVersion]) -> Dict[str, Any]:
        """Run enhanced detection algorithms on processed PyPI packages."""
        if not packages:
            return {}
        
        logger.info("🛡️  Running PyPI enhanced detection analysis...")
        
        results = {
            'typosquatting_attempts': 0,
            'suspicious_keywords': 0,
            'size_anomalies': 0,
            'suspicious_authors': 0,
            'guarddog_metadata_suspicious': 0,
            'packages_analyzed': len(packages)
        }
        
        # Group packages by author for analysis
        author_packages = defaultdict(list)
        for pkg in packages:
            author_packages[pkg.author].append(pkg)
        
        # Track suspicious packages for GuardDog static analysis
        suspicious_packages = []
        
        for author, author_pkgs in author_packages.items():
            if self._is_automated_author(author):
                continue
            
            # Check for tyrosquatting against popular packages
            typosquat_packages = self._detect_pypi_typosquatting(author_pkgs)
            results['typosquatting_attempts'] += len(typosquat_packages)
            suspicious_packages.extend(typosquat_packages)
            
            # Check for suspicious keywords
            keyword_packages = self._detect_suspicious_keywords(author_pkgs)
            results['suspicious_keywords'] += len(keyword_packages)
            suspicious_packages.extend(keyword_packages)
            
            # Check for size anomalies
            size_anomaly_packages = self._detect_size_anomalies(author_pkgs)
            results['size_anomalies'] += len(size_anomaly_packages)
            suspicious_packages.extend(size_anomaly_packages)
            
            # Check for GuardDog metadata-based suspicious indicators
            guarddog_suspicious = self._detect_guarddog_metadata_suspicious(author_pkgs)
            results['guarddog_metadata_suspicious'] += len(guarddog_suspicious)
            suspicious_packages.extend(guarddog_suspicious)
            
            if guarddog_suspicious:
                logger.info(f"🛡️ GuardDog metadata analysis identified {len(guarddog_suspicious)} additional suspicious PyPI packages for {author}")
            
            # Check for suspicious author patterns
            if self._is_suspicious_author(author, author_pkgs):
                results['suspicious_authors'] += 1
        
        # Run GuardDog static analysis on suspicious packages
        if enhanced_guarddog_service.available and suspicious_packages:
            # Remove duplicates
            unique_suspicious = list({pkg.name: pkg for pkg in suspicious_packages}.values())
            
            logger.info(f"🛡️ Running GuardDog static analysis on {len(unique_suspicious)} suspicious PyPI packages")
            guarddog_analyses = enhanced_guarddog_service.analyze_package_code_with_diff(unique_suspicious)
            
            for analysis in guarddog_analyses:
                database.add_guarddog_analysis(analysis)
                
                # Log high-risk findings
                if analysis.risk_score >= 0.7:
                    logger.warning(f"🚨 High-risk GuardDog findings for {analysis.package_name}@{analysis.version} (score: {analysis.risk_score:.2f})")
        
        return results
    
    def _is_test_package(self, package_name: str) -> bool:
        """Check if a package appears to be a test package."""
        return any(pattern in package_name for pattern in self.test_package_patterns)
    
    def _is_suspicious_version(self, version: str) -> bool:
        """Check if version string looks suspicious."""
        if not version:
            return False
        
        # Look for obviously fake versions
        suspicious_patterns = ['0.0.0', '1.0.0', '0.1.0', '999.999.999']
        return version in suspicious_patterns
    
    def _has_recent_data(self, package_name: str) -> bool:
        """Check if we already have recent data for a package."""
        # This could be enhanced to check the actual database
        # For now, return False to process all packages
        return False
    
    def _is_automated_author(self, author: str) -> bool:
        """Check if an author appears to be an automated service."""
        if not author or author.lower() in self.excluded_authors:
            return True
        
        # Check for bot patterns
        bot_patterns = ['bot', 'ci', 'auto', 'deploy', 'publish', 'release', 'automated']
        author_lower = author.lower()
        
        return any(pattern in author_lower for pattern in bot_patterns)
    
    def _detect_pypi_typosquatting(self, packages: List[PackageVersion]) -> List[PackageVersion]:
        """Detect potential typosquatting attempts against popular PyPI packages."""
        suspicious_packages = []
        
        # Popular PyPI packages to check against
        popular_packages = [
            'numpy', 'pandas', 'requests', 'django', 'flask', 'tensorflow',
            'pytorch', 'scikit-learn', 'matplotlib', 'pillow', 'click',
            'sqlalchemy', 'boto3', 'pyyaml', 'jinja2', 'werkzeug',
            'setuptools', 'pip', 'wheel', 'pytest', 'black', 'flake8'
        ]
        
        for pkg in packages:
            name_lower = pkg.name.lower()
            
            for popular in popular_packages:
                # Check for various typosquatting patterns
                if (self._is_similar_name(name_lower, popular) and 
                    name_lower != popular):
                    suspicious_packages.append(pkg)
                    logger.warning(f"   🎯 Potential PyPI typosquatting: {pkg.name} (similar to {popular})")
                    break
                
                # Check for common substitutions
                if self._check_character_substitution(name_lower, popular):
                    suspicious_packages.append(pkg)
                    logger.warning(f"   🎯 Potential character substitution: {pkg.name} (similar to {popular})")
                    break
        
        return suspicious_packages
    
    def _is_similar_name(self, name1: str, name2: str) -> bool:
        """Check if two package names are suspiciously similar."""
        if abs(len(name1) - len(name2)) > 2:
            return False
        
        # Simple edit distance check
        if len(name1) == len(name2):
            differences = sum(c1 != c2 for c1, c2 in zip(name1, name2))
            return differences == 1  # Only one character different
        
        # Check for single character insertion/deletion
        if abs(len(name1) - len(name2)) == 1:
            shorter, longer = (name1, name2) if len(name1) < len(name2) else (name2, name1)
            for i in range(len(longer)):
                if longer[:i] + longer[i+1:] == shorter:
                    return True
        
        return False
    
    def _check_character_substitution(self, name1: str, name2: str) -> bool:
        """Check for common character substitutions (0/o, 1/l, etc.)."""
        if len(name1) != len(name2):
            return False
        
        substitutions = {
            '0': 'o', 'o': '0',
            '1': 'l', 'l': '1', 'i': '1',
            '5': 's', 's': '5',
            'u': 'v', 'v': 'u',
            'r': 'n', 'n': 'r'
        }
        
        differences = 0
        for c1, c2 in zip(name1, name2):
            if c1 != c2:
                if substitutions.get(c1) != c2 and substitutions.get(c2) != c1:
                    return False
                differences += 1
                
        return differences == 1
    
    def _detect_suspicious_keywords(self, packages: List[PackageVersion]) -> List[PackageVersion]:
        """Detect suspicious keywords in package descriptions."""
        suspicious_keywords = [
            'bitcoin', 'crypto', 'wallet', 'mining', 'password', 'credential',
            'steal', 'hack', 'exploit', 'backdoor', 'malware', 'virus',
            'keylogger', 'trojan', 'ransomware', 'phishing'
        ]
        
        suspicious_packages = []
        
        for pkg in packages:
            if not pkg.description:
                continue
                
            desc_lower = pkg.description.lower()
            found_keywords = [kw for kw in suspicious_keywords if kw in desc_lower]
            
            if found_keywords:
                suspicious_packages.append(pkg)
                logger.warning(f"   🚨 Suspicious keywords in {pkg.name}: {found_keywords}")
        
        return suspicious_packages
        return suspicious_count
    
    def _detect_size_anomalies(self, packages: List[PackageVersion]) -> List[PackageVersion]:
        """Detect packages with unusual size characteristics."""
        anomaly_packages = []
        
        for pkg in packages:
            # PyPI packages often don't have unpack_size, so check download_size if available
            size_to_check = pkg.unpack_size or getattr(pkg, 'download_size', None)
            
            if not size_to_check:
                continue
            
            # Flag packages that are unusually large
            if size_to_check > 100_000_000:  # > 100MB
                anomaly_packages.append(pkg)
                logger.warning(f"   📏 Large PyPI package: {pkg.name} ({size_to_check:,} bytes)")
        
        return anomaly_packages
    
    def _is_suspicious_author(self, author: str, packages: List[PackageVersion]) -> bool:
        """Check if an author exhibits suspicious patterns."""
        if not author or len(packages) < 2:
            return False
        
        # Check for rapid publishing pattern
        if len(packages) > 10:  # More than 10 packages in short time
            logger.warning(f"   👤 High-velocity author: {author} ({len(packages)} packages)")
            return True
        
        # Check for generic/suspicious author names
        suspicious_patterns = ['user', 'test', 'admin', 'owner', 'publisher', 'bot']
        if any(pattern in author.lower() for pattern in suspicious_patterns):
            return True
        
        return False
    
    def _detect_guarddog_metadata_suspicious(self, packages: List[PackageVersion]) -> List[PackageVersion]:
        """Detect suspicious packages using GuardDog metadata analysis."""
        suspicious_packages = []
        
        if not enhanced_guarddog_service or not enhanced_guarddog_service.available:
            return suspicious_packages
        
        for pkg in packages:
            try:
                # Get existing GuardDog metadata analysis (already stored in database)
                analysis = database.get_guarddog_analysis(pkg.name, pkg.version, PackageEcosystem.PYPI)
                
                if analysis and analysis.risk_score >= 0.4:  # Threshold for suspicious
                    suspicious_packages.append(pkg)
                    logger.warning(f"   🛡️ GuardDog metadata flagged: {pkg.name}@{pkg.version} (risk: {analysis.risk_score:.2f})")
                    
            except Exception as e:
                logger.debug(f"Error checking GuardDog analysis for {pkg.name}@{pkg.version}: {e}")
                continue
        
        return suspicious_packages
    
    def run_full_scan_cycle(self) -> ScanningSession:
        """Run a complete PyPI scanning cycle with all analysis phases."""
        session = self.start_scanning_session()
        
        try:
            logger.info("🚀 Starting PyPI scan cycle")
            
            # Phase 1: Package Discovery from RSS feed
            packages = self.discover_packages(config.CHANGES_FEED_LIMIT)
            
            # Phase 2: Filtering
            filtered_packages = self.filter_packages(packages)
            
            # Phase 3: Package Processing
            processed_packages = []
            early_stop_count = 0
            
            for i, package_data in enumerate(filtered_packages):
                if config.EARLY_STOPPING_ENABLED and early_stop_count >= config.EARLY_STOPPING_THRESHOLD:
                    logger.info(f"   🛑 Early stopping after {i} packages (no new data in last {config.EARLY_STOPPING_THRESHOLD})")
                    break
                
                result = self.process_package(package_data)
                if result:
                    processed_packages.append(result)
                    early_stop_count = 0  # Reset counter
                else:
                    early_stop_count += 1
                
                if session:
                    session.packages_processed = len(processed_packages)
                    session.packages_skipped = i + 1 - len(processed_packages)
            
            logger.info(f"   📦 Processed {len(processed_packages)} PyPI packages")
            
            # Phase 4: Velocity Analysis
            velocity_patterns = self.run_velocity_analysis()
            
            # Phase 5: Enhanced Detection
            enhanced_results = self.run_enhanced_detection(processed_packages)
            
            # Generate summary
            stats = database.get_stats(PackageEcosystem.PYPI)
            logger.info(f"📊 PYPI SCAN SUMMARY:")
            logger.info(f"   Total packages in database: {stats['unique_packages']:,}")
            logger.info(f"   Total versions: {stats['total_versions']:,}")
            logger.info(f"   Unique authors: {stats['unique_authors']:,}")
            logger.info(f"   Suspicious patterns found: {len(velocity_patterns)}")
            logger.info(f"   Typosquatting attempts: {enhanced_results.get('typosquatting_attempts', 0)}")
            
        except Exception as e:
            logger.error(f"Error during PyPI scan cycle: {e}")
            if session:
                session.errors_encountered += 1
        finally:
            session = self.complete_scanning_session()
        
        return session


# Global PyPI scanner instance
pypi_scanner = PyPIScanner()
