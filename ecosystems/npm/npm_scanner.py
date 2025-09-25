"""
NPM-specific scanner implementation.

This module implements the NPM package scanner using the base scanner architecture,
providing NPM registry integration, package processing, and threat detection.
"""
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Set
from collections import defaultdict

from core.config import config
from core.database import database
from core.enhanced_guarddog_service import enhanced_guarddog_service
from core.models import PackageVersion, PackageEcosystem, VelocityPattern, ScanningSession
from ecosystems.common.base_scanner import BaseScanner
from ecosystems.npm.npm_client import NPMClient
from notifications.slack_alerts import slack_manager

logger = logging.getLogger(__name__)


class NPMScanner(BaseScanner):
    """NPM package ecosystem scanner."""
    
    def __init__(self):
        """Initialize NPM scanner with NPM client."""
        client = NPMClient()
        super().__init__(PackageEcosystem.NPM, client)
        
        # NPM-specific configuration
        self.excluded_authors = {
            'npm-bot', 'greenkeeper[bot]', 'renovate[bot]', 'dependabot[bot]',
            'snyk-bot', 'semantic-release-bot', 'github-actions[bot]',
            'npm-publisher', 'jenkins', 'travis-ci', 'circleci', 'gitlab-ci',
            'azure-devops', 'teamcity', 'bamboo', 'drone', 'codeship'
        }
    
    def discover_packages(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """Discover recent NPM packages from changes feed."""
        try:
            logger.info(f"📡 Fetching NPM package changes (limit: {limit})...")
            
            changes_data = self.client.get_recent_changes(limit=limit)
            
            if not changes_data or 'results' not in changes_data:
                logger.warning("No package changes found in NPM feed")
                return []
            
            packages = []
            for change in changes_data['results']:
                if 'id' in change and not change['id'].startswith('_'):
                    packages.append({'name': change['id']})
            
            logger.info(f"   📊 Successfully discovered {len(packages)} packages")
            
            if self.current_session:
                self.current_session.packages_discovered = len(packages)
            
            return packages
            
        except Exception as e:
            logger.error(f"Error discovering NPM packages: {e}")
            return []
    
    def filter_packages(self, packages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter packages to reduce API calls and processing load."""
        if not packages:
            return []
        
        logger.info(f"🔍 Pre-filtering {len(packages)} packages to reduce API calls...")
        
        filtered_packages = []
        api_calls_saved = 0
        
        for package in packages:
            package_name = package.get('name', '')
            
            # Skip packages that are clearly automated or system packages
            if self._should_skip_package(package_name):
                api_calls_saved += 1
                continue
            
            # Check if we already have recent data for this package
            if self._has_recent_data(package_name):
                api_calls_saved += 1
                continue
            
            filtered_packages.append(package)
        
        logger.info(f"   ⚡ Pre-filtering saved {api_calls_saved} API calls ({(api_calls_saved/len(packages)*100):.1f}% reduction)")
        
        return filtered_packages
    
    def process_package(self, package_data: Dict[str, Any]) -> Optional[PackageVersion]:
        """Process a single NPM package and extract recent versions."""
        package_name = package_data.get('name', '')
        
        if not package_name:
            return None
        
        try:
            # Get full package information
            full_package_data = self.client.get_package_info(package_name)
            
            if not full_package_data:
                return None
            
            # Extract recent versions (last 24 hours)
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
            logger.error(f"Error processing NPM package {package_name}: {e}")
            if self.current_session:
                self.current_session.errors_encountered += 1
            return None
    
    def run_velocity_analysis(self) -> List[VelocityPattern]:
        """Run velocity-based threat detection analysis."""
        logger.info("🔍 Starting NPM velocity pattern analysis...")
        
        # Get recent author activities within velocity detection window (15 minutes)
        author_activities = database.get_velocity_window_activities(
            ecosystem=PackageEcosystem.NPM,
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
                    PackageEcosystem.NPM, 
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
        """Run enhanced detection algorithms on processed packages."""
        if not packages:
            return {}
        
        logger.info("🛡️  Running NPM enhanced detection analysis...")
        
        # Analyze packages for various threat indicators
        results = {
            'typosquatting_attempts': 0,
            'account_takeover_candidates': 0,
            'suspicious_keywords': 0,
            'size_anomalies': 0,
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
            
            # Check for typosquatting
            typosquat_packages = self._detect_typosquatting(author_pkgs)
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
                logger.info(f"🛡️ GuardDog metadata analysis identified {len(guarddog_suspicious)} additional suspicious packages for {author}")
        
        # Run GuardDog static analysis on suspicious packages
        if enhanced_guarddog_service.available and suspicious_packages:
            # Remove duplicates
            unique_suspicious = list({pkg.name: pkg for pkg in suspicious_packages}.values())
            
            logger.info(f"🛡️ Running GuardDog static analysis on {len(unique_suspicious)} suspicious packages")
            guarddog_analyses = enhanced_guarddog_service.analyze_package_code_with_diff(unique_suspicious)
            
            for analysis in guarddog_analyses:
                database.add_guarddog_analysis(analysis)
                
                # Log high-risk findings
                if analysis.risk_score >= 0.7:
                    logger.warning(f"🚨 High-risk GuardDog findings for {analysis.package_name}@{analysis.version} (score: {analysis.risk_score:.2f})")
        
        return results
    
    def _should_skip_package(self, package_name: str) -> bool:
        """Check if a package should be skipped during filtering."""
        skip_patterns = [
            '@types/', '@babel/', '@angular/', '@react/',
            'eslint-', 'babel-', 'webpack-', 'rollup-'
        ]
        
        return any(pattern in package_name for pattern in skip_patterns)
    
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
        bot_patterns = ['bot', 'ci', 'auto', 'deploy', 'publish', 'release']
        author_lower = author.lower()
        
        return any(pattern in author_lower for pattern in bot_patterns)
    
    def _detect_typosquatting(self, packages: List[PackageVersion]) -> List[PackageVersion]:
        """Detect potential typosquatting attempts."""
        # This is a simplified implementation
        # In production, you'd want more sophisticated similarity matching
        suspicious_packages = []
        
        for pkg in packages:
            # Check for common typosquatting patterns
            name_lower = pkg.name.lower()
            
            # Popular package names to check against
            popular_packages = [
                'react', 'angular', 'vue', 'express', 'lodash',
                'moment', 'axios', 'webpack', 'babel', 'eslint'
            ]
            
            for popular in popular_packages:
                # Simple character substitution detection
                if (self._is_similar_name(name_lower, popular) and 
                    name_lower != popular):
                    suspicious_packages.append(pkg)
                    logger.warning(f"   🎯 Potential typosquatting: {pkg.name} (similar to {popular})")
                    break
        
        return suspicious_packages
    
    def _is_similar_name(self, name1: str, name2: str) -> bool:
        """Check if two package names are suspiciously similar."""
        # Simple Levenshtein-like check
        if len(name1) != len(name2):
            return False
        
        differences = sum(c1 != c2 for c1, c2 in zip(name1, name2))
        return differences == 1  # Only one character different
    
    def _detect_suspicious_keywords(self, packages: List[PackageVersion]) -> List[PackageVersion]:
        """Detect suspicious keywords in package descriptions."""
        suspicious_keywords = [
            'bitcoin', 'crypto', 'wallet', 'mining', 'password',
            'steal', 'hack', 'exploit', 'backdoor', 'malware'
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
    
    def _detect_size_anomalies(self, packages: List[PackageVersion]) -> List[PackageVersion]:
        """Detect packages with unusual size characteristics."""
        anomaly_packages = []
        
        for pkg in packages:
            if not pkg.unpack_size:
                continue
            
            # Flag packages that are unusually large for what they claim to do
            if pkg.unpack_size > 50_000_000:  # > 50MB
                anomaly_packages.append(pkg)
                logger.warning(f"   📏 Large package: {pkg.name} ({pkg.unpack_size:,} bytes)")
        
        return anomaly_packages
    
    def _detect_guarddog_metadata_suspicious(self, packages: List[PackageVersion]) -> List[PackageVersion]:
        """Detect suspicious packages using GuardDog metadata analysis."""
        suspicious_packages = []
        
        if not enhanced_guarddog_service or not enhanced_guarddog_service.available:
            return suspicious_packages
        
        for pkg in packages:
            try:
                # Get existing GuardDog metadata analysis (already stored in database)
                analysis = database.get_guarddog_analysis(pkg.name, pkg.version)
                
                if analysis and analysis.risk_score >= 0.4:  # Threshold for suspicious
                    suspicious_packages.append(pkg)
                    logger.warning(f"   🛡️ GuardDog metadata flagged: {pkg.name}@{pkg.version} (risk: {analysis.risk_score:.2f})")
                    
            except Exception as e:
                logger.debug(f"Error checking GuardDog analysis for {pkg.name}@{pkg.version}: {e}")
                continue
        
        return suspicious_packages
    
    def run_full_scan_cycle(self) -> ScanningSession:
        """Run a complete NPM scanning cycle with all analysis phases."""
        session = self.start_scanning_session()
        
        try:
            logger.info("🚀 Starting NPM scan cycle")
            
            # Phase 1: Package Discovery
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
            
            logger.info(f"   📦 Processed {len(processed_packages)} packages")
            
            # Phase 4: Velocity Analysis
            velocity_patterns = self.run_velocity_analysis()
            
            # Phase 5: Enhanced Detection
            enhanced_results = self.run_enhanced_detection(processed_packages)
            
            # Phase 6: Database Cleanup
            cleanup_results = database.cleanup_old_entries(config.HOURS_BACK)
            logger.info(f"🧹 Cleaned up {cleanup_results['packages']} old package entries")
            
            # Generate summary
            stats = database.get_stats(PackageEcosystem.NPM)
            logger.info(f"📊 SCAN SUMMARY:")
            logger.info(f"   Total packages in database: {stats['unique_packages']:,}")
            logger.info(f"   Total versions: {stats['total_versions']:,}")
            logger.info(f"   Unique authors: {stats['unique_authors']:,}")
            logger.info(f"   Suspicious patterns found: {len(velocity_patterns)}")
            
        except Exception as e:
            logger.error(f"Error during NPM scan cycle: {e}")
            if session:
                session.errors_encountered += 1
        finally:
            session = self.complete_scanning_session()
        
        return session


# Global NPM scanner instance
npm_scanner = NPMScanner()
