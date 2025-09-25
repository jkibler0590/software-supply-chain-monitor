"""
Base classes for ecosystem-specific scanners.

This module provides abstract base classes that define the common interface
for all package ecosystem scanners (NPM, PyPI, etc.).
"""
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Set
from datetime import datetime, timedelta

from core.models import (
    PackageVersion, VelocityPattern, ThreatDetectionResult,
    ScanningSession, PackageEcosystem, SecurityFinding, RiskLevel
)
from core.config import config


class BasePackageClient(ABC):
    """Abstract base class for package registry API clients."""
    
    def __init__(self, ecosystem: PackageEcosystem):
        self.ecosystem = ecosystem
        self.session_stats = {}
    
    @abstractmethod
    def get_recent_changes(self, limit: int = 1000, since: Optional[str] = None) -> Dict[str, Any]:
        """Get recent package changes from the registry."""
        pass
    
    @abstractmethod  
    def get_package_info(self, package_name: str) -> Dict[str, Any]:
        """Get detailed information about a package."""
        pass
    
    @abstractmethod
    def get_package_version_info(self, package_name: str, version: str) -> Dict[str, Any]:
        """Get information about a specific package version."""
        pass
    
    @abstractmethod
    def download_package(self, package_name: str, version: str, destination: str) -> Optional[str]:
        """Download a package to the specified destination."""
        pass
    
    @abstractmethod
    def parse_package_data(self, raw_data: Dict[str, Any]) -> PackageVersion:
        """Parse raw package data into a PackageVersion object."""
        pass


class BaseScanner(ABC):
    """Abstract base class for ecosystem-specific scanners."""
    
    def __init__(self, ecosystem: PackageEcosystem, client: BasePackageClient):
        self.ecosystem = ecosystem
        self.client = client
        self.current_session: Optional[ScanningSession] = None
        
    def start_scanning_session(self) -> ScanningSession:
        """Start a new scanning session."""
        self.current_session = ScanningSession(
            ecosystem=self.ecosystem,
            started_at=datetime.now(),
            early_stopping_enabled=config.EARLY_STOPPING_ENABLED
        )
        return self.current_session
    
    def complete_scanning_session(self) -> ScanningSession:
        """Complete the current scanning session."""
        if self.current_session:
            self.current_session.completed_at = datetime.now()
        return self.current_session
    
    @abstractmethod
    def discover_packages(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """Discover recent packages for analysis."""
        pass
    
    @abstractmethod
    def filter_packages(self, packages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter packages to reduce processing load.""" 
        pass
    
    @abstractmethod
    def process_package(self, package_data: Dict[str, Any]) -> Optional[PackageVersion]:
        """Process a single package and store in database."""
        pass
    
    def analyze_author_patterns(self, author_activities: Dict[str, List[PackageVersion]]) -> List[VelocityPattern]:
        """Analyze author activities for suspicious patterns.""" 
        patterns = []
        
        for author, packages in author_activities.items():
            # Remove duplicate package names - only consider unique packages per author
            unique_packages_dict = {}
            for pkg in packages:
                # Keep the most recent version of each package
                if pkg.name not in unique_packages_dict or pkg.published_at > unique_packages_dict[pkg.name].published_at:
                    unique_packages_dict[pkg.name] = pkg
            
            unique_packages = list(unique_packages_dict.values())
            
            if len(unique_packages) < config.MIN_PACKAGES_FOR_ALERT:
                continue
                
            # Calculate diversity score on unique packages only
            diversity_score = self._calculate_diversity_score(unique_packages)
            
            if diversity_score >= config.MIN_DIVERSITY_SCORE:
                pattern = VelocityPattern(
                    author=author,
                    packages=unique_packages,  # Use unique packages only
                    diversity_score=diversity_score,
                    time_window=config.VELOCITY_WINDOW_MINUTES,  # Use minutes for velocity detection
                    pattern_type="velocity_attack",
                    ecosystem=self.ecosystem,
                    detected_at=datetime.now(),
                    risk_level=self._assess_velocity_risk_level(diversity_score, len(unique_packages))
                )
                patterns.append(pattern)
        
        return patterns
    
    def _calculate_diversity_score(self, packages: List[PackageVersion]) -> float:
        """Calculate diversity score using sophisticated similarity analysis."""
        if not packages or len(packages) <= 1:
            return 0.0
            
        # Extract package names for analysis
        package_names = [pkg.name for pkg in packages]
        unique_packages = list(set(package_names))
        
        if len(unique_packages) <= 1:
            return 0.0
            
        import difflib
        from collections import Counter
        import re
        import os
        
        total_packages = len(unique_packages)
        
        # 1. String similarity analysis
        similarity_scores = []
        for i in range(len(unique_packages)):
            for j in range(i + 1, len(unique_packages)):
                pkg1, pkg2 = unique_packages[i], unique_packages[j]
                
                # Calculate multiple similarity metrics
                seq_similarity = difflib.SequenceMatcher(None, pkg1.lower(), pkg2.lower()).ratio()
                
                # Prefix similarity (weighted by length)
                common_prefix_len = len(os.path.commonprefix([pkg1.lower(), pkg2.lower()]))
                prefix_similarity = (common_prefix_len / max(len(pkg1), len(pkg2))) if max(len(pkg1), len(pkg2)) > 0 else 0
                
                # Suffix similarity
                common_suffix_len = len(os.path.commonprefix([pkg1.lower()[::-1], pkg2.lower()[::-1]]))
                suffix_similarity = (common_suffix_len / max(len(pkg1), len(pkg2))) if max(len(pkg1), len(pkg2)) > 0 else 0
                
                # Token overlap (split on common separators)
                tokens1 = set(re.split(r'[-._@/]', pkg1.lower()))
                tokens2 = set(re.split(r'[-._@/]', pkg2.lower()))
                token_overlap = len(tokens1 & tokens2) / len(tokens1 | tokens2) if len(tokens1 | tokens2) > 0 else 0
                
                # Combined similarity (weighted average)
                combined_similarity = (
                    seq_similarity * 0.3 +
                    prefix_similarity * 0.3 +
                    suffix_similarity * 0.2 +
                    token_overlap * 0.2
                )
                
                similarity_scores.append(combined_similarity)
        
        # 2. Dynamic clustering based on similarity threshold
        # Find groups of similar packages
        similarity_matrix = {}
        idx = 0
        for i in range(len(unique_packages)):
            for j in range(i + 1, len(unique_packages)):
                similarity_matrix[(i, j)] = similarity_scores[idx]
                idx += 1
        
        # Simple clustering: packages are in same group if similarity > threshold
        similarity_threshold = 0.4  # Dynamic threshold based on data
        clusters = []
        assigned = set()
        
        for i, pkg in enumerate(unique_packages):
            if i in assigned:
                continue
                
            cluster = {i}
            for j in range(len(unique_packages)):
                if j != i and j not in assigned:
                    sim_key = (min(i, j), max(i, j))
                    if sim_key in similarity_matrix and similarity_matrix[sim_key] > similarity_threshold:
                        cluster.add(j)
            
            if len(cluster) > 1:
                assigned.update(cluster)
                clusters.append(cluster)
        
        # Count isolated packages (not in any cluster)
        isolated_packages = total_packages - len(assigned)
        
        # 3. Semantic analysis - extract common patterns dynamically
        all_tokens = []
        for pkg in unique_packages:
            tokens = re.split(r'[-._@/]', pkg.lower())
            all_tokens.extend([t for t in tokens if len(t) > 1])  # Filter short tokens
        
        token_frequency = Counter(all_tokens)
        common_tokens = {token for token, count in token_frequency.items() if count > 1}
        
        # Calculate semantic diversity based on shared tokens
        packages_with_common_tokens = 0
        for pkg in unique_packages:
            pkg_tokens = set(re.split(r'[-._@/]', pkg.lower()))
            if pkg_tokens & common_tokens:
                packages_with_common_tokens += 1
        
        semantic_diversity = 1 - (packages_with_common_tokens / total_packages)
        
        # 4. Structural diversity (scoping patterns, length variation, etc.)
        scoped_count = sum(1 for pkg in unique_packages if pkg.startswith('@'))
        dotted_count = sum(1 for pkg in unique_packages if '.' in pkg and not pkg.startswith('@'))
        hyphenated_count = sum(1 for pkg in unique_packages if '-' in pkg)
        
        structural_diversity = len(set([
            'scoped' if scoped_count > 0 else None,
            'dotted' if dotted_count > 0 else None,
            'hyphenated' if hyphenated_count > 0 else None,
            'simple' if (total_packages - scoped_count - dotted_count - hyphenated_count) > 0 else None
        ]) - {None}) / 4  # Normalize by max possible structural types
        
        # 5. Calculate final diversity score
        cluster_diversity = (len(clusters) + isolated_packages) / total_packages
        
        # If all packages are isolated (no clusters), it's highly diverse
        if isolated_packages == total_packages:
            cluster_diversity = 1.0
        
        # 6. Time clustering analysis
        time_clustering_score = self._calculate_time_clustering(packages)
        
        # 7. Combine all metrics with weights
        # Higher weights on clustering and semantic analysis as they're most reliable
        final_score = (
            cluster_diversity * 0.4 +        # Primary indicator: package name clustering
            semantic_diversity * 0.3 +       # Secondary: semantic token analysis  
            structural_diversity * 0.2 +     # Supporting: structural patterns
            time_clustering_score * 0.1      # Supporting: publication timing
        )
        
        return min(final_score, 1.0)
    
    def _calculate_time_clustering(self, packages: List[PackageVersion]) -> float:
        """Calculate time clustering score (higher = more suspicious)."""
        if len(packages) < 2:
            return 0.0
            
        timestamps = [pkg.published_at for pkg in packages if pkg.published_at]
        if len(timestamps) < 2:
            return 0.0
            
        # Calculate average time difference between packages
        timestamps.sort()
        time_diffs = []
        for i in range(1, len(timestamps)):
            diff = (timestamps[i] - timestamps[i-1]).total_seconds() / 3600  # hours
            time_diffs.append(diff)
        
        avg_time_diff = sum(time_diffs) / len(time_diffs)
        
        # Score inversely proportional to time difference (closer = more suspicious)
        if avg_time_diff < 1:  # Less than 1 hour average
            return 0.9
        elif avg_time_diff < 6:  # Less than 6 hours average
            return 0.7
        elif avg_time_diff < 24:  # Less than 1 day average
            return 0.4
        else:
            return 0.1
    
    def _calculate_size_variation(self, sizes: List[int]) -> float:
        """Calculate size variation score."""
        if len(sizes) < 2:
            return 0.0
            
        mean_size = sum(sizes) / len(sizes)
        if mean_size == 0:
            return 0.0
            
        # Calculate coefficient of variation
        variance = sum((size - mean_size) ** 2 for size in sizes) / len(sizes)
        std_dev = variance ** 0.5
        cv = std_dev / mean_size
        
        # Normalize to 0-1 range (high variation is suspicious)
        return min(cv, 1.0)
    
    def _assess_velocity_risk_level(self, diversity_score: float, package_count: int):
        """Assess risk level based on velocity pattern characteristics."""
        
        if diversity_score >= 0.8 or package_count >= 10:
            return RiskLevel.CRITICAL
        elif diversity_score >= 0.7 or package_count >= 7:
            return RiskLevel.HIGH
        elif diversity_score >= 0.6 or package_count >= 5:
            return RiskLevel.MEDIUM
        elif diversity_score >= 0.5 or package_count >= 3:
            return RiskLevel.LOW
        else:
            return RiskLevel.CLEAN
            return RiskLevel.CLEAN
    
    def run_scan_cycle(self) -> ScanningSession:
        """Run a complete scan cycle."""
        session = self.start_scanning_session()
        
        try:
            # Discover packages
            packages = self.discover_packages(config.CHANGES_FEED_LIMIT)
            session.packages_discovered = len(packages)
            
            # Filter packages
            filtered_packages = self.filter_packages(packages)
            
            # Process packages
            processed_count = 0
            skipped_count = 0
            errors = 0
            
            for package_data in filtered_packages:
                try:
                    result = self.process_package(package_data)
                    if result:
                        processed_count += 1
                    else:
                        skipped_count += 1
                except Exception as e:
                    errors += 1
                    continue
            
            session.packages_processed = processed_count
            session.packages_skipped = skipped_count  
            session.errors_encountered = errors
            
        finally:
            self.complete_scanning_session()
        
        return session
