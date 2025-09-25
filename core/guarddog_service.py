"""
GuardDog integration service for the multi-ecosystem scanner.

This service provides both metadata analysis and static code analysis
using GuardDog for NPM and PyPI packages.
"""
import logging
import os
import tempfile
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone

from core.models import PackageVersion, PackageEcosystem, GuardDogAnalysis, SecurityFinding, RiskLevel
from core.config import config

logger = logging.getLogger(__name__)

try:
    import guarddog
    from guarddog.analyzers.metadata import get_metadata_detectors
    from guarddog.scanners.pypi_package_scanner import PyPIPackageScanner
    from guarddog.scanners.npm_package_scanner import NPMPackageScanner
    GUARDDOG_AVAILABLE = True
    logger.info("🛡️ GuardDog integration enabled")
except ImportError as e:
    GUARDDOG_AVAILABLE = False
    logger.warning(f"⚠️ GuardDog not available: {e}")


class GuardDogService:
    """Service for GuardDog integration."""
    
    def __init__(self):
        self.available = GUARDDOG_AVAILABLE
        if self.available:
            self._setup_scanners()
    
    def _setup_scanners(self):
        """Initialize GuardDog scanners."""
        try:
            self.npm_scanner = NPMPackageScanner()
            self.pypi_scanner = PyPIPackageScanner()
            self.metadata_detectors = get_metadata_detectors()
            logger.debug("GuardDog scanners initialized")
        except Exception as e:
            logger.error(f"Failed to initialize GuardDog scanners: {e}")
            self.available = False
    
    def analyze_package_metadata(self, package: PackageVersion) -> Optional[GuardDogAnalysis]:
        """
        Analyze package metadata using GuardDog.
        This should be run for ALL packages we process.
        """
        if not self.available:
            return None
        
        try:
            # Select appropriate scanner based on ecosystem
            if package.ecosystem == PackageEcosystem.NPM:
                scanner = self.npm_scanner
            elif package.ecosystem == PackageEcosystem.PYPI:
                scanner = self.pypi_scanner
            else:
                return None
            
            # Prepare package metadata for GuardDog
            metadata = self._package_to_guarddog_metadata(package)
            
            # Run metadata detectors
            findings = []
            risk_score = 0.0
            
            for detector in self.metadata_detectors:
                try:
                    if detector.match(metadata):
                        findings.append({
                            'detector': detector.__class__.__name__,
                            'description': detector.description,
                            'severity': self._determine_severity(detector),
                            'message': f"Metadata detection: {detector.description}"
                        })
                        # Accumulate risk score
                        risk_score += self._get_detector_score(detector)
                except Exception as e:
                    logger.debug(f"Detector {detector.__class__.__name__} failed: {e}")
                    continue
            
            # Normalize risk score
            risk_score = min(risk_score, 1.0)
            
            return GuardDogAnalysis(
                package_name=package.name,
                version=package.version,
                ecosystem=package.ecosystem,
                analysis_type="metadata",
                risk_score=risk_score,
                findings=findings,
                analysis_timestamp=datetime.now(timezone.utc),
                guarddog_version=getattr(guarddog, '__version__', 'unknown')
            )
            
        except Exception as e:
            logger.error(f"GuardDog metadata analysis failed for {package.name}@{package.version}: {e}")
            return None
    
    def analyze_package_code(self, packages: List[PackageVersion]) -> List[GuardDogAnalysis]:
        """
        Perform static code analysis on suspicious packages.
        This is more resource-intensive and should only be used for suspicious findings.
        """
        if not self.available:
            return []
        
        analyses = []
        
        for package in packages:
            try:
                analysis = self._analyze_single_package_code(package)
                if analysis:
                    analyses.append(analysis)
            except Exception as e:
                logger.error(f"Code analysis failed for {package.name}@{package.version}: {e}")
                continue
        
        return analyses
    
    def _analyze_single_package_code(self, package: PackageVersion) -> Optional[GuardDogAnalysis]:
        """Analyze a single package's code using GuardDog."""
        try:
            # Create temporary directory for package download
            with tempfile.TemporaryDirectory() as temp_dir:
                # Download and analyze package
                if package.ecosystem == PackageEcosystem.NPM:
                    results = self._analyze_npm_package_code(package, temp_dir)
                elif package.ecosystem == PackageEcosystem.PYPI:
                    results = self._analyze_pypi_package_code(package, temp_dir)
                else:
                    return None
                
                # Convert results to our format
                findings = []
                risk_score = 0.0
                
                if results:
                    for result in results.get('detections', []):
                        findings.append({
                            'detector': result.get('detector', 'unknown'),
                            'description': result.get('description', ''),
                            'severity': result.get('severity', 'medium'),
                            'message': result.get('message', ''),
                            'file_path': result.get('file_path', ''),
                            'line_number': result.get('line_number', 0)
                        })
                        risk_score += self._calculate_finding_score(result)
                
                # Normalize risk score
                risk_score = min(risk_score / max(len(findings), 1), 1.0)
                
                return GuardDogAnalysis(
                    package_name=package.name,
                    version=package.version,
                    ecosystem=package.ecosystem,
                    analysis_type="static_analysis",
                    risk_score=risk_score,
                    findings=findings,
                    analysis_timestamp=datetime.now(timezone.utc),
                    guarddog_version=getattr(guarddog, '__version__', 'unknown')
                )
                
        except Exception as e:
            logger.error(f"Static analysis failed for {package.name}@{package.version}: {e}")
            return None
    
    def _analyze_npm_package_code(self, package: PackageVersion, temp_dir: str) -> Optional[Dict]:
        """Analyze NPM package code."""
        # This would involve downloading the package and running GuardDog's code analysis
        # Implementation depends on GuardDog's API
        logger.debug(f"Static NPM analysis for {package.name}@{package.version} not yet implemented")
        return None
    
    def _analyze_pypi_package_code(self, package: PackageVersion, temp_dir: str) -> Optional[Dict]:
        """Analyze PyPI package code."""
        # This would involve downloading the package and running GuardDog's code analysis
        # Implementation depends on GuardDog's API
        logger.debug(f"Static PyPI analysis for {package.name}@{package.version} not yet implemented")
        return None
    
    def _package_to_guarddog_metadata(self, package: PackageVersion) -> Dict[str, Any]:
        """Convert PackageVersion to GuardDog metadata format."""
        metadata = {
            'name': package.name,
            'version': package.version,
            'author': package.author,
            'author_email': package.author_email,
            'description': package.description,
            'homepage': package.homepage,
            'repository': package.repository_url,
            'keywords': package.keywords.split(',') if package.keywords else [],
            'license': package.license,
            'dependencies': package.dependencies or {},
            'dev_dependencies': package.dev_dependencies or {},
            'maintainers': package.maintainers.split(',') if package.maintainers else [],
            'published_at': package.published_at.isoformat() if package.published_at else None,
            'file_count': package.file_count,
            'unpack_size': package.unpack_size,
            'tarball_size': package.tarball_size
        }
        
        # Add ecosystem-specific fields
        if package.ecosystem == PackageEcosystem.NPM:
            metadata.update({
                'dist_tags': package.dist_tags or {},
                'shasum': package.shasum,
                'integrity': package.integrity
            })
        
        return metadata
    
    def _determine_severity(self, detector) -> str:
        """Determine severity based on detector type."""
        detector_name = detector.__class__.__name__.lower()
        
        if any(word in detector_name for word in ['typosquat', 'stealer', 'backdoor', 'malware']):
            return 'high'
        elif any(word in detector_name for word in ['suspicious', 'empty', 'obfuscat']):
            return 'medium'
        else:
            return 'low'
    
    def _get_detector_score(self, detector) -> float:
        """Get risk score contribution for detector."""
        severity = self._determine_severity(detector)
        
        score_map = {
            'high': 0.8,
            'medium': 0.4,
            'low': 0.2
        }
        
        return score_map.get(severity, 0.2)
    
    def _calculate_finding_score(self, result: Dict) -> float:
        """Calculate risk score for a finding."""
        severity = result.get('severity', 'medium')
        
        score_map = {
            'critical': 1.0,
            'high': 0.8,
            'medium': 0.4,
            'low': 0.2,
            'info': 0.1
        }
        
        return score_map.get(severity.lower(), 0.4)


# Global service instance
guarddog_service = GuardDogService()
