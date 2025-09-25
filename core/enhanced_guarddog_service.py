"""
Enhanced GuardDog service with custom rule support and diff analysis.

This service integrates our custom security detections through GuardDog's
rule system while adding package version comparison capabilities.
"""
import logging
import os
import tempfile
import json
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timezone
from pathlib import Path

from core.models import PackageVersion, PackageEcosystem, GuardDogAnalysis, SecurityFinding, RiskLevel
from core.config import config

logger = logging.getLogger(__name__)

try:
    import guarddog
    from guarddog.analyzer.analyzer import Analyzer
    from guarddog.scanners.pypi_package_scanner import PyPIPackageScanner
    from guarddog.scanners.npm_package_scanner import NPMPackageScanner
    GUARDDOG_AVAILABLE = True
    logger.info("🛡️ Enhanced GuardDog integration enabled")
except ImportError as e:
    GUARDDOG_AVAILABLE = False
    logger.warning(f"⚠️ GuardDog not available: {e}")


class EnhancedGuardDogService:
    """Enhanced GuardDog service with custom rules and diff analysis."""
    
    def __init__(self):
        self.available = GUARDDOG_AVAILABLE
        if self.available:
            self._setup_analyzers()
            self._setup_custom_rules()
    
    def _setup_analyzers(self):
        """Initialize GuardDog analyzers for different ecosystems."""
        try:
            self.npm_analyzer = Analyzer(ecosystem=guarddog.ecosystems.ECOSYSTEM.NPM)
            self.pypi_analyzer = Analyzer(ecosystem=guarddog.ecosystems.ECOSYSTEM.PYPI)
            
            # Package scanners for tarball downloads
            self.npm_scanner = NPMPackageScanner()
            self.pypi_scanner = PyPIPackageScanner()
            
            logger.debug("Enhanced GuardDog analyzers initialized")
        except Exception as e:
            logger.error(f"Failed to initialize GuardDog analyzers: {e}")
            self.available = False
    
    def _setup_custom_rules(self):
        """Set up our custom detection rules for GuardDog."""
        try:
            # Find GuardDog's sourcecode rules directory
            import guarddog
            guarddog_path = Path(guarddog.__file__).parent
            guarddog_rules_dir = guarddog_path / "analyzer" / "sourcecode"
            
            if not guarddog_rules_dir.exists():
                logger.warning("GuardDog sourcecode directory not found")
                return
            
            # Our custom rules directory
            custom_rules_dir = Path(__file__).parent / "custom_guarddog_rules"
            
            # Copy our custom rules to GuardDog's directory
            self._install_custom_rules_to_guarddog(custom_rules_dir, guarddog_rules_dir)
            
            logger.info("✅ Custom GuardDog rules installed successfully")
        except Exception as e:
            logger.error(f"Failed to setup custom rules: {e}")
    
    def _install_custom_rules_to_guarddog(self, source_dir: Path, target_dir: Path):
        """Install our custom rules to GuardDog's sourcecode directory."""
        try:
            import shutil
            
            # Copy all rule files
            for rule_file in source_dir.glob("*"):
                if rule_file.suffix in ['.yml', '.yar']:
                    target_file = target_dir / rule_file.name
                    # Only copy if it doesn't exist to avoid overwriting GuardDog's rules
                    if not target_file.exists():
                        shutil.copy2(rule_file, target_file)
                        logger.debug(f"Copied custom rule: {rule_file.name}")
        except Exception as e:
            logger.error(f"Failed to install custom rules: {e}")
    
    def _install_npm_custom_rules(self, rules_dir: Path):
        """Install custom Semgrep rules for NPM packages."""
        
        # NPM Install Scripts Detection - Fixed YAML format
        install_scripts_rule = """rules:
  - id: npm-install-scripts
    languages: [json]
    message: Package contains install scripts (preinstall/postinstall)
    metadata:
      description: Detects packages with preinstall or postinstall scripts
      category: security
    patterns:
      - pattern-either:
          - pattern: |
              {
                ...
                "scripts": {
                  ...
                  "preinstall": $SCRIPT,
                  ...
                }
              }
          - pattern: |
              {
                ...
                "scripts": {
                  ...
                  "postinstall": $SCRIPT,
                  ...
                }
              }
          - pattern: |
              {
                ...
                "scripts": {
                  ...
                  "install": $SCRIPT,
                  ...
                }
              }
    severity: WARNING"""
        
        # Network Request Detection  
        network_requests_rule = """rules:
  - id: npm-network-requests
    languages: [javascript, typescript]
    message: Package makes network requests that could be malicious
    metadata:
      description: Detects HTTP requests, downloads, and remote code execution
      category: security
    patterns:
      - pattern-either:
          - pattern: require('http')
          - pattern: require('https')
          - pattern: require('axios')
          - pattern: require('request')
          - pattern: require('node-fetch')
          - pattern: fetch($URL)
          - pattern: axios.get($URL)
          - pattern: axios.post($URL)
          - pattern: request($URL)
          - pattern: http.get($URL)
          - pattern: https.get($URL)
    severity: INFO
  
  - id: npm-code-execution
    languages: [javascript, typescript]  
    message: Package uses potentially dangerous code execution
    metadata:
      description: Detects eval, Function constructor, and child process execution
      category: security
    patterns:
      - pattern-either:
          - pattern: eval($CODE)
          - pattern: Function($CODE)
          - pattern: new Function($CODE)
          - pattern: require('child_process').exec($CMD)
          - pattern: require('child_process').spawn($CMD)
          - pattern: child_process.exec($CMD)
          - pattern: child_process.spawn($CMD)
    severity: WARNING"""
        
        # File System Access
        filesystem_rule = """rules:
  - id: npm-filesystem-access
    languages: [javascript, typescript]
    message: Package accesses sensitive file system locations
    metadata:
      description: Detects access to sensitive files like SSH keys, passwords, etc.
      category: security
    patterns:
      - pattern-either:
          - pattern: fs.readFile("~/.ssh/...", ...)
          - pattern: fs.readFile("~/.aws/...", ...)
          - pattern: fs.readFile("/etc/passwd", ...)
          - pattern: fs.readFileSync("~/.ssh/...")
          - pattern: fs.readFileSync("~/.aws/...")
          - pattern: fs.readFileSync("/etc/passwd")
    severity: WARNING"""
        
        # Write rules to files
        rules = [
            ("npm-install-scripts.yml", install_scripts_rule),
            ("npm-malicious-patterns.yml", network_requests_rule), 
            ("npm-filesystem-access.yml", filesystem_rule)
        ]
        
        for filename, rule_content in rules:
            rule_file = rules_dir / filename
            with open(rule_file, 'w') as f:
                f.write(rule_content)
    
    def _install_python_custom_rules(self, rules_dir: Path):
        """Install custom Semgrep rules for Python packages."""
        
        # Network Requests in Python
        python_network_rule = """rules:
  - id: python-network-requests
    languages: [python]
    message: Python package makes network requests
    metadata:
      description: Detects HTTP requests and remote code execution in Python
      category: security
    patterns:
      - pattern-either:
          - pattern: import requests
          - pattern: import urllib
          - pattern: import http
          - pattern: from requests import $X
          - pattern: from urllib import $X  
          - pattern: requests.get($URL)
          - pattern: requests.post($URL)
          - pattern: urllib.request.urlopen($URL)
    severity: INFO

  - id: python-code-execution
    languages: [python]
    message: Python package uses dangerous code execution
    metadata:
      description: Detects eval, exec, and subprocess execution in Python
      category: security
    patterns:
      - pattern-either:
          - pattern: eval($CODE)
          - pattern: exec($CODE) 
          - pattern: subprocess.call($CMD)
          - pattern: subprocess.run($CMD)
          - pattern: os.system($CMD)
          - pattern: os.popen($CMD)
    severity: WARNING"""
        
        # File System Access
        python_filesystem_rule = """rules:
  - id: python-filesystem-access
    languages: [python]
    message: Python package accesses sensitive files
    metadata:
      description: Detects access to sensitive file locations
      category: security
    patterns:
      - pattern-either:
          - pattern: 'open("~/.ssh/...", ...)'
          - pattern: 'open("~/.aws/...", ...)'
          - pattern: 'open("/etc/passwd", ...)'
          - pattern: "os.environ['HOME']"
    severity: WARNING"""
        
        rules = [
            ("python-network-requests.yml", python_network_rule),
            ("python-filesystem-access.yml", python_filesystem_rule)
        ]
        
        for filename, rule_content in rules:
            rule_file = rules_dir / filename
            with open(rule_file, 'w') as f:
                f.write(rule_content)
    
    def analyze_package_metadata(self, package: PackageVersion) -> Optional[GuardDogAnalysis]:
        """Analyze package metadata using GuardDog with enhanced detection."""
        if not self.available:
            return None
        
        try:
            analyzer = self._get_analyzer(package.ecosystem)
            if not analyzer:
                return None
            
            # Prepare package metadata
            metadata = self._package_to_guarddog_metadata(package)
            
            # Run metadata analysis
            result = analyzer.analyze_metadata(
                path="",  # Not needed for metadata analysis
                info=metadata,
                name=package.name,
                version=package.version
            )
            
            # Convert to our format
            risk_score = min(result.get('issues', 0) / 10.0, 1.0)  # Normalize
            findings = self._convert_metadata_findings(result.get('results', {}))
            
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
    
    def analyze_package_code_with_diff(self, packages: List[PackageVersion]) -> List[GuardDogAnalysis]:
        """
        Perform static code analysis with diff comparison for version changes.
        This replaces our old tarball analysis with GuardDog integration.
        """
        if not self.available:
            return []
        
        analyses = []
        
        for package in packages:
            try:
                # Get previous version for diff analysis
                previous_version = self._get_previous_version(package)
                
                analysis = self._analyze_single_package_with_diff(package, previous_version)
                if analysis:
                    analyses.append(analysis)
                    
            except Exception as e:
                logger.error(f"Code analysis failed for {package.name}@{package.version}: {e}")
                continue
        
        return analyses
    
    def _analyze_single_package_with_diff(self, package: PackageVersion, 
                                        previous_version: Optional[PackageVersion] = None) -> Optional[GuardDogAnalysis]:
        """Analyze a single package with diff comparison."""
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                # Download and extract current version
                current_dir = self._download_and_extract_package(package, temp_dir, "current")
                if not current_dir:
                    return None
                
                # Run GuardDog static analysis on current version
                analyzer = self._get_analyzer(package.ecosystem)
                if not analyzer:
                    return None
                
                result = analyzer.analyze_sourcecode(current_dir)
                
                # If we have a previous version, do diff analysis
                diff_findings = []
                if previous_version:
                    previous_dir = self._download_and_extract_package(previous_version, temp_dir, "previous")
                    if previous_dir:
                        diff_findings = self._perform_diff_analysis(current_dir, previous_dir, package)
                
                # Combine GuardDog findings with diff analysis
                all_findings = self._convert_sourcecode_findings(result.get('results', {}))
                all_findings.extend(diff_findings)
                
                # Calculate risk score
                risk_score = min(result.get('issues', 0) / 20.0, 1.0)
                if diff_findings:
                    risk_score = min(risk_score + 0.3, 1.0)  # Boost risk for version changes
                
                return GuardDogAnalysis(
                    package_name=package.name,
                    version=package.version,
                    ecosystem=package.ecosystem,
                    analysis_type="static_analysis_with_diff",
                    risk_score=risk_score,
                    findings=all_findings,
                    analysis_timestamp=datetime.now(timezone.utc),
                    guarddog_version=getattr(guarddog, '__version__', 'unknown')
                )
                
        except Exception as e:
            logger.error(f"Static analysis with diff failed for {package.name}@{package.version}: {e}")
            return None
    
    def _download_and_extract_package(self, package: PackageVersion, temp_dir: str, subdir: str) -> Optional[str]:
        """Download and extract package tarball using GuardDog scanners."""
        try:
            package_dir = os.path.join(temp_dir, subdir)
            os.makedirs(package_dir, exist_ok=True)
            
            if package.ecosystem == PackageEcosystem.NPM:
                # Use GuardDog's NPM scanner to download
                self.npm_scanner.download_and_get_package_info(
                    package.name, 
                    package.version, 
                    package_dir
                )
            elif package.ecosystem == PackageEcosystem.PYPI:
                # Use GuardDog's PyPI scanner to download  
                self.pypi_scanner.download_and_get_package_info(
                    package.name,
                    package.version,
                    package_dir
                )
            else:
                return None
            
            return package_dir
            
        except Exception as e:
            logger.debug(f"Failed to download {package.name}@{package.version}: {e}")
            return None
    
    def _perform_diff_analysis(self, current_dir: str, previous_dir: str, package: PackageVersion) -> List[Dict[str, Any]]:
        """Perform diff analysis between package versions."""
        findings = []
        
        try:
            # Check for new install scripts
            if package.ecosystem == PackageEcosystem.NPM:
                findings.extend(self._check_npm_install_script_changes(current_dir, previous_dir))
            
            # Check for new suspicious files
            findings.extend(self._check_new_suspicious_files(current_dir, previous_dir))
            
            # Check for significant code changes
            findings.extend(self._check_suspicious_code_changes(current_dir, previous_dir))
            
        except Exception as e:
            logger.debug(f"Diff analysis failed: {e}")
        
        return findings
    
    def _check_npm_install_script_changes(self, current_dir: str, previous_dir: str) -> List[Dict[str, Any]]:
        """Check for changes in NPM install scripts between versions."""
        findings = []
        
        try:
            current_package_json = os.path.join(current_dir, "package.json")
            previous_package_json = os.path.join(previous_dir, "package.json")
            
            if not (os.path.exists(current_package_json) and os.path.exists(previous_package_json)):
                return findings
            
            with open(current_package_json) as f:
                current_pkg = json.load(f)
            with open(previous_package_json) as f:
                previous_pkg = json.load(f)
            
            # Check for new or changed install scripts
            current_scripts = current_pkg.get('scripts', {})
            previous_scripts = previous_pkg.get('scripts', {})
            
            for script_type in ['preinstall', 'postinstall', 'install']:
                current_script = current_scripts.get(script_type)
                previous_script = previous_scripts.get(script_type)
                
                if current_script and current_script != previous_script:
                    findings.append({
                        'detector': 'version_diff_install_scripts',
                        'description': f'Install script {script_type} changed between versions',
                        'severity': 'high',
                        'message': f'New or modified {script_type} script: {current_script}',
                        'file_path': 'package.json',
                        'line_number': 0
                    })
            
        except Exception as e:
            logger.debug(f"Install script diff check failed: {e}")
        
        return findings
    
    def _check_new_suspicious_files(self, current_dir: str, previous_dir: str) -> List[Dict[str, Any]]:
        """Check for new suspicious files added between versions."""
        findings = []
        
        try:
            current_files = set()
            previous_files = set()
            
            for root, dirs, files in os.walk(current_dir):
                for file in files:
                    rel_path = os.path.relpath(os.path.join(root, file), current_dir)
                    current_files.add(rel_path)
            
            for root, dirs, files in os.walk(previous_dir):
                for file in files:
                    rel_path = os.path.relpath(os.path.join(root, file), previous_dir)
                    previous_files.add(rel_path)
            
            # Find new files
            new_files = current_files - previous_files
            
            # Check for suspicious new files
            suspicious_patterns = [
                '.exe', '.dll', '.so', '.dylib',  # Binaries
                'install.sh', 'setup.sh', 'run.sh',  # Shell scripts
                '.env', '.npmrc', '.ssh',  # Config files
            ]
            
            for file_path in new_files:
                if any(pattern in file_path.lower() for pattern in suspicious_patterns):
                    findings.append({
                        'detector': 'version_diff_suspicious_files',
                        'description': 'New suspicious file added between versions',
                        'severity': 'medium',
                        'message': f'New suspicious file: {file_path}',
                        'file_path': file_path,
                        'line_number': 0
                    })
        
        except Exception as e:
            logger.debug(f"Suspicious files check failed: {e}")
        
        return findings
    
    def _check_suspicious_code_changes(self, current_dir: str, previous_dir: str) -> List[Dict[str, Any]]:
        """Check for suspicious code changes between versions."""
        findings = []
        
        # This is a simplified implementation - in production you'd want
        # more sophisticated diff analysis
        
        try:
            # Look for common malicious patterns in new code
            malicious_patterns = [
                'eval(', 'Function(', 'child_process',
                'exec(', 'spawn(', 'bitcoin', 'crypto',
                'base64', 'atob(', 'btoa('
            ]
            
            # Basic file content comparison for key files
            key_files = ['index.js', 'main.js', '__init__.py', 'setup.py']
            
            for filename in key_files:
                current_file = os.path.join(current_dir, filename)
                previous_file = os.path.join(previous_dir, filename)
                
                if os.path.exists(current_file):
                    with open(current_file, 'r', errors='ignore') as f:
                        current_content = f.read()
                    
                    previous_content = ""
                    if os.path.exists(previous_file):
                        with open(previous_file, 'r', errors='ignore') as f:
                            previous_content = f.read()
                    
                    # Check for new suspicious patterns
                    for pattern in malicious_patterns:
                        if pattern in current_content and pattern not in previous_content:
                            findings.append({
                                'detector': 'version_diff_code_analysis',
                                'description': 'Suspicious code pattern added between versions',
                                'severity': 'high',
                                'message': f'New suspicious pattern "{pattern}" in {filename}',
                                'file_path': filename,
                                'line_number': 0
                            })
        
        except Exception as e:
            logger.debug(f"Code changes check failed: {e}")
        
        return findings
    
    def _get_analyzer(self, ecosystem: PackageEcosystem) -> Optional[Analyzer]:
        """Get appropriate GuardDog analyzer for ecosystem."""
        if ecosystem == PackageEcosystem.NPM:
            return self.npm_analyzer
        elif ecosystem == PackageEcosystem.PYPI:
            return self.pypi_analyzer
        return None
    
    def _get_previous_version(self, package: PackageVersion) -> Optional[PackageVersion]:
        """Get previous version of package for diff analysis."""
        # This would query the database for the previous version
        # For now, return None - implement based on your database schema
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
    
    def _convert_metadata_findings(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Convert GuardDog metadata results to our findings format."""
        findings = []
        
        for rule_name, result in results.items():
            if result:  # Rule matched
                findings.append({
                    'detector': rule_name,
                    'description': f'Metadata rule {rule_name} matched',
                    'severity': 'medium',
                    'message': str(result) if isinstance(result, str) else f'{rule_name} detected',
                    'file_path': 'metadata',
                    'line_number': 0
                })
        
        return findings
    
    def _convert_sourcecode_findings(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Convert GuardDog sourcecode results to our findings format.""" 
        findings = []
        
        for rule_name, rule_results in results.items():
            if isinstance(rule_results, list):
                for result in rule_results:
                    findings.append({
                        'detector': rule_name,
                        'description': result.get('message', f'Rule {rule_name} matched'),
                        'severity': 'high' if 'exec' in rule_name or 'eval' in rule_name else 'medium',
                        'message': result.get('message', ''),
                        'file_path': result.get('location', '').split(':')[0] if result.get('location') else '',
                        'line_number': int(result.get('location', '0').split(':')[1]) if ':' in result.get('location', '') else 0
                    })
        
        return findings


# Global enhanced service instance
enhanced_guarddog_service = EnhancedGuardDogService()
