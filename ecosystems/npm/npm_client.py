"""
NPM registry client for Supply Chain Security Monitor.

This module handles all interactions with the NPM registry API,
including package discovery, metadata retrieval, and downloads.
"""
import json
import requests
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
import tempfile
import tarfile
import gzip
import shutil

from core.config import config
from core.models import PackageVersion, PackageEcosystem
from ecosystems.common.base_scanner import BasePackageClient


class NPMClient(BasePackageClient):
    """Client for interacting with NPM registry API."""
    
    def __init__(self):
        super().__init__(PackageEcosystem.NPM)
        self.registry_url = config.NPM_REGISTRY_URL
        self.changes_url = config.NPM_CHANGES_URL
        self.session = requests.Session()
        self.session.headers.update(config.get_realistic_headers())
        
    def get_recent_changes(self, limit: int = 1000, since: Optional[str] = None) -> Dict[str, Any]:
        """Get recent package changes from NPM changes feed."""
        params = {
            'limit': limit,
            'descending': 'true'  # Get most recent first
        }
        
        if since:
            params['since'] = since
            
        # Try multiple NPM change feed endpoints
        endpoints = [
            self.changes_url,
            "https://replicate.npmjs.com/registry/_changes",
            "https://registry.npmjs.org/_changes",
        ]
        
        for endpoint in endpoints:
            try:
                # Set headers to accept JSON and disable compression for now
                headers = self.session.headers.copy()
                headers.update({
                    'Accept': 'application/json',
                    'Accept-Encoding': 'identity',  # Disable compression
                    'User-Agent': 'Supply-Chain-Monitor/1.0'
                })
                
                response = self.session.get(
                    endpoint,
                    params=params,
                    headers=headers,
                    timeout=config.REQUEST_TIMEOUT,
                    verify=config.VERIFY_SSL
                )
                response.raise_for_status()
                
                # Check if response has content
                if not response.text.strip():
                    continue  # Try next endpoint
                
                try:
                    data = response.json()
                    # Validate that we got a proper changes feed
                    if isinstance(data, dict) and ('results' in data or 'last_seq' in data):
                        return data
                    else:
                        continue  # Not a proper changes feed format
                except ValueError as json_err:
                    continue  # Try next endpoint
                    
            except requests.RequestException:
                continue  # Try next endpoint
        
        # If all endpoints failed, use NPM search API as fallback
        try:
            return self._get_recent_packages_via_search(limit)
        except Exception as search_error:
            raise RuntimeError(f"All NPM discovery methods failed. Changes feed error and search fallback error: {search_error}")
    
    def _get_recent_packages_via_search(self, limit: int = 100) -> Dict[str, Any]:
        """Fallback method using NPM search API to get recent packages."""
        search_url = "https://registry.npmjs.org/-/v1/search"
        
        # Search for recently updated packages
        params = {
            'text': '*',
            'size': min(limit, 250),  # API limit
            'from': 0,
            'quality': 0.1,
            'popularity': 0.1,
            'maintenance': 0.8  # Prioritize recently maintained packages
        }
        
        response = self.session.get(
            search_url,
            params=params,
            timeout=config.REQUEST_TIMEOUT,
            verify=config.VERIFY_SSL
        )
        response.raise_for_status()
        
        search_data = response.json()
        
        # Convert search results to changes feed format
        results = []
        for pkg in search_data.get('objects', [])[:limit]:
            package_info = pkg.get('package', {})
            results.append({
                'id': package_info.get('name', ''),
                'changes': [{
                    'rev': '1-fake',  # Fake revision for compatibility
                    'doc': {
                        'name': package_info.get('name', ''),
                        'description': package_info.get('description', ''),
                        'version': package_info.get('version', ''),
                        'author': package_info.get('author', {}),
                        'time': {
                            package_info.get('version', ''): package_info.get('date', datetime.now(timezone.utc).isoformat())
                        }
                    }
                }]
            })
        
        return {
            'results': results,
            'last_seq': len(results),
            'fallback_method': 'search_api'
        }
    
    def get_package_info(self, package_name: str) -> Dict[str, Any]:
        """Get detailed information about an NPM package."""
        url = f"{self.registry_url}/{package_name}"
        
        try:
            response = self.session.get(
                url,
                timeout=config.REQUEST_TIMEOUT,
                verify=config.VERIFY_SSL
            )
            response.raise_for_status()
            return response.json()
            
        except requests.RequestException as e:
            raise RuntimeError(f"Failed to fetch package info for {package_name}: {e}")
    
    def get_package_version_info(self, package_name: str, version: str) -> Dict[str, Any]:
        """Get information about a specific NPM package version."""
        url = f"{self.registry_url}/{package_name}/{version}"
        
        try:
            response = self.session.get(
                url,
                timeout=config.REQUEST_TIMEOUT,
                verify=config.VERIFY_SSL
            )
            response.raise_for_status()
            return response.json()
            
        except requests.RequestException as e:
            raise RuntimeError(f"Failed to fetch version info for {package_name}@{version}: {e}")
    
    def download_package(self, package_name: str, version: str, destination: str) -> Optional[str]:
        """Download an NPM package tarball."""
        try:
            # Get package info to find tarball URL
            package_info = self.get_package_info(package_name)
            
            if version not in package_info.get('versions', {}):
                return None
                
            version_info = package_info['versions'][version]
            tarball_url = version_info.get('dist', {}).get('tarball')
            
            if not tarball_url:
                return None
            
            return self._download_tarball(tarball_url, destination)
            
        except Exception as e:
            print(f"Error downloading {package_name}@{version}: {e}")
            return None
    
    def _download_tarball(self, tarball_url: str, destination: str) -> Optional[str]:
        """Download a tarball from URL to destination."""
        try:
            response = self.session.get(
                tarball_url,
                timeout=config.REQUEST_TIMEOUT,
                verify=config.VERIFY_SSL,
                stream=True
            )
            response.raise_for_status()
            
            # Create destination path
            dest_path = Path(destination)
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Write tarball
            with open(dest_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            return str(dest_path)
            
        except requests.RequestException as e:
            print(f"Error downloading tarball {tarball_url}: {e}")
            return None
    
    def extract_tarball(self, tarball_path: str, extract_dir: str) -> Optional[str]:
        """Extract NPM package tarball to directory."""
        try:
            extract_path = Path(extract_dir)
            extract_path.mkdir(parents=True, exist_ok=True)
            
            with tarfile.open(tarball_path, 'r:gz') as tar:
                # Extract all files
                tar.extractall(extract_path)
                
                # NPM packages are typically extracted to a 'package' subdirectory
                package_dir = extract_path / 'package'
                if package_dir.exists():
                    return str(package_dir)
                else:
                    # Sometimes the structure is different, return the extract dir
                    return str(extract_path)
                    
        except Exception as e:
            print(f"Error extracting tarball {tarball_path}: {e}")
            return None
    
    def parse_package_data(self, raw_data: Dict[str, Any]) -> PackageVersion:
        """Parse raw NPM package data into PackageVersion object."""
        # Handle different data structures (full package vs version-specific)
        if 'versions' in raw_data:
            # Full package data - get latest version
            latest_version = raw_data.get('dist-tags', {}).get('latest')
            if not latest_version:
                # Fallback to first version
                versions = list(raw_data.get('versions', {}).keys())
                latest_version = versions[0] if versions else '1.0.0'
            
            version_data = raw_data['versions'].get(latest_version, {})
            package_name = raw_data.get('name', version_data.get('name', ''))
        else:
            # Single version data
            version_data = raw_data
            package_name = version_data.get('name', '')
            latest_version = version_data.get('version', '1.0.0')
        
        # Extract maintainers/author info
        maintainers_data = version_data.get('maintainers', raw_data.get('maintainers', []))
        author_data = version_data.get('author', raw_data.get('author', {}))
        npm_user_data = version_data.get('_npmUser', {})
        
        # Parse author - prioritize _npmUser (actual publisher) over author field
        if isinstance(npm_user_data, dict) and npm_user_data.get('name'):
            # Use actual publisher from _npmUser field
            author = npm_user_data.get('name')
            author_email = npm_user_data.get('email')
        elif isinstance(author_data, dict) and author_data.get('name'):
            # Valid author dict with name
            author = author_data.get('name', 'unknown')
            author_email = author_data.get('email')
        elif isinstance(author_data, str) and author_data.strip():
            # Valid author string
            author = author_data.strip()
            author_email = None
        else:
            # Fallback to first maintainer
            if maintainers_data and len(maintainers_data) > 0:
                maintainer = maintainers_data[0]
                if isinstance(maintainer, dict):
                    author = maintainer.get('name', 'unknown')
                    author_email = maintainer.get('email')
                else:
                    author = str(maintainer)
                    author_email = None
            else:
                author = 'unknown'
                author_email = None
        
        # Parse timestamps
        published_at = None
        time_data = raw_data.get('time', {})
        if isinstance(time_data, dict) and latest_version in time_data:
            try:
                published_at = datetime.fromisoformat(time_data[latest_version].replace('Z', '+00:00'))
            except (ValueError, KeyError):
                pass
        
        # Parse dist info
        dist_info = version_data.get('dist', {})
        
        return PackageVersion(
            name=package_name,
            version=latest_version,
            author=author,
            author_email=author_email,
            published_at=published_at,
            processed_at=datetime.now(timezone.utc),
            description=version_data.get('description'),
            keywords=version_data.get('keywords', []),
            homepage=version_data.get('homepage'),
            repository_url=self._extract_repo_url(version_data.get('repository')),
            license=self._extract_license(version_data.get('license')),
            dependencies=version_data.get('dependencies', {}),
            dev_dependencies=version_data.get('devDependencies', {}),
            maintainers=[m.get('name') if isinstance(m, dict) else str(m) for m in maintainers_data],
            file_count=dist_info.get('fileCount'),
            unpack_size=dist_info.get('unpackedSize'),
            tarball_size=None,  # Will be calculated if needed
            is_deprecated=raw_data.get('deprecated') is not None,
            deprecated_reason=raw_data.get('deprecated') if isinstance(raw_data.get('deprecated'), str) else None,
            dist_tags=raw_data.get('dist-tags', {}),
            shasum=dist_info.get('shasum'),
            integrity=dist_info.get('integrity'),
            ecosystem=PackageEcosystem.NPM
        )
    
    def _extract_repo_url(self, repo_data) -> Optional[str]:
        """Extract repository URL from various NPM repository formats."""
        if not repo_data:
            return None
            
        if isinstance(repo_data, str):
            return repo_data
        elif isinstance(repo_data, dict):
            return repo_data.get('url')
        
        return None
    
    def _extract_license(self, license_data) -> Optional[str]:
        """Extract license string from various NPM license formats."""
        if not license_data:
            return None
            
        if isinstance(license_data, str):
            return license_data
        elif isinstance(license_data, dict):
            return license_data.get('type') or license_data.get('name')
        elif isinstance(license_data, list):
            # Multiple licenses - join them
            licenses = []
            for lic in license_data:
                if isinstance(lic, str):
                    licenses.append(lic)
                elif isinstance(lic, dict):
                    licenses.append(lic.get('type') or lic.get('name') or str(lic))
            return ', '.join(filter(None, licenses))
        
        return str(license_data)
    
    def extract_recent_versions(self, package_data: Dict[str, Any], hours_back: int = 24) -> List[PackageVersion]:
        """Extract recent versions from package data."""
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours_back)
        recent_versions = []
        
        versions = package_data.get('versions', {})
        time_data = package_data.get('time', {})
        
        for version, version_info in versions.items():
            # Check if this version was published recently
            if version in time_data:
                try:
                    published_at = datetime.fromisoformat(time_data[version].replace('Z', '+00:00'))
                    if published_at >= cutoff_time:
                        # Create a mock package data structure for this specific version
                        version_package_data = package_data.copy()
                        version_package_data['versions'] = {version: version_info}
                        version_package_data['dist-tags'] = {'latest': version}
                        
                        parsed_version = self.parse_package_data(version_package_data)
                        recent_versions.append(parsed_version)
                except (ValueError, KeyError):
                    continue
        
        return recent_versions
