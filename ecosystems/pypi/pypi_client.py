"""
PyPI registry client for Supply Chain Security Monitor.

This module handles all interactions with the PyPI registry API,
including package discovery, metadata retrieval, and downloads.
"""
import json
import requests
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
import tempfile
import zipfile
import tarfile

from core.config import config
from core.models import PackageVersion, PackageEcosystem
from ecosystems.common.base_scanner import BasePackageClient


class PyPIClient(BasePackageClient):
    """Client for interacting with PyPI registry API."""
    
    def __init__(self):
        super().__init__(PackageEcosystem.PYPI)
        self.registry_url = config.PYPI_REGISTRY_URL
        self.rss_url = config.PYPI_RSS_URL
        self.simple_url = config.PYPI_SIMPLE_URL
        self.session = requests.Session()
        self.session.headers.update(config.get_realistic_headers())
        
    def get_recent_changes(self, limit: int = 1000, since: Optional[str] = None) -> Dict[str, Any]:
        """Get recent package changes from PyPI RSS feed."""
        try:
            response = self.session.get(
                self.rss_url,
                timeout=config.REQUEST_TIMEOUT,
                verify=config.VERIFY_SSL
            )
            response.raise_for_status()
            
            # Parse RSS XML
            root = ET.fromstring(response.content)
            
            packages = []
            count = 0
            
            # Extract packages from RSS items
            for item in root.findall('.//item'):
                if count >= limit:
                    break
                    
                title_elem = item.find('title')
                link_elem = item.find('link') 
                pubdate_elem = item.find('pubDate')
                description_elem = item.find('description')
                
                if title_elem is not None and title_elem.text:
                    # Parse title like "package-name 1.0.0" 
                    # Sometimes the RSS feed includes extra text like "package-name added to..."
                    title_text = title_elem.text.strip()
                    title_parts = title_text.split(' ')
                    
                    if len(title_parts) >= 2:
                        # Clean package name - remove common RSS feed artifacts
                        raw_package_name = ' '.join(title_parts[:-1])
                        
                        # Remove common RSS feed suffixes
                        package_name = raw_package_name
                        for suffix in [' added to', ' updated in', ' published to']:
                            if suffix in package_name:
                                package_name = package_name.split(suffix)[0]
                        
                        # Only process valid-looking package names (basic validation)
                        if package_name and len(package_name.strip()) > 0 and not package_name.strip().startswith('<'):
                            version = title_parts[-1]
                        else:
                            continue  # Skip invalid package names
                        
                        # Parse publication date
                        published_at = None
                        if pubdate_elem is not None and pubdate_elem.text:
                            try:
                                # Parse RFC 2822 date format
                                published_at = datetime.strptime(
                                    pubdate_elem.text, 
                                    '%a, %d %b %Y %H:%M:%S %Z'
                                ).replace(tzinfo=timezone.utc)
                            except ValueError:
                                pass
                        
                        packages.append({
                            'name': package_name,
                            'version': version,
                            'link': link_elem.text if link_elem is not None else None,
                            'description': description_elem.text if description_elem is not None else None,
                            'published_at': published_at
                        })
                        count += 1
            
            return {
                'packages': packages,
                'total': len(packages)
            }
            
        except (requests.RequestException, ET.ParseError) as e:
            raise RuntimeError(f"Failed to fetch PyPI RSS feed: {e}")
    
    def get_package_info(self, package_name: str) -> Dict[str, Any]:
        """Get detailed information about a PyPI package."""
        url = f"{self.registry_url}/{package_name}/json"
        
        try:
            response = self.session.get(
                url,
                timeout=config.REQUEST_TIMEOUT,
                verify=config.VERIFY_SSL
            )
            response.raise_for_status()
            
            data = response.json()
            
            # Check if the data is valid
            if not data or data is None:
                raise RuntimeError(f"PyPI API returned null data for package {package_name}")
            
            # Check for error responses
            if 'message' in data and 'error' in str(data.get('message', '')).lower():
                raise RuntimeError(f"PyPI API error for {package_name}: {data['message']}")
                
            return data
            
        except requests.RequestException as e:
            raise RuntimeError(f"Failed to fetch package info for {package_name}: {e}")
    
    def get_package_version_info(self, package_name: str, version: str) -> Dict[str, Any]:
        """Get information about a specific PyPI package version."""
        url = f"{self.registry_url}/{package_name}/{version}/json"
        
        try:
            response = self.session.get(
                url,
                timeout=config.REQUEST_TIMEOUT,
                verify=config.VERIFY_SSL
            )
            response.raise_for_status()
            return response.json()
            
        except requests.RequestException as e:
            raise RuntimeError(f"Failed to fetch version info for {package_name}=={version}: {e}")
    
    def download_package(self, package_name: str, version: str, destination: str) -> Optional[str]:
        """Download a PyPI package."""
        try:
            # Get package version info to find download URLs
            version_info = self.get_package_version_info(package_name, version)
            
            # Look for source distribution first, then wheel
            urls = version_info.get('urls', [])
            download_url = None
            
            for url_info in urls:
                if url_info.get('packagetype') == 'sdist':
                    download_url = url_info.get('url')
                    break
            
            # Fallback to first available URL
            if not download_url and urls:
                download_url = urls[0].get('url')
            
            if not download_url:
                return None
            
            return self._download_file(download_url, destination)
            
        except Exception as e:
            print(f"Error downloading {package_name}=={version}: {e}")
            return None
    
    def _download_file(self, url: str, destination: str) -> Optional[str]:
        """Download a file from URL to destination."""
        try:
            response = self.session.get(
                url,
                timeout=config.REQUEST_TIMEOUT,
                verify=config.VERIFY_SSL,
                stream=True
            )
            response.raise_for_status()
            
            # Create destination path
            dest_path = Path(destination)
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Write file
            with open(dest_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            return str(dest_path)
            
        except requests.RequestException as e:
            print(f"Error downloading file {url}: {e}")
            return None
    
    def extract_package(self, package_path: str, extract_dir: str) -> Optional[str]:
        """Extract PyPI package (tar.gz or zip) to directory."""
        try:
            extract_path = Path(extract_dir)
            extract_path.mkdir(parents=True, exist_ok=True)
            
            package_file = Path(package_path)
            
            if package_file.suffix == '.zip' or package_path.endswith('.whl'):
                # Handle zip/wheel files
                with zipfile.ZipFile(package_path, 'r') as zip_file:
                    zip_file.extractall(extract_path)
            elif package_path.endswith('.tar.gz') or package_path.endswith('.tgz'):
                # Handle tar.gz files
                with tarfile.open(package_path, 'r:gz') as tar:
                    tar.extractall(extract_path)
            else:
                print(f"Unknown package format: {package_path}")
                return None
            
            return str(extract_path)
                    
        except Exception as e:
            print(f"Error extracting package {package_path}: {e}")
            return None
    
    def parse_package_data(self, raw_data: Dict[str, Any]) -> PackageVersion:
        """Parse raw PyPI package data into PackageVersion object."""
        info = raw_data.get('info', {})
        
        # Handle different data sources (RSS vs JSON API)
        if 'name' in raw_data and 'version' in raw_data:
            # RSS feed data
            package_name = raw_data['name']
            version = raw_data['version']
            description = raw_data.get('description')
            published_at = raw_data.get('published_at')
            
            # We'll need to fetch full info later for complete data
            return PackageVersion(
                name=package_name,
                version=version,
                author='unknown',  # Not available in RSS
                published_at=published_at,
                processed_at=datetime.now(timezone.utc),
                description=description,
                ecosystem=PackageEcosystem.PYPI
            )
        else:
            # Full JSON API data
            package_name = info.get('name', '')
            version = info.get('version', '1.0.0')
            
            # Parse author info
            author = info.get('author', 'unknown')
            if not author or author == 'UNKNOWN':
                author = info.get('maintainer', 'unknown')
            
            author_email = info.get('author_email')
            if not author_email:
                author_email = info.get('maintainer_email')
            
            # Parse URLs
            home_page = info.get('home_page')
            project_urls = info.get('project_urls') or {}
            
            # Find repository URL
            repository_url = None
            if project_urls:
                for key, url in project_urls.items():
                    if any(keyword in key.lower() for keyword in ['github', 'gitlab', 'repository', 'source']):
                        repository_url = url
                        break
            
            if not repository_url and home_page:
                repository_url = home_page
            
            # Parse keywords
            keywords = []
            keywords_str = info.get('keywords', '')
            if keywords_str:
                keywords = [k.strip() for k in keywords_str.split(',')]
            
            # Parse classifiers for additional info
            classifiers = info.get('classifiers', [])
            
            return PackageVersion(
                name=package_name,
                version=version,
                author=author,
                author_email=author_email,
                processed_at=datetime.now(timezone.utc),
                description=info.get('summary') or info.get('description'),
                keywords=keywords,
                homepage=home_page,
                repository_url=repository_url,
                license=info.get('license'),
                # PyPI doesn't have direct dependency info in main API
                dependencies={},
                dev_dependencies={},
                maintainers=[author] if author != 'unknown' else [],
                ecosystem=PackageEcosystem.PYPI
            )
    
    def get_package_dependencies(self, package_name: str, version: str) -> Dict[str, str]:
        """Get package dependencies (requires parsing setup.py or metadata)."""
        # This would require downloading and parsing the package
        # For now, return empty dict - can be enhanced later
        return {}
    
    def extract_recent_versions(self, package_data: Dict[str, Any], hours_back: int = 24) -> List[PackageVersion]:
        """Extract recent versions from package data.""" 
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours_back)
        recent_versions = []
        
        releases = package_data.get('releases') or {}
        
        if not releases:
            return recent_versions
        
        for version, release_files in releases.items():
            if not release_files:
                continue
                
            # Get the upload time from the first file
            first_file = release_files[0]
            upload_time_str = first_file.get('upload_time_iso_8601')
            
            if upload_time_str:
                try:
                    upload_time = datetime.fromisoformat(upload_time_str.replace('Z', '+00:00'))
                    if upload_time >= cutoff_time:
                        # Create version-specific data
                        version_data = {
                            'info': package_data.get('info', {}).copy()
                        }
                        version_data['info']['version'] = version
                        
                        parsed_version = self.parse_package_data(version_data)
                        parsed_version.published_at = upload_time
                        recent_versions.append(parsed_version)
                except (ValueError, KeyError):
                    continue
        
        return recent_versions
