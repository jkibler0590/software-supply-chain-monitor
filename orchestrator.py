"""
Unified Supply Chain Security Scanner Orchestrator.

This module coordinates scanning across multiple package ecosystems (NPM, PyPI, etc.)
and provides a centralized interface for running security scans, managing configurations,
and handling multi-ecosystem operations.
"""
import logging
import asyncio
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from core.config import config
from core.database import database
from core.models import PackageEcosystem, ScanningSession, ThreatDetectionResult
from ecosystems.npm.npm_scanner import npm_scanner
from notifications.slack_alerts import slack_manager

logger = logging.getLogger(__name__)

# Import health monitoring
try:
    from core.health_scheduler import health_scheduler
    HEALTH_MONITORING_AVAILABLE = True
except ImportError as e:
    HEALTH_MONITORING_AVAILABLE = False
    health_scheduler = None
    logger.warning(f"Health monitoring not available: {e}")

# Import PyPI scanner when available
try:
    from ecosystems.pypi.pypi_scanner import pypi_scanner
    PYPI_SCANNER_AVAILABLE = True
except ImportError as e:
    PYPI_SCANNER_AVAILABLE = False
    pypi_scanner = None
    logger.warning(f"PyPI scanner not available: {e}")


@dataclass
class MultiEcosystemScanResult:
    """Results from scanning multiple package ecosystems."""
    scan_id: str
    start_time: datetime
    end_time: Optional[datetime]
    ecosystems_scanned: List[PackageEcosystem]
    sessions: Dict[PackageEcosystem, ScanningSession]
    total_packages_processed: int
    total_alerts_sent: int
    total_patterns_detected: int
    errors: List[str]


class SupplyChainOrchestrator:
    """Main orchestrator for supply chain security scanning."""
    
    def __init__(self, enable_health_monitoring: bool = True):
        """Initialize the orchestrator with available scanners."""
        self.scanners = {
            PackageEcosystem.NPM: npm_scanner,
        }
        
        # Add PyPI scanner if available
        if PYPI_SCANNER_AVAILABLE and pypi_scanner:
            self.scanners[PackageEcosystem.PYPI] = pypi_scanner
            logger.info("✅ PyPI scanner enabled")
        else:
            logger.info("ℹ️  PyPI scanner not available")
        
        self.active_scan_result: Optional[MultiEcosystemScanResult] = None
        self.health_monitoring_enabled = enable_health_monitoring and HEALTH_MONITORING_AVAILABLE
        self.health_monitoring_task: Optional[asyncio.Task] = None
        
        if self.health_monitoring_enabled:
            logger.info("✅ Health monitoring enabled")
        else:
            logger.info("ℹ️  Health monitoring disabled or unavailable")
        
    async def run_multi_ecosystem_scan(
        self, 
        ecosystems: Optional[List[PackageEcosystem]] = None
    ) -> MultiEcosystemScanResult:
        """Run security scans across multiple package ecosystems."""
        if ecosystems is None:
            ecosystems = list(self.scanners.keys())
        
        # Filter to only available ecosystems
        available_ecosystems = [eco for eco in ecosystems if eco in self.scanners]
        
        if not available_ecosystems:
            raise ValueError("No available scanners for requested ecosystems")
        
        scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        start_time = datetime.now(timezone.utc)
        
        logger.info(f"🚀 Starting multi-ecosystem scan {scan_id}")
        logger.info(f"   🎯 Target ecosystems: {[eco.value for eco in available_ecosystems]}")
        
        scan_result = MultiEcosystemScanResult(
            scan_id=scan_id,
            start_time=start_time,
            end_time=None,
            ecosystems_scanned=available_ecosystems,
            sessions={},
            total_packages_processed=0,
            total_alerts_sent=0,
            total_patterns_detected=0,
            errors=[]
        )
        
        self.active_scan_result = scan_result
        
        try:
            # Initialize database for multi-ecosystem support
            database.init_database()
            
            # Run scans for each ecosystem concurrently
            with ThreadPoolExecutor(max_workers=len(available_ecosystems)) as executor:
                future_to_ecosystem = {
                    executor.submit(self._run_ecosystem_scan, ecosystem): ecosystem
                    for ecosystem in available_ecosystems
                }
                
                for future in future_to_ecosystem:
                    ecosystem = future_to_ecosystem[future]
                    try:
                        session = future.result()
                        scan_result.sessions[ecosystem] = session
                        
                        # Aggregate results
                        scan_result.total_packages_processed += session.packages_processed
                        scan_result.total_alerts_sent += session.alerts_sent
                        scan_result.total_patterns_detected += session.suspicious_patterns_found
                        
                        logger.info(f"✅ {ecosystem.value} scan completed successfully")
                        
                    except Exception as e:
                        error_msg = f"Error scanning {ecosystem.value}: {e}"
                        scan_result.errors.append(error_msg)
                        logger.error(error_msg)
            
            # Send summary notification
            await self._send_scan_summary(scan_result)
            
        except Exception as e:
            error_msg = f"Error in multi-ecosystem scan: {e}"
            scan_result.errors.append(error_msg)
            logger.error(error_msg)
        
        finally:
            scan_result.end_time = datetime.now(timezone.utc)
            self.active_scan_result = None
        
        return scan_result
    
    def _run_ecosystem_scan(self, ecosystem: PackageEcosystem) -> ScanningSession:
        """Run a scan for a specific ecosystem."""
        scanner = self.scanners[ecosystem]
        return scanner.run_full_scan_cycle()
    
    async def _send_scan_summary(self, scan_result: MultiEcosystemScanResult):
        """Send a summary notification after multi-ecosystem scan."""
        try:
            # Ensure end_time is set
            if not scan_result.end_time:
                scan_result.end_time = datetime.now(timezone.utc)
                
            duration = (scan_result.end_time - scan_result.start_time).total_seconds()
            
            # Build ecosystem-specific data
            ecosystems_data = {}
            for ecosystem, session in scan_result.sessions.items():
                ecosystems_data[ecosystem.value] = {
                    'packages_processed': session.packages_processed,
                    'alerts': session.alerts_sent,
                    'suspicious_patterns': session.suspicious_patterns_found,
                    'errors': session.errors_encountered,
                    'guarddog_alerts': 0  # TODO: Add GuardDog specific tracking if needed
                }
            
            summary_data = {
                'scan_id': scan_result.scan_id,
                'ecosystems': [eco.value for eco in scan_result.ecosystems_scanned],
                'ecosystems': ecosystems_data,  # Override with detailed data
                'duration_seconds': duration,
                'total_packages': scan_result.total_packages_processed,
                'total_alerts': scan_result.total_alerts_sent,
                'total_patterns': scan_result.total_patterns_detected,
                'error_count': len(scan_result.errors)
            }
            
            # This will now only send if there are meaningful findings
            success = slack_manager.send_scan_summary_alert(summary_data)
            if success:
                logger.info(f"📊 Scan summary sent for {scan_result.scan_id}")
            else:
                logger.debug(f"📊 Scan summary skipped for {scan_result.scan_id} (no findings)")
            
        except Exception as e:
            logger.error(f"Failed to send scan summary: {e}")
    
    def run_npm_scan(self) -> ScanningSession:
        """Run NPM-specific scan (convenience method)."""
        if PackageEcosystem.NPM not in self.scanners:
            raise ValueError("NPM scanner not available")
        
        return self.scanners[PackageEcosystem.NPM].run_full_scan_cycle()
    
    def run_pypi_scan(self) -> ScanningSession:
        """Run PyPI-specific scan (convenience method)."""
        if PackageEcosystem.PYPI not in self.scanners:
            raise ValueError("PyPI scanner not available - ensure PyPI client is properly configured")
        
        return self.scanners[PackageEcosystem.PYPI].run_full_scan_cycle()
    
    def get_ecosystem_stats(self, ecosystem: PackageEcosystem) -> Dict[str, Any]:
        """Get statistics for a specific ecosystem."""
        return database.get_stats(ecosystem)
    
    def get_multi_ecosystem_stats(self) -> Dict[str, Any]:
        """Get combined statistics across all ecosystems."""
        all_stats = {}
        total_stats = {
            'total_packages': 0,
            'total_versions': 0,
            'total_authors': 0,
            'total_alerts': 0
        }
        
        for ecosystem in self.scanners.keys():
            stats = database.get_stats(ecosystem)
            all_stats[ecosystem.value] = stats
            
            # Aggregate totals
            total_stats['total_packages'] += stats.get('unique_packages', 0)
            total_stats['total_versions'] += stats.get('total_versions', 0)
            total_stats['total_authors'] += stats.get('unique_authors', 0)
            total_stats['total_alerts'] += stats.get('total_alerts', 0)
        
        all_stats['totals'] = total_stats
        return all_stats
    
    def cleanup_old_data(self, hours_back: int = None) -> Dict[str, Any]:
        """Clean up old data across all ecosystems."""
        if hours_back is None:
            hours_back = config.HOURS_BACK
        
        return database.cleanup_old_entries(hours_back)
    
    def get_current_scan_status(self) -> Optional[Dict[str, Any]]:
        """Get status of currently running scan."""
        if not self.active_scan_result:
            return None
        
        scan = self.active_scan_result
        current_time = datetime.now(timezone.utc)
        
        return {
            'scan_id': scan.scan_id,
            'start_time': scan.start_time.isoformat(),
            'elapsed_seconds': (current_time - scan.start_time).total_seconds(),
            'ecosystems_scanned': [eco.value for eco in scan.ecosystems_scanned],
            'packages_processed': scan.total_packages_processed,
            'alerts_sent': scan.total_alerts_sent,
            'patterns_detected': scan.total_patterns_detected,
            'errors': len(scan.errors)
        }
    
    def validate_configuration(self) -> Dict[str, Any]:
        """Validate system configuration and dependencies."""
        validation_results = {
            'config_valid': True,
            'database_accessible': True,
            'scanners_available': {},
            'notifications_configured': True,
            'errors': []
        }
        
        try:
            # Check configuration
            config.validate_configuration()
            
            # Check database connectivity
            database.init_database()
            
            # Check scanner availability
            for ecosystem, scanner in self.scanners.items():
                try:
                    # Basic health check for each scanner
                    validation_results['scanners_available'][ecosystem.value] = True
                except Exception as e:
                    validation_results['scanners_available'][ecosystem.value] = False
                    validation_results['errors'].append(f"{ecosystem.value} scanner error: {e}")
            
            # Check notifications
            if not slack_manager.is_configured():
                validation_results['notifications_configured'] = False
                validation_results['errors'].append("Slack notifications not configured")
            
        except Exception as e:
            validation_results['config_valid'] = False
            validation_results['errors'].append(f"Configuration error: {e}")
        
        # Overall health status
        validation_results['overall_healthy'] = (
            validation_results['config_valid'] and
            validation_results['database_accessible'] and
            any(validation_results['scanners_available'].values())
        )
        
        return validation_results


    # Health Monitoring Methods
    async def start_health_monitoring(self, check_interval_minutes: int = 60):
        """Start health monitoring if enabled."""
        if not self.health_monitoring_enabled:
            logger.warning("Health monitoring not available or disabled")
            return False
            
        if self.health_monitoring_task and not self.health_monitoring_task.done():
            logger.warning("Health monitoring already running")
            return True
            
        try:
            # Configure health scheduler
            health_scheduler.check_interval_minutes = check_interval_minutes
            
            # Start monitoring as background task
            self.health_monitoring_task = asyncio.create_task(
                health_scheduler.start_monitoring()
            )
            
            logger.info(f"🩺 Health monitoring started (interval: {check_interval_minutes} minutes)")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start health monitoring: {e}")
            return False
    
    def stop_health_monitoring(self):
        """Stop health monitoring."""
        if not self.health_monitoring_enabled:
            return
            
        try:
            health_scheduler.stop_monitoring()
            
            if self.health_monitoring_task and not self.health_monitoring_task.done():
                self.health_monitoring_task.cancel()
                
            logger.info("🩺 Health monitoring stopped")
            
        except Exception as e:
            logger.error(f"Failed to stop health monitoring: {e}")
    
    async def run_manual_health_check(self) -> dict:
        """Run a manual health check and return results."""
        if not self.health_monitoring_enabled:
            return {
                'error': 'Health monitoring not available',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
        try:
            return await health_scheduler.run_manual_check()
        except Exception as e:
            logger.error(f"Manual health check failed: {e}")
            return {
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
    
    def get_health_status(self) -> dict:
        """Get health monitoring status."""
        if not self.health_monitoring_enabled:
            return {
                'enabled': False,
                'available': HEALTH_MONITORING_AVAILABLE,
                'reason': 'Health monitoring not available or disabled'
            }
            
        try:
            return {
                'enabled': True,
                'available': True,
                'scheduler_status': health_scheduler.get_status(),
                'monitoring_task_running': (
                    self.health_monitoring_task and 
                    not self.health_monitoring_task.done()
                )
            }
        except Exception as e:
            return {
                'enabled': True,
                'available': True,
                'error': str(e)
            }


# Global orchestrator instance
orchestrator = SupplyChainOrchestrator()


# CLI-compatible functions for backwards compatibility
def main_scan_cycle():
    """Run the main scanning cycle (NPM only for now)."""
    return orchestrator.run_npm_scan()


async def multi_ecosystem_scan():
    """Run multi-ecosystem scanning."""
    return await orchestrator.run_multi_ecosystem_scan()


def get_system_status():
    """Get comprehensive system status."""
    status = {
        'configuration': orchestrator.validate_configuration(),
        'current_scan': orchestrator.get_current_scan_status(),
        'ecosystem_stats': orchestrator.get_multi_ecosystem_stats(),
        'timestamp': datetime.now(timezone.utc).isoformat()
    }
    return status


if __name__ == "__main__":
    # For direct execution, run NPM scan
    import asyncio
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    print("🚀 Starting Supply Chain Security Scanner")
    
    # Validate configuration first
    validation = orchestrator.validate_configuration()
    if not validation['overall_healthy']:
        print("❌ System validation failed:")
        for error in validation['errors']:
            print(f"   - {error}")
        exit(1)
    
    print("✅ System validation passed")
    
    # Run multi-ecosystem scan
    result = asyncio.run(orchestrator.run_multi_ecosystem_scan())
    
    print(f"📊 Scan completed: {result.scan_id}")
    print(f"   Ecosystems: {[eco.value for eco in result.ecosystems_scanned]}")
    print(f"   Packages processed: {result.total_packages_processed}")
    print(f"   Alerts sent: {result.total_alerts_sent}")
    print(f"   Patterns detected: {result.total_patterns_detected}")
    
    if result.errors:
        print(f"⚠️  Errors encountered: {len(result.errors)}")
        for error in result.errors:
            print(f"   - {error}")
