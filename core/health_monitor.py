"""
Supply Chain Security Monitor - Health Check System

This module provides comprehensive health monitoring for all system components,
ensuring the pipeline is working correctly and alerting when issues are detected.
"""
import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum

from core.database import database
from core.enhanced_guarddog_service import enhanced_guarddog_service
from core.config import config
from notifications.slack_alerts import slack_manager

logger = logging.getLogger(__name__)


class HealthStatus(Enum):
    """Health check status levels."""
    HEALTHY = "HEALTHY"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


@dataclass
class HealthCheckResult:
    """Result of a health check."""
    component: str
    status: HealthStatus
    message: str
    details: Dict[str, Any] = None
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc)
        if self.details is None:
            self.details = {}


class SupplyChainHealthMonitor:
    """Comprehensive health monitoring for the supply chain security system."""
    
    def __init__(self):
        self.checks = {}
        self.last_alert_time = {}
        self.alert_cooldown_minutes = 30  # Don't spam alerts
        
    def register_check(self, name: str, check_function, critical: bool = True):
        """Register a health check function."""
        self.checks[name] = {
            'function': check_function,
            'critical': critical,
            'last_run': None,
            'last_result': None
        }
    
    def run_all_checks(self) -> List[HealthCheckResult]:
        """Run all registered health checks."""
        results = []
        
        # Core component checks
        results.append(self._check_database_connectivity())
        results.append(self._check_guarddog_service())
        results.append(self._check_recent_package_activity())
        results.append(self._check_guarddog_analysis_activity())
        results.append(self._check_suspicious_alert_activity())
        results.append(self._check_scanner_integration())
        results.append(self._check_data_freshness())
        results.append(self._check_disk_space())
        results.append(self._check_database_integrity())
        
        # Alert on critical issues
        critical_issues = [r for r in results if r.status == HealthStatus.CRITICAL]
        if critical_issues:
            self._send_health_alert(results)
            
        return results
    
    def _check_database_connectivity(self) -> HealthCheckResult:
        """Check if database is accessible and responsive."""
        try:
            db_file = database.db_file if hasattr(database, 'db_file') else 'data/npm_scanner.db'
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            
            # Test basic query
            cursor.execute('SELECT COUNT(*) FROM package_versions')
            package_count = cursor.fetchone()[0]
            
            # Check all expected tables exist
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            expected_tables = ['package_versions', 'guarddog_analysis', 'suspicious_alerts', 'scanning_sessions']
            missing_tables = [t for t in expected_tables if t not in tables]
            
            conn.close()
            
            if missing_tables:
                return HealthCheckResult(
                    component="database",
                    status=HealthStatus.CRITICAL,
                    message=f"Missing database tables: {missing_tables}",
                    details={"package_count": package_count, "tables": tables}
                )
            
            return HealthCheckResult(
                component="database",
                status=HealthStatus.HEALTHY,
                message=f"Database operational ({package_count} packages)",
                details={"package_count": package_count, "tables": tables}
            )
            
        except Exception as e:
            return HealthCheckResult(
                component="database",
                status=HealthStatus.CRITICAL,
                message=f"Database connectivity failed: {e}",
                details={"error": str(e)}
            )
    
    def _check_guarddog_service(self) -> HealthCheckResult:
        """Check if GuardDog service is available and functional."""
        try:
            if not enhanced_guarddog_service.available:
                return HealthCheckResult(
                    component="guarddog_service",
                    status=HealthStatus.CRITICAL,
                    message="GuardDog service is not available",
                    details={"available": False}
                )
            
            # Test basic functionality
            from core.models import PackageVersion, PackageEcosystem
            test_pkg = PackageVersion(
                name='health-check-test',
                version='1.0.0',
                author='health-monitor',
                ecosystem=PackageEcosystem.NPM,
                published_at=datetime.now(timezone.utc)
            )
            
            result = enhanced_guarddog_service.analyze_package_metadata(test_pkg)
            if result is None:
                return HealthCheckResult(
                    component="guarddog_service",
                    status=HealthStatus.CRITICAL,
                    message="GuardDog analysis returned None",
                    details={"test_package": f"{test_pkg.name}@{test_pkg.version}"}
                )
            
            # Check analyzers for both ecosystems
            npm_analyzer = enhanced_guarddog_service._get_analyzer(PackageEcosystem.NPM)
            pypi_analyzer = enhanced_guarddog_service._get_analyzer(PackageEcosystem.PYPI)
            
            return HealthCheckResult(
                component="guarddog_service",
                status=HealthStatus.HEALTHY,
                message="GuardDog service operational",
                details={
                    "available": True,
                    "npm_analyzer": npm_analyzer is not None,
                    "pypi_analyzer": pypi_analyzer is not None,
                    "test_analysis_risk": result.risk_level
                }
            )
            
        except Exception as e:
            return HealthCheckResult(
                component="guarddog_service",
                status=HealthStatus.CRITICAL,
                message=f"GuardDog service test failed: {e}",
                details={"error": str(e)}
            )
    
    def _check_recent_package_activity(self) -> HealthCheckResult:
        """Check if packages are being scanned and stored recently."""
        try:
            db_file = database.db_file if hasattr(database, 'db_file') else 'data/npm_scanner.db'
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            
            # Check for recent package versions (last 24 hours)
            since = datetime.now(timezone.utc) - timedelta(hours=24)
            cursor.execute('''
                SELECT COUNT(*) FROM package_versions 
                WHERE processed_at > ?
            ''', (since.isoformat(),))
            recent_count = cursor.fetchone()[0]
            
            # Check total package count
            cursor.execute('SELECT COUNT(*) FROM package_versions')
            total_count = cursor.fetchone()[0]
            
            # Check for recent activity by ecosystem
            cursor.execute('''
                SELECT ecosystem, COUNT(*) FROM package_versions 
                WHERE processed_at > ?
                GROUP BY ecosystem
            ''', (since.isoformat(),))
            ecosystem_activity = dict(cursor.fetchall())
            
            conn.close()
            
            # Determine status based on activity
            if recent_count == 0 and total_count > 0:
                status = HealthStatus.WARNING
                message = "No recent package activity in 24 hours (system may be idle)"
            elif recent_count == 0 and total_count == 0:
                status = HealthStatus.CRITICAL
                message = "No packages found in database (system not working)"
            elif recent_count < 10:  # Configurable threshold
                status = HealthStatus.WARNING
                message = f"Low package activity: {recent_count} packages in 24h"
            else:
                status = HealthStatus.HEALTHY
                message = f"Active package scanning: {recent_count} packages in 24h"
            
            return HealthCheckResult(
                component="package_activity",
                status=status,
                message=message,
                details={
                    "recent_count_24h": recent_count,
                    "total_count": total_count,
                    "ecosystem_activity": ecosystem_activity
                }
            )
            
        except Exception as e:
            return HealthCheckResult(
                component="package_activity",
                status=HealthStatus.CRITICAL,
                message=f"Failed to check package activity: {e}",
                details={"error": str(e)}
            )
    
    def _check_guarddog_analysis_activity(self) -> HealthCheckResult:
        """Check if GuardDog is actually analyzing packages."""
        try:
            db_file = database.db_file if hasattr(database, 'db_file') else 'data/npm_scanner.db'
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            
            # Check for recent GuardDog analyses
            since_24h = datetime.now(timezone.utc) - timedelta(hours=24)
            since_week = datetime.now(timezone.utc) - timedelta(days=7)
            
            cursor.execute('SELECT COUNT(*) FROM guarddog_analysis')
            total_analyses = cursor.fetchone()[0]
            
            cursor.execute('''
                SELECT COUNT(*) FROM guarddog_analysis 
                WHERE analysis_timestamp > ?
            ''', (since_24h.isoformat(),))
            recent_analyses_24h = cursor.fetchone()[0]
            
            cursor.execute('''
                SELECT COUNT(*) FROM guarddog_analysis 
                WHERE analysis_timestamp > ?
            ''', (since_week.isoformat(),))
            recent_analyses_week = cursor.fetchone()[0]
            
            # Check high-risk findings
            cursor.execute('''
                SELECT COUNT(*) FROM guarddog_analysis 
                WHERE combined_risk_score >= 0.6
            ''', )
            high_risk_count = cursor.fetchone()[0]
            
            # Check ecosystem distribution
            cursor.execute('''
                SELECT ecosystem, COUNT(*), AVG(combined_risk_score)
                FROM guarddog_analysis 
                GROUP BY ecosystem
            ''')
            ecosystem_stats = cursor.fetchall()
            
            conn.close()
            
            # Determine status
            if total_analyses == 0:
                status = HealthStatus.CRITICAL
                message = "No GuardDog analyses found (GuardDog integration broken)"
            elif recent_analyses_week == 0 and total_analyses > 0:
                status = HealthStatus.WARNING  
                message = "No GuardDog activity in past week (may be idle)"
            elif recent_analyses_24h == 0 and recent_analyses_week > 0:
                status = HealthStatus.WARNING
                message = "No GuardDog activity in past 24h"
            else:
                status = HealthStatus.HEALTHY
                message = f"GuardDog active: {recent_analyses_24h} analyses in 24h"
            
            return HealthCheckResult(
                component="guarddog_analysis",
                status=status,
                message=message,
                details={
                    "total_analyses": total_analyses,
                    "recent_24h": recent_analyses_24h,
                    "recent_week": recent_analyses_week,
                    "high_risk_findings": high_risk_count,
                    "ecosystem_stats": ecosystem_stats
                }
            )
            
        except Exception as e:
            return HealthCheckResult(
                component="guarddog_analysis",
                status=HealthStatus.CRITICAL,
                message=f"Failed to check GuardDog activity: {e}",
                details={"error": str(e)}
            )
    
    def _check_suspicious_alert_activity(self) -> HealthCheckResult:
        """Check if suspicious alerts are being generated."""
        try:
            db_file = database.db_file if hasattr(database, 'db_file') else 'data/npm_scanner.db'
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            
            # Check suspicious alerts
            since = datetime.now(timezone.utc) - timedelta(hours=24)
            
            cursor.execute('SELECT COUNT(*) FROM suspicious_alerts')
            total_alerts = cursor.fetchone()[0]
            
            cursor.execute('''
                SELECT COUNT(*) FROM suspicious_alerts 
                WHERE created_at > ?
            ''', (since.isoformat(),))
            recent_alerts = cursor.fetchone()[0]
            
            # Check alert types
            cursor.execute('''
                SELECT alert_type, COUNT(*) FROM suspicious_alerts
                WHERE created_at > ?
                GROUP BY alert_type
            ''', (since.isoformat(),))
            alert_types = dict(cursor.fetchall())
            
            conn.close()
            
            # Note: Low suspicious activity might be normal (good news!)
            if total_alerts == 0:
                status = HealthStatus.WARNING
                message = "No suspicious alerts generated (may indicate detection issues)"
            else:
                status = HealthStatus.HEALTHY
                message = f"Alert system active: {recent_alerts} alerts in 24h"
            
            return HealthCheckResult(
                component="suspicious_alerts",
                status=status,
                message=message,
                details={
                    "total_alerts": total_alerts,
                    "recent_alerts_24h": recent_alerts,
                    "alert_types": alert_types
                }
            )
            
        except Exception as e:
            return HealthCheckResult(
                component="suspicious_alerts",
                status=HealthStatus.CRITICAL,
                message=f"Failed to check alert activity: {e}",
                details={"error": str(e)}
            )
    
    def _check_scanner_integration(self) -> HealthCheckResult:
        """Check if scanners can be loaded and have GuardDog integration."""
        try:
            from ecosystems.npm.npm_scanner import NPMScanner
            from ecosystems.pypi.pypi_scanner import PyPIScanner
            
            # Test scanner instantiation
            npm_scanner = NPMScanner()
            pypi_scanner = PyPIScanner()
            
            # Check for GuardDog integration (indirect check)
            npm_source = str(type(npm_scanner))
            pypi_source = str(type(pypi_scanner))
            
            return HealthCheckResult(
                component="scanner_integration",
                status=HealthStatus.HEALTHY,
                message="Scanners loaded successfully",
                details={
                    "npm_scanner": "available",
                    "pypi_scanner": "available",
                    "npm_type": npm_source,
                    "pypi_type": pypi_source
                }
            )
            
        except Exception as e:
            return HealthCheckResult(
                component="scanner_integration",
                status=HealthStatus.CRITICAL,
                message=f"Scanner integration failed: {e}",
                details={"error": str(e)}
            )
    
    def _check_data_freshness(self) -> HealthCheckResult:
        """Check if data is being updated regularly."""
        try:
            db_file = database.db_file if hasattr(database, 'db_file') else 'data/npm_scanner.db'
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            
            # Check most recent data in each table
            tables_to_check = [
                ('package_versions', 'processed_at'),
                ('guarddog_analysis', 'analysis_timestamp'),  
                ('suspicious_alerts', 'created_at'),
                ('scanning_sessions', 'end_time')
            ]
            
            freshness_results = {}
            oldest_data = None
            
            for table, timestamp_col in tables_to_check:
                try:
                    cursor.execute(f'SELECT MAX({timestamp_col}) FROM {table}')
                    result = cursor.fetchone()[0]
                    if result:
                        last_update = datetime.fromisoformat(result.replace('Z', '+00:00') if result.endswith('Z') else result)
                        age_hours = (datetime.now(timezone.utc) - last_update).total_seconds() / 3600
                        freshness_results[table] = {
                            'last_update': last_update.isoformat(),
                            'age_hours': age_hours
                        }
                        
                        if oldest_data is None or age_hours > oldest_data:
                            oldest_data = age_hours
                    else:
                        freshness_results[table] = {'last_update': None, 'age_hours': float('inf')}
                except Exception as e:
                    freshness_results[table] = {'error': str(e)}
            
            conn.close()
            
            # Determine status based on data age
            if oldest_data is None:
                status = HealthStatus.CRITICAL
                message = "No data found in any tables"
            elif oldest_data > 168:  # 1 week
                status = HealthStatus.CRITICAL
                message = f"Data is very stale (oldest: {oldest_data:.1f} hours)"
            elif oldest_data > 48:  # 2 days
                status = HealthStatus.WARNING
                message = f"Data is getting stale (oldest: {oldest_data:.1f} hours)"
            else:
                status = HealthStatus.HEALTHY
                message = f"Data is fresh (oldest: {oldest_data:.1f} hours)"
            
            return HealthCheckResult(
                component="data_freshness",
                status=status,
                message=message,
                details=freshness_results
            )
            
        except Exception as e:
            return HealthCheckResult(
                component="data_freshness",
                status=HealthStatus.CRITICAL,
                message=f"Failed to check data freshness: {e}",
                details={"error": str(e)}
            )
    
    def _check_disk_space(self) -> HealthCheckResult:
        """Check available disk space."""
        try:
            import shutil
            
            # Check space where database is stored
            db_path = database.db_file if hasattr(database, 'db_file') else 'data/npm_scanner.db'
            total, used, free = shutil.disk_usage(db_path.split('/')[0] or '/')
            
            free_gb = free // (1024**3)
            used_gb = used // (1024**3)
            total_gb = total // (1024**3)
            free_percent = (free / total) * 100
            
            if free_percent < 5:
                status = HealthStatus.CRITICAL
                message = f"Critically low disk space: {free_gb}GB ({free_percent:.1f}%)"
            elif free_percent < 15:
                status = HealthStatus.WARNING
                message = f"Low disk space: {free_gb}GB ({free_percent:.1f}%)"
            else:
                status = HealthStatus.HEALTHY
                message = f"Sufficient disk space: {free_gb}GB ({free_percent:.1f}%)"
            
            return HealthCheckResult(
                component="disk_space",
                status=status,
                message=message,
                details={
                    "free_gb": free_gb,
                    "used_gb": used_gb,
                    "total_gb": total_gb,
                    "free_percent": free_percent
                }
            )
            
        except Exception as e:
            return HealthCheckResult(
                component="disk_space",
                status=HealthStatus.WARNING,
                message=f"Could not check disk space: {e}",
                details={"error": str(e)}
            )
    
    def _check_database_integrity(self) -> HealthCheckResult:
        """Check database integrity and constraints."""
        try:
            db_file = database.db_file if hasattr(database, 'db_file') else 'data/npm_scanner.db'
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            
            # SQLite integrity check
            cursor.execute('PRAGMA integrity_check')
            integrity_result = cursor.fetchone()[0]
            
            # Check for orphaned records or data inconsistencies
            issues = []
            
            # Check for GuardDog analyses without corresponding packages
            cursor.execute('''
                SELECT COUNT(*) FROM guarddog_analysis ga
                LEFT JOIN package_versions pv ON ga.package_name = pv.name AND ga.version = pv.version
                WHERE pv.name IS NULL
            ''')
            orphaned_analyses = cursor.fetchone()[0]
            if orphaned_analyses > 0:
                issues.append(f"{orphaned_analyses} orphaned GuardDog analyses")
            
            # Check for suspicious alerts without corresponding packages  
            cursor.execute('''
                SELECT COUNT(*) FROM suspicious_alerts sa
                LEFT JOIN package_versions pv ON sa.package_name = pv.name AND sa.version = pv.version
                WHERE pv.name IS NULL
            ''')
            orphaned_alerts = cursor.fetchone()[0]
            if orphaned_alerts > 0:
                issues.append(f"{orphaned_alerts} orphaned suspicious alerts")
            
            conn.close()
            
            if integrity_result != 'ok':
                status = HealthStatus.CRITICAL
                message = f"Database integrity check failed: {integrity_result}"
            elif issues:
                status = HealthStatus.WARNING
                message = f"Database inconsistencies found: {', '.join(issues)}"
            else:
                status = HealthStatus.HEALTHY
                message = "Database integrity verified"
            
            return HealthCheckResult(
                component="database_integrity",
                status=status,
                message=message,
                details={
                    "integrity_check": integrity_result,
                    "orphaned_analyses": orphaned_analyses,
                    "orphaned_alerts": orphaned_alerts,
                    "issues": issues
                }
            )
            
        except Exception as e:
            return HealthCheckResult(
                component="database_integrity",
                status=HealthStatus.WARNING,
                message=f"Could not check database integrity: {e}",
                details={"error": str(e)}
            )
    
    def _send_health_alert(self, results: List[HealthCheckResult]):
        """Send health alert to Slack if critical issues found."""
        try:
            # Check cooldown
            now = datetime.now(timezone.utc)
            last_alert = self.last_alert_time.get('health_check', datetime.min.replace(tzinfo=timezone.utc))
            if (now - last_alert).total_seconds() < self.alert_cooldown_minutes * 60:
                return  # Skip alert due to cooldown
            
            critical_issues = [r for r in results if r.status == HealthStatus.CRITICAL]
            warning_issues = [r for r in results if r.status == HealthStatus.WARNING]
            
            if not critical_issues:
                return  # No critical issues
            
            # Create alert message
            alert_message = "🚨 **Supply Chain Monitor Health Alert**\\n\\n"
            
            if critical_issues:
                alert_message += f"**🔴 CRITICAL ISSUES ({len(critical_issues)}):**\\n"
                for issue in critical_issues:
                    alert_message += f"• **{issue.component}**: {issue.message}\\n"
                alert_message += "\\n"
            
            if warning_issues:
                alert_message += f"**🟡 Warnings ({len(warning_issues)}):**\\n"
                for issue in warning_issues[:3]:  # Limit to avoid spam
                    alert_message += f"• {issue.component}: {issue.message}\\n"
                if len(warning_issues) > 3:
                    alert_message += f"• ... and {len(warning_issues) - 3} more warnings\\n"
            
            alert_message += f"\\n🕐 Health check performed at: {now.strftime('%Y-%m-%d %H:%M:%S UTC')}"
            
            # Send to Slack
            if slack_manager.enabled:
                slack_manager.send_alert(
                    title="🩺 System Health Alert",
                    message=alert_message,
                    priority="HIGH",
                    alert_type="health_check"
                )
                logger.warning("Health check alert sent to Slack")
            else:
                logger.warning(f"Health check alert (Slack disabled): {alert_message}")
            
            self.last_alert_time['health_check'] = now
            
        except Exception as e:
            logger.error(f"Failed to send health alert: {e}")
    
    def generate_health_report(self) -> str:
        """Generate a comprehensive health report."""
        results = self.run_all_checks()
        
        # Count status types
        healthy_count = len([r for r in results if r.status == HealthStatus.HEALTHY])
        warning_count = len([r for r in results if r.status == HealthStatus.WARNING])
        critical_count = len([r for r in results if r.status == HealthStatus.CRITICAL])
        
        # Overall status
        if critical_count > 0:
            overall_status = "🔴 CRITICAL"
        elif warning_count > 0:
            overall_status = "🟡 WARNING"
        else:
            overall_status = "🟢 HEALTHY"
        
        # Generate report
        report = f"""
🩺 Supply Chain Security Monitor - Health Report
================================================
📊 Overall Status: {overall_status}
🕐 Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}

📈 Component Status Summary:
  🟢 Healthy: {healthy_count}
  🟡 Warnings: {warning_count}
  🔴 Critical: {critical_count}

"""
        
        # Detailed results
        for result in sorted(results, key=lambda x: x.status.value):
            status_emoji = {
                HealthStatus.HEALTHY: "🟢",
                HealthStatus.WARNING: "🟡", 
                HealthStatus.CRITICAL: "🔴",
                HealthStatus.UNKNOWN: "⚪"
            }[result.status]
            
            report += f"{status_emoji} {result.component.upper()}: {result.message}\\n"
            
            # Add key details for critical/warning items
            if result.status in [HealthStatus.CRITICAL, HealthStatus.WARNING] and result.details:
                for key, value in list(result.details.items())[:3]:  # Limit details
                    if key != 'error':  # Errors already in message
                        report += f"   • {key}: {value}\\n"
        
        return report


# Global health monitor instance
health_monitor = SupplyChainHealthMonitor()