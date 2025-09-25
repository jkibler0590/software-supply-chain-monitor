"""
Slack alerting functionality for Supply Chain Security Monitor.

This module handles all Slack notification logic, including alert formatting,
webhook management, and template rendering.
"""
import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime

# Optional Slack SDK import
try:
    from slack_sdk.webhook import WebhookClient
    from slack_sdk.errors import SlackApiError
    SLACK_SDK_AVAILABLE = True
except ImportError:
    SLACK_SDK_AVAILABLE = False
    # Fallback to requests
    try:
        import requests
        REQUESTS_AVAILABLE = True
    except ImportError:
        REQUESTS_AVAILABLE = False

from core.config import config
from core.models import (
    SlackAlert, AlertPriority, RiskLevel, VelocityPattern, 
    GuardDogAnalysis, ThreatDetectionResult, PackageVersion
)

logger = logging.getLogger(__name__)


class SlackAlertManager:
    """Manages Slack alert sending and formatting."""
    
    def __init__(self, webhook_url: Optional[str] = None):
        """Initialize with optional webhook URL override."""
        self.webhook_url = webhook_url or config.SLACK_WEBHOOK_URL
        
        # Initialize client based on available dependencies
        self.client = None
        self.enabled = False
        
        if self.webhook_url:
            if SLACK_SDK_AVAILABLE:
                self.client = WebhookClient(self.webhook_url)
                self.enabled = True
                logger.info("Slack alerts enabled (using slack_sdk)")
            elif REQUESTS_AVAILABLE:
                # Will use requests fallback
                self.enabled = True
                logger.info("Slack alerts enabled (using requests fallback)")
            else:
                logger.warning("Slack alerts disabled - no compatible HTTP client available")
        else:
            logger.warning("Slack alerts disabled - no webhook URL configured")
        
    def is_configured(self) -> bool:
        """Check if Slack alerts are properly configured."""
        return self.enabled
        
    def send_alert(self, alert: SlackAlert) -> bool:
        """Send a SlackAlert to the configured webhook."""
        if not self.enabled:
            logger.warning("Slack alerts disabled")
            return False
            
        try:
            payload = alert.to_webhook_payload()
            
            if self.client and SLACK_SDK_AVAILABLE:
                # Use slack_sdk - remove channel as WebhookClient doesn't support it
                if 'channel' in payload:
                    del payload['channel']
                response = self.client.send(**payload)
                success = response.status_code == 200
            elif REQUESTS_AVAILABLE:
                # Fallback to requests
                import requests
                response = requests.post(
                    self.webhook_url, 
                    json=payload, 
                    timeout=10,
                    verify=config.VERIFY_SSL
                )
                success = response.status_code == 200
            else:
                logger.error("No HTTP client available for Slack alerts")
                return False
            
            if success:
                logger.info(f"Slack alert sent successfully: {alert.title}")
                return True
            else:
                logger.error(f"Slack alert failed with status {response.status_code}")
                return False
                
        except SlackApiError as e:
            logger.error(f"Slack API error: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending Slack alert: {e}")
            return False
    
    def send_startup_notification(self, data: Optional[Dict[str, Any]] = None) -> bool:
        """Send system startup notification."""
        alert = self.create_startup_alert(data)
        return self.send_alert(alert)
    
    def send_threat_detection_alert(self, threat: ThreatDetectionResult) -> bool:
        """Send comprehensive threat detection alert."""
        alert = self.create_threat_detection_alert(threat)
        return self.send_alert(alert)
    
    def send_velocity_pattern_alert(self, pattern: VelocityPattern) -> bool:
        """Send velocity-based pattern detection alert.""" 
        alert = self.create_velocity_pattern_alert(pattern)
        return self.send_alert(alert)
    
    def send_guarddog_alert(self, analysis: GuardDogAnalysis) -> bool:
        """Send GuardDog-specific analysis alert."""
        alert = self.create_guarddog_alert(analysis)
        return self.send_alert(alert)
    
    def send_shutdown_notification(self, data: Optional[Dict[str, Any]] = None) -> bool:
        """Send system shutdown notification.""" 
        alert = self.create_shutdown_alert(data)
        return self.send_alert(alert)
    
    def send_error_notification(self, data: Optional[Dict[str, Any]] = None) -> bool:
        """Send error notification."""
        alert = self.create_error_alert(data)
        return self.send_alert(alert)
    
    def send_scan_summary_alert(self, data: Optional[Dict[str, Any]] = None) -> bool:
        """Send scan summary alert only if there are findings worth reporting."""
        if not data:
            logger.debug("No scan data provided - skipping scan summary alert")
            return False
        
        # Check if there are any meaningful findings to report
        has_findings = self._has_meaningful_findings(data)
        if not has_findings:
            logger.debug("No meaningful findings in scan - skipping scan summary alert")
            return False
            
        alert = self.create_scan_summary_alert(data)
        return self.send_alert(alert)
    
    def _has_meaningful_findings(self, data: Dict[str, Any]) -> bool:
        """Check if scan data contains findings worth reporting."""
        # Check for any alerts or suspicious patterns
        total_alerts = data.get('total_alerts', 0)
        total_patterns = data.get('total_patterns', 0)
        
        if total_alerts > 0 or total_patterns > 0:
            return True
        
        # Check ecosystem-specific findings
        ecosystems_data = data.get('ecosystems', {})
        for ecosystem, eco_data in ecosystems_data.items():
            if eco_data.get('alerts', 0) > 0:
                return True
            if eco_data.get('suspicious_patterns', 0) > 0:
                return True
            if eco_data.get('guarddog_alerts', 0) > 0:
                return True
        
        # No findings worth reporting
        return False
        
    def create_startup_alert(self, data: Optional[Dict[str, Any]] = None) -> SlackAlert:
        """Create system startup notification."""
        # Use provided data or defaults
        ecosystems = data.get('ecosystems_enabled', ['NPM']) if data else ['NPM']
        version = data.get('version', 'Unknown') if data else 'Unknown'
        scan_interval = data.get('scan_interval', config.SCAN_INTERVAL_MINUTES) if data else config.SCAN_INTERVAL_MINUTES
        
        return SlackAlert(
            title="🚀 Supply Chain Security Monitor Started",
            priority=AlertPriority.LOW,
            color="good",
            fields=[],
            attachments=[{
                "color": "good",
                "title": "🚀 Supply Chain Security Monitor Started",
                "fields": [
                    {
                        "title": "📊 Status",
                        "value": "System online and monitoring for threats",
                        "short": True
                    },
                    {
                        "title": "� Version", 
                        "value": version,
                        "short": True
                    },
                    {
                        "title": "⏱️ Scan Interval",
                        "value": f"{scan_interval} minutes",
                        "short": True
                    },
                    {
                        "title": "📡 Monitoring",
                        "value": " + ".join(ecosystems) + " ecosystems",
                        "short": True
                    }
                ],
                "footer": "Supply Chain Security Monitor",
                "ts": int(datetime.now().timestamp())
            }]
        )
    
    def create_threat_detection_alert(self, threat: ThreatDetectionResult) -> SlackAlert:
        """Create comprehensive threat detection alert."""
        pkg = threat.package
        
        # Determine color and priority based on risk level
        color_map = {
            RiskLevel.CRITICAL: "danger",
            RiskLevel.HIGH: "warning",
            RiskLevel.MEDIUM: "warning", 
            RiskLevel.LOW: "good",
            RiskLevel.CLEAN: "good"
        }
        
        color = color_map.get(threat.risk_level, "warning")
        
        # Build fields
        fields = [
            {
                "title": "📦 Package",
                "value": f"`{pkg.name}@{pkg.version}`",
                "short": True
            },
            {
                "title": "👤 Author", 
                "value": f"`{pkg.author}`",
                "short": True
            },
            {
                "title": "🎯 Combined Risk Score",
                "value": f"**{threat.combined_risk_score:.3f}** ({threat.risk_level.value})",
                "short": True
            },
            {
                "title": "🌐 Ecosystem",
                "value": pkg.ecosystem.value.upper(),
                "short": True
            }
        ]
        
        # Add velocity analysis if present
        if threat.velocity_pattern:
            fields.append({
                "title": "⚡ Velocity Analysis",
                "value": f"Pattern: {threat.velocity_pattern.pattern_type}\nDiversity Score: {threat.velocity_pattern.diversity_score:.3f}\nPackages: {len(threat.velocity_pattern.packages)}",
                "short": False
            })
        
        # Add GuardDog findings if present
        if threat.guarddog_analysis and threat.guarddog_analysis.metadata_findings:
            findings_text = "\n".join([f"• {finding}" for finding in threat.guarddog_analysis.metadata_findings[:5]])
            if len(threat.guarddog_analysis.metadata_findings) > 5:
                findings_text += f"\n• ... and {len(threat.guarddog_analysis.metadata_findings) - 5} more"
                
            fields.append({
                "title": "🛡️ GuardDog Findings",
                "value": findings_text,
                "short": False
            })
        
        # Add general security findings
        if threat.security_findings:
            findings_text = "\n".join([f"• {finding.description}" for finding in threat.security_findings[:5]])
            if len(threat.security_findings) > 5:
                findings_text += f"\n• ... and {len(threat.security_findings) - 5} more"
                
            fields.append({
                "title": "🔍 Security Findings",
                "value": findings_text,
                "short": False
            })
        
        return SlackAlert(
            title=f"{threat.alert_priority.value} - Supply Chain Threat Detected",
            priority=threat.alert_priority,
            color=color,
            fields=fields,
            attachments=[{
                "color": color,
                "title": f"{threat.alert_priority.value} - Supply Chain Threat Detected",
                "fields": fields,
                "footer": "Supply Chain Security Monitor",
                "ts": int(datetime.now().timestamp())
            }]
        )
    
    def create_velocity_pattern_alert(self, pattern: VelocityPattern) -> SlackAlert:
        """Create velocity-based pattern alert."""
        # Determine priority based on diversity score and risk level
        if pattern.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH] or pattern.diversity_score >= 0.8:
            priority = AlertPriority.CRITICAL
            color = "danger"
        elif pattern.risk_level == RiskLevel.MEDIUM or pattern.diversity_score >= 0.6:
            priority = AlertPriority.HIGH
            color = "warning"
        else:
            priority = AlertPriority.MEDIUM
            color = "warning"
        
        # Build package list
        package_names = [pkg.name for pkg in pattern.packages[:5]]
        package_text = "\n".join([f"• `{name}`" for name in package_names])
        if len(pattern.packages) > 5:
            package_text += f"\n• ... and {len(pattern.packages) - 5} more packages"
        
        fields = [
            {
                "title": "👤 Author",
                "value": f"`{pattern.author}`", 
                "short": True
            },
            {
                "title": "⚡ Pattern Type",
                "value": pattern.pattern_type.replace('_', ' ').title(),
                "short": True
            },
            {
                "title": "📊 Diversity Score",
                "value": f"**{pattern.diversity_score:.3f}**",
                "short": True
            },
            {
                "title": "📦 Packages Count",
                "value": str(len(pattern.packages)),
                "short": True
            },
            {
                "title": "📋 Package Names", 
                "value": package_text,
                "short": False
            }
        ]
        
        return SlackAlert(
            title=f"{priority.value} - Velocity Pattern Detected",
            priority=priority,
            color=color,
            fields=fields,
            attachments=[{
                "color": color,
                "title": f"{priority.value} - Velocity Pattern Detected", 
                "fields": fields,
                "footer": "Supply Chain Security Monitor",
                "ts": int(datetime.now().timestamp())
            }]
        )
    
    def create_guarddog_alert(self, analysis: GuardDogAnalysis) -> SlackAlert:
        """Create GuardDog-specific alert."""
        # Determine priority and color
        if analysis.risk_level == RiskLevel.CRITICAL:
            priority = AlertPriority.CRITICAL
            color = "danger"
        elif analysis.risk_level == RiskLevel.HIGH:
            priority = AlertPriority.HIGH
            color = "warning"
        else:
            priority = AlertPriority.MEDIUM
            color = "warning"
        
        fields = [
            {
                "title": "📦 Package",
                "value": f"`{analysis.package_name}@{analysis.version}`",
                "short": True
            },
            {
                "title": "🛡️ Risk Level",
                "value": f"**{analysis.risk_level.value}** ({analysis.combined_risk_score:.3f})",
                "short": True
            },
            {
                "title": "📊 Metadata Risk",
                "value": f"{analysis.metadata_risk_score:.3f}",
                "short": True
            }
        ]
        
        if analysis.source_risk_score is not None:
            fields.append({
                "title": "🔍 Source Risk",
                "value": f"{analysis.source_risk_score:.3f}",
                "short": True
            })
        
        # Add findings
        all_findings = analysis.metadata_findings + analysis.source_findings
        if all_findings:
            findings_text = "\n".join([f"• {finding}" for finding in all_findings[:8]])
            if len(all_findings) > 8:
                findings_text += f"\n• ... and {len(all_findings) - 8} more"
                
            fields.append({
                "title": "🔍 Security Findings",
                "value": findings_text,
                "short": False
            })
        
        return SlackAlert(
            title=f"{priority.value} - GuardDog Detection",
            priority=priority,
            color=color,
            fields=fields,
            attachments=[{
                "color": color,
                "title": f"{priority.value} - GuardDog Detection",
                "fields": fields,
                "footer": "Supply Chain Security Monitor - GuardDog",
                "ts": int(datetime.now().timestamp())
            }]
        )
    
    def create_shutdown_alert(self, data: Optional[Dict[str, Any]] = None) -> SlackAlert:
        """Create system shutdown notification."""
        total_scans = data.get('total_scans', 0) if data else 0
        reason = data.get('reason', 'Unknown') if data else 'Unknown'
        
        return SlackAlert(
            title="🛑 Supply Chain Security Monitor Stopped",
            priority=AlertPriority.LOW,
            color="warning",
            fields=[],
            attachments=[{
                "color": "warning",
                "title": "🛑 Supply Chain Security Monitor Stopped",
                "fields": [
                    {
                        "title": "📊 Total Scans Completed",
                        "value": str(total_scans),
                        "short": True
                    },
                    {
                        "title": "🔄 Shutdown Reason", 
                        "value": reason,
                        "short": True
                    }
                ],
                "footer": "Supply Chain Security Monitor",
                "ts": int(datetime.now().timestamp())
            }]
        )
    
    def create_error_alert(self, data: Optional[Dict[str, Any]] = None) -> SlackAlert:
        """Create error notification."""
        error_message = data.get('error_message', 'Unknown error') if data else 'Unknown error'
        scan_cycle = data.get('scan_cycle', 0) if data else 0
        
        return SlackAlert(
            title="❌ Supply Chain Monitor Error",
            priority=AlertPriority.HIGH,
            color="danger",
            fields=[],
            attachments=[{
                "color": "danger",
                "title": "❌ Supply Chain Monitor Error",
                "fields": [
                    {
                        "title": "🔄 Scan Cycle",
                        "value": str(scan_cycle),
                        "short": True
                    },
                    {
                        "title": "❌ Error Message", 
                        "value": error_message,
                        "short": False
                    }
                ],
                "footer": "Supply Chain Security Monitor",
                "ts": int(datetime.now().timestamp())
            }]
        )
    
    def create_scan_summary_alert(self, data: Optional[Dict[str, Any]] = None) -> SlackAlert:
        """Create scan summary notification."""
        if not data:
            data = {}
            
        scan_id = data.get('scan_id', 'Unknown')
        ecosystems = data.get('ecosystems', [])
        duration = data.get('duration_seconds', 0)
        total_packages = data.get('total_packages', 0)
        total_alerts = data.get('total_alerts', 0)
        error_count = data.get('error_count', 0)
        
        return SlackAlert(
            title="📊 Scan Summary",
            priority=AlertPriority.LOW,
            color="good",
            fields=[],
            attachments=[{
                "color": "good",
                "title": f"📊 Scan Summary - {scan_id}",
                "fields": [
                    {
                        "title": "🌍 Ecosystems",
                        "value": ", ".join(ecosystems),
                        "short": True
                    },
                    {
                        "title": "⏱️ Duration",
                        "value": f"{duration:.1f} seconds",
                        "short": True
                    },
                    {
                        "title": "📦 Packages Processed",
                        "value": str(total_packages),
                        "short": True
                    },
                    {
                        "title": "🚨 Alerts Sent",
                        "value": str(total_alerts),
                        "short": True
                    }
                ] + ([{
                    "title": "⚠️ Errors",
                    "value": str(error_count),
                    "short": True
                }] if error_count > 0 else []),
                "footer": "Supply Chain Security Monitor",
                "ts": int(datetime.now().timestamp())
            }]
        )


# Global instance with graceful fallback
try:
    slack_manager = SlackAlertManager()
except Exception as e:
    logger.warning(f"Failed to initialize Slack manager: {e}")
    # Create a dummy slack manager for graceful degradation
    class DummySlackManager:
        def __init__(self):
            self.enabled = False
            
        def is_configured(self):
            return False
            
        def send_alert(self, alert):
            logger.info(f"Slack disabled - would send: {getattr(alert, 'title', 'Unknown alert')}")
            return False
            
        def send_velocity_pattern_alert(self, pattern):
            logger.info(f"Slack disabled - velocity pattern alert for: {pattern.author}")
            return False
            
        def send_guarddog_alert(self, analysis):
            logger.info(f"Slack disabled - GuardDog alert for: {analysis.package_name}")
            return False
            
        def send_threat_detection_alert(self, result):
            logger.info(f"Slack disabled - threat detection alert")
            return False
            
        def send_startup_notification(self, data=None):
            logger.info("Slack disabled - startup notification")
            return False
            
        def send_shutdown_notification(self, data=None):
            logger.info("Slack disabled - shutdown notification")
            return False
            
        def send_error_notification(self, data=None):
            logger.info(f"Slack disabled - error notification: {data.get('error_message', 'Unknown') if data else 'Unknown'}")
            return False
            
        def send_scan_summary_alert(self, data=None):
            logger.info(f"Slack disabled - scan summary for: {data.get('scan_id', 'Unknown') if data else 'Unknown'}")
            return False
    
    slack_manager = DummySlackManager()


# Legacy compatibility functions
def send_slack_alert(pattern: Dict) -> bool:
    """Legacy compatibility function."""
    # Convert old format to new models if needed
    # This is a temporary bridge during migration
    logger.warning("Using legacy send_slack_alert - consider updating to new SlackAlertManager")
    return slack_manager.enabled
