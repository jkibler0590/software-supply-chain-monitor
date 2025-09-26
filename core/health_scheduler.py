"""
Health Check Scheduler

Integrates health monitoring into the main orchestrator system.
Runs periodic health checks and sends alerts when issues are detected.
"""
import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from core.health_monitor import health_monitor, HealthStatus

logger = logging.getLogger(__name__)


class HealthCheckScheduler:
    """Schedules and manages periodic health checks."""
    
    def __init__(self, check_interval_minutes: int = 60):
        self.check_interval_minutes = check_interval_minutes
        self.running = False
        self.last_check_time: Optional[datetime] = None
        self.consecutive_failures = 0
        self.max_consecutive_failures = 3
        
    async def start_monitoring(self):
        """Start periodic health monitoring."""
        if self.running:
            logger.warning("Health monitoring already running")
            return
            
        self.running = True
        logger.info(f"Starting health monitoring (interval: {self.check_interval_minutes} minutes)")
        
        try:
            while self.running:
                await self._run_health_check()
                
                # Wait for next check interval
                await asyncio.sleep(self.check_interval_minutes * 60)
                
        except asyncio.CancelledError:
            logger.info("Health monitoring cancelled")
        except Exception as e:
            logger.error(f"Health monitoring failed: {e}")
        finally:
            self.running = False
    
    def stop_monitoring(self):
        """Stop health monitoring."""
        self.running = False
        logger.info("Health monitoring stopped")
    
    async def _run_health_check(self):
        """Run health check and handle results."""
        try:
            self.last_check_time = datetime.now(timezone.utc)
            
            logger.info("Running scheduled health check...")
            results = health_monitor.run_all_checks()
            
            # Count issues
            critical = [r for r in results if r.status == HealthStatus.CRITICAL]
            warnings = [r for r in results if r.status == HealthStatus.WARNING]
            healthy = [r for r in results if r.status == HealthStatus.HEALTHY]
            
            # Log summary
            logger.info(f"Health check complete: {len(healthy)} healthy, {len(warnings)} warnings, {len(critical)} critical")
            
            # Log critical issues
            if critical:
                self.consecutive_failures += 1
                logger.warning(f"Critical health issues detected ({self.consecutive_failures}/{self.max_consecutive_failures} consecutive):")
                for result in critical:
                    logger.warning(f"  - {result.component}: {result.message}")
                    
                # Escalate if too many consecutive failures
                if self.consecutive_failures >= self.max_consecutive_failures:
                    logger.critical(f"System has been unhealthy for {self.consecutive_failures} consecutive checks!")
                    await self._escalate_critical_issues(critical)
            else:
                # Reset failure counter if we're healthy
                if self.consecutive_failures > 0:
                    logger.info(f"System recovered after {self.consecutive_failures} failed checks")
                self.consecutive_failures = 0
            
            # Log warnings
            for result in warnings:
                logger.warning(f"Health warning - {result.component}: {result.message}")
                
        except Exception as e:
            self.consecutive_failures += 1
            logger.error(f"Health check execution failed ({self.consecutive_failures}/{self.max_consecutive_failures}): {e}")
    
    async def _escalate_critical_issues(self, critical_issues):
        """Escalate persistent critical issues."""
        try:
            # Additional alerting for persistent issues
            escalation_message = f"""
🚨 **ESCALATED ALERT: System Persistently Unhealthy**

The Supply Chain Security Monitor has been unhealthy for {self.consecutive_failures} consecutive health checks.

**Critical Issues:**
"""
            for issue in critical_issues:
                escalation_message += f"• **{issue.component}**: {issue.message}\\n"
            
            escalation_message += f"""
**Next Actions Required:**
1. Investigate system components immediately
2. Check logs for detailed error information  
3. Verify database connectivity and GuardDog service
4. Restart services if necessary

**System Status**: CRITICAL - Immediate attention required
**Check Interval**: {self.check_interval_minutes} minutes
**Consecutive Failures**: {self.consecutive_failures}
"""
            
            # Send escalated alert
            from notifications.slack_alerts import slack_manager
            if slack_manager.enabled:
                slack_manager.send_alert(
                    title="🆘 ESCALATED: System Persistently Unhealthy", 
                    message=escalation_message,
                    priority="CRITICAL",
                    alert_type="health_escalation"
                )
                logger.critical("Escalated health alert sent to Slack")
            else:
                logger.critical(f"Escalated alert (Slack disabled): {escalation_message}")
                
        except Exception as e:
            logger.error(f"Failed to escalate critical health issues: {e}")
    
    def get_status(self) -> dict:
        """Get current scheduler status."""
        return {
            'running': self.running,
            'check_interval_minutes': self.check_interval_minutes,
            'last_check_time': self.last_check_time.isoformat() if self.last_check_time else None,
            'consecutive_failures': self.consecutive_failures,
            'max_consecutive_failures': self.max_consecutive_failures
        }
    
    async def run_manual_check(self) -> dict:
        """Run a manual health check and return results."""
        logger.info("Running manual health check...")
        results = health_monitor.run_all_checks()
        
        # Convert results to serializable format
        result_data = []
        for result in results:
            result_data.append({
                'component': result.component,
                'status': result.status.value,
                'message': result.message,
                'details': result.details,
                'timestamp': result.timestamp.isoformat()
            })
        
        return {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'results': result_data,
            'summary': {
                'healthy': len([r for r in results if r.status == HealthStatus.HEALTHY]),
                'warnings': len([r for r in results if r.status == HealthStatus.WARNING]),
                'critical': len([r for r in results if r.status == HealthStatus.CRITICAL])
            }
        }


# Global scheduler instance
health_scheduler = HealthCheckScheduler()