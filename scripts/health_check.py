#!/usr/bin/env python3
"""
Supply Chain Health Check Script

Usage:
  python3 scripts/health_check.py [options]

Options:
  --report           Generate detailed health report
  --alert            Send alerts for critical issues  
  --continuous       Run continuously with specified interval
  --interval MINS    Check interval in minutes (default: 60)
  --quiet            Suppress normal output, only show issues
"""
import sys
import time
import argparse
import logging
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from core.health_monitor import health_monitor, HealthStatus
from core.config import config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def run_health_check(args):
    """Run health checks based on command line arguments."""
    try:
        print("🩺 Running Supply Chain Health Check...")
        
        if not args.quiet:
            print("=" * 50)
        
        results = health_monitor.run_all_checks()
        
        # Count results by status
        healthy = [r for r in results if r.status == HealthStatus.HEALTHY]
        warnings = [r for r in results if r.status == HealthStatus.WARNING]
        critical = [r for r in results if r.status == HealthStatus.CRITICAL]
        
        # Print summary
        if not args.quiet:
            print(f"📊 Health Check Complete:")
            print(f"  🟢 Healthy: {len(healthy)}")
            print(f"  🟡 Warnings: {len(warnings)}")  
            print(f"  🔴 Critical: {len(critical)}")
            print()
        
        # Show issues
        if critical:
            print("🔴 CRITICAL ISSUES:")
            for result in critical:
                print(f"  • {result.component}: {result.message}")
                if args.report and result.details:
                    for key, value in result.details.items():
                        if key != 'error':
                            print(f"    - {key}: {value}")
            print()
        
        if warnings and not args.quiet:
            print("🟡 WARNINGS:")
            for result in warnings:
                print(f"  • {result.component}: {result.message}")
            print()
        
        if healthy and args.report:
            print("🟢 HEALTHY COMPONENTS:")
            for result in healthy:
                print(f"  • {result.component}: {result.message}")
            print()
        
        # Generate full report if requested
        if args.report:
            print("\\n" + health_monitor.generate_health_report())
        
        # Return appropriate exit code
        if critical:
            return 2  # Critical issues
        elif warnings:
            return 1  # Warnings only
        else:
            return 0  # All healthy
            
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        print(f"❌ Health check failed: {e}")
        return 3  # Health check failure


def continuous_monitoring(interval_minutes):
    """Run health checks continuously at specified interval."""
    print(f"🔄 Starting continuous health monitoring (interval: {interval_minutes} minutes)")
    
    try:
        while True:
            print(f"\\n⏰ {time.strftime('%Y-%m-%d %H:%M:%S')} - Running health check...")
            
            results = health_monitor.run_all_checks()
            
            # Count issues
            critical = [r for r in results if r.status == HealthStatus.CRITICAL]
            warnings = [r for r in results if r.status == HealthStatus.WARNING]
            
            if critical:
                print(f"🔴 {len(critical)} critical issues found:")
                for result in critical:
                    print(f"  • {result.component}: {result.message}")
            elif warnings:
                print(f"🟡 {len(warnings)} warnings found:")
                for result in warnings:
                    print(f"  • {result.component}: {result.message}")
            else:
                print("🟢 All systems healthy")
            
            print(f"💤 Sleeping for {interval_minutes} minutes...")
            time.sleep(interval_minutes * 60)
            
    except KeyboardInterrupt:
        print("\\n🛑 Continuous monitoring stopped by user")
    except Exception as e:
        logger.error(f"Continuous monitoring failed: {e}")
        print(f"❌ Continuous monitoring failed: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Supply Chain Security Monitor - Health Check",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--report',
        action='store_true',
        help='Generate detailed health report'
    )
    
    parser.add_argument(
        '--alert',
        action='store_true', 
        help='Send alerts for critical issues'
    )
    
    parser.add_argument(
        '--continuous',
        action='store_true',
        help='Run continuously with specified interval'
    )
    
    parser.add_argument(
        '--interval',
        type=int,
        default=60,
        metavar='MINS',
        help='Check interval in minutes for continuous mode (default: 60)'
    )
    
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Suppress normal output, only show issues'
    )
    
    args = parser.parse_args()
    
    if args.continuous:
        continuous_monitoring(args.interval)
    else:
        exit_code = run_health_check(args)
        sys.exit(exit_code)


if __name__ == '__main__':
    main()