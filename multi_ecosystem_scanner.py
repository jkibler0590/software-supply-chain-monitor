"""
Supply Chain Security Scanner - Modular Multi-Ecosystem Entry Point.

This is the main entry point for the modular multi-ecosystem scanner.
"""
import logging
import sys
import os
import asyncio
import signal
import time
from pathlib import Path
from datetime import datetime, timezone
import warnings

# Suppress SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Suppress general SSL warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Add the project root to Python path for imports
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global flag for graceful shutdown
shutdown_requested = False


def signal_handler(signum, frame):
    """Handle graceful shutdown signals."""
    global shutdown_requested
    logger.info(f"Received signal {signum}, initiating graceful shutdown...")
    shutdown_requested = True


# Register signal handlers
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def main():
    """Main entry point for Supply Chain Security Scanner."""
    global shutdown_requested
    
    print("🚀 Supply Chain Security Scanner - Multi-Ecosystem")
    print("=" * 60)
    
    try:
        # Import modular components
        from orchestrator import orchestrator
        from core.config import config
        from notifications.slack_alerts import slack_manager
        
        print("✅ Modular architecture loaded successfully")
        
        # Show available ecosystems
        available_ecosystems = list(orchestrator.scanners.keys())
        print(f"📦 Available ecosystems: {[eco.value for eco in available_ecosystems]}")
        
        # Validate system configuration
        validation = orchestrator.validate_configuration()
        if not validation['overall_healthy']:
            print("❌ System validation failed:")
            for error in validation['errors']:
                print(f"   - {error}")
            return 1
        
        print("✅ System validation passed")
        
        # Send startup notification
        startup_data = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'version': 'Multi-Ecosystem Scanner v3.0',
            'scan_interval': config.SCAN_INTERVAL_MINUTES,
            'ecosystems_enabled': [eco.value for eco in available_ecosystems]
        }
        slack_manager.send_startup_notification(startup_data)
        
        scan_count = 0
        
        # Main scanning loop
        while not shutdown_requested:
            try:
                scan_count += 1
                print(f"\n🔍 Starting multi-ecosystem scan #{scan_count}")
                print(f"   Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"   Ecosystems: {[eco.value for eco in available_ecosystems]}")
                
                # Run multi-ecosystem scan
                scan_result = asyncio.run(orchestrator.run_multi_ecosystem_scan())
                
                print(f"✅ Multi-ecosystem scan #{scan_count} completed")
                print(f"   Total packages processed: {scan_result.total_packages_processed}")
                print(f"   Total alerts sent: {scan_result.total_alerts_sent}")
                print(f"   Total patterns detected: {scan_result.total_patterns_detected}")
                
                # Show per-ecosystem results
                for ecosystem, session in scan_result.sessions.items():
                    print(f"   {ecosystem.value}: {session.packages_processed} packages, {session.alerts_sent} alerts")
                
                if scan_result.errors:
                    print(f"   ⚠️  Non-critical errors: {len(scan_result.errors)}")
                
                if config.SCAN_INTERVAL_MINUTES > 0 and not shutdown_requested:
                    print(f"\n💤 Sleeping for {config.SCAN_INTERVAL_MINUTES} minutes until next scan...")
                    
                    # Sleep in smaller chunks to allow for responsive shutdown
                    sleep_time = config.SCAN_INTERVAL_MINUTES * 60
                    sleep_chunk = 10  # seconds
                    
                    while sleep_time > 0 and not shutdown_requested:
                        time.sleep(min(sleep_chunk, sleep_time))
                        sleep_time -= sleep_chunk
                else:
                    print("Single scan mode completed.")
                    break
                    
            except Exception as e:
                logger.error(f"Error in scan cycle #{scan_count}: {e}")
                
                # Send error notification
                error_data = {
                    'scan_cycle': scan_count,
                    'error_message': str(e),
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }
                slack_manager.send_error_notification(error_data)
                
                if config.SCAN_INTERVAL_MINUTES <= 0:
                    return 1  # Exit on error in single scan mode
                
                # Continue with next cycle in continuous mode
                continue
        
        # Graceful shutdown
        print("\n🛑 Graceful shutdown initiated...")
        
        # Send shutdown notification
        shutdown_data = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'total_scans': scan_count,
            'reason': 'Manual shutdown' if shutdown_requested else 'Completed'
        }
        slack_manager.send_shutdown_notification(shutdown_data)
        
        print("✅ Scanner stopped gracefully")
        return 0
        
    except ImportError as e:
        print(f"❌ Failed to load modular architecture: {e}")
        print("   Please ensure all modules are properly installed")
        return 1
    except Exception as e:
        logger.error(f"Critical error in main: {e}")
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
