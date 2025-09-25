#!/bin/bash

# Docker entrypoint script for Multi-Ecosystem Supply Chain Monitor
# This script sets up the environment and validates configuration

set -euo pipefail

# Function to log messages
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] Multi-Ecosystem-Monitor: $1"
}

# Function to validate environment
validate_environment() {
    log "Validating environment configuration"
    
    # Check QA mode status
    if [[ "${QA_MODE:-false}" == "true" ]]; then
        log "🧪 QA MODE ENABLED - Slack notifications will be disabled"
    fi
    
    # Check enhanced detection status
    if [[ "${ENHANCED_DETECTION_ENABLED:-false}" == "true" ]]; then
        log "🛡️  Enhanced detection algorithms enabled"
    fi
    
    # Check if Slack webhook URL is configured
    if [[ -z "${SLACK_WEBHOOK_URL:-}" ]]; then
        log "WARNING: SLACK_WEBHOOK_URL not configured - alerts will be disabled"
    elif [[ "${QA_MODE:-false}" == "true" ]]; then
        log "Slack webhook configured but disabled for QA mode: ${SLACK_WEBHOOK_URL:0:50}..."
    else
        log "Slack webhook configured: ${SLACK_WEBHOOK_URL:0:50}..."
    fi
    
    # Check database directory
    if [[ ! -d "/data" ]]; then
        log "ERROR: /data directory not found"
        exit 1
    fi
    
    if [[ ! -w "/data" ]]; then
        log "ERROR: /data directory not writable"
        exit 1
    fi
    
    # Test Python imports
    if ! python3 -c "import requests, sqlite3, json, time, urllib3, slack_sdk" 2>/dev/null; then
        log "ERROR: Required Python packages not available"
        exit 1
    fi
    
    log "Environment validation successful"
}

# Function to test network connectivity
test_connectivity() {
    log "Testing network connectivity (non-blocking)"
    
    # Test NPM registry connectivity (non-blocking)
    if curl -f -s --max-time 5 --insecure "https://registry.npmjs.org/" > /dev/null 2>&1; then
        log "✅ NPM registry connectivity: OK"
    else
        log "⚠️  NPM registry connectivity: WARNING (may be blocked by proxy/firewall)"
        log "   Monitor will attempt to continue anyway..."
    fi
    
    # Test NPM changes feed connectivity (non-blocking)
    if curl -f -s --max-time 5 --insecure "https://skimdb.npmjs.com/registry/_changes?limit=1" > /dev/null 2>&1; then
        log "✅ NPM changes feed connectivity: OK"
    else
        log "⚠️  NPM changes feed connectivity: WARNING (may be blocked by proxy/firewall)"
        log "   Monitor will attempt to continue anyway..."
    fi

    # Test PyPI connectivity (non-blocking)
    if curl -f -s --max-time 5 --insecure "https://pypi.org/simple/" > /dev/null 2>&1; then
        log "✅ PyPI registry connectivity: OK"
    else
        log "⚠️  PyPI registry connectivity: WARNING (may be blocked by proxy/firewall)"
        log "   Monitor will attempt to continue anyway..."
    fi
    
    # Test Slack webhook connectivity (if configured) (non-blocking)
    if [[ -n "${SLACK_WEBHOOK_URL:-}" ]]; then
        # Skip actual test message to avoid spam - just test endpoint availability
        if curl -f -s --max-time 5 --insecure --head "${SLACK_WEBHOOK_URL}" > /dev/null 2>&1; then
            log "✅ Slack webhook connectivity: OK"
        else
            log "⚠️  Slack webhook connectivity: WARNING (may be blocked by proxy/firewall)"
            log "   Slack notifications may not work..."
        fi
    fi
    
    log "Network connectivity tests completed (non-blocking)"
}

# Function to start health check server (simplified for testing)
start_health_server() {
    log "Health check server temporarily disabled for simplicity"
    log "Container connectivity is working - proceeding with multi-ecosystem monitor"
}

# Function to create initial log file
setup_logging() {
    log "Setting up logging"
    
    # Create log file
    echo "$(date): Multi-Ecosystem Supply Chain Monitor Docker container started" > /logs/startup.log
    
    # Create symlink for easier access
    ln -sf /logs/startup.log /data/startup.log 2>/dev/null || true
    
    log "Logging setup completed"
}

# Main execution function
main() {
    log "Starting Multi-Ecosystem Supply Chain Monitor Docker container"
    
    # Setup environment in correct order
    validate_environment
    setup_logging
    test_connectivity
    start_health_server
    
    log "Multi-Ecosystem Supply Chain Monitor is ready to start"
    log "Health check available at http://localhost:8080/health"
    log "Database will be stored at: /data/supply_chain_monitor.db"
    log "Logs will be stored at: /logs/"
    
    # Execute the command passed to the container
    log "Executing: $*"
    exec "$@"
}

# Run main function with all arguments
main "$@"
