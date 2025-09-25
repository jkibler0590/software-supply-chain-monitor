# Utility Scripts

This directory contains utility scripts for managing and querying the Software Supply Chain Monitor (SSCM).

## Scripts

### `manage_scanner.py`
Container and database management utility.

```bash
# Container management
python scripts/manage_scanner.py status        # Check container status
python scripts/manage_scanner.py start         # Start the scanner
python scripts/manage_scanner.py stop          # Stop the scanner
python scripts/manage_scanner.py logs          # Show container logs

# Database management
python scripts/manage_scanner.py backup        # Backup database
python scripts/manage_scanner.py restore backup.db  # Restore from backup
python scripts/manage_scanner.py query "SELECT COUNT(*) FROM packages"
```

### `query_database.py`
Database querying utility for interactive and batch SQL execution.

```bash
# Interactive mode
python scripts/query_database.py

# Single query
python scripts/query_database.py "SELECT * FROM packages LIMIT 5"

# Execute from file
python scripts/query_database.py --file queries.sql

# Show statistics
python scripts/query_database.py --stats

# Show schema
python scripts/query_database.py --schema
```

## Usage from Project Root

All scripts should be run from the project root directory:

```bash
cd /path/to/software-supply-chain-monitor
python scripts/manage_scanner.py status
python scripts/query_database.py --stats
```
