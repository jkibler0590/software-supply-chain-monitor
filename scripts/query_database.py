#!/usr/bin/env python3
"""
SQLite Query Script for NPM Scanner Database
============================================

This script allows you to execute SQLite queries against the NPM Scanner database
running inside the Docker container. It provides both interactive and batch query
execution capabilities.

Usage:
    python query_database.py                           # Interactive mode
    python query_database.py "SELECT * FROM package_versions LIMIT 5"  # Single query
    python query_database.py --file queries.sql       # Execute from file
    python query_database.py --stats                   # Show database statistics
    python query_database.py --schema                  # Show database schema
"""

import subprocess
import sys
import json
import argparse
from datetime import datetime
from typing import List, Optional, Dict, Any

class NPMDatabaseQuerier:
    """Execute SQLite queries against the NPM Scanner database in Docker container."""
    
    def __init__(self, container_name: str = "software-supply-chain-monitor"):
        self.container_name = container_name
        self.db_path = "/data/supply_chain_monitor.db"
    
    def _execute_container_command(self, command: str) -> tuple[str, str, int]:
        """Execute a command inside the Docker container."""
        docker_cmd = [
            "docker", "exec", "-i", self.container_name,
            "sh", "-c", command
        ]
        
        try:
            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=60  # Increased timeout to 60 seconds
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "Query timeout after 60 seconds", 1
        except Exception as e:
            return "", f"Error executing command: {str(e)}", 1
    
    def check_container_status(self) -> bool:
        """Check if the container is running and accessible."""
        stdout, stderr, returncode = self._execute_container_command("echo 'Container accessible'")
        if returncode != 0:
            print(f"❌ Container '{self.container_name}' is not accessible:")
            print(f"   Error: {stderr}")
            print(f"   Make sure the container is running: docker ps")
            return False
        return True
    
    def execute_query(self, query: str) -> tuple[List[Dict[str, Any]], str]:
        """
        Execute a SQLite query and return results.
        
        Returns:
            tuple: (results_list, error_message)
        """
        # Sanitize and prepare the query
        query = query.strip()
        if not query:
            return [], "Empty query provided"
        
        # Ensure query ends with semicolon
        if not query.endswith(';'):
            query += ';'
        
        # Create a simple Python one-liner to execute the query
        # We'll use base64 to avoid shell escaping issues
        import base64
        
        python_script = f"""
import sqlite3, json, sys
try:
    conn = sqlite3.connect('{self.db_path}')
    conn.row_factory = sqlite3.Row
    cursor = conn.execute('''{query}''')
    results = [dict(row) for row in cursor]
    conn.close()
    print(json.dumps(results, default=str))
except Exception as e:
    print(f'ERROR: {{e}}', file=sys.stderr)
    sys.exit(1)
""".strip()
        
        # Encode the script to base64 to avoid shell escaping issues
        script_b64 = base64.b64encode(python_script.encode()).decode()
        
        # Execute the base64-encoded script
        python_cmd = f"python3 -c \"import base64; exec(base64.b64decode('{script_b64}').decode())\""
        stdout, stderr, returncode = self._execute_container_command(python_cmd)
        
        if returncode != 0:
            return [], f"SQLite error: {stderr}"
        
        try:
            # Parse JSON output
            if stdout.strip():
                results = json.loads(stdout)
                return results, ""
            else:
                return [], ""
        except json.JSONDecodeError as e:
            # Fallback for non-JSON output
            if stdout.strip():
                return [{"output": stdout.strip()}], ""
            return [], f"Failed to parse query results: {str(e)}"
    
    def get_database_stats(self) -> Dict[str, Any]:
        """Get comprehensive database statistics."""
        stats_queries = {
            "total_packages": "SELECT COUNT(*) as count FROM package_versions",
            "unique_packages": "SELECT COUNT(DISTINCT package_name) as count FROM package_versions",
            "unique_authors": "SELECT COUNT(DISTINCT author) as count FROM package_versions WHERE author != ''",
            "total_alerts": "SELECT COUNT(*) as count FROM suspicious_alerts",
            "latest_package": "SELECT package_name, version, author, published_at FROM package_versions ORDER BY published_at DESC LIMIT 1",
            "oldest_package": "SELECT package_name, version, author, published_at FROM package_versions ORDER BY published_at ASC LIMIT 1",
            "top_authors": "SELECT author, COUNT(*) as package_count FROM package_versions WHERE author != '' GROUP BY author ORDER BY package_count DESC LIMIT 5",
            "recent_alerts": "SELECT COUNT(*) as count FROM suspicious_alerts WHERE alert_time > datetime('now', '-24 hours')"
        }
        
        stats = {}
        for name, query in stats_queries.items():
            results, error = self.execute_query(query)
            if error:
                stats[name] = f"Error: {error}"
            elif results:
                if name in ["latest_package", "oldest_package"]:
                    stats[name] = results[0] if results else "No data"
                elif name == "top_authors":
                    stats[name] = results
                else:
                    stats[name] = results[0].get("count", 0) if results else 0
            else:
                stats[name] = 0
        
        return stats
    
    def get_database_schema(self) -> List[Dict[str, Any]]:
        """Get database schema information."""
        schema_queries = [
            "SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name",
            "PRAGMA table_info(package_versions)",
            "PRAGMA table_info(suspicious_alerts)"
        ]
        
        schema_info = {}
        
        # Get table definitions
        results, error = self.execute_query(schema_queries[0])
        if not error and results:
            schema_info["tables"] = results
        
        # Get column info for package_versions
        results, error = self.execute_query(schema_queries[1])
        if not error and results:
            schema_info["package_versions_columns"] = results
        
        # Get column info for suspicious_alerts
        results, error = self.execute_query(schema_queries[2])
        if not error and results:
            schema_info["suspicious_alerts_columns"] = results
        
        return schema_info
    
    def format_results(self, results: List[Dict[str, Any]], max_width: int = 100, no_truncate: bool = False) -> str:
        """Format query results for display."""
        if not results:
            return "No results found."
        
        # Handle single column results
        if len(results[0]) == 1:
            key = list(results[0].keys())[0]
            return "\n".join(str(row[key]) for row in results)
        
        # Format as table
        output = []
        headers = list(results[0].keys())
        
        # Calculate column widths
        col_widths = {}
        for header in headers:
            col_widths[header] = max(
                len(header),
                max(len(str(row.get(header, ""))) for row in results),
                10  # minimum width
            )
            
            # Apply width limits only if truncation is enabled
            if not no_truncate:
                # Limit maximum column width based on terminal width
                col_widths[header] = min(col_widths[header], max_width // len(headers))
        
        # Create header row
        if no_truncate:
            header_row = " | ".join(header.ljust(col_widths[header]) for header in headers)
        else:
            header_row = " | ".join(header.ljust(col_widths[header]) for header in headers)
        separator = "-" * len(header_row)
        
        output.append(header_row)
        output.append(separator)
        
        # Add data rows
        for row in results:
            if no_truncate:
                data_row = " | ".join(
                    str(row.get(header, "")).ljust(col_widths[header])
                    for header in headers
                )
            else:
                data_row = " | ".join(
                    str(row.get(header, "")).ljust(col_widths[header])[:col_widths[header]]
                    for header in headers
                )
            output.append(data_row)
        
        return "\n".join(output)

def print_stats(querier: NPMDatabaseQuerier):
    """Print database statistics."""
    print("📊 NPM Scanner Database Statistics")
    print("=" * 50)
    
    stats = querier.get_database_stats()
    
    print(f"📦 Total package versions: {stats.get('total_packages', 0):,}")
    print(f"🔍 Unique packages: {stats.get('unique_packages', 0):,}")
    print(f"👤 Unique authors: {stats.get('unique_authors', 0):,}")
    print(f"🚨 Total alerts: {stats.get('total_alerts', 0):,}")
    print(f"⚡ Recent alerts (24h): {stats.get('recent_alerts', 0):,}")
    
    if isinstance(stats.get('latest_package'), dict):
        latest = stats['latest_package']
        print(f"\n📅 Latest package: {latest.get('package_name', 'N/A')}@{latest.get('version', 'N/A')}")
        print(f"   Author: {latest.get('author', 'N/A')}")
        print(f"   Published: {latest.get('published_at', 'N/A')}")
    
    top_authors = stats.get('top_authors', [])
    if top_authors and isinstance(top_authors, list):
        print(f"\n🏆 Top 5 Authors by Package Count:")
        for i, author_info in enumerate(top_authors[:5], 1):
            print(f"   {i}. {author_info.get('author', 'N/A')}: {author_info.get('package_count', 0)} packages")

def print_schema(querier: NPMDatabaseQuerier):
    """Print database schema information."""
    print("🗂️  NPM Scanner Database Schema")
    print("=" * 50)
    
    schema = querier.get_database_schema()
    
    if "tables" in schema:
        print("📋 Tables:")
        for table in schema["tables"]:
            print(f"   • {table.get('name', 'unknown')}")
    
    if "package_versions_columns" in schema:
        print(f"\n📦 package_versions table columns:")
        for col in schema["package_versions_columns"]:
            col_name = col.get('name', 'unknown')
            col_type = col.get('type', 'unknown')
            is_pk = col.get('pk', 0)
            not_null = col.get('notnull', 0)
            
            flags = []
            if is_pk: flags.append("PK")
            if not_null: flags.append("NOT NULL")
            flag_str = f" ({', '.join(flags)})" if flags else ""
            
            print(f"   • {col_name}: {col_type}{flag_str}")
    
    if "suspicious_alerts_columns" in schema:
        print(f"\n🚨 suspicious_alerts table columns:")
        for col in schema["suspicious_alerts_columns"]:
            col_name = col.get('name', 'unknown')
            col_type = col.get('type', 'unknown')
            is_pk = col.get('pk', 0)
            not_null = col.get('notnull', 0)
            
            flags = []
            if is_pk: flags.append("PK")
            if not_null: flags.append("NOT NULL")
            flag_str = f" ({', '.join(flags)})" if flags else ""
            
            print(f"   • {col_name}: {col_type}{flag_str}")

def interactive_mode(querier: NPMDatabaseQuerier):
    """Run interactive query mode."""
    print("🔍 NPM Scanner Database Interactive Query Mode")
    print("=" * 60)
    print("Type your SQLite queries below. Commands:")
    print("  - Type 'quit' or 'exit' to leave")
    print("  - Type 'stats' for database statistics")
    print("  - Type 'schema' for database schema")
    print("  - Type 'help' for example queries")
    print("=" * 60)
    
    while True:
        try:
            query = input("\n📝 SQL> ").strip()
            
            if query.lower() in ['quit', 'exit', 'q']:
                print("👋 Goodbye!")
                break
            elif query.lower() == 'stats':
                print_stats(querier)
                continue
            elif query.lower() == 'schema':
                print_schema(querier)
                continue
            elif query.lower() == 'help':
                print_help_examples()
                continue
            elif not query:
                continue
            
            print(f"⏳ Executing query...")
            results, error = querier.execute_query(query)
            
            if error:
                print(f"❌ Error: {error}")
            else:
                formatted_results = querier.format_results(results, no_truncate=True)  # No truncate in interactive mode
                print(f"✅ Results ({len(results)} rows):")
                print(formatted_results)
                
        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"❌ Unexpected error: {e}")

def print_help_examples():
    """Print example queries."""
    examples = [
        ("Show recent packages", "SELECT package_name, version, author, published_at FROM package_versions ORDER BY published_at DESC LIMIT 10;"),
        ("Find packages by author", "SELECT package_name, version, published_at FROM package_versions WHERE author = 'author_name';"),
        ("Show suspicious alerts", "SELECT author, packages, diversity_score, alert_time FROM suspicious_alerts ORDER BY alert_time DESC;"),
        ("Count packages per author", "SELECT author, COUNT(*) as package_count FROM package_versions WHERE author != '' GROUP BY author ORDER BY package_count DESC LIMIT 10;"),
        ("Find large packages", "SELECT package_name, version, author, unpack_size FROM package_versions WHERE unpack_size > 1000000 ORDER BY unpack_size DESC;"),
        ("Search package names", "SELECT DISTINCT package_name FROM package_versions WHERE package_name LIKE '%search_term%';"),
        ("Show deprecated packages", "SELECT package_name, version, author, deprecated_reason FROM package_versions WHERE is_deprecated = 1;"),
        ("Recent activity (24h)", "SELECT package_name, version, author, published_at FROM package_versions WHERE published_at > datetime('now', '-24 hours') ORDER BY published_at DESC;")
    ]
    
    print("\n💡 Example Queries:")
    print("-" * 40)
    for description, query in examples:
        print(f"\n🔸 {description}:")
        print(f"   {query}")

def main():
    parser = argparse.ArgumentParser(
        description="Execute SQLite queries against NPM Scanner database in Docker container",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    parser.add_argument(
        "query", 
        nargs="?", 
        help="SQL query to execute (if not provided, enters interactive mode)"
    )
    parser.add_argument(
        "--file", "-f",
        help="Execute queries from a file"
    )
    parser.add_argument(
        "--container", "-c",
        default="software-supply-chain-monitor",
        help="Docker container name (default: software-supply-chain-monitor)"
    )
    parser.add_argument(
        "--stats", "-s",
        action="store_true",
        help="Show database statistics"
    )
    parser.add_argument(
        "--schema",
        action="store_true",
        help="Show database schema"
    )
    parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Output results as JSON"
    )
    parser.add_argument(
        "--no-truncate",
        action="store_true",
        help="Don't truncate column values (may cause wide output)"
    )
    parser.add_argument(
        "--max-width",
        type=int,
        default=120,
        help="Maximum total table width in characters (default: 120)"
    )
    
    args = parser.parse_args()
    
    # Initialize querier
    querier = NPMDatabaseQuerier(args.container)
    
    # Check container accessibility
    if not querier.check_container_status():
        sys.exit(1)
    
    # Handle different modes
    if args.stats:
        if args.json:
            stats = querier.get_database_stats()
            print(json.dumps(stats, indent=2, default=str))
        else:
            print_stats(querier)
    elif args.schema:
        if args.json:
            schema = querier.get_database_schema()
            print(json.dumps(schema, indent=2, default=str))
        else:
            print_schema(querier)
    elif args.file:
        # Execute queries from file
        try:
            with open(args.file, 'r') as f:
                queries = f.read()
            
            # Split by semicolon and execute each query
            for query in queries.split(';'):
                query = query.strip()
                if query:
                    print(f"📝 Executing: {query[:50]}...")
                    results, error = querier.execute_query(query)
                    
                    if error:
                        print(f"❌ Error: {error}")
                    else:
                        if args.json:
                            print(json.dumps(results, indent=2, default=str))
                        else:
                            formatted_results = querier.format_results(
                                results, 
                                max_width=args.max_width, 
                                no_truncate=args.no_truncate
                            )
                            print(f"✅ Results ({len(results)} rows):")
                            print(formatted_results)
                    print("-" * 40)
                    
        except FileNotFoundError:
            print(f"❌ File not found: {args.file}")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error reading file: {e}")
            sys.exit(1)
    elif args.query:
        # Execute single query
        results, error = querier.execute_query(args.query)
        
        if error:
            print(f"❌ Error: {error}")
            sys.exit(1)
        else:
            if args.json:
                print(json.dumps(results, indent=2, default=str))
            else:
                formatted_results = querier.format_results(
                    results, 
                    max_width=args.max_width, 
                    no_truncate=args.no_truncate
                )
                print(formatted_results)
    else:
        # Interactive mode
        interactive_mode(querier)

if __name__ == "__main__":
    main()
