#!/usr/bin/env python3
"""
NPM Scanner Database Management Script
=====================================

This script provides easy management of the NPM Scanner container and database.
It combines container management with database querying capabilities.

Usage:
    python manage_scanner.py status              # Check container status
    python manage_scanner.py start               # Start the scanner
    python manage_scanner.py stop                # Stop the scanner
    python manage_scanner.py logs                # Show container logs
    python manage_scanner.py query "SQL_QUERY"   # Execute SQL query
    python manage_scanner.py backup              # Backup database
    python manage_scanner.py restore backup.db   # Restore database
"""

import subprocess
import sys
import os
import shutil
from datetime import datetime
from pathlib import Path
import argparse

class NPMScannerManager:
    """Manager for NPM Scanner Docker container and database operations."""
    
    def __init__(self, container_name: str = "software-supply-chain-monitor"):
        self.container_name = container_name
        self.backup_dir = Path("backups")
        self.backup_dir.mkdir(exist_ok=True)
    
    def run_command(self, command: list, capture_output: bool = True) -> tuple[str, str, int]:
        """Run a shell command and return output."""
        try:
            result = subprocess.run(
                command,
                capture_output=capture_output,
                text=True,
                timeout=60
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "Command timeout after 60 seconds", 1
        except Exception as e:
            return "", f"Error executing command: {str(e)}", 1
    
    def get_container_status(self) -> dict:
        """Get detailed container status information."""
        # Check if container exists
        stdout, stderr, returncode = self.run_command([
            "docker", "ps", "-a", "--filter", f"name={self.container_name}", 
            "--format", "{{.Names}}\t{{.Status}}\t{{.Ports}}"
        ])
        
        if returncode != 0:
            return {"exists": False, "error": stderr}
        
        if not stdout.strip():
            return {"exists": False, "running": False}
        
        # Parse status
        lines = stdout.strip().split('\n')
        if lines:
            parts = lines[0].split('\t')
            if len(parts) >= 2:
                status = parts[1]
                is_running = "Up" in status
                ports = parts[2] if len(parts) > 2 else ""
                
                return {
                    "exists": True,
                    "running": is_running,
                    "status": status,
                    "ports": ports
                }
        
        return {"exists": True, "running": False, "status": "unknown"}
    
    def start_container(self) -> bool:
        """Start the NPM scanner container."""
        print("🚀 Starting NPM Scanner container...")
        
        # Check if docker-compose files exist
        compose_files = ["docker-compose.yml", "docker-compose-wsl.yml"]
        available_compose = [f for f in compose_files if os.path.exists(f)]
        
        if not available_compose:
            print("❌ No docker-compose files found. Available files should be:")
            for f in compose_files:
                print(f"   • {f}")
            return False
        
        # Use the first available compose file
        compose_file = available_compose[0]
        print(f"📋 Using compose file: {compose_file}")
        
        stdout, stderr, returncode = self.run_command([
            "docker-compose", "-f", compose_file, "up", "-d"
        ])
        
        if returncode == 0:
            print("✅ Container started successfully")
            return True
        else:
            print(f"❌ Failed to start container: {stderr}")
            return False
    
    def stop_container(self) -> bool:
        """Stop the NPM scanner container."""
        print("🛑 Stopping NPM Scanner container...")
        
        stdout, stderr, returncode = self.run_command([
            "docker", "stop", self.container_name
        ])
        
        if returncode == 0:
            print("✅ Container stopped successfully")
            return True
        else:
            print(f"❌ Failed to stop container: {stderr}")
            return False
    
    def show_logs(self, follow: bool = False, lines: int = 100, raw: bool = False):
        """Show container logs."""
        cmd = ["docker", "logs"]
        if follow:
            cmd.append("-f")
        cmd.extend(["--tail", str(lines), self.container_name])
        
        # For raw output (when piping), skip headers and send directly to stdout
        if raw or follow:
            subprocess.run(cmd)
        else:
            print(f"📋 Container logs (last {lines} lines):")
            print("=" * 60)
            
            stdout, stderr, returncode = self.run_command(cmd)
            if returncode == 0:
                print(stdout)
                if stderr:
                    print("STDERR:", stderr)
            else:
                print(f"❌ Failed to get logs: {stderr}")
    
    def backup_database(self) -> str:
        """Create a backup of the database."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"npm_scanner_backup_{timestamp}.db"
        backup_path = self.backup_dir / backup_filename
        
        print(f"💾 Creating database backup: {backup_filename}")
        
        # Copy database from container
        stdout, stderr, returncode = self.run_command([
            "docker", "cp", 
            f"{self.container_name}:/data/supply_chain_monitor.db",
            str(backup_path)
        ])
        
        if returncode == 0:
            file_size = os.path.getsize(backup_path) / (1024 * 1024)  # MB
            print(f"✅ Backup created successfully: {backup_path} ({file_size:.2f} MB)")
            return str(backup_path)
        else:
            print(f"❌ Failed to create backup: {stderr}")
            return ""
    
    def restore_database(self, backup_path: str) -> bool:
        """Restore database from backup."""
        if not os.path.exists(backup_path):
            print(f"❌ Backup file not found: {backup_path}")
            return False
        
        print(f"🔄 Restoring database from: {backup_path}")
        
        # Stop container first
        print("⏸️  Stopping container for safe restore...")
        self.stop_container()
        
        # Copy backup to container
        stdout, stderr, returncode = self.run_command([
            "docker", "cp", backup_path,
            f"{self.container_name}:/data/supply_chain_monitor.db"
        ])
        
        if returncode == 0:
            print("✅ Database restored successfully")
            print("🚀 Starting container...")
            self.start_container()
            return True
        else:
            print(f"❌ Failed to restore database: {stderr}")
            return False
    
    def execute_query(self, query: str) -> bool:
        """Execute a SQL query using the query_database.py script."""
        print(f"📝 Executing query: {query[:50]}...")
        
        if not os.path.exists("query_database.py"):
            print("❌ query_database.py not found. Please ensure it's in the current directory.")
            return False
        
        stdout, stderr, returncode = self.run_command([
            sys.executable, "query_database.py", query
        ])
        
        if returncode == 0:
            print("✅ Query executed successfully:")
            print(stdout)
            return True
        else:
            print(f"❌ Query failed: {stderr}")
            return False
    
    def show_status(self):
        """Show comprehensive status information."""
        print("🔍 NPM Scanner Status Report")
        print("=" * 50)
        
        # Container status
        status = self.get_container_status()
        if not status["exists"]:
            print("❌ Container does not exist")
            print("   Run: python manage_scanner.py start")
            return
        
        if status["running"]:
            print("✅ Container is running")
            print(f"   Status: {status['status']}")
            if status.get("ports"):
                print(f"   Ports: {status['ports']}")
        else:
            print("⏸️  Container exists but is not running")
            print(f"   Status: {status['status']}")
            print("   Run: python manage_scanner.py start")
            return
        
        # Database stats
        print("\n📊 Database Information:")
        if os.path.exists("query_database.py"):
            stdout, stderr, returncode = self.run_command([
                sys.executable, "query_database.py", "--stats", "--json"
            ])
            if returncode == 0:
                try:
                    import json
                    stats = json.loads(stdout)
                    print(f"   📦 Total packages: {stats.get('total_packages', 0):,}")
                    print(f"   🔍 Unique packages: {stats.get('unique_packages', 0):,}")
                    print(f"   👤 Unique authors: {stats.get('unique_authors', 0):,}")
                    print(f"   🚨 Total alerts: {stats.get('total_alerts', 0):,}")
                except:
                    print("   ❌ Failed to parse database stats")
            else:
                print("   ❌ Failed to retrieve database stats")
        else:
            print("   ❌ query_database.py not found")
        
        # Recent backups
        if self.backup_dir.exists():
            backups = list(self.backup_dir.glob("*.db"))
            if backups:
                print(f"\n💾 Recent backups ({len(backups)} found):")
                for backup in sorted(backups, key=lambda x: x.stat().st_mtime, reverse=True)[:3]:
                    size_mb = backup.stat().st_size / (1024 * 1024)
                    mtime = datetime.fromtimestamp(backup.stat().st_mtime)
                    print(f"   • {backup.name} ({size_mb:.1f} MB, {mtime.strftime('%Y-%m-%d %H:%M')})")
            else:
                print("\n💾 No backups found")

def main():
    parser = argparse.ArgumentParser(
        description="NPM Scanner container and database management",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    parser.add_argument(
        "action",
        choices=["status", "start", "stop", "logs", "query", "backup", "restore"],
        help="Action to perform"
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="Query string (for query action) or backup file (for restore action)"
    )
    parser.add_argument(
        "--container", "-c",
        default="software-supply-chain-monitor",
        help="Container name (default: software-supply-chain-monitor)"
    )
    parser.add_argument(
        "--follow", "-f",
        action="store_true",
        help="Follow logs (for logs action)"
    )
    parser.add_argument(
        "--lines", "-n",
        type=int,
        default=100,
        help="Number of log lines to show (default: 100)"
    )
    parser.add_argument(
        "--raw", "-r",
        action="store_true",
        help="Raw output without headers (useful for piping)"
    )
    
    args = parser.parse_args()
    
    manager = NPMScannerManager(args.container)
    
    if args.action == "status":
        manager.show_status()
    elif args.action == "start":
        manager.start_container()
    elif args.action == "stop":
        manager.stop_container()
    elif args.action == "logs":
        # Auto-detect piping: if stdout is not a terminal, use raw mode
        raw_mode = args.raw or not sys.stdout.isatty()
        manager.show_logs(follow=args.follow, lines=args.lines, raw=raw_mode)
    elif args.action == "query":
        if not args.target:
            print("❌ Query string required for query action")
            sys.exit(1)
        manager.execute_query(args.target)
    elif args.action == "backup":
        backup_path = manager.backup_database()
        if backup_path:
            print(f"\n💡 To restore this backup later:")
            print(f"   python manage_scanner.py restore {backup_path}")
    elif args.action == "restore":
        if not args.target:
            print("❌ Backup file path required for restore action")
            sys.exit(1)
        manager.restore_database(args.target)

if __name__ == "__main__":
    main()
