"""
Database layer for Supply Chain Security Monitor.

This module provides a unified database interface that works across all 
package ecosystems (NPM, PyPI, etc.) with proper schema management and migrations.
"""
import sqlite3
import json
import logging
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple

from core.config import config
from core.models import (
    PackageVersion, GuardDogAnalysis, VelocityPattern, ScanningSession,
    PackageEcosystem, RiskLevel
)

logger = logging.getLogger(__name__)


class SupplyChainDatabase:
    """
    Unified database for Supply Chain Security Monitor.
    
    Handles package versions, security analysis results, and alerting state
    for all supported package ecosystems.
    """
    
    def __init__(self, db_path: Optional[str] = None):
        """Initialize database with migrations."""
        self.db_path = db_path or config.DB_PATH
        self.init_database()
        self.migrate_to_enhanced_schema()
    
    def init_database(self):
        """Initialize the database schema with all required tables."""
        with sqlite3.connect(self.db_path) as conn:
            # Package versions table - supports all ecosystems
            conn.execute('''
                CREATE TABLE IF NOT EXISTS package_versions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    package_name TEXT NOT NULL,
                    version TEXT NOT NULL,
                    ecosystem TEXT NOT NULL DEFAULT 'npm',
                    author TEXT NOT NULL,
                    author_email TEXT,
                    published_at TIMESTAMP NOT NULL,
                    processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    description TEXT,
                    keywords TEXT,  -- JSON array
                    homepage TEXT,
                    repository_url TEXT,
                    license TEXT,
                    dependencies TEXT,  -- JSON object
                    dev_dependencies TEXT,  -- JSON object
                    maintainers TEXT,  -- JSON array
                    file_count INTEGER,
                    unpack_size INTEGER,
                    tarball_size INTEGER,
                    created_at TEXT,
                    is_deprecated BOOLEAN,
                    deprecated_reason TEXT,
                    dist_tags TEXT,  -- JSON object (NPM) or classifier tags (PyPI)
                    shasum TEXT,     -- SHA1 hash for code change detection
                    integrity TEXT,  -- SHA512 integrity hash
                    git_head TEXT,   -- Git commit SHA when available
                    UNIQUE(package_name, version, ecosystem)
                )
            ''')
            
            # GuardDog analysis results table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS guarddog_analysis (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    package_name TEXT NOT NULL,
                    version TEXT NOT NULL,
                    ecosystem TEXT NOT NULL DEFAULT 'npm',
                    analysis_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    metadata_risk_score REAL DEFAULT 0.0,
                    source_risk_score REAL,
                    combined_risk_score REAL DEFAULT 0.0,
                    risk_level TEXT DEFAULT 'CLEAN',
                    metadata_findings TEXT,  -- JSON array
                    source_findings TEXT,    -- JSON array
                    guarddog_metadata_results TEXT,  -- JSON object
                    guarddog_source_results TEXT,    -- JSON object
                    analysis_error TEXT,
                    UNIQUE(package_name, version, ecosystem)
                )
            ''')
            
            # Velocity patterns and suspicious alerts
            conn.execute('''
                CREATE TABLE IF NOT EXISTS suspicious_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    author TEXT NOT NULL,
                    ecosystem TEXT NOT NULL DEFAULT 'npm',
                    packages TEXT NOT NULL,  -- JSON array of package names
                    diversity_score REAL NOT NULL,
                    pattern_type TEXT NOT NULL DEFAULT 'velocity_attack',
                    time_window_start TIMESTAMP NOT NULL,
                    time_window_end TIMESTAMP NOT NULL,
                    alert_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    risk_level TEXT DEFAULT 'MEDIUM',
                    UNIQUE(author, ecosystem, time_window_start)
                )
            ''')
            
            # Scanning sessions for tracking performance and results
            conn.execute('''
                CREATE TABLE IF NOT EXISTS scanning_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ecosystem TEXT NOT NULL,
                    started_at TIMESTAMP NOT NULL,
                    completed_at TIMESTAMP,
                    packages_discovered INTEGER DEFAULT 0,
                    packages_processed INTEGER DEFAULT 0,
                    packages_skipped INTEGER DEFAULT 0,
                    errors_encountered INTEGER DEFAULT 0,
                    suspicious_patterns_found INTEGER DEFAULT 0,
                    alerts_sent INTEGER DEFAULT 0,
                    database_entries_added INTEGER DEFAULT 0,
                    early_stopping_enabled BOOLEAN DEFAULT TRUE,
                    performance_stats TEXT  -- JSON object
                )
            ''')
            
            self._create_indexes(conn)
            conn.commit()
    
    def _create_indexes(self, conn: sqlite3.Connection):
        """Create database indexes for performance."""
        # Package versions indexes
        conn.execute('CREATE INDEX IF NOT EXISTS idx_package_ecosystem ON package_versions(ecosystem)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_package_author ON package_versions(author, ecosystem)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_published_at ON package_versions(published_at)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_processed_at ON package_versions(processed_at)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_package_name ON package_versions(package_name, ecosystem)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_author_email ON package_versions(author_email)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_license ON package_versions(license)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_is_deprecated ON package_versions(is_deprecated)')
        
        # GuardDog analysis indexes
        conn.execute('CREATE INDEX IF NOT EXISTS idx_guarddog_ecosystem ON guarddog_analysis(ecosystem)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_guarddog_risk ON guarddog_analysis(risk_level, combined_risk_score)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_guarddog_timestamp ON guarddog_analysis(analysis_timestamp)')
        
        # Alert indexes
        conn.execute('CREATE INDEX IF NOT EXISTS idx_alerts_ecosystem ON suspicious_alerts(ecosystem)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_alerts_author ON suspicious_alerts(author, ecosystem)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_alerts_time ON suspicious_alerts(alert_time)')
        
        # Session indexes
        conn.execute('CREATE INDEX IF NOT EXISTS idx_sessions_ecosystem ON scanning_sessions(ecosystem)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_sessions_time ON scanning_sessions(started_at)')
    
    def migrate_to_enhanced_schema(self):
        """Migrate existing database to support multi-ecosystem and enhanced features."""
        with sqlite3.connect(self.db_path) as conn:
            # Check if we need ecosystem column migration
            cursor = conn.execute("PRAGMA table_info(package_versions)")
            columns = {row[1] for row in cursor.fetchall()}
            
            needs_ecosystem_migration = 'ecosystem' not in columns
            needs_enhanced_migration = 'shasum' not in columns or 'integrity' not in columns
            
            if not needs_ecosystem_migration and not needs_enhanced_migration:
                logger.info("✅ Database already has full enhanced multi-ecosystem schema")
                return
            
            logger.info("🔄 Migrating database to enhanced multi-ecosystem schema...")
            
            # Add ecosystem column if missing
            if needs_ecosystem_migration:
                try:
                    conn.execute("ALTER TABLE package_versions ADD COLUMN ecosystem TEXT DEFAULT 'npm'")
                    conn.execute("UPDATE package_versions SET ecosystem = 'npm' WHERE ecosystem IS NULL")
                    logger.info("   ✅ Added ecosystem support")
                except sqlite3.OperationalError:
                    logger.warning("   ⚠️  Could not add ecosystem column")
            
            # Add enhanced metadata columns if missing
            enhanced_columns = [
                ('description', 'TEXT'),
                ('keywords', 'TEXT'),
                ('homepage', 'TEXT'), 
                ('repository_url', 'TEXT'),
                ('license', 'TEXT'),
                ('dependencies', 'TEXT'),
                ('dev_dependencies', 'TEXT'),
                ('maintainers', 'TEXT'),
                ('file_count', 'INTEGER'),
                ('unpack_size', 'INTEGER'),
                ('tarball_size', 'INTEGER'),
                ('created_at', 'TEXT'),
                ('is_deprecated', 'BOOLEAN'),
                ('deprecated_reason', 'TEXT'),
                ('dist_tags', 'TEXT'),
                ('shasum', 'TEXT'),
                ('integrity', 'TEXT'),
                ('git_head', 'TEXT')
            ]
            
            for column_name, column_type in enhanced_columns:
                if column_name not in columns:
                    try:
                        conn.execute(f'ALTER TABLE package_versions ADD COLUMN {column_name} {column_type}')
                        logger.info(f"   ✅ Added column: {column_name}")
                    except sqlite3.OperationalError as e:
                        logger.warning(f"   ⚠️  Could not add column {column_name}: {e}")
            
            # Update indexes
            self._create_indexes(conn)
            conn.commit()
            logger.info("🎉 Database migration completed!")
    
    def add_package_version(self, package: PackageVersion) -> bool:
        """Add a single package version to the database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                self._optimize_connection(conn)
                
                conn.execute('''
                    INSERT OR IGNORE INTO package_versions 
                    (package_name, version, ecosystem, author, author_email, published_at,
                     processed_at, description, keywords, homepage, repository_url, license,
                     dependencies, dev_dependencies, maintainers, file_count,
                     unpack_size, tarball_size, created_at, is_deprecated, deprecated_reason, 
                     dist_tags, shasum, integrity, git_head)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    package.name, package.version, package.ecosystem.value,
                    package.author, package.author_email,
                    package.published_at.isoformat() if package.published_at else None,
                    package.processed_at.isoformat() if package.processed_at else datetime.now(timezone.utc).isoformat(),
                    package.description,
                    json.dumps(package.keywords or []),
                    package.homepage,
                    package.repository_url,
                    package.license,
                    json.dumps(package.dependencies or {}),
                    json.dumps(package.dev_dependencies or {}),
                    json.dumps(package.maintainers or []),
                    package.file_count,
                    package.unpack_size,
                    package.tarball_size,
                    package.created_at,
                    package.is_deprecated,
                    package.deprecated_reason,
                    json.dumps(package.dist_tags or {}),
                    package.shasum,
                    package.integrity,
                    package.git_head
                ))
                
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"Error adding package {package.name}@{package.version}: {e}")
            return False
    
    def add_package_versions_bulk(self, packages: List[PackageVersion]) -> int:
        """Bulk insert package versions for better performance."""
        if not packages:
            return 0
            
        try:
            with sqlite3.connect(self.db_path) as conn:
                self._optimize_connection(conn)
                
                # Convert PackageVersion objects to tuples
                versions_data = []
                for pkg in packages:
                    versions_data.append((
                        pkg.name, pkg.version, pkg.ecosystem.value,
                        pkg.author, pkg.author_email,
                        pkg.published_at.isoformat() if pkg.published_at else None,
                        pkg.processed_at.isoformat() if pkg.processed_at else datetime.now(timezone.utc).isoformat(),
                        pkg.description,
                        json.dumps(pkg.keywords or []),
                        pkg.homepage,
                        pkg.repository_url, 
                        pkg.license,
                        json.dumps(pkg.dependencies or {}),
                        json.dumps(pkg.dev_dependencies or {}),
                        json.dumps(pkg.maintainers or []),
                        pkg.file_count,
                        pkg.unpack_size,
                        pkg.tarball_size,
                        pkg.created_at,
                        pkg.is_deprecated,
                        pkg.deprecated_reason,
                        json.dumps(pkg.dist_tags or {}),
                        pkg.shasum,
                        pkg.integrity,
                        pkg.git_head
                    ))
                
                cursor = conn.executemany('''
                    INSERT OR IGNORE INTO package_versions 
                    (package_name, version, ecosystem, author, author_email, published_at,
                     processed_at, description, keywords, homepage, repository_url, license,
                     dependencies, dev_dependencies, maintainers, file_count,
                     unpack_size, tarball_size, created_at, is_deprecated, deprecated_reason, 
                     dist_tags, shasum, integrity, git_head)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', versions_data)
                
                conn.commit()
                return cursor.rowcount
                
        except Exception as e:
            logger.error(f"Error bulk inserting {len(packages)} packages: {e}")
            return 0
    
    def add_guarddog_analysis(self, analysis: GuardDogAnalysis) -> bool:
        """Store GuardDog analysis results."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO guarddog_analysis
                    (package_name, version, ecosystem, analysis_timestamp, metadata_risk_score,
                     source_risk_score, combined_risk_score, risk_level, metadata_findings,
                     source_findings, guarddog_metadata_results, guarddog_source_results, analysis_error)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    analysis.package_name, analysis.version, analysis.ecosystem.value,
                    analysis.analysis_timestamp.isoformat(),
                    analysis.metadata_risk_score,
                    analysis.source_risk_score,
                    analysis.combined_risk_score,
                    analysis.risk_level.value,
                    json.dumps(analysis.metadata_findings),
                    json.dumps(analysis.source_findings),
                    json.dumps(analysis.guarddog_metadata_results or {}),
                    json.dumps(analysis.guarddog_source_results or {}),
                    analysis.analysis_error
                ))
                
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"Error storing GuardDog analysis: {e}")
            return False
    
    def get_guarddog_analysis(self, package_name: str, version: str, ecosystem: PackageEcosystem = PackageEcosystem.NPM) -> Optional[GuardDogAnalysis]:
        """Retrieve GuardDog analysis for a specific package version."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('''
                    SELECT package_name, version, ecosystem, analysis_timestamp, metadata_risk_score,
                           source_risk_score, combined_risk_score, risk_level, metadata_findings,
                           source_findings, guarddog_metadata_results, guarddog_source_results, analysis_error
                    FROM guarddog_analysis
                    WHERE package_name = ? AND version = ? AND ecosystem = ?
                    ORDER BY analysis_timestamp DESC
                    LIMIT 1
                ''', (package_name, version, ecosystem.value))
                
                row = cursor.fetchone()
                if not row:
                    return None
                
                # Parse the results back into a GuardDogAnalysis object
                return GuardDogAnalysis(
                    package_name=row[0],
                    version=row[1],
                    ecosystem=PackageEcosystem(row[2]),
                    analysis_type="combined",
                    risk_score=row[6],  # combined_risk_score
                    findings=json.loads(row[8] or '[]') + json.loads(row[9] or '[]'),  # metadata + source findings
                    analysis_timestamp=datetime.fromisoformat(row[3]),
                    guarddog_version="unknown",
                    metadata_risk_score=row[4],
                    source_risk_score=row[5],
                    combined_risk_score=row[6],
                    risk_level=RiskLevel(row[7]),
                    metadata_findings=json.loads(row[8] or '[]'),
                    source_findings=json.loads(row[9] or '[]'),
                    guarddog_metadata_results=json.loads(row[10] or '{}'),
                    guarddog_source_results=json.loads(row[11] or '{}'),
                    analysis_error=row[12]
                )
                
        except Exception as e:
            logger.error(f"Error retrieving GuardDog analysis for {package_name}@{version}: {e}")
            return None
    
    def record_suspicious_alert(self, pattern: VelocityPattern) -> bool:
        """Record that an alert was sent for a suspicious pattern."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                package_names = [pkg.name for pkg in pattern.packages]
                
                conn.execute('''
                    INSERT OR IGNORE INTO suspicious_alerts 
                    (author, ecosystem, packages, diversity_score, pattern_type,
                     time_window_start, time_window_end, risk_level)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    pattern.author,
                    pattern.ecosystem.value, 
                    json.dumps(package_names),
                    pattern.diversity_score,
                    pattern.pattern_type,
                    pattern.detected_at.isoformat(),  # Use detected_at as window start
                    (pattern.detected_at + timedelta(hours=pattern.time_window)).isoformat(),
                    pattern.risk_level.value
                ))
                
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"Error recording suspicious alert: {e}")
            return False
    
    def has_alerted_for_pattern(self, author: str, ecosystem: PackageEcosystem, 
                               time_window_start: datetime) -> bool:
        """Check if we've already alerted for this specific pattern."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('''
                SELECT 1 FROM suspicious_alerts 
                WHERE author = ? AND ecosystem = ? AND time_window_start = ?
            ''', (author, ecosystem.value, time_window_start.isoformat()))
            
            return cursor.fetchone() is not None
    
    def is_version_processed(self, package_name: str, version: str, 
                           ecosystem: PackageEcosystem) -> bool:
        """Check if a package version has been processed."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('''
                SELECT 1 FROM package_versions 
                WHERE package_name = ? AND version = ? AND ecosystem = ?
            ''', (package_name, version, ecosystem.value))
            
            return cursor.fetchone() is not None
    
    def get_package_versions_history(self, package_name: str, ecosystem: PackageEcosystem, limit: int = 10) -> List[PackageVersion]:
        """Get version history for a package, ordered by published date (newest first)."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute('''
                    SELECT package_name, version, ecosystem, author, author_email, published_at,
                           processed_at, description, keywords, homepage, repository_url, license,
                           dependencies, dev_dependencies, maintainers, file_count, unpack_size, 
                           tarball_size, created_at, is_deprecated, deprecated_reason, dist_tags,
                           shasum, integrity, git_head
                    FROM package_versions
                    WHERE package_name = ? AND ecosystem = ?
                    ORDER BY published_at DESC, version DESC
                    LIMIT ?
                ''', (package_name, ecosystem.value, limit))
                
                return [self._row_to_package_version(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error getting package version history: {e}")
            return []
    
    def get_previous_version(self, package_name: str, current_version: str, ecosystem: PackageEcosystem) -> Optional[PackageVersion]:
        """Get the most recent version before the current version."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute('''
                    SELECT package_name, version, ecosystem, author, author_email, published_at,
                           processed_at, description, keywords, homepage, repository_url, license,
                           dependencies, dev_dependencies, maintainers, file_count, unpack_size, 
                           tarball_size, created_at, is_deprecated, deprecated_reason, dist_tags,
                           shasum, integrity, git_head
                    FROM package_versions
                    WHERE package_name = ? AND ecosystem = ? AND version != ?
                    ORDER BY published_at DESC, version DESC
                    LIMIT 1
                ''', (package_name, ecosystem.value, current_version))
                
                row = cursor.fetchone()
                return self._row_to_package_version(row) if row else None
        except Exception as e:
            logger.error(f"Error getting previous version: {e}")
            return None

    def get_recent_author_activities(self, ecosystem: PackageEcosystem,
                                   hours_back: int = 24,
                                   package_filter: Optional[Set[str]] = None) -> Dict[str, List[PackageVersion]]:
        """Get recent package activities by author."""
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours_back)
        
        # Build base query
        query = '''
            SELECT package_name, version, ecosystem, author, author_email, published_at,
                   processed_at, description, keywords, homepage, repository_url, license,
                   dependencies, dev_dependencies, maintainers, file_count, unpack_size,
                   tarball_size, created_at, is_deprecated, deprecated_reason, dist_tags,
                   shasum, integrity, git_head
            FROM package_versions 
            WHERE ecosystem = ? AND published_at > ? AND author != ''
        '''
        
        params = [ecosystem.value, cutoff_time.isoformat()]
        
        # Add package filter if provided
        if package_filter:
            placeholders = ','.join(['?' for _ in package_filter])
            query += f' AND package_name IN ({placeholders})'
            params.extend(package_filter)
        
        query += ' ORDER BY author, published_at'
        
        activities = defaultdict(list)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(query, params)
            
            for row in cursor:
                package = self._row_to_package_version(row)
                activities[package.author].append(package)
        
        return dict(activities)

    def get_velocity_window_activities(self, ecosystem: PackageEcosystem,
                                     minutes_back: int = 15) -> Dict[str, List[PackageVersion]]:
        """Get package activities within velocity detection window (minutes)."""
        cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=minutes_back)
        
        query = '''
            SELECT package_name, version, ecosystem, author, author_email, published_at,
                   processed_at, description, keywords, homepage, repository_url, license,
                   dependencies, dev_dependencies, maintainers, file_count, unpack_size,
                   tarball_size, created_at, is_deprecated, deprecated_reason, dist_tags,
                   shasum, integrity, git_head
            FROM package_versions 
            WHERE ecosystem = ? AND published_at > ? AND author != ''
            ORDER BY author, published_at
        '''
        
        activities = defaultdict(list)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(query, [ecosystem.value, cutoff_time.isoformat()])
            
            for row in cursor:
                package = self._row_to_package_version(row)
                activities[package.author].append(package)
        
        return dict(activities)
    
    def cleanup_old_entries(self, hours_back: int = 24) -> Dict[str, int]:
        """Remove old entries from the database."""
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours_back)
        
        with sqlite3.connect(self.db_path) as conn:
            # Clean up old package versions
            cursor = conn.execute(
                'DELETE FROM package_versions WHERE published_at < ?',
                (cutoff_time.isoformat(),)
            )
            packages_deleted = cursor.rowcount
            
            # Clean up old alerts  
            cursor = conn.execute(
                'DELETE FROM suspicious_alerts WHERE alert_time < ?',
                (cutoff_time.isoformat(),)
            )
            alerts_deleted = cursor.rowcount
            
            # Clean up old GuardDog analysis
            cursor = conn.execute(
                'DELETE FROM guarddog_analysis WHERE analysis_timestamp < ?',
                (cutoff_time.isoformat(),)
            )
            analysis_deleted = cursor.rowcount
            
            # Clean up old sessions (keep more session history)
            session_cutoff = datetime.now(timezone.utc) - timedelta(days=7)
            cursor = conn.execute(
                'DELETE FROM scanning_sessions WHERE started_at < ?',
                (session_cutoff.isoformat(),)
            )
            sessions_deleted = cursor.rowcount
            
            conn.commit()
            
            return {
                'packages': packages_deleted,
                'alerts': alerts_deleted, 
                'analysis': analysis_deleted,
                'sessions': sessions_deleted
            }
    
    def get_stats(self, ecosystem: Optional[PackageEcosystem] = None) -> Dict[str, Any]:
        """Get database statistics."""
        with sqlite3.connect(self.db_path) as conn:
            where_clause = f"WHERE ecosystem = '{ecosystem.value}'" if ecosystem else ""
            
            # Package statistics
            cursor = conn.execute(f'SELECT COUNT(*) FROM package_versions {where_clause}')
            total_versions = cursor.fetchone()[0]
            
            cursor = conn.execute(f'SELECT COUNT(DISTINCT package_name) FROM package_versions {where_clause}')
            unique_packages = cursor.fetchone()[0]
            
            cursor = conn.execute(f'SELECT COUNT(DISTINCT author) FROM package_versions {where_clause} AND author != ""')
            unique_authors = cursor.fetchone()[0]
            
            # Alert statistics
            cursor = conn.execute(f'SELECT COUNT(*) FROM suspicious_alerts {where_clause}')
            total_alerts = cursor.fetchone()[0]
            
            # GuardDog statistics
            cursor = conn.execute(f'SELECT COUNT(*) FROM guarddog_analysis {where_clause}')
            guarddog_analyses = cursor.fetchone()[0]
            
            cursor = conn.execute(f'''
                SELECT risk_level, COUNT(*) 
                FROM guarddog_analysis {where_clause}
                GROUP BY risk_level
            ''')
            risk_breakdown = dict(cursor.fetchall())
            
            return {
                'total_versions': total_versions,
                'unique_packages': unique_packages,
                'unique_authors': unique_authors,
                'total_alerts': total_alerts,
                'guarddog_analyses': guarddog_analyses,
                'risk_breakdown': risk_breakdown
            }
    
    def _optimize_connection(self, conn: sqlite3.Connection):
        """Apply performance optimizations to database connection."""
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA synchronous=NORMAL')
        conn.execute('PRAGMA cache_size=10000')
        conn.execute('PRAGMA temp_store=memory')
    
    def _row_to_package_version(self, row: sqlite3.Row) -> PackageVersion:
        """Convert database row to PackageVersion object.""" 
        return PackageVersion(
            name=row['package_name'],
            version=row['version'],
            ecosystem=PackageEcosystem(row['ecosystem']),
            author=row['author'],
            author_email=row.get('author_email'),
            published_at=datetime.fromisoformat(row['published_at']) if row['published_at'] else None,
            processed_at=datetime.fromisoformat(row['processed_at']) if row.get('processed_at') else None,
            description=row.get('description'),
            keywords=json.loads(row['keywords']) if row.get('keywords') else [],
            homepage=row.get('homepage'),
            repository_url=row.get('repository_url'),
            license=row.get('license'),
            dependencies=json.loads(row['dependencies']) if row.get('dependencies') else {},
            dev_dependencies=json.loads(row['dev_dependencies']) if row.get('dev_dependencies') else {},
            maintainers=json.loads(row['maintainers']) if row.get('maintainers') else [],
            file_count=row.get('file_count'),
            unpack_size=row.get('unpack_size'),
            tarball_size=row.get('tarball_size'),
            created_at=row.get('created_at'),
            is_deprecated=bool(row.get('is_deprecated', False)),
            deprecated_reason=row.get('deprecated_reason'),
            dist_tags=json.loads(row['dist_tags']) if row.get('dist_tags') else {},
            shasum=row.get('shasum'),
            integrity=row.get('integrity'),
            git_head=row.get('git_head')
        )


# Global database instance
database = SupplyChainDatabase()


# Legacy compatibility for existing code
NPMDatabase = SupplyChainDatabase  # Alias for backwards compatibility
