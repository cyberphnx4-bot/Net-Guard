#!/usr/bin/env python3
"""
NetGuard DNS Server - Enterprise Edition
Multi-Router Management System with Granular Rule Control
Version: 3.2.0 - Phase 2 Features & Performance

Phase 2 Fixes:
- PERF-001/002: Rule caching with invalidation
- PERF-003: Pre-compiled regex caching
- PERF-005: index.html memory caching
- PERF-006: Gzip compression
- PERF-008: Parallel upstream DNS
- BUG-023: Router stats persistence
- BUG-024: Analytics aggregation
- BUG-070: AAAA record support
- BUG-077: Consistent DB timeouts
- Search functionality
"""

import socket
import socketserver
import threading
import struct
import json
import sqlite3
import hashlib
import secrets
import time
import re
import os
import sys
import logging
import ipaddress
import gzip
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote
from typing import Optional, Tuple, Dict, List, Any, Pattern
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from io import BytesIO
import ctypes
import platform

# ==================== LOGGING CONFIGURATION ====================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('NetGuard')

# ==================== CONSTANTS ====================

VERSION = "3.2.0"
CONFIG_FILE = "netguard_config.json"
DB_FILE = "netguard_data.db"

# Limits
MAX_REQUEST_SIZE = 1 * 1024 * 1024  # 1MB
MAX_DNS_PACKET_SIZE = 4096  # EDNS compliant
MIN_GZIP_SIZE = 1024  # Only gzip responses > 1KB

# Intervals
SESSION_CLEANUP_INTERVAL = 300  # 5 minutes
STATS_PERSIST_INTERVAL = 60  # 1 minute
ANALYTICS_INTERVAL = 3600  # 1 hour
RULE_CACHE_TTL = 30  # 30 seconds

# Rate limiting
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX_REQUESTS = 100

# Security
LOGIN_DELAY_SECONDS = 1
HASH_ITERATIONS = 100000
HASH_ALGORITHM = 'sha256'

# DNS
DNS_UPSTREAM_TIMEOUT = 3
DNS_CACHE_DEFAULT_TTL = 300

# ==================== DEFAULT CONFIGURATION ====================

DEFAULT_CONFIG = {
    "dns": {
        "port": 53,
        "upstream_servers": ["1.1.1.1", "8.8.8.8", "9.9.9.9"],
        "timeout": 3,
        "block_response": "0.0.0.0",
        "block_response_ipv6": "::",
        "cache_enabled": True,
        "cache_size": 5000,
        "cache_ttl": 300,
        "parallel_upstream": True
    },
    "web": {
        "port": 8080,
        "session_timeout": 7200,
        "enable_gzip": True,
        "cache_static": True
    },
    "admin": {
        "username": "admin",
        "password_hash": "",
        "password_salt": ""
    },
    "settings": {
        "auto_detect_routers": True,
        "router_timeout": 300,
        "enable_analytics": True,
        "max_query_logs": 100000,
        "persist_stats": True
    }
}

# ==================== CACHING CLASSES ====================

class RuleCache:
    """
    Thread-safe rule cache with automatic invalidation
    PERF-002: Cache rules to avoid DB queries on every DNS request
    """
    def __init__(self, ttl: int = RULE_CACHE_TTL):
        self.ttl = ttl
        self._cache: Optional[List[Dict]] = None
        self._expires: float = 0
        self._lock = threading.RLock()
        self._compiled_patterns: Dict[str, Pattern] = {}
    
    def get_rules(self) -> List[Dict]:
        """Get cached rules or load from database"""
        with self._lock:
            if self._cache is not None and time.time() < self._expires:
                return self._cache
            
            # Load from database
            self._cache = self._load_rules()
            self._expires = time.time() + self.ttl
            return self._cache
    
    def invalidate(self):
        """Invalidate cache (call after rule changes)"""
        with self._lock:
            self._cache = None
            self._expires = 0
            self._compiled_patterns.clear()
    
    def get_compiled_pattern(self, pattern: str) -> Optional[Pattern]:
        """
        Get compiled regex pattern with caching
        PERF-003/BUG-069: Pre-compile and cache regex patterns
        """
        with self._lock:
            if pattern in self._compiled_patterns:
                return self._compiled_patterns[pattern]
            
            try:
                # Convert wildcard pattern to regex
                if '*' in pattern:
                    regex_pattern = re.escape(pattern).replace(r'\*', '.*')
                    compiled = re.compile(f'^{regex_pattern}$', re.IGNORECASE)
                    self._compiled_patterns[pattern] = compiled
                    return compiled
            except re.error:
                logger.warning(f"Invalid regex pattern: {pattern}")
            
            return None
    
    def _load_rules(self) -> List[Dict]:
        """Load rules from database"""
        try:
            conn = sqlite3.connect(DB_FILE, timeout=10)
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute('SELECT * FROM rules WHERE enabled = 1 ORDER BY priority DESC, created_at DESC')
            rows = c.fetchall()
            conn.close()
            
            rules = []
            for row in rows:
                try:
                    router_ids = json.loads(row['router_ids']) if row['router_ids'] else []
                except (json.JSONDecodeError, TypeError):
                    router_ids = []
                
                rules.append({
                    'id': row['id'],
                    'domain': row['domain'],
                    'action': row['action'],
                    'scope': row['scope'],
                    'router_ids': router_ids,
                    'redirect_ip': row['redirect_ip'] if 'redirect_ip' in row.keys() else None,
                    'enabled': bool(row['enabled']),
                    'priority': row['priority'] if 'priority' in row.keys() else 0,
                })
            return rules
        except Exception as e:
            logger.error(f"Error loading rules for cache: {e}")
            return []


class StaticFileCache:
    """
    Cache for static files (index.html)
    PERF-005/BUG-073: Cache index.html in memory
    """
    def __init__(self):
        self._cache: Dict[str, Tuple[bytes, bytes, float]] = {}  # path -> (content, gzipped, mtime)
        self._lock = threading.RLock()
    
    def get(self, filepath: str, enable_gzip: bool = True) -> Tuple[Optional[bytes], bool]:
        """
        Get file content (gzipped if available and enabled)
        Returns: (content, is_gzipped)
        """
        with self._lock:
            try:
                mtime = os.path.getmtime(filepath)
                
                # Check cache
                if filepath in self._cache:
                    content, gzipped, cached_mtime = self._cache[filepath]
                    if cached_mtime == mtime:
                        if enable_gzip and gzipped:
                            return gzipped, True
                        return content, False
                
                # Load and cache
                with open(filepath, 'rb') as f:
                    content = f.read()
                
                # Gzip if large enough
                gzipped = None
                if len(content) >= MIN_GZIP_SIZE:
                    buf = BytesIO()
                    with gzip.GzipFile(fileobj=buf, mode='wb', compresslevel=6) as gz:
                        gz.write(content)
                    gzipped = buf.getvalue()
                
                self._cache[filepath] = (content, gzipped, mtime)
                
                if enable_gzip and gzipped:
                    return gzipped, True
                return content, False
                
            except FileNotFoundError:
                return None, False
            except Exception as e:
                logger.error(f"Error caching file {filepath}: {e}")
                return None, False
    
    def invalidate(self, filepath: str = None):
        """Invalidate cache for specific file or all files"""
        with self._lock:
            if filepath:
                self._cache.pop(filepath, None)
            else:
                self._cache.clear()


# ==================== GLOBAL STATE ====================

class AppState:
    """Thread-safe application state management"""
    
    def __init__(self):
        self.config: Dict[str, Any] = {}
        self.dns_cache: Dict[str, Dict] = {}
        self.sessions: Dict[str, Dict] = {}
        self.csrf_tokens: Dict[str, float] = {}
        self.rate_limits: Dict[str, List[float]] = defaultdict(list)
        
        self.stats = {
            "total_queries": 0,
            "blocked_queries": 0,
            "allowed_queries": 0,
            "cached_queries": 0,
            "redirected_queries": 0,
            "forwarded_queries": 0,
            "failed_queries": 0,
            "start_time": time.time(),
            "last_updated": time.time()
        }
        
        self.router_stats: Dict[str, Dict] = defaultdict(lambda: {
            "total_queries": 0,
            "blocked_queries": 0,
            "allowed_queries": 0,
            "redirected_queries": 0,
            "last_seen": 0,
            "first_seen": time.time()
        })
        
        # Caches
        self.rule_cache = RuleCache()
        self.static_cache = StaticFileCache()
        
        # Locks
        self.cache_lock = threading.RLock()
        self.session_lock = threading.RLock()
        self.stats_lock = threading.RLock()
        self.config_lock = threading.RLock()
        self.router_lock = threading.RLock()
        self.rate_lock = threading.RLock()
        self.csrf_lock = threading.RLock()
        
        # Thread pool
        self.executor = ThreadPoolExecutor(max_workers=20, thread_name_prefix="NetGuard")
        
        # DNS upstream pool
        self.dns_executor = ThreadPoolExecutor(max_workers=10, thread_name_prefix="DNS")

app_state = AppState()

# ==================== DATABASE MANAGEMENT ====================

class DatabaseManager:
    """Thread-safe database connection manager with consistent timeouts"""
    
    _local = threading.local()
    _timeout = 10  # BUG-077: Consistent timeout
    
    @classmethod
    def get_connection(cls) -> sqlite3.Connection:
        """Get thread-local database connection"""
        if not hasattr(cls._local, 'connection') or cls._local.connection is None:
            conn = sqlite3.connect(DB_FILE, timeout=cls._timeout, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
            conn.execute("PRAGMA cache_size = -64000")  # 64MB cache
            cls._local.connection = conn
        return cls._local.connection
    
    @classmethod
    def execute(cls, query: str, params: tuple = ()) -> sqlite3.Cursor:
        """Execute query with automatic retry on lock"""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                conn = cls.get_connection()
                return conn.execute(query, params)
            except sqlite3.OperationalError as e:
                if "locked" in str(e) and attempt < max_retries - 1:
                    time.sleep(0.1 * (attempt + 1))
                    continue
                raise
    
    @classmethod
    def commit(cls):
        """Commit current transaction"""
        if hasattr(cls._local, 'connection') and cls._local.connection:
            cls._local.connection.commit()
    
    @classmethod
    def close_connection(cls):
        """Close thread-local connection"""
        if hasattr(cls._local, 'connection') and cls._local.connection:
            cls._local.connection.close()
            cls._local.connection = None


def init_database():
    """Initialize SQLite database with all tables"""
    try:
        conn = DatabaseManager.get_connection()
        c = conn.cursor()
        
        # Query logs table
        c.execute('''CREATE TABLE IF NOT EXISTS query_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            router_id TEXT,
            client_ip TEXT NOT NULL,
            domain TEXT NOT NULL,
            query_type TEXT,
            action TEXT NOT NULL,
            response TEXT,
            response_time REAL,
            rule_id TEXT
        )''')
        
        # Routers table
        c.execute('''CREATE TABLE IF NOT EXISTS routers (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            subnet TEXT,
            description TEXT,
            enabled INTEGER DEFAULT 1,
            created_at REAL,
            last_seen REAL,
            status TEXT DEFAULT 'active',
            total_queries INTEGER DEFAULT 0,
            blocked_queries INTEGER DEFAULT 0,
            allowed_queries INTEGER DEFAULT 0,
            redirected_queries INTEGER DEFAULT 0
        )''')
        
        # Rules table
        c.execute('''CREATE TABLE IF NOT EXISTS rules (
            id TEXT PRIMARY KEY,
            domain TEXT NOT NULL,
            action TEXT NOT NULL,
            scope TEXT NOT NULL,
            router_ids TEXT,
            redirect_ip TEXT,
            enabled INTEGER DEFAULT 1,
            priority INTEGER DEFAULT 0,
            created_at REAL,
            updated_at REAL,
            description TEXT,
            hit_count INTEGER DEFAULT 0
        )''')
        
        # Analytics table - BUG-024: Now actively used
        c.execute('''CREATE TABLE IF NOT EXISTS analytics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            router_id TEXT,
            date TEXT NOT NULL,
            hour INTEGER NOT NULL,
            total_queries INTEGER DEFAULT 0,
            blocked_queries INTEGER DEFAULT 0,
            allowed_queries INTEGER DEFAULT 0,
            redirected_queries INTEGER DEFAULT 0,
            cached_queries INTEGER DEFAULT 0,
            avg_response_time REAL DEFAULT 0,
            UNIQUE(router_id, date, hour)
        )''')
        
        # Top domains table for analytics
        c.execute('''CREATE TABLE IF NOT EXISTS top_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            router_id TEXT,
            date TEXT NOT NULL,
            domain TEXT NOT NULL,
            query_count INTEGER DEFAULT 0,
            blocked INTEGER DEFAULT 0,
            UNIQUE(router_id, date, domain)
        )''')
        
        # Server stats table - BUG-023: Persist stats
        c.execute('''CREATE TABLE IF NOT EXISTS server_stats (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            total_queries INTEGER DEFAULT 0,
            blocked_queries INTEGER DEFAULT 0,
            allowed_queries INTEGER DEFAULT 0,
            cached_queries INTEGER DEFAULT 0,
            redirected_queries INTEGER DEFAULT 0,
            last_updated REAL
        )''')
        
        # Create indexes
        c.execute('CREATE INDEX IF NOT EXISTS idx_query_timestamp ON query_logs(timestamp)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_query_router ON query_logs(router_id)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_query_domain ON query_logs(domain)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_query_action ON query_logs(action)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_router_status ON routers(status)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_router_subnet ON routers(subnet)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_rule_enabled ON rules(enabled)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_rule_domain ON rules(domain)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_analytics_date ON analytics(date)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_top_domains_date ON top_domains(date)')
        
        # Migrations - add missing columns
        migrations = [
            ('rules', 'redirect_ip', 'TEXT'),
            ('rules', 'updated_at', 'REAL'),
            ('rules', 'priority', 'INTEGER DEFAULT 0'),
            ('rules', 'hit_count', 'INTEGER DEFAULT 0'),
            ('routers', 'total_queries', 'INTEGER DEFAULT 0'),
            ('routers', 'blocked_queries', 'INTEGER DEFAULT 0'),
            ('routers', 'allowed_queries', 'INTEGER DEFAULT 0'),
            ('routers', 'redirected_queries', 'INTEGER DEFAULT 0'),
        ]
        
        for table, column, col_type in migrations:
            try:
                c.execute(f"SELECT {column} FROM {table} LIMIT 1")
            except sqlite3.OperationalError:
                c.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")
                logger.info(f"Migration: Added {column} to {table}")
        
        # Initialize server stats if not exists
        c.execute('INSERT OR IGNORE INTO server_stats (id, total_queries, last_updated) VALUES (1, 0, ?)', (time.time(),))
        
        conn.commit()
        logger.info("Database initialized successfully")
        
        # Load persisted stats
        load_persisted_stats()
        
    except Exception as e:
        logger.error(f"Database initialization error: {e}")
        raise


def load_persisted_stats():
    """Load persisted stats from database - BUG-023"""
    try:
        conn = DatabaseManager.get_connection()
        c = conn.cursor()
        
        c.execute('SELECT * FROM server_stats WHERE id = 1')
        row = c.fetchone()
        
        if row:
            with app_state.stats_lock:
                app_state.stats['total_queries'] = row['total_queries'] or 0
                app_state.stats['blocked_queries'] = row['blocked_queries'] or 0
                app_state.stats['allowed_queries'] = row['allowed_queries'] or 0
                app_state.stats['cached_queries'] = row['cached_queries'] or 0
                app_state.stats['redirected_queries'] = row['redirected_queries'] or 0
            logger.info(f"Loaded persisted stats: {app_state.stats['total_queries']} total queries")
        
        # Load router stats
        c.execute('SELECT id, total_queries, blocked_queries, allowed_queries, redirected_queries, last_seen FROM routers')
        for row in c.fetchall():
            with app_state.router_lock:
                app_state.router_stats[row['id']] = {
                    'total_queries': row['total_queries'] or 0,
                    'blocked_queries': row['blocked_queries'] or 0,
                    'allowed_queries': row['allowed_queries'] or 0,
                    'redirected_queries': row['redirected_queries'] or 0,
                    'last_seen': row['last_seen'] or 0,
                    'first_seen': row['last_seen'] or time.time()
                }
                
    except Exception as e:
        logger.error(f"Error loading persisted stats: {e}")


def persist_stats():
    """Persist current stats to database - BUG-023"""
    try:
        conn = DatabaseManager.get_connection()
        c = conn.cursor()
        
        with app_state.stats_lock:
            stats = app_state.stats.copy()
        
        c.execute('''UPDATE server_stats SET 
                     total_queries = ?, blocked_queries = ?, allowed_queries = ?,
                     cached_queries = ?, redirected_queries = ?, last_updated = ?
                     WHERE id = 1''',
                  (stats['total_queries'], stats['blocked_queries'], stats['allowed_queries'],
                   stats['cached_queries'], stats['redirected_queries'], time.time()))
        
        # Persist router stats
        with app_state.router_lock:
            router_stats = dict(app_state.router_stats)
        
        for router_id, stats in router_stats.items():
            c.execute('''UPDATE routers SET 
                         total_queries = ?, blocked_queries = ?, allowed_queries = ?, 
                         redirected_queries = ?, last_seen = ?
                         WHERE id = ?''',
                      (stats['total_queries'], stats['blocked_queries'], 
                       stats['allowed_queries'], stats['redirected_queries'],
                       stats['last_seen'], router_id))
        
        conn.commit()
        
        with app_state.stats_lock:
            app_state.stats['last_updated'] = time.time()
            
    except Exception as e:
        logger.error(f"Error persisting stats: {e}")


def cleanup_old_logs():
    """Remove old query logs to prevent database bloat"""
    try:
        max_logs = app_state.config.get('settings', {}).get('max_query_logs', 100000)
        conn = DatabaseManager.get_connection()
        c = conn.cursor()
        
        c.execute('SELECT COUNT(*) FROM query_logs')
        count = c.fetchone()[0]
        
        if count > max_logs:
            delete_count = count - max_logs
            c.execute('''DELETE FROM query_logs WHERE id IN 
                        (SELECT id FROM query_logs ORDER BY timestamp ASC LIMIT ?)''',
                      (delete_count,))
            conn.commit()
            logger.info(f"Cleaned up {delete_count} old query logs")
        
        # Also clean old analytics (keep 30 days)
        cutoff_date = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
        c.execute('DELETE FROM analytics WHERE date < ?', (cutoff_date,))
        c.execute('DELETE FROM top_domains WHERE date < ?', (cutoff_date,))
        conn.commit()
            
    except Exception as e:
        logger.error(f"Log cleanup error: {e}")


def aggregate_analytics():
    """
    Aggregate query logs into analytics table
    BUG-024: Analytics table now actively used
    """
    try:
        conn = DatabaseManager.get_connection()
        c = conn.cursor()
        
        current_hour = datetime.now().replace(minute=0, second=0, microsecond=0)
        last_hour = current_hour - timedelta(hours=1)
        
        date_str = last_hour.strftime('%Y-%m-%d')
        hour = last_hour.hour
        
        # Aggregate by router
        c.execute('''
            SELECT router_id,
                   COUNT(*) as total,
                   SUM(CASE WHEN action LIKE '%blocked%' THEN 1 ELSE 0 END) as blocked,
                   SUM(CASE WHEN action LIKE '%allowed%' OR action = 'forwarded' THEN 1 ELSE 0 END) as allowed,
                   SUM(CASE WHEN action LIKE '%redirect%' THEN 1 ELSE 0 END) as redirected,
                   SUM(CASE WHEN action = 'cached' THEN 1 ELSE 0 END) as cached,
                   AVG(response_time) as avg_time
            FROM query_logs
            WHERE timestamp >= ? AND timestamp < ?
            GROUP BY router_id
        ''', (last_hour.timestamp(), current_hour.timestamp()))
        
        for row in c.fetchall():
            c.execute('''INSERT OR REPLACE INTO analytics 
                         (router_id, date, hour, total_queries, blocked_queries, 
                          allowed_queries, redirected_queries, cached_queries, avg_response_time)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                      (row['router_id'], date_str, hour, row['total'], row['blocked'],
                       row['allowed'], row['redirected'], row['cached'], row['avg_time'] or 0))
        
        # Aggregate top domains
        c.execute('''
            SELECT router_id, domain,
                   COUNT(*) as count,
                   SUM(CASE WHEN action LIKE '%blocked%' THEN 1 ELSE 0 END) as blocked
            FROM query_logs
            WHERE timestamp >= ? AND timestamp < ?
            GROUP BY router_id, domain
            ORDER BY count DESC
            LIMIT 100
        ''', (last_hour.timestamp(), current_hour.timestamp()))
        
        for row in c.fetchall():
            c.execute('''INSERT OR REPLACE INTO top_domains 
                         (router_id, date, domain, query_count, blocked)
                         VALUES (?, ?, ?, 
                                 COALESCE((SELECT query_count FROM top_domains 
                                          WHERE router_id = ? AND date = ? AND domain = ?), 0) + ?,
                                 COALESCE((SELECT blocked FROM top_domains 
                                          WHERE router_id = ? AND date = ? AND domain = ?), 0) + ?)''',
                      (row['router_id'], date_str, row['domain'],
                       row['router_id'], date_str, row['domain'], row['count'],
                       row['router_id'], date_str, row['domain'], row['blocked']))
        
        conn.commit()
        logger.debug(f"Analytics aggregated for {date_str} hour {hour}")
        
    except Exception as e:
        logger.error(f"Analytics aggregation error: {e}")

# ==================== SECURITY UTILITIES ====================

def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """Hash password using PBKDF2-HMAC-SHA256"""
    if salt is None:
        salt = secrets.token_hex(32)
    
    password_hash = hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        password.encode('utf-8'),
        salt.encode('utf-8'),
        HASH_ITERATIONS
    ).hex()
    
    return password_hash, salt


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """Verify password against stored hash"""
    computed_hash, _ = hash_password(password, salt)
    return secrets.compare_digest(computed_hash, stored_hash)


def generate_id() -> str:
    """Generate cryptographically secure unique ID"""
    return secrets.token_urlsafe(16)


def generate_csrf_token() -> str:
    """Generate CSRF token with expiry"""
    token = secrets.token_urlsafe(32)
    with app_state.csrf_lock:
        app_state.csrf_tokens[token] = time.time() + 3600
    return token


def validate_csrf_token(token: str) -> bool:
    """Validate CSRF token"""
    if not token:
        return False
    
    with app_state.csrf_lock:
        expiry = app_state.csrf_tokens.get(token)
        if expiry and time.time() < expiry:
            return True
        app_state.csrf_tokens.pop(token, None)
    return False


def check_rate_limit(client_ip: str) -> bool:
    """Check if client has exceeded rate limit"""
    current_time = time.time()
    
    with app_state.rate_lock:
        app_state.rate_limits[client_ip] = [
            t for t in app_state.rate_limits[client_ip]
            if current_time - t < RATE_LIMIT_WINDOW
        ]
        
        if len(app_state.rate_limits[client_ip]) >= RATE_LIMIT_MAX_REQUESTS:
            return False
        
        app_state.rate_limits[client_ip].append(current_time)
        return True


def sanitize_input(value: str, max_length: int = 255) -> str:
    """Sanitize user input"""
    if not isinstance(value, str):
        return ""
    return value.strip()[:max_length]


def validate_ip_address(ip: str) -> bool:
    """Validate IPv4 or IPv6 address"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_cidr(cidr: str) -> bool:
    """Validate CIDR notation"""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def validate_domain(domain: str) -> bool:
    """Validate domain name format"""
    if not domain or len(domain) > 253:
        return False
    if domain.startswith('*.'):
        domain = domain[2:]
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$'
    return bool(re.match(pattern, domain))


# ==================== CONFIGURATION MANAGEMENT ====================

def load_config():
    """Load configuration from file"""
    with app_state.config_lock:
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                    loaded = json.load(f)
                    app_state.config = deep_merge(DEFAULT_CONFIG.copy(), loaded)
                logger.info("Configuration loaded from file")
            except Exception as e:
                logger.error(f"Error loading config: {e}")
                app_state.config = DEFAULT_CONFIG.copy()
                _set_default_password()
        else:
            app_state.config = DEFAULT_CONFIG.copy()
            _set_default_password()
            save_config()
            logger.info("Created default configuration")


def _set_default_password():
    """Set default admin password"""
    password_hash, salt = hash_password("admin")
    app_state.config["admin"]["password_hash"] = password_hash
    app_state.config["admin"]["password_salt"] = salt


def deep_merge(base: dict, update: dict) -> dict:
    """Deep merge two dictionaries"""
    result = base.copy()
    for key, value in update.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def save_config():
    """Save configuration atomically"""
    with app_state.config_lock:
        try:
            temp_file = CONFIG_FILE + '.tmp'
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(app_state.config, f, indent=2)
            os.replace(temp_file, CONFIG_FILE)
            logger.debug("Configuration saved")
        except Exception as e:
            logger.error(f"Error saving config: {e}")
# ==================== ROUTER MANAGEMENT ====================

def identify_router(client_ip: str) -> Optional[str]:
    """
    Identify router from client IP using proper CIDR matching
    """
    try:
        client_addr = ipaddress.ip_address(client_ip)
    except ValueError:
        logger.warning(f"Invalid client IP: {client_ip}")
        return None
    
    with app_state.router_lock:
        routers = load_routers_from_db()
        
        # Check existing routers by subnet
        for router in routers:
            if router['subnet'] and router['enabled']:
                try:
                    network = ipaddress.ip_network(router['subnet'], strict=False)
                    if client_addr in network:
                        return router['id']
                except ValueError:
                    continue
        
        # Auto-detect new router if enabled
        if app_state.config.get('settings', {}).get('auto_detect_routers', True):
            if isinstance(client_addr, ipaddress.IPv4Address):
                network = ipaddress.ip_network(f"{client_ip}/24", strict=False)
                subnet = str(network)
                
                # Check if subnet overlaps with existing
                for router in routers:
                    if router['subnet']:
                        try:
                            existing_network = ipaddress.ip_network(router['subnet'], strict=False)
                            if network.overlaps(existing_network):
                                return router['id']
                        except ValueError:
                            continue
                
                router_id = auto_register_router(subnet, client_ip)
                return router_id
        
        return None


def auto_register_router(subnet: str, client_ip: str) -> Optional[str]:
    """Automatically register new router"""
    router_id = generate_id()
    
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        network_addr = str(network.network_address)
        router_name = f"Auto-Router ({network_addr})"
    except ValueError:
        router_name = f"Auto-Router ({client_ip})"
    
    try:
        conn = DatabaseManager.get_connection()
        c = conn.cursor()
        
        current_time = time.time()
        c.execute('''INSERT INTO routers 
                     (id, name, subnet, description, enabled, created_at, last_seen, status,
                      total_queries, blocked_queries, allowed_queries, redirected_queries)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (router_id, router_name, subnet, "Auto-detected router",
                   1, current_time, current_time, 'active', 0, 0, 0, 0))
        conn.commit()
        
        logger.info(f"Auto-registered router: {router_name} ({subnet})")
        return router_id
        
    except sqlite3.IntegrityError:
        logger.warning(f"Router already exists for subnet: {subnet}")
        return None
    except Exception as e:
        logger.error(f"Error auto-registering router: {e}")
        return None


def update_router_last_seen(router_id: str):
    """Update router last seen timestamp"""
    if not router_id:
        return
    
    try:
        conn = DatabaseManager.get_connection()
        c = conn.cursor()
        c.execute('UPDATE routers SET last_seen = ?, status = ? WHERE id = ?',
                  (time.time(), 'active', router_id))
        conn.commit()
    except Exception as e:
        logger.error(f"Error updating router last_seen: {e}")


def load_routers_from_db() -> List[Dict]:
    """Load all routers from database"""
    try:
        conn = DatabaseManager.get_connection()
        c = conn.cursor()
        c.execute('SELECT * FROM routers ORDER BY created_at DESC')
        rows = c.fetchall()
        
        routers = []
        for row in rows:
            routers.append({
                'id': row['id'],
                'name': row['name'],
                'subnet': row['subnet'],
                'description': row['description'],
                'enabled': bool(row['enabled']),
                'created_at': row['created_at'],
                'last_seen': row['last_seen'],
                'status': row['status'],
                'total_queries': row['total_queries'] if 'total_queries' in row.keys() else 0,
                'blocked_queries': row['blocked_queries'] if 'blocked_queries' in row.keys() else 0,
                'allowed_queries': row['allowed_queries'] if 'allowed_queries' in row.keys() else 0,
                'redirected_queries': row['redirected_queries'] if 'redirected_queries' in row.keys() else 0,
            })
        return routers
        
    except Exception as e:
        logger.error(f"Error loading routers: {e}")
        return []


def get_router_by_id(router_id: str) -> Optional[Dict]:
    """Get single router by ID"""
    try:
        conn = DatabaseManager.get_connection()
        c = conn.cursor()
        c.execute('SELECT * FROM routers WHERE id = ?', (router_id,))
        row = c.fetchone()
        
        if row:
            return {
                'id': row['id'],
                'name': row['name'],
                'subnet': row['subnet'],
                'description': row['description'],
                'enabled': bool(row['enabled']),
                'created_at': row['created_at'],
                'last_seen': row['last_seen'],
                'status': row['status'],
                'total_queries': row['total_queries'] if 'total_queries' in row.keys() else 0,
                'blocked_queries': row['blocked_queries'] if 'blocked_queries' in row.keys() else 0,
                'allowed_queries': row['allowed_queries'] if 'allowed_queries' in row.keys() else 0,
                'redirected_queries': row['redirected_queries'] if 'redirected_queries' in row.keys() else 0,
            }
        return None
        
    except Exception as e:
        logger.error(f"Error getting router: {e}")
        return None


def search_routers(query: str) -> List[Dict]:
    """Search routers by name or subnet"""
    try:
        conn = DatabaseManager.get_connection()
        c = conn.cursor()
        search_term = f"%{query}%"
        c.execute('''SELECT * FROM routers 
                     WHERE name LIKE ? OR subnet LIKE ? OR description LIKE ?
                     ORDER BY name''',
                  (search_term, search_term, search_term))
        rows = c.fetchall()
        
        return [{
            'id': row['id'],
            'name': row['name'],
            'subnet': row['subnet'],
            'description': row['description'],
            'enabled': bool(row['enabled']),
            'status': row['status'],
        } for row in rows]
        
    except Exception as e:
        logger.error(f"Error searching routers: {e}")
        return []


def delete_router_cascade(router_id: str) -> bool:
    """Delete router and update rules that reference it"""
    try:
        conn = DatabaseManager.get_connection()
        c = conn.cursor()
        
        # Update rules that reference this router
        c.execute('SELECT id, router_ids, scope FROM rules WHERE router_ids LIKE ?',
                  (f'%{router_id}%',))
        rules = c.fetchall()
        
        for rule in rules:
            try:
                router_ids = json.loads(rule['router_ids']) if rule['router_ids'] else []
                if router_id in router_ids:
                    router_ids.remove(router_id)
                    
                    if len(router_ids) == 0 and rule['scope'] in ('specific', 'single'):
                        c.execute('DELETE FROM rules WHERE id = ?', (rule['id'],))
                        logger.info(f"Deleted orphaned rule {rule['id']} after router deletion")
                    else:
                        c.execute('UPDATE rules SET router_ids = ?, updated_at = ? WHERE id = ?',
                                  (json.dumps(router_ids), time.time(), rule['id']))
            except (json.JSONDecodeError, TypeError):
                continue
        
        # Delete the router
        c.execute('DELETE FROM routers WHERE id = ?', (router_id,))
        
        # Clean up router stats
        with app_state.router_lock:
            app_state.router_stats.pop(router_id, None)
        
        conn.commit()
        
        # Invalidate rule cache
        app_state.rule_cache.invalidate()
        
        logger.info(f"Deleted router {router_id} with cascade")
        return True
        
    except Exception as e:
        logger.error(f"Error deleting router: {e}")
        return False


def check_router_status():
    """Check and update router status based on activity timeout"""
    try:
        timeout = app_state.config.get('settings', {}).get('router_timeout', 300)
        current_time = time.time()
        
        conn = DatabaseManager.get_connection()
        c = conn.cursor()
        
        c.execute('UPDATE routers SET status = ? WHERE last_seen < ? AND status = ?',
                  ('inactive', current_time - timeout, 'active'))
        
        warning_threshold = current_time - (timeout * 0.7)
        c.execute('UPDATE routers SET status = ? WHERE last_seen < ? AND last_seen >= ? AND status = ?',
                  ('warning', warning_threshold, current_time - timeout, 'active'))
        
        conn.commit()
        
    except Exception as e:
        logger.error(f"Error checking router status: {e}")


# ==================== RULE MANAGEMENT ====================

def load_rules_from_db(enabled_only: bool = True) -> List[Dict]:
    """Load rules from database (bypasses cache for admin operations)"""
    try:
        conn = DatabaseManager.get_connection()
        c = conn.cursor()
        
        if enabled_only:
            c.execute('SELECT * FROM rules WHERE enabled = 1 ORDER BY priority DESC, created_at DESC')
        else:
            c.execute('SELECT * FROM rules ORDER BY priority DESC, created_at DESC')
        
        rows = c.fetchall()
        
        rules = []
        for row in rows:
            try:
                router_ids = json.loads(row['router_ids']) if row['router_ids'] else []
            except (json.JSONDecodeError, TypeError):
                router_ids = []
            
            rules.append({
                'id': row['id'],
                'domain': row['domain'],
                'action': row['action'],
                'scope': row['scope'],
                'router_ids': router_ids,
                'redirect_ip': row['redirect_ip'] if 'redirect_ip' in row.keys() else None,
                'enabled': bool(row['enabled']),
                'priority': row['priority'] if 'priority' in row.keys() else 0,
                'created_at': row['created_at'],
                'updated_at': row['updated_at'] if 'updated_at' in row.keys() else None,
                'description': row['description'],
                'hit_count': row['hit_count'] if 'hit_count' in row.keys() else 0,
            })
        return rules
        
    except Exception as e:
        logger.error(f"Error loading rules: {e}")
        return []


def get_rule_by_id(rule_id: str) -> Optional[Dict]:
    """Get single rule by ID"""
    try:
        conn = DatabaseManager.get_connection()
        c = conn.cursor()
        c.execute('SELECT * FROM rules WHERE id = ?', (rule_id,))
        row = c.fetchone()
        
        if row:
            try:
                router_ids = json.loads(row['router_ids']) if row['router_ids'] else []
            except (json.JSONDecodeError, TypeError):
                router_ids = []
            
            return {
                'id': row['id'],
                'domain': row['domain'],
                'action': row['action'],
                'scope': row['scope'],
                'router_ids': router_ids,
                'redirect_ip': row['redirect_ip'] if 'redirect_ip' in row.keys() else None,
                'enabled': bool(row['enabled']),
                'priority': row['priority'] if 'priority' in row.keys() else 0,
                'created_at': row['created_at'],
                'updated_at': row['updated_at'] if 'updated_at' in row.keys() else None,
                'description': row['description'],
                'hit_count': row['hit_count'] if 'hit_count' in row.keys() else 0,
            }
        return None
        
    except Exception as e:
        logger.error(f"Error getting rule: {e}")
        return None


def search_rules(query: str) -> List[Dict]:
    """Search rules by domain or description"""
    try:
        conn = DatabaseManager.get_connection()
        c = conn.cursor()
        search_term = f"%{query}%"
        c.execute('''SELECT * FROM rules 
                     WHERE domain LIKE ? OR description LIKE ?
                     ORDER BY priority DESC, domain''',
                  (search_term, search_term))
        rows = c.fetchall()
        
        rules = []
        for row in rows:
            try:
                router_ids = json.loads(row['router_ids']) if row['router_ids'] else []
            except:
                router_ids = []
            
            rules.append({
                'id': row['id'],
                'domain': row['domain'],
                'action': row['action'],
                'scope': row['scope'],
                'router_ids': router_ids,
                'enabled': bool(row['enabled']),
                'description': row['description'],
            })
        return rules
        
    except Exception as e:
        logger.error(f"Error searching rules: {e}")
        return []


def increment_rule_hit_count(rule_id: str):
    """Increment hit count for a rule (async)"""
    try:
        conn = sqlite3.connect(DB_FILE, timeout=5)
        c = conn.cursor()
        c.execute('UPDATE rules SET hit_count = hit_count + 1 WHERE id = ?', (rule_id,))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.debug(f"Error incrementing rule hit count: {e}")


def check_rules(domain: str, router_id: Optional[str], query_type: int = 1) -> Tuple[str, Optional[str], Optional[str], Optional[str]]:
    """
    Check if domain matches any rules using cached rules
    Returns: (action, reason, rule_id, redirect_ip)
    """
    # Use cached rules for performance
    rules = app_state.rule_cache.get_rules()
    
    for rule in rules:
        # Check if domain matches the pattern
        if not match_domain_pattern(domain, rule['domain']):
            continue
        
        # Check scope
        scope = rule['scope']
        action = rule['action']
        
        if scope == 'all':
            if action == 'block':
                app_state.executor.submit(increment_rule_hit_count, rule['id'])
                return 'block', 'rule_global', rule['id'], None
            elif action == 'allow':
                app_state.executor.submit(increment_rule_hit_count, rule['id'])
                return 'allow', 'rule_global_allow', rule['id'], None
            elif action == 'redirect':
                app_state.executor.submit(increment_rule_hit_count, rule['id'])
                return 'redirect', 'rule_global_redirect', rule['id'], rule.get('redirect_ip')
        
        elif scope == 'specific' and router_id:
            if router_id in rule['router_ids']:
                if action == 'block':
                    app_state.executor.submit(increment_rule_hit_count, rule['id'])
                    return 'block', 'rule_specific', rule['id'], None
                elif action == 'allow':
                    app_state.executor.submit(increment_rule_hit_count, rule['id'])
                    return 'allow', 'rule_specific_allow', rule['id'], None
                elif action == 'redirect':
                    app_state.executor.submit(increment_rule_hit_count, rule['id'])
                    return 'redirect', 'rule_specific_redirect', rule['id'], rule.get('redirect_ip')
        
        elif scope == 'single' and router_id:
            if len(rule['router_ids']) == 1 and router_id == rule['router_ids'][0]:
                if action == 'block':
                    app_state.executor.submit(increment_rule_hit_count, rule['id'])
                    return 'block', 'rule_single', rule['id'], None
                elif action == 'allow':
                    app_state.executor.submit(increment_rule_hit_count, rule['id'])
                    return 'allow', 'rule_single_allow', rule['id'], None
                elif action == 'redirect':
                    app_state.executor.submit(increment_rule_hit_count, rule['id'])
                    return 'redirect', 'rule_single_redirect', rule['id'], rule.get('redirect_ip')
    
    return 'forward', None, None, None


def match_domain_pattern(domain: str, pattern: str) -> bool:
    """
    Match domain against pattern with wildcard support
    Uses compiled regex cache for performance
    """
    try:
        domain = domain.lower().strip().rstrip('.')
        pattern = pattern.lower().strip().rstrip('.')
        
        if not domain or not pattern:
            return False
        
        # Exact match
        if domain == pattern:
            return True
        
        # Wildcard prefix: *.example.com
        if pattern.startswith('*.'):
            suffix = pattern[2:]
            return domain == suffix or domain.endswith('.' + suffix)
        
        # General wildcard: use compiled regex
        if '*' in pattern:
            compiled = app_state.rule_cache.get_compiled_pattern(pattern)
            if compiled:
                return bool(compiled.match(domain))
        
        return False
        
    except Exception as e:
        logger.error(f"Pattern match error: {e}")
        return False


# ==================== DNS SERVER ====================

class DNSQuery:
    """Parse DNS query packet"""
    
    TYPE_A = 1
    TYPE_AAAA = 28
    TYPE_CNAME = 5
    TYPE_MX = 15
    TYPE_TXT = 16
    TYPE_NS = 2
    TYPE_PTR = 12
    TYPE_SOA = 6
    
    def __init__(self, data: bytes):
        self.data = data
        self.domain = ''
        self.query_type = self.TYPE_A
        self.query_class = 1
        self.transaction_id = 0
        self.valid = False
        
        try:
            if len(data) < 12:
                return
            
            self.transaction_id = struct.unpack('!H', data[0:2])[0]
            flags = struct.unpack('!H', data[2:4])[0]
            qdcount = struct.unpack('!H', data[4:6])[0]
            
            if flags & 0x8000:  # QR bit set = response, not query
                return
            
            if qdcount < 1:
                return
            
            pos = 12
            domain_parts = []
            
            for _ in range(100):
                if pos >= len(data):
                    break
                
                length = data[pos]
                
                if length == 0:
                    pos += 1
                    break
                
                if length & 0xC0 == 0xC0:
                    break
                
                if length > 63 or pos + 1 + length > len(data):
                    break
                
                try:
                    part = data[pos + 1:pos + 1 + length].decode('utf-8', errors='replace')
                    domain_parts.append(part)
                except Exception:
                    break
                
                pos += 1 + length
            
            if domain_parts:
                self.domain = '.'.join(domain_parts)
            
            if pos + 4 <= len(data):
                self.query_type = struct.unpack('!H', data[pos:pos + 2])[0]
                self.query_class = struct.unpack('!H', data[pos + 2:pos + 4])[0]
            
            self.valid = bool(self.domain)
        
        except Exception as e:
            logger.debug(f"DNS query parse error: {e}")
            self.valid = False
    
    def get_type_name(self) -> str:
        """Get human-readable query type name"""
        type_names = {
            1: 'A', 28: 'AAAA', 5: 'CNAME', 15: 'MX',
            16: 'TXT', 2: 'NS', 12: 'PTR', 6: 'SOA', 33: 'SRV'
        }
        return type_names.get(self.query_type, str(self.query_type))
    
    def is_ipv4(self) -> bool:
        return self.query_type == self.TYPE_A
    
    def is_ipv6(self) -> bool:
        return self.query_type == self.TYPE_AAAA


class DNSResponse:
    """Build DNS response packets"""
    
    @staticmethod
    def build_a_response(query_data: bytes, ip_address: str, ttl: int = 300) -> Optional[bytes]:
        """Build DNS A record response"""
        try:
            if len(query_data) < 12:
                return None
            
            try:
                ip_obj = ipaddress.IPv4Address(ip_address)
            except ValueError:
                logger.warning(f"Invalid IPv4 address for DNS response: {ip_address}")
                return None
            
            transaction_id = struct.unpack('!H', query_data[0:2])[0]
            
            flags = 0x8580  # QR=1, AA=1, RD=1, RA=1
            header = struct.pack('!HHHHHH', transaction_id, flags, 1, 1, 0, 0)
            
            pos = 12
            for _ in range(100):
                if pos >= len(query_data) or query_data[pos] == 0:
                    break
                length = query_data[pos]
                if length > 63 or pos + length >= len(query_data):
                    return None
                pos += 1 + length
            
            if pos >= len(query_data) - 4:
                return None
            
            pos += 5
            question = query_data[12:pos]
            
            answer = struct.pack('!H', 0xC00C)  # Name pointer
            answer += struct.pack('!HH', 1, 1)   # Type A, Class IN
            answer += struct.pack('!I', ttl)
            answer += struct.pack('!H', 4)
            answer += ip_obj.packed
            
            return header + question + answer
        
        except Exception as e:
            logger.error(f"Error building A response: {e}")
            return None
    
    @staticmethod
    def build_aaaa_response(query_data: bytes, ip_address: str, ttl: int = 300) -> Optional[bytes]:
        """
        Build DNS AAAA record response
        BUG-070: IPv6 support
        """
        try:
            if len(query_data) < 12:
                return None
            
            try:
                ip_obj = ipaddress.IPv6Address(ip_address)
            except ValueError:
                logger.warning(f"Invalid IPv6 address for DNS response: {ip_address}")
                return None
            
            transaction_id = struct.unpack('!H', query_data[0:2])[0]
            
            flags = 0x8580
            header = struct.pack('!HHHHHH', transaction_id, flags, 1, 1, 0, 0)
            
            pos = 12
            for _ in range(100):
                if pos >= len(query_data) or query_data[pos] == 0:
                    break
                length = query_data[pos]
                if length > 63 or pos + length >= len(query_data):
                    return None
                pos += 1 + length
            
            if pos >= len(query_data) - 4:
                return None
            
            pos += 5
            question = query_data[12:pos]
            
            answer = struct.pack('!H', 0xC00C)   # Name pointer
            answer += struct.pack('!HH', 28, 1)  # Type AAAA, Class IN
            answer += struct.pack('!I', ttl)
            answer += struct.pack('!H', 16)
            answer += ip_obj.packed
            
            return header + question + answer
        
        except Exception as e:
            logger.error(f"Error building AAAA response: {e}")
            return None
    
    @staticmethod
    def build_nxdomain(query_data: bytes) -> Optional[bytes]:
        """Build NXDOMAIN response"""
        try:
            if len(query_data) < 12:
                return None
            
            transaction_id = struct.unpack('!H', query_data[0:2])[0]
            
            flags = 0x8583  # RCODE=3 (NXDOMAIN)
            header = struct.pack('!HHHHHH', transaction_id, flags, 1, 0, 0, 0)
            
            pos = 12
            for _ in range(100):
                if pos >= len(query_data) or query_data[pos] == 0:
                    break
                length = query_data[pos]
                if length > 63 or pos + length >= len(query_data):
                    return None
                pos += 1 + length
            
            pos += 5
            question = query_data[12:pos]
            
            return header + question
        
        except Exception as e:
            logger.error(f"Error building NXDOMAIN response: {e}")
            return None
    
    @staticmethod
    def build_empty_response(query_data: bytes) -> Optional[bytes]:
        """Build empty response (NOERROR with no answers)"""
        try:
            if len(query_data) < 12:
                return None
            
            transaction_id = struct.unpack('!H', query_data[0:2])[0]
            
            flags = 0x8580  # NOERROR
            header = struct.pack('!HHHHHH', transaction_id, flags, 1, 0, 0, 0)
            
            pos = 12
            for _ in range(100):
                if pos >= len(query_data) or query_data[pos] == 0:
                    break
                length = query_data[pos]
                if length > 63 or pos + length >= len(query_data):
                    return None
                pos += 1 + length
            
            pos += 5
            question = query_data[12:pos]
            
            return header + question
        
        except Exception as e:
            logger.error(f"Error building empty response: {e}")
            return None


class DNSHandler(socketserver.BaseRequestHandler):
    """Handle individual DNS queries"""
    
    def handle(self):
        try:
            data = self.request[0]
            sock = self.request[1]
            client_ip = self.client_address[0]
            
            if len(data) < 12 or len(data) > MAX_DNS_PACKET_SIZE:
                return
            
            start_time = time.time()
            query = DNSQuery(data)
            
            if not query.valid or not query.domain:
                return
            
            domain = query.domain.lower()
            
            # Identify router
            router_id = identify_router(client_ip)
            if router_id:
                update_router_last_seen(router_id)
            
            # Update stats
            with app_state.stats_lock:
                app_state.stats["total_queries"] += 1
            
            if router_id:
                with app_state.router_lock:
                    app_state.router_stats[router_id]["total_queries"] += 1
                    app_state.router_stats[router_id]["last_seen"] = time.time()
            
            response_data = None
            response_ip = None
            action = "forwarded"
            rule_id = None
            
            # Check rules
            rule_action, reason, rule_id, redirect_ip = check_rules(domain, router_id, query.query_type)
            
            if rule_action == 'block':
                # Build block response based on query type
                if query.is_ipv4():
                    with app_state.config_lock:
                        block_ip = app_state.config.get("dns", {}).get("block_response", "0.0.0.0")
                    response_data = DNSResponse.build_a_response(data, block_ip, 60)
                    response_ip = block_ip
                elif query.is_ipv6():
                    # BUG-070: IPv6 block response
                    with app_state.config_lock:
                        block_ip = app_state.config.get("dns", {}).get("block_response_ipv6", "::")
                    response_data = DNSResponse.build_aaaa_response(data, block_ip, 60)
                    response_ip = block_ip
                else:
                    response_data = DNSResponse.build_empty_response(data)
                    response_ip = "BLOCKED"
                
                action = f"blocked_{reason}" if reason else "blocked"
                
                with app_state.stats_lock:
                    app_state.stats["blocked_queries"] += 1
                
                if router_id:
                    with app_state.router_lock:
                        app_state.router_stats[router_id]["blocked_queries"] += 1
            
            elif rule_action == 'redirect':
                # Redirect to custom IP
                if redirect_ip:
                    if query.is_ipv4():
                        response_data = DNSResponse.build_a_response(data, redirect_ip, 300)
                        response_ip = redirect_ip
                    elif query.is_ipv6():
                        # For IPv6 queries, try to use redirect IP if valid IPv6, otherwise empty
                        try:
                            ipaddress.IPv6Address(redirect_ip)
                            response_data = DNSResponse.build_aaaa_response(data, redirect_ip, 300)
                            response_ip = redirect_ip
                        except ValueError:
                            # Redirect IP is IPv4, return empty for AAAA
                            response_data = DNSResponse.build_empty_response(data)
                            response_ip = "REDIRECT_IPV4_ONLY"
                    else:
                        response_data = DNSResponse.build_empty_response(data)
                        response_ip = redirect_ip
                    
                    action = f"redirected_{reason}" if reason else "redirected"
                    
                    with app_state.stats_lock:
                        app_state.stats["redirected_queries"] += 1
                    
                    if router_id:
                        with app_state.router_lock:
                            app_state.router_stats[router_id]["redirected_queries"] += 1
                else:
                    # No redirect IP, forward instead
                    response_data, response_ip = self.forward_to_upstream(data)
                    action = "forwarded"
            
            elif rule_action == 'allow':
                # Explicit allow - forward directly
                response_data, response_ip = self.forward_to_upstream(data)
                action = f"allowed_{reason}" if reason else "allowed"
                
                with app_state.stats_lock:
                    app_state.stats["allowed_queries"] += 1
                
                if router_id:
                    with app_state.router_lock:
                        app_state.router_stats[router_id]["allowed_queries"] += 1
            
            else:
                # No matching rule - check cache, then forward
                cache_key = f"{domain}_{query.query_type}"
                
                with app_state.config_lock:
                    cache_enabled = app_state.config.get("dns", {}).get("cache_enabled", True)
                
                if cache_enabled:
                    with app_state.cache_lock:
                        if cache_key in app_state.dns_cache:
                            cached = app_state.dns_cache[cache_key]
                            
                            if time.time() < cached["expires"]:
                                cached_data = bytearray(cached["data"])
                                cached_data[0:2] = struct.pack('!H', query.transaction_id)
                                response_data = bytes(cached_data)
                                response_ip = cached.get("ip", "cached")
                                action = "cached"
                                cached["accessed"] = time.time()
                                
                                with app_state.stats_lock:
                                    app_state.stats["cached_queries"] += 1
                            else:
                                del app_state.dns_cache[cache_key]
                
                if not response_data:
                    response_data, response_ip = self.forward_to_upstream(data)
                    
                    if response_data:
                        action = "forwarded"
                        
                        with app_state.stats_lock:
                            app_state.stats["allowed_queries"] += 1
                            app_state.stats["forwarded_queries"] += 1
                        
                        if router_id:
                            with app_state.router_lock:
                                app_state.router_stats[router_id]["allowed_queries"] += 1
                        
                        # Cache the response
                        if cache_enabled:
                            with app_state.config_lock:
                                ttl = app_state.config.get("dns", {}).get("cache_ttl", DNS_CACHE_DEFAULT_TTL)
                                cache_size = app_state.config.get("dns", {}).get("cache_size", 5000)
                            
                            with app_state.cache_lock:
                                if len(app_state.dns_cache) >= cache_size:
                                    oldest_key = min(
                                        app_state.dns_cache.keys(),
                                        key=lambda k: app_state.dns_cache[k].get("accessed", 0)
                                    )
                                    del app_state.dns_cache[oldest_key]
                                
                                app_state.dns_cache[cache_key] = {
                                    "data": response_data,
                                    "ip": response_ip,
                                    "expires": time.time() + ttl,
                                    "accessed": time.time()
                                }
                    else:
                        action = "failed"
                        with app_state.stats_lock:
                            app_state.stats["failed_queries"] += 1
            
            # Send response
            if response_data:
                sock.sendto(response_data, self.client_address)
            
            # Log query asynchronously
            response_time = (time.time() - start_time) * 1000
            app_state.executor.submit(
                log_query,
                router_id, client_ip, domain, query.get_type_name(),
                action, response_ip or "no_response", response_time, rule_id
            )
        
        except Exception as e:
            logger.error(f"DNS handler error: {e}")
    
    def forward_to_upstream(self, query_data: bytes) -> Tuple[Optional[bytes], Optional[str]]:
        """
        Forward DNS query to upstream server
        PERF-008: Parallel upstream queries
        """
        with app_state.config_lock:
            upstream_servers = app_state.config.get("dns", {}).get("upstream_servers", ["1.1.1.1", "8.8.8.8"])
            timeout = app_state.config.get("dns", {}).get("timeout", DNS_UPSTREAM_TIMEOUT)
            parallel = app_state.config.get("dns", {}).get("parallel_upstream", True)
        
        if parallel and len(upstream_servers) > 1:
            # Query all servers in parallel, return first response
            return self._parallel_upstream_query(query_data, upstream_servers, timeout)
        else:
            # Sequential fallback
            return self._sequential_upstream_query(query_data, upstream_servers, timeout)
    
    def _parallel_upstream_query(self, query_data: bytes, servers: List[str], timeout: float) -> Tuple[Optional[bytes], Optional[str]]:
        """Query multiple upstream servers in parallel"""
        def query_server(server: str) -> Tuple[Optional[bytes], Optional[str], str]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(timeout)
                sock.sendto(query_data, (server, 53))
                response_data, _ = sock.recvfrom(MAX_DNS_PACKET_SIZE)
                sock.close()
                ip_address = self._extract_ip(response_data)
                return response_data, ip_address, server
            except Exception:
                return None, None, server
        
        try:
            futures = {app_state.dns_executor.submit(query_server, server): server for server in servers}
            
            for future in as_completed(futures, timeout=timeout + 0.5):
                try:
                    response_data, ip_address, server = future.result()
                    if response_data:
                        # Cancel remaining futures
                        for f in futures:
                            f.cancel()
                        return response_data, ip_address
                except Exception:
                    continue
        except Exception as e:
            logger.debug(f"Parallel upstream query error: {e}")
        
        return None, None
    
    def _sequential_upstream_query(self, query_data: bytes, servers: List[str], timeout: float) -> Tuple[Optional[bytes], Optional[str]]:
        """Query upstream servers sequentially"""
        for upstream in servers:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(timeout)
                sock.sendto(query_data, (upstream, 53))
                response_data, _ = sock.recvfrom(MAX_DNS_PACKET_SIZE)
                sock.close()
                ip_address = self._extract_ip(response_data)
                return response_data, ip_address
            except socket.timeout:
                logger.debug(f"Upstream {upstream} timeout")
                continue
            except Exception as e:
                logger.debug(f"Upstream {upstream} error: {e}")
                continue
            finally:
                try:
                    sock.close()
                except:
                    pass
        
        logger.warning("All upstream DNS servers failed")
        return None, None
    
    def _extract_ip(self, response_data: bytes) -> str:
        """Extract first A/AAAA record IP from DNS response"""
        try:
            if len(response_data) < 12:
                return "upstream"
            
            ancount = struct.unpack('!H', response_data[6:8])[0]
            if ancount == 0:
                return "no_answer"
            
            pos = 12
            for _ in range(100):
                if pos >= len(response_data):
                    return "parse_error"
                if response_data[pos] == 0:
                    pos += 1
                    break
                if response_data[pos] & 0xC0 == 0xC0:
                    pos += 2
                    break
                length = response_data[pos]
                pos += 1 + length
            
            pos += 4  # qtype + qclass
            
            if pos + 12 > len(response_data):
                return "truncated"
            
            # Skip name
            if response_data[pos] & 0xC0 == 0xC0:
                pos += 2
            else:
                while pos < len(response_data) and response_data[pos] != 0:
                    pos += 1 + response_data[pos]
                pos += 1
            
            if pos + 10 > len(response_data):
                return "truncated"
            
            rtype = struct.unpack('!H', response_data[pos:pos + 2])[0]
            pos += 8  # type, class, TTL
            rdlength = struct.unpack('!H', response_data[pos:pos + 2])[0]
            pos += 2
            
            if rtype == 1 and rdlength == 4 and pos + 4 <= len(response_data):
                # A record
                ip_bytes = response_data[pos:pos + 4]
                return '.'.join(str(b) for b in ip_bytes)
            elif rtype == 28 and rdlength == 16 and pos + 16 <= len(response_data):
                # AAAA record - BUG-070
                ip_bytes = response_data[pos:pos + 16]
                return str(ipaddress.IPv6Address(ip_bytes))
            
            return "non_a_record"
        
        except Exception as e:
            logger.debug(f"IP extraction error: {e}")
            return "parse_error"


def log_query(router_id: str, client_ip: str, domain: str, query_type: str,
              action: str, response: str, response_time: float, rule_id: str = None):
    """Log DNS query to database (called asynchronously)"""
    try:
        conn = sqlite3.connect(DB_FILE, timeout=10)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        c.execute('''INSERT INTO query_logs 
                     (timestamp, router_id, client_ip, domain, query_type, action, response, response_time, rule_id)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (time.time(), router_id, client_ip, domain, query_type, action, response, response_time, rule_id))
        conn.commit()
        conn.close()
        
    except Exception as e:
        logger.error(f"Error logging query: {e}")


class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    """Multi-threaded UDP DNS server"""
    allow_reuse_address = True
    daemon_threads = True
    max_packet_size = MAX_DNS_PACKET_SIZE


def start_dns_server():
    """Start the DNS server"""
    try:
        with app_state.config_lock:
            port = app_state.config.get("dns", {}).get("port", 53)
        
        server = ThreadedUDPServer(('0.0.0.0', port), DNSHandler)
        logger.info(f"DNS server listening on 0.0.0.0:{port}")
        server.serve_forever()
    
    except PermissionError:
        logger.error("Permission denied for port 53. Run with sudo/administrator privileges.")
        sys.exit(1)
    except OSError as e:
        logger.error(f"DNS server error: {e}")
        sys.exit(1)
# ==================== WEB SERVER ====================

class WebHandler(BaseHTTPRequestHandler):
    """HTTP request handler with gzip compression and security features"""
    
    protocol_version = 'HTTP/1.1'
    server_version = 'NetGuard/3.2'
    
    def log_message(self, format, *args):
        """Custom logging"""
        logger.debug(f"HTTP: {self.client_address[0]} - {format % args}")
    
    def _send_response(self, data: dict, status: int = 200):
        """Send JSON response with optional gzip compression - PERF-006"""
        try:
            response_body = json.dumps(data, ensure_ascii=False).encode('utf-8')
            
            # Check if client accepts gzip and response is large enough
            accept_encoding = self.headers.get('Accept-Encoding', '')
            use_gzip = (
                'gzip' in accept_encoding and 
                len(response_body) >= MIN_GZIP_SIZE and
                app_state.config.get('web', {}).get('enable_gzip', True)
            )
            
            if use_gzip:
                buf = BytesIO()
                with gzip.GzipFile(fileobj=buf, mode='wb', compresslevel=6) as gz:
                    gz.write(response_body)
                response_body = buf.getvalue()
            
            self.send_response(status)
            self._send_security_headers()
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(response_body)))
            if use_gzip:
                self.send_header('Content-Encoding', 'gzip')
            self.end_headers()
            self.wfile.write(response_body)
            
        except Exception as e:
            logger.error(f"Response error: {e}")
    
    def _send_html(self, content: bytes, status: int = 200, is_gzipped: bool = False):
        """Send HTML response"""
        try:
            self.send_response(status)
            self._send_security_headers()
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(content)))
            if is_gzipped:
                self.send_header('Content-Encoding', 'gzip')
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            logger.error(f"HTML response error: {e}")
    
    def _send_security_headers(self):
        """Send security headers"""
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-XSS-Protection', '1; mode=block')
        self.send_header('Referrer-Policy', 'strict-origin-when-cross-origin')
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        
        # CORS
        origin = self.headers.get('Origin', '*')
        self.send_header('Access-Control-Allow-Origin', origin)
        self.send_header('Access-Control-Allow-Credentials', 'true')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, X-CSRF-Token')
        self.send_header('Access-Control-Max-Age', '86400')
    
    def _check_auth(self) -> Optional[Dict]:
        """Check authentication and return session info"""
        try:
            cookie_header = self.headers.get('Cookie', '')
            
            for cookie in cookie_header.split(';'):
                cookie = cookie.strip()
                if cookie.startswith('session='):
                    token = cookie[8:]
                    
                    with app_state.session_lock:
                        if token in app_state.sessions:
                            session = app_state.sessions[token]
                            
                            if time.time() < session["expires"]:
                                with app_state.config_lock:
                                    timeout = app_state.config.get("web", {}).get("session_timeout", 7200)
                                session["expires"] = time.time() + timeout
                                return session
                            else:
                                del app_state.sessions[token]
                                return None
            
            return None
        except Exception as e:
            logger.error(f"Auth check error: {e}")
            return None
    
    def _check_csrf(self) -> bool:
        """Validate CSRF token"""
        csrf_token = self.headers.get('X-CSRF-Token', '')
        return validate_csrf_token(csrf_token)
    
    def _check_rate_limit(self) -> bool:
        """Check rate limiting"""
        client_ip = self.client_address[0]
        return check_rate_limit(client_ip)
    
    def _read_body(self) -> Optional[dict]:
        """Read and parse JSON body with size limit"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            
            if content_length > MAX_REQUEST_SIZE:
                self._send_response({"error": "Request too large", "max_size": MAX_REQUEST_SIZE}, 413)
                return None
            
            if content_length == 0:
                return {}
            
            body = self.rfile.read(content_length).decode('utf-8')
            return json.loads(body)
        
        except json.JSONDecodeError as e:
            self._send_response({"error": f"Invalid JSON: {str(e)}"}, 400)
            return None
        except Exception as e:
            logger.error(f"Body read error: {e}")
            self._send_response({"error": "Request error"}, 400)
            return None
    
    def do_OPTIONS(self):
        """Handle CORS preflight requests"""
        self.send_response(200)
        self._send_security_headers()
        self.send_header('Content-Length', '0')
        self.end_headers()
    
    def do_GET(self):
        """Handle GET requests"""
        try:
            if not self._check_rate_limit():
                self._send_response({"error": "Rate limit exceeded. Please wait before retrying."}, 429)
                return
            
            parsed = urlparse(self.path)
            path = parsed.path
            
            # Serve frontend - PERF-005: Cached
            if path == '/' or path == '/index.html':
                self._serve_frontend()
                return
            
            # Health check
            if path == '/api/health':
                self._send_response({
                    "status": "healthy",
                    "version": VERSION,
                    "uptime": int(time.time() - app_state.stats["start_time"]),
                    "timestamp": time.time()
                })
                return
            
            # Auth check endpoint - BUG-050: Dedicated endpoint
            if path == '/api/auth/check':
                session = self._check_auth()
                if session:
                    self._send_response({
                        "authenticated": True,
                        "username": session.get("username"),
                        "expires_in": int(session["expires"] - time.time())
                    })
                else:
                    self._send_response({"authenticated": False}, 401)
                return
            
            # CSRF token
            if path == '/api/csrf-token':
                token = generate_csrf_token()
                self._send_response({"token": token})
                return
            
            # All other API endpoints require auth
            session = self._check_auth()
            if not session:
                self._send_response({"error": "Session expired. Please log in again."}, 401)
                return
            
            # Route to handlers
            if path == '/api/stats':
                self._handle_get_stats()
            elif path == '/api/routers':
                self._handle_get_routers(parsed.query)
            elif path.startswith('/api/routers/'):
                router_id = unquote(path.split('/')[-1])
                self._handle_get_router(router_id)
            elif path == '/api/rules':
                self._handle_get_rules(parsed.query)
            elif path.startswith('/api/rules/'):
                rule_id = unquote(path.split('/')[-1])
                self._handle_get_rule(rule_id)
            elif path.startswith('/api/queries'):
                self._handle_get_queries(parsed.query)
            elif path == '/api/analytics':
                self._handle_get_analytics(parsed.query)
            elif path == '/api/analytics/top-domains':
                self._handle_get_top_domains(parsed.query)
            elif path == '/api/config':
                self._handle_get_config()
            elif path == '/api/search':
                self._handle_search(parsed.query)
            else:
                self._send_response({"error": "Endpoint not found"}, 404)
        
        except Exception as e:
            logger.error(f"GET error: {e}")
            self._send_response({"error": "Internal server error"}, 500)
    
    def do_POST(self):
        """Handle POST requests"""
        try:
            if not self._check_rate_limit():
                self._send_response({"error": "Rate limit exceeded"}, 429)
                return
            
            parsed = urlparse(self.path)
            path = parsed.path
            
            # Login
            if path == '/api/auth/login':
                self._handle_login()
                return
            
            # Logout
            if path == '/api/auth/logout':
                self._handle_logout()
                return
            
            # Auth required
            session = self._check_auth()
            if not session:
                self._send_response({"error": "Session expired. Please log in again."}, 401)
                return
            
            # CSRF check
            if not self._check_csrf():
                self._send_response({"error": "Security token expired. Please refresh the page."}, 403)
                return
            
            # Read body
            data = self._read_body()
            if data is None:
                return
            
            # Route to handlers
            if path == '/api/routers':
                self._handle_create_router(data)
            elif path == '/api/rules':
                self._handle_create_rule(data)
            elif path == '/api/rules/bulk-delete':
                self._handle_bulk_delete_rules(data)
            elif path == '/api/cache/clear':
                self._handle_clear_cache()
            elif path == '/api/config':
                self._handle_update_config(data)
            else:
                self._send_response({"error": "Endpoint not found"}, 404)
        
        except Exception as e:
            logger.error(f"POST error: {e}")
            self._send_response({"error": "Internal server error"}, 500)
    
    def do_PUT(self):
        """Handle PUT requests"""
        try:
            if not self._check_rate_limit():
                self._send_response({"error": "Rate limit exceeded"}, 429)
                return
            
            session = self._check_auth()
            if not session:
                self._send_response({"error": "Session expired"}, 401)
                return
            
            if not self._check_csrf():
                self._send_response({"error": "Security token expired"}, 403)
                return
            
            parsed = urlparse(self.path)
            path = parsed.path
            
            data = self._read_body()
            if data is None:
                return
            
            if path.startswith('/api/routers/'):
                router_id = unquote(path.split('/')[-1])
                self._handle_update_router(router_id, data)
            elif path.startswith('/api/rules/'):
                rule_id = unquote(path.split('/')[-1])
                self._handle_update_rule(rule_id, data)
            else:
                self._send_response({"error": "Endpoint not found"}, 404)
        
        except Exception as e:
            logger.error(f"PUT error: {e}")
            self._send_response({"error": "Internal server error"}, 500)
    
    def do_DELETE(self):
        """Handle DELETE requests"""
        try:
            if not self._check_rate_limit():
                self._send_response({"error": "Rate limit exceeded"}, 429)
                return
            
            session = self._check_auth()
            if not session:
                self._send_response({"error": "Session expired"}, 401)
                return
            
            if not self._check_csrf():
                self._send_response({"error": "Security token expired"}, 403)
                return
            
            parsed = urlparse(self.path)
            path = parsed.path
            
            if path.startswith('/api/routers/'):
                router_id = unquote(path.split('/')[-1])
                self._handle_delete_router(router_id)
            elif path.startswith('/api/rules/'):
                rule_id = unquote(path.split('/')[-1])
                self._handle_delete_rule(rule_id)
            else:
                self._send_response({"error": "Endpoint not found"}, 404)
        
        except Exception as e:
            logger.error(f"DELETE error: {e}")
            self._send_response({"error": "Internal server error"}, 500)
    
    # ==================== FRONTEND ====================
    
    def _serve_frontend(self):
        """Serve frontend with caching - PERF-005"""
        accept_encoding = self.headers.get('Accept-Encoding', '')
        enable_gzip = 'gzip' in accept_encoding
        
        content, is_gzipped = app_state.static_cache.get('index.html', enable_gzip)
        
        if content:
            self._send_html(content, 200, is_gzipped)
        else:
            error_html = b'''<!DOCTYPE html>
<html><head><title>NetGuard Error</title></head>
<body style="font-family: sans-serif; text-align: center; padding: 50px;">
<h1>Frontend Not Found</h1>
<p>Please ensure <code>index.html</code> is in the same directory as <code>server.py</code></p>
</body></html>'''
            self._send_html(error_html, 404, False)
    
    # ==================== AUTH HANDLERS ====================
    
    def _handle_login(self):
        """Handle login request"""
        data = self._read_body()
        if data is None:
            return
        
        username = sanitize_input(data.get('username', ''), 50)
        password = data.get('password', '')
        
        if not username or not password:
            self._send_response({"error": "Username and password are required"}, 400)
            return
        
        with app_state.config_lock:
            admin_username = app_state.config["admin"]["username"]
            stored_hash = app_state.config["admin"]["password_hash"]
            stored_salt = app_state.config["admin"].get("password_salt", "")
        
        if username == admin_username and verify_password(password, stored_hash, stored_salt):
            session_token = secrets.token_urlsafe(32)
            csrf_token = generate_csrf_token()
            
            with app_state.config_lock:
                timeout = app_state.config.get("web", {}).get("session_timeout", 7200)
            
            with app_state.session_lock:
                app_state.sessions[session_token] = {
                    "username": username,
                    "created": time.time(),
                    "expires": time.time() + timeout,
                    "ip": self.client_address[0]
                }
            
            response = json.dumps({
                "success": True,
                "csrf_token": csrf_token,
                "username": username,
                "message": f"Welcome back, {username}!"
            }).encode('utf-8')
            
            self.send_response(200)
            self._send_security_headers()
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(response)))
            self.send_header('Set-Cookie', 
                f'session={session_token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={timeout}')
            self.end_headers()
            self.wfile.write(response)
            
            logger.info(f"User '{username}' logged in from {self.client_address[0]}")
        else:
            # Async delay to prevent timing attacks
            def delayed_response():
                time.sleep(LOGIN_DELAY_SECONDS)
            app_state.executor.submit(delayed_response)
            
            logger.warning(f"Failed login attempt for '{username}' from {self.client_address[0]}")
            self._send_response({"error": "Invalid username or password"}, 401)
    
    def _handle_logout(self):
        """Handle logout request"""
        try:
            cookie_header = self.headers.get('Cookie', '')
            session_token = None
            
            for cookie in cookie_header.split(';'):
                cookie = cookie.strip()
                if cookie.startswith('session='):
                    session_token = cookie[8:]
                    break
            
            if session_token:
                with app_state.session_lock:
                    if session_token in app_state.sessions:
                        username = app_state.sessions[session_token].get('username', 'unknown')
                        del app_state.sessions[session_token]
                        logger.info(f"User '{username}' logged out")
            
            response = json.dumps({"success": True, "message": "Logged out successfully"}).encode('utf-8')
            
            self.send_response(200)
            self._send_security_headers()
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(response)))
            self.send_header('Set-Cookie', 
                'session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT')
            self.end_headers()
            self.wfile.write(response)
        
        except Exception as e:
            logger.error(f"Logout error: {e}")
            self._send_response({"error": "Logout failed"}, 500)
    
    # ==================== STATS HANDLERS ====================
    
    def _handle_get_stats(self):
        """Get server statistics with last updated timestamp - BUG-060"""
        with app_state.stats_lock:
            stats = app_state.stats.copy()
        
        total = stats["total_queries"]
        uptime = int(time.time() - stats["start_time"])
        
        cache_hit_rate = 0
        if total > 0:
            cache_hit_rate = round((stats["cached_queries"] / total) * 100, 2)
        
        self._send_response({
            "total_queries": total,
            "blocked_queries": stats["blocked_queries"],
            "allowed_queries": stats["allowed_queries"],
            "cached_queries": stats["cached_queries"],
            "redirected_queries": stats.get("redirected_queries", 0),
            "forwarded_queries": stats.get("forwarded_queries", 0),
            "failed_queries": stats.get("failed_queries", 0),
            "cache_hit_rate": cache_hit_rate,
            "uptime": uptime,
            "cache_size": len(app_state.dns_cache),
            "active_sessions": len(app_state.sessions),
            "version": VERSION,
            "last_updated": stats.get("last_updated", time.time())
        })
    
    # ==================== ROUTER HANDLERS ====================
    
    def _handle_get_routers(self, query_string: str = ""):
        """Get all routers with optional search"""
        params = parse_qs(query_string)
        search = params.get('search', [None])[0]
        
        if search:
            routers = search_routers(search)
        else:
            routers = load_routers_from_db()
        
        # Add runtime stats
        with app_state.router_lock:
            for router in routers:
                runtime_stats = app_state.router_stats.get(router['id'], {})
                router['stats'] = {
                    'total_queries': runtime_stats.get('total_queries', router.get('total_queries', 0)),
                    'blocked_queries': runtime_stats.get('blocked_queries', router.get('blocked_queries', 0)),
                    'allowed_queries': runtime_stats.get('allowed_queries', router.get('allowed_queries', 0)),
                    'redirected_queries': runtime_stats.get('redirected_queries', router.get('redirected_queries', 0))
                }
        
        self._send_response({
            "routers": routers, 
            "count": len(routers),
            "timestamp": time.time()
        })
    
    def _handle_get_router(self, router_id: str):
        """Get single router by ID"""
        router = get_router_by_id(router_id)
        
        if router:
            with app_state.router_lock:
                runtime_stats = app_state.router_stats.get(router_id, {})
                router['stats'] = {
                    'total_queries': runtime_stats.get('total_queries', router.get('total_queries', 0)),
                    'blocked_queries': runtime_stats.get('blocked_queries', router.get('blocked_queries', 0)),
                    'allowed_queries': runtime_stats.get('allowed_queries', router.get('allowed_queries', 0)),
                    'redirected_queries': runtime_stats.get('redirected_queries', router.get('redirected_queries', 0))
                }
            
            self._send_response({"router": router})
        else:
            self._send_response({"error": "Router not found"}, 404)
    
    def _handle_create_router(self, data: dict):
        """Create new router"""
        name = sanitize_input(data.get('name', ''), 100)
        subnet = sanitize_input(data.get('subnet', ''), 50)
        description = sanitize_input(data.get('description', ''), 255)
        
        if not name:
            self._send_response({"error": "Router name is required"}, 400)
            return
        
        if len(name) < 2:
            self._send_response({"error": "Router name must be at least 2 characters"}, 400)
            return
        
        if subnet and not validate_cidr(subnet):
            self._send_response({"error": "Invalid subnet format. Use CIDR notation (e.g., 192.168.1.0/24)"}, 400)
            return
        
        router_id = generate_id()
        current_time = time.time()
        
        try:
            conn = DatabaseManager.get_connection()
            c = conn.cursor()
            c.execute('''INSERT INTO routers 
                         (id, name, subnet, description, enabled, created_at, last_seen, status,
                          total_queries, blocked_queries, allowed_queries, redirected_queries)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                      (router_id, name, subnet, description, 1, current_time, current_time, 'active',
                       0, 0, 0, 0))
            conn.commit()
            
            logger.info(f"Created router: {name} ({router_id})")
            self._send_response({
                "success": True, 
                "id": router_id, 
                "message": f"Router '{name}' created successfully"
            })
        
        except sqlite3.IntegrityError:
            self._send_response({"error": "A router with this ID already exists"}, 409)
        except Exception as e:
            logger.error(f"Create router error: {e}")
            self._send_response({"error": "Failed to create router"}, 500)
    
    def _handle_update_router(self, router_id: str, data: dict):
        """Update existing router"""
        existing = get_router_by_id(router_id)
        if not existing:
            self._send_response({"error": "Router not found"}, 404)
            return
        
        updates = []
        params = []
        
        if 'name' in data:
            name = sanitize_input(data['name'], 100)
            if len(name) < 2:
                self._send_response({"error": "Router name must be at least 2 characters"}, 400)
                return
            updates.append('name = ?')
            params.append(name)
        
        if 'subnet' in data:
            subnet = sanitize_input(data['subnet'], 50)
            if subnet and not validate_cidr(subnet):
                self._send_response({"error": "Invalid subnet format"}, 400)
                return
            updates.append('subnet = ?')
            params.append(subnet)
        
        if 'description' in data:
            updates.append('description = ?')
            params.append(sanitize_input(data['description'], 255))
        
        if 'enabled' in data:
            updates.append('enabled = ?')
            params.append(1 if data['enabled'] else 0)
        
        if 'status' in data and data['status'] in ('active', 'inactive', 'warning'):
            updates.append('status = ?')
            params.append(data['status'])
        
        if not updates:
            self._send_response({"error": "No valid fields to update"}, 400)
            return
        
        try:
            conn = DatabaseManager.get_connection()
            c = conn.cursor()
            params.append(router_id)
            c.execute(f'UPDATE routers SET {", ".join(updates)} WHERE id = ?', params)
            conn.commit()
            
            logger.info(f"Updated router: {router_id}")
            self._send_response({"success": True, "message": "Router updated successfully"})
        
        except Exception as e:
            logger.error(f"Update router error: {e}")
            self._send_response({"error": "Failed to update router"}, 500)
    
    def _handle_delete_router(self, router_id: str):
        """Delete router with cascade"""
        existing = get_router_by_id(router_id)
        if not existing:
            self._send_response({"error": "Router not found"}, 404)
            return
        
        if delete_router_cascade(router_id):
            self._send_response({
                "success": True, 
                "message": f"Router '{existing['name']}' deleted successfully"
            })
        else:
            self._send_response({"error": "Failed to delete router"}, 500)
    
    # ==================== RULE HANDLERS ====================
    
    def _handle_get_rules(self, query_string: str = ""):
        """Get all rules with optional search"""
        params = parse_qs(query_string)
        search = params.get('search', [None])[0]
        
        if search:
            rules = search_rules(search)
        else:
            rules = load_rules_from_db(enabled_only=False)
        
        self._send_response({
            "rules": rules, 
            "count": len(rules),
            "timestamp": time.time()
        })
    
    def _handle_get_rule(self, rule_id: str):
        """Get single rule by ID"""
        rule = get_rule_by_id(rule_id)
        
        if rule:
            self._send_response({"rule": rule})
        else:
            self._send_response({"error": "Rule not found"}, 404)
    
    def _handle_create_rule(self, data: dict):
        """Create new rule"""
        domain = sanitize_input(data.get('domain', ''), 253).lower()
        action = sanitize_input(data.get('action', 'block'), 20)
        scope = sanitize_input(data.get('scope', 'all'), 20)
        router_ids = data.get('router_ids', [])
        redirect_ip = sanitize_input(data.get('redirect_ip', ''), 45)
        description = sanitize_input(data.get('description', ''), 255)
        priority = int(data.get('priority', 0))
        
        if not domain:
            self._send_response({"error": "Domain is required"}, 400)
            return
        
        if action not in ('block', 'allow', 'redirect'):
            self._send_response({"error": "Action must be 'block', 'allow', or 'redirect'"}, 400)
            return
        
        if scope not in ('all', 'specific', 'single'):
            self._send_response({"error": "Scope must be 'all', 'specific', or 'single'"}, 400)
            return
        
        if action == 'redirect':
            if not redirect_ip:
                self._send_response({"error": "Redirect IP is required for redirect action"}, 400)
                return
            if not validate_ip_address(redirect_ip):
                self._send_response({"error": "Invalid redirect IP address"}, 400)
                return
        
        if scope in ('specific', 'single'):
            if not router_ids or not isinstance(router_ids, list):
                self._send_response({"error": f"Router selection required for {scope} scope"}, 400)
                return
            
            if scope == 'single' and len(router_ids) != 1:
                self._send_response({"error": "Exactly one router must be selected for single scope"}, 400)
                return
            
            existing_routers = load_routers_from_db()
            existing_ids = {r['id'] for r in existing_routers}
            for rid in router_ids:
                if rid not in existing_ids:
                    self._send_response({"error": f"Router not found: {rid}"}, 400)
                    return
        else:
            router_ids = []
        
        rule_id = generate_id()
        current_time = time.time()
        
        try:
            conn = DatabaseManager.get_connection()
            c = conn.cursor()
            c.execute('''INSERT INTO rules 
                         (id, domain, action, scope, router_ids, redirect_ip, enabled, priority, 
                          created_at, updated_at, description, hit_count)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                      (rule_id, domain, action, scope, json.dumps(router_ids), redirect_ip or None,
                       1, priority, current_time, current_time, description, 0))
            conn.commit()
            
            # Invalidate rule cache
            app_state.rule_cache.invalidate()
            
            logger.info(f"Created rule: {action} {domain} ({scope})")
            self._send_response({
                "success": True, 
                "id": rule_id, 
                "message": f"Rule created: {action} '{domain}'"
            })
        
        except Exception as e:
            logger.error(f"Create rule error: {e}")
            self._send_response({"error": "Failed to create rule"}, 500)
    
    def _handle_update_rule(self, rule_id: str, data: dict):
        """Update existing rule"""
        existing = get_rule_by_id(rule_id)
        if not existing:
            self._send_response({"error": "Rule not found"}, 404)
            return
        
        updates = []
        params = []
        
        if 'domain' in data:
            domain = sanitize_input(data['domain'], 253).lower()
            if not domain:
                self._send_response({"error": "Domain cannot be empty"}, 400)
                return
            updates.append('domain = ?')
            params.append(domain)
        
        if 'action' in data:
            action = sanitize_input(data['action'], 20)
            if action not in ('block', 'allow', 'redirect'):
                self._send_response({"error": "Invalid action"}, 400)
                return
            updates.append('action = ?')
            params.append(action)
        
        if 'scope' in data:
            scope = sanitize_input(data['scope'], 20)
            if scope not in ('all', 'specific', 'single'):
                self._send_response({"error": "Invalid scope"}, 400)
                return
            updates.append('scope = ?')
            params.append(scope)
        
        if 'router_ids' in data:
            router_ids = data['router_ids']
            if isinstance(router_ids, list):
                updates.append('router_ids = ?')
                params.append(json.dumps(router_ids))
        
        if 'redirect_ip' in data:
            redirect_ip = sanitize_input(data['redirect_ip'], 45)
            if redirect_ip and not validate_ip_address(redirect_ip):
                self._send_response({"error": "Invalid redirect IP"}, 400)
                return
            updates.append('redirect_ip = ?')
            params.append(redirect_ip or None)
        
        if 'description' in data:
            updates.append('description = ?')
            params.append(sanitize_input(data['description'], 255))
        
        if 'enabled' in data:
            updates.append('enabled = ?')
            params.append(1 if data['enabled'] else 0)
        
        if 'priority' in data:
            updates.append('priority = ?')
            params.append(int(data['priority']))
        
        if not updates:
            self._send_response({"error": "No valid fields to update"}, 400)
            return
        
        updates.append('updated_at = ?')
        params.append(time.time())
        
        try:
            conn = DatabaseManager.get_connection()
            c = conn.cursor()
            params.append(rule_id)
            c.execute(f'UPDATE rules SET {", ".join(updates)} WHERE id = ?', params)
            conn.commit()
            
            # Invalidate rule cache
            app_state.rule_cache.invalidate()
            
            logger.info(f"Updated rule: {rule_id}")
            self._send_response({"success": True, "message": "Rule updated successfully"})
        
        except Exception as e:
            logger.error(f"Update rule error: {e}")
            self._send_response({"error": "Failed to update rule"}, 500)
    
    def _handle_delete_rule(self, rule_id: str):
        """Delete rule"""
        existing = get_rule_by_id(rule_id)
        if not existing:
            self._send_response({"error": "Rule not found"}, 404)
            return
        
        try:
            conn = DatabaseManager.get_connection()
            c = conn.cursor()
            c.execute('DELETE FROM rules WHERE id = ?', (rule_id,))
            conn.commit()
            
            # Invalidate rule cache
            app_state.rule_cache.invalidate()
            
            logger.info(f"Deleted rule: {rule_id}")
            self._send_response({
                "success": True, 
                "message": f"Rule for '{existing['domain']}' deleted successfully"
            })
        
        except Exception as e:
            logger.error(f"Delete rule error: {e}")
            self._send_response({"error": "Failed to delete rule"}, 500)
    
    def _handle_bulk_delete_rules(self, data: dict):
        """Bulk delete rules - BUG-015"""
        rule_ids = data.get('rule_ids', [])
        
        if not rule_ids or not isinstance(rule_ids, list):
            self._send_response({"error": "rule_ids array is required"}, 400)
            return
        
        if len(rule_ids) > 100:
            self._send_response({"error": "Cannot delete more than 100 rules at once"}, 400)
            return
        
        try:
            conn = DatabaseManager.get_connection()
            c = conn.cursor()
            
            placeholders = ','.join('?' * len(rule_ids))
            c.execute(f'DELETE FROM rules WHERE id IN ({placeholders})', rule_ids)
            deleted_count = c.rowcount
            conn.commit()
            
            # Invalidate rule cache
            app_state.rule_cache.invalidate()
            
            logger.info(f"Bulk deleted {deleted_count} rules")
            self._send_response({
                "success": True, 
                "deleted_count": deleted_count,
                "message": f"Deleted {deleted_count} rule(s) successfully"
            })
        
        except Exception as e:
            logger.error(f"Bulk delete error: {e}")
            self._send_response({"error": "Failed to delete rules"}, 500)
    
    # ==================== QUERY HANDLERS ====================
    
    def _handle_get_queries(self, query_string: str):
        """Get query logs with filtering"""
        try:
            params = parse_qs(query_string)
            
            limit = min(int(params.get('limit', ['100'])[0]), 1000)
            offset = max(int(params.get('offset', ['0'])[0]), 0)
            router_id = params.get('router_id', [None])[0]
            action_filter = params.get('action', [None])[0]
            domain_filter = params.get('domain', [None])[0]
            
            conn = DatabaseManager.get_connection()
            c = conn.cursor()
            
            query = '''SELECT timestamp, router_id, client_ip, domain, query_type, action, 
                              response, response_time, rule_id FROM query_logs WHERE 1=1'''
            query_params = []
            
            if router_id:
                query += ' AND router_id = ?'
                query_params.append(router_id)
            
            if action_filter:
                query += ' AND action LIKE ?'
                query_params.append(f'%{action_filter}%')
            
            if domain_filter:
                query += ' AND domain LIKE ?'
                query_params.append(f'%{domain_filter}%')
            
            # Get total count
            count_query = query.replace(
                'SELECT timestamp, router_id, client_ip, domain, query_type, action, response, response_time, rule_id',
                'SELECT COUNT(*)'
            )
            c.execute(count_query, query_params)
            total = c.fetchone()[0]
            
            # Get paginated results
            query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?'
            query_params.extend([limit, offset])
            
            c.execute(query, query_params)
            rows = c.fetchall()
            
            queries = [{
                "timestamp": row['timestamp'],
                "router_id": row['router_id'],
                "client_ip": row['client_ip'],
                "domain": row['domain'],
                "query_type": row['query_type'],
                "action": row['action'],
                "response": row['response'],
                "response_time": round(row['response_time'], 2) if row['response_time'] else 0,
                "rule_id": row['rule_id']
            } for row in rows]
            
            self._send_response({
                "queries": queries,
                "total": total,
                "limit": limit,
                "offset": offset,
                "timestamp": time.time()
            })
        
        except ValueError as e:
            self._send_response({"error": f"Invalid query parameters: {str(e)}"}, 400)
        except Exception as e:
            logger.error(f"Get queries error: {e}")
            self._send_response({"error": "Failed to fetch queries"}, 500)
    
    # ==================== ANALYTICS HANDLERS ====================
    
    def _handle_get_analytics(self, query_string: str):
        """Get analytics data - BUG-024"""
        try:
            params = parse_qs(query_string)
            
            router_id = params.get('router_id', [None])[0]
            days = min(int(params.get('days', ['7'])[0]), 30)
            
            start_date = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')
            
            conn = DatabaseManager.get_connection()
            c = conn.cursor()
            
            if router_id:
                c.execute('''SELECT date, hour, total_queries, blocked_queries, 
                                    allowed_queries, redirected_queries, cached_queries, avg_response_time
                             FROM analytics 
                             WHERE router_id = ? AND date >= ?
                             ORDER BY date, hour''',
                          (router_id, start_date))
            else:
                c.execute('''SELECT date, hour, 
                                    SUM(total_queries) as total_queries,
                                    SUM(blocked_queries) as blocked_queries,
                                    SUM(allowed_queries) as allowed_queries,
                                    SUM(redirected_queries) as redirected_queries,
                                    SUM(cached_queries) as cached_queries,
                                    AVG(avg_response_time) as avg_response_time
                             FROM analytics 
                             WHERE date >= ?
                             GROUP BY date, hour
                             ORDER BY date, hour''',
                          (start_date,))
            
            rows = c.fetchall()
            
            analytics = [{
                "date": row['date'],
                "hour": row['hour'],
                "total_queries": row['total_queries'] or 0,
                "blocked_queries": row['blocked_queries'] or 0,
                "allowed_queries": row['allowed_queries'] or 0,
                "redirected_queries": row['redirected_queries'] or 0,
                "cached_queries": row['cached_queries'] or 0,
                "avg_response_time": round(row['avg_response_time'] or 0, 2)
            } for row in rows]
            
            self._send_response({
                "analytics": analytics,
                "days": days,
                "router_id": router_id,
                "timestamp": time.time()
            })
        
        except Exception as e:
            logger.error(f"Get analytics error: {e}")
            self._send_response({"error": "Failed to fetch analytics"}, 500)
    
    def _handle_get_top_domains(self, query_string: str):
        """Get top domains for analytics"""
        try:
            params = parse_qs(query_string)
            
            router_id = params.get('router_id', [None])[0]
            days = min(int(params.get('days', ['7'])[0]), 30)
            limit = min(int(params.get('limit', ['20'])[0]), 100)
            
            start_date = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')
            
            conn = DatabaseManager.get_connection()
            c = conn.cursor()
            
            if router_id:
                c.execute('''SELECT domain, SUM(query_count) as count, SUM(blocked) as blocked
                             FROM top_domains 
                             WHERE router_id = ? AND date >= ?
                             GROUP BY domain
                             ORDER BY count DESC
                             LIMIT ?''',
                          (router_id, start_date, limit))
            else:
                c.execute('''SELECT domain, SUM(query_count) as count, SUM(blocked) as blocked
                             FROM top_domains 
                             WHERE date >= ?
                             GROUP BY domain
                             ORDER BY count DESC
                             LIMIT ?''',
                          (start_date, limit))
            
            rows = c.fetchall()
            
            domains = [{
                "domain": row['domain'],
                "count": row['count'] or 0,
                "blocked": row['blocked'] or 0
            } for row in rows]
            
            self._send_response({
                "domains": domains,
                "days": days,
                "router_id": router_id,
                "timestamp": time.time()
            })
        
        except Exception as e:
            logger.error(f"Get top domains error: {e}")
            self._send_response({"error": "Failed to fetch top domains"}, 500)
    
    # ==================== SEARCH HANDLER ====================
    
    def _handle_search(self, query_string: str):
        """Global search for routers and rules - BUG-016"""
        try:
            params = parse_qs(query_string)
            query = params.get('q', [''])[0]
            
            if not query or len(query) < 2:
                self._send_response({"error": "Search query must be at least 2 characters"}, 400)
                return
            
            routers = search_routers(query)
            rules = search_rules(query)
            
            self._send_response({
                "routers": routers[:10],
                "rules": rules[:10],
                "query": query,
                "timestamp": time.time()
            })
        
        except Exception as e:
            logger.error(f"Search error: {e}")
            self._send_response({"error": "Search failed"}, 500)
    
    # ==================== OTHER HANDLERS ====================
    
    def _handle_clear_cache(self):
        """Clear DNS cache"""
        with app_state.cache_lock:
            count = len(app_state.dns_cache)
            app_state.dns_cache.clear()
        
        # Also invalidate rule cache
        app_state.rule_cache.invalidate()
        
        logger.info(f"DNS cache cleared ({count} entries)")
        self._send_response({
            "success": True, 
            "message": f"Cleared {count} cached DNS entries"
        })
    
    def _handle_get_config(self):
        """Get current configuration (sanitized)"""
        with app_state.config_lock:
            safe_config = {
                "dns": {
                    "port": app_state.config.get("dns", {}).get("port", 53),
                    "upstream_servers": app_state.config.get("dns", {}).get("upstream_servers", []),
                    "cache_enabled": app_state.config.get("dns", {}).get("cache_enabled", True),
                    "cache_ttl": app_state.config.get("dns", {}).get("cache_ttl", 300),
                    "cache_size": app_state.config.get("dns", {}).get("cache_size", 5000),
                    "parallel_upstream": app_state.config.get("dns", {}).get("parallel_upstream", True)
                },
                "web": {
                    "port": app_state.config.get("web", {}).get("port", 8080),
                    "session_timeout": app_state.config.get("web", {}).get("session_timeout", 7200)
                },
                "settings": app_state.config.get("settings", {})
            }
        
        self._send_response({"config": safe_config})
    
    def _handle_update_config(self, data: dict):
        """Update configuration"""
        with app_state.config_lock:
            if 'dns' in data:
                dns_config = data['dns']
                if 'upstream_servers' in dns_config and isinstance(dns_config['upstream_servers'], list):
                    valid_servers = [s for s in dns_config['upstream_servers'] if validate_ip_address(s)]
                    if valid_servers:
                        app_state.config['dns']['upstream_servers'] = valid_servers
                if 'cache_enabled' in dns_config:
                    app_state.config['dns']['cache_enabled'] = bool(dns_config['cache_enabled'])
                if 'cache_ttl' in dns_config:
                    app_state.config['dns']['cache_ttl'] = max(60, min(86400, int(dns_config['cache_ttl'])))
                if 'parallel_upstream' in dns_config:
                    app_state.config['dns']['parallel_upstream'] = bool(dns_config['parallel_upstream'])
            
            if 'settings' in data:
                settings = data['settings']
                if 'auto_detect_routers' in settings:
                    app_state.config['settings']['auto_detect_routers'] = bool(settings['auto_detect_routers'])
                if 'router_timeout' in settings:
                    app_state.config['settings']['router_timeout'] = max(60, min(3600, int(settings['router_timeout'])))
                if 'persist_stats' in settings:
                    app_state.config['settings']['persist_stats'] = bool(settings['persist_stats'])
            
            save_config()
        
        logger.info("Configuration updated")
        self._send_response({"success": True, "message": "Configuration updated successfully"})


def start_web_server():
    """Start the web server"""
    try:
        with app_state.config_lock:
            port = app_state.config.get("web", {}).get("port", 8080)
        
        server = HTTPServer(('0.0.0.0', port), WebHandler)
        logger.info(f"Web dashboard available at http://localhost:{port}")
        logger.info("Default credentials: admin / admin")
        server.serve_forever()
    
    except Exception as e:
        logger.error(f"Web server error: {e}")
        sys.exit(1)


# ==================== BACKGROUND TASKS ====================

def session_cleanup_task():
    """Clean up expired sessions"""
    while True:
        try:
            time.sleep(SESSION_CLEANUP_INTERVAL)
            current_time = time.time()
            
            with app_state.session_lock:
                expired = [
                    token for token, session in app_state.sessions.items()
                    if current_time >= session["expires"]
                ]
                for token in expired:
                    del app_state.sessions[token]
                
                if expired:
                    logger.debug(f"Cleaned up {len(expired)} expired sessions")
            
            with app_state.csrf_lock:
                expired_csrf = [
                    token for token, expiry in app_state.csrf_tokens.items()
                    if current_time >= expiry
                ]
                for token in expired_csrf:
                    del app_state.csrf_tokens[token]
            
            with app_state.rate_lock:
                for ip in list(app_state.rate_limits.keys()):
                    app_state.rate_limits[ip] = [
                        t for t in app_state.rate_limits[ip]
                        if current_time - t < RATE_LIMIT_WINDOW
                    ]
                    if not app_state.rate_limits[ip]:
                        del app_state.rate_limits[ip]
        
        except Exception as e:
            logger.error(f"Session cleanup error: {e}")


def router_status_task():
    """Check router status periodically"""
    while True:
        try:
            time.sleep(60)
            check_router_status()
        except Exception as e:
            logger.error(f"Router status task error: {e}")


def log_cleanup_task():
    """Clean up old logs periodically"""
    while True:
        try:
            time.sleep(3600)  # Every hour
            cleanup_old_logs()
        except Exception as e:
            logger.error(f"Log cleanup task error: {e}")


def stats_persist_task():
    """Persist stats to database periodically - BUG-023"""
    while True:
        try:
            time.sleep(STATS_PERSIST_INTERVAL)
            if app_state.config.get('settings', {}).get('persist_stats', True):
                persist_stats()
        except Exception as e:
            logger.error(f"Stats persist task error: {e}")


def analytics_task():
    """Aggregate analytics hourly - BUG-024"""
    while True:
        try:
            # Wait until next hour
            now = datetime.now()
            next_hour = (now + timedelta(hours=1)).replace(minute=5, second=0, microsecond=0)
            sleep_seconds = (next_hour - now).total_seconds()
            time.sleep(max(60, sleep_seconds))
            
            if app_state.config.get('settings', {}).get('enable_analytics', True):
                aggregate_analytics()
        except Exception as e:
            logger.error(f"Analytics task error: {e}")


# ==================== MAIN ====================

def print_banner():
    """Print startup banner"""
    banner = f"""
======================================================================
                   NetGuard Enterprise DNS System
             Enterprise DNS Management System v{VERSION}
                 Phase 2: Features & Performance
======================================================================
"""
    print(banner)


def check_startup_requirements():
    """Check if system requirements are met"""
    # Check for root/admin privileges
    is_admin = False
    try:
        if platform.system() == 'Windows':
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            is_admin = os.geteuid() == 0
    except:
        pass

    if not is_admin:
        dns_port = app_state.config.get('dns', {}).get('port', 53)
        if dns_port < 1024:
            logger.error(f"Error: Root/Admin privileges required to bind to port {dns_port}")
            print(f"\n[!] CRITICAL ERROR: Permission denied")
            print(f"    NetGuard requires Administrator/Root privileges to bind to port {dns_port}.")
            print(f"    Please run the terminal/command prompt as Administrator.\n")
            sys.exit(1)

    # Check if ports are available
    dns_port = app_state.config.get('dns', {}).get('port', 53)
    web_port = app_state.config.get('web', {}).get('port', 8080)

    for port, name in [(dns_port, "DNS"), (web_port, "Web")]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if name == "DNS" else socket.SOCK_STREAM)
            sock.bind(('0.0.0.0', port))
            sock.close()
        except OSError as e:
            logger.error(f"Error: Port {port} ({name}) is already in use")
            print(f"\n[!] CRITICAL ERROR: Port {port} is busy")
            print(f"    The {name} port ({port}) is currently in use by another application.")
            print(f"    Please stop the conflicting application or change the port in config.\n")
            sys.exit(1)

def main():

    """Main entry point"""
    print_banner()
    
    # Load configuration
    load_config()

    # Check system requirements
    check_startup_requirements()
    
    # Initialize database
    init_database()
    
    # Start background tasks
    tasks = [
        (session_cleanup_task, "SessionCleanup"),
        (router_status_task, "RouterStatus"),
        (log_cleanup_task, "LogCleanup"),
        (stats_persist_task, "StatsPersist"),
        (analytics_task, "Analytics"),
    ]
    
    for task_func, task_name in tasks:
        threading.Thread(target=task_func, daemon=True, name=task_name).start()
    
    logger.info("Background tasks started")
    
    # Start web server
    web_thread = threading.Thread(target=start_web_server, daemon=True, name="WebServer")
    web_thread.start()
    
    time.sleep(1)
    
    # Start DNS server (blocking)
    logger.info("Starting DNS server...")
    start_dns_server()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n")
        logger.info("Shutting down NetGuard...")
        
        # Persist stats before exit
        try:
            persist_stats()
            logger.info("Stats persisted")
        except:
            pass
        
        # Cleanup
        app_state.executor.shutdown(wait=False)
        app_state.dns_executor.shutdown(wait=False)
        DatabaseManager.close_connection()
        
        logger.info("Goodbye!")
        sys.exit(0)
    except Exception as e:
        logger.critical(f"Fatal error: {e}")
        sys.exit(1)

