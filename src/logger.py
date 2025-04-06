import os
import logging
import sqlite3
from datetime import datetime
import threading
from typing import Dict, List, Tuple, Optional, Any, Union

class Logger:
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the logger for file logging and database tracking
        
        Args:
            config: Config dict from config.yaml
        """
        self.config = config
        self.setup_file_logging()
        self.setup_database()
        self.db_lock = threading.Lock()

    def setup_file_logging(self):
        """
        Setup up file logging with config
        """
        log_path = self.config['logging']['file_path']
        
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        
        log_level = getattr(logging, self.config['logging']['level'])
        
        logging.basicConfig(
            filename=log_path,
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        self.logger = logging.getLogger('autoshield')
        

        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        self.logger.info("File logging initialized")

    def setup_database(self):
        """
        Create database if does nto exist
        """
        db_path = self.config['database']['path']
        
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        self.conn = sqlite3.connect(db_path)
        cursor = self.conn.cursor()
        
        # Attempts table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            timestamp DATETIME NOT NULL,
            details TEXT
        )
        ''')
        
        # Blocks table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            block_timestamp DATETIME NOT NULL,
            expiry_timestamp DATETIME NOT NULL,
            block_count INTEGER DEFAULT 1
        )
        ''')
        
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_attempts_ip ON attempts(ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_attempts_timestamp ON attempts(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_blocks_ip ON blocks(ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_blocks_expiry ON blocks(expiry_timestamp)')
        
        self.conn.commit()
        self.logger.info("Database initialized")
    
    def log_attempt(self, ip: str, timestamp: datetime, details: Optional[str] = None) -> None:
        """
        Log a failed connection attempt to both file and database
        
        Args:
            ip: The IP that failed to connect
            timestamp: When the attempt occurred
            Optional details: Details about the attempt
        """
        # Log to file
        self.logger.info(f"Failed attempt from IP {ip} at {timestamp}: {details or 'No details'}")
        
        # Log to database
        with self.db_lock:
            cursor = self.conn.cursor()
            cursor.execute(
                'INSERT INTO attempts (ip, timestamp, details) VALUES (?, ?, ?)',
                (ip, timestamp.isoformat(), details)
            )
            self.conn.commit()
    
    def log_block(self, ip: str, block_timestamp: datetime, expiry_timestamp: datetime) -> None:
        """
        Log a block action to both file and database
        
        Args:
            ip: The IP being blocked
            block_timestamp: When the block was applied
            expiry_timestamp: When the block will expire
        """
        with self.db_lock:
            cursor = self.conn.cursor()
            
            # Check if blocked before
            cursor.execute('SELECT block_count FROM blocks WHERE ip = ? ORDER BY id DESC LIMIT 1', (ip,))
            result = cursor.fetchone()
            
            if result:
                block_count = result[0] + 1
            else:
                block_count = 1
                
            # Log to file
            duration_minutes = (expiry_timestamp - block_timestamp).total_seconds() / 60
            self.logger.warning(
                f"Blocking IP {ip} at {block_timestamp} for {duration_minutes:.1f} minutes. "
                f"Block count: {block_count}"
            )
            
            # Log to database
            cursor.execute(
                'INSERT INTO blocks (ip, block_timestamp, expiry_timestamp, block_count) VALUES (?, ?, ?, ?)',
                (ip, block_timestamp.isoformat(), expiry_timestamp.isoformat(), block_count)
            )
            self.conn.commit()
    
    def log_unblock(self, ip: str, timestamp: Optional[datetime] = None) -> None:
        """
        Log when a block is removed.
        
        Args:
            ip: The IP being unblocked
            Optional timestamp: When the unblock occurred, or now if None
        """
        if timestamp == None:
            timestamp = datetime.now()
        self.logger.info(f"Unblocking IP {ip} at {timestamp}")
        
    def get_recent_attempts(self, ip: str, time_window_minutes: int) -> List[datetime]:
        """
        Get recent attempts for IP within a time window
        
        Args:
            ip: The IP to check
            time_window_minutes: Number of minutes to look back
            
        Returns:
            List of attempt timestamps for the IP within the time window
        """
        time_window = datetime.now().timestamp() - (time_window_minutes * 60)
        time_window_dt = datetime.fromtimestamp(time_window).isoformat()
        
        with self.db_lock:
            cursor = self.conn.cursor()
            cursor.execute(
                'SELECT timestamp FROM attempts WHERE ip = ? AND timestamp > ? ORDER BY timestamp',
                (ip, time_window_dt)
            )
            attempts = [datetime.fromisoformat(row[0]) for row in cursor.fetchall()]
            
        return attempts
    
    def get_block_history(self, ip: str) -> Tuple[int, Optional[datetime], Optional[datetime]]:
        """
        Get block history for IP
        
        Args:
            ip: The IP address to check
            
        Returns:
            (block_count, last_block_timestamp, last_expiry_timestamp) or (0, None, None)
        """
        with self.db_lock:
            cursor = self.conn.cursor()
            cursor.execute(
                'SELECT block_count, block_timestamp, expiry_timestamp FROM blocks '
                'WHERE ip = ? ORDER BY id DESC LIMIT 1',
                (ip,)
            )
            result = cursor.fetchone()
            
        if result:
            block_count = result[0]
            block_timestamp = datetime.fromisoformat(result[1])
            expiry_timestamp = datetime.fromisoformat(result[2])
            return block_count, block_timestamp, expiry_timestamp
        
        return 0, None, None
    
    def get_active_blocks(self) -> List[Tuple[str, datetime]]:
        """
        Get all currently active blocks
        
        Returns:
            List of (ip, expiry_timestamp) tuples for active blocks
        """
        now = datetime.now().isoformat()
        
        with self.db_lock:
            cursor = self.conn.cursor()
            cursor.execute(
                'SELECT ip, expiry_timestamp FROM blocks WHERE expiry_timestamp > ? '
                'GROUP BY ip HAVING MAX(id)',
                (now,)
            )
            blocks = [(row[0], datetime.fromisoformat(row[1])) for row in cursor.fetchall()]
            
        return blocks
    
    def close(self) -> None:
        """
        Close database connection
        """
        if hasattr(self, 'conn'):
            self.conn.close()
            self.logger.info("Database connection closed")