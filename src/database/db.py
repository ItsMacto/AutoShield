import sqlite3
import os
import logging
from datetime import datetime

class Blocks:
    """
    Stores history of blocked IP addresses and manages active blocks
    """
    def __init__(self, db_path: str):
        """
        Initialize the block history database
        
        Args:
            db_path: Path to the SQLite database
        """
        self.db_path = db_path
        self.logger = logging.getLogger('AutoShield.storage')
        
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        # connect 
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        
        # create if does not exist
        self._create_tables()
        
    def _create_tables(self):
        """Create database tables if they don't exist"""
        cursor = self.conn.cursor()
        
        # blocks table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            duration INTEGER NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_blocked INTEGER DEFAULT 1,
            unblock_time TIMESTAMP
        )
        ''')
        

        cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_blocks_ip ON blocks(ip)
        ''')
        

        cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_unblock_time ON blocks(unblock_time)
        ''')
        

        self.conn.commit()
        
    def add_block(self, ip: str, rule_name: str, duration: int):
        """
        Add a block record to the database and mark as actively blocked
        
        Args:
            ip: IP address that was blocked
            rule_name: Name of the rule that triggered the block
            duration: Duration of the block in seconds
        
        Returns:
            The ID of the new block record
        """
        try:
            cursor = self.conn.cursor()
            
            # calculate unblock time
            unblock_time = datetime.now().timestamp() + duration
            
            
            cursor.execute(
                'INSERT INTO blocks (ip, rule_name, duration, is_blocked, unblock_time) VALUES (?, ?, ?, 1, ?)',
                (ip, rule_name, duration, unblock_time)
            )
            
            block_id = cursor.lastrowid
            self.conn.commit()
            return block_id
            
        except Exception as e:
            self.logger.error(f"Error adding block record: {str(e)}")
            self.conn.rollback()
            return None
            
    def mark_unblocked(self, ip: str):
        """
        Mark an IP as unblocked in the database
        
        Args:
            ip: IP address to mark as unblocked
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                'UPDATE blocks SET is_blocked = 0 WHERE ip = ? AND is_blocked = 1',
                (ip,)
            )
            self.conn.commit()
            
        except Exception as e:
            self.logger.error(f"Error marking IP as unblocked: {str(e)}")
            self.conn.rollback()
    
    def get_active_blocks(self):
        """
        Get all active blocks from the database
        
        Returns:
            List of dictionaries with active block information including IPs and unblock times
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                'SELECT ip, rule_name, unblock_time FROM blocks WHERE is_blocked = 1'
            )
            
            blocks = []
            for row in cursor.fetchall():
                blocks.append({
                    'ip': row['ip'],
                    'rule_name': row['rule_name'],
                    'unblock_time': row['unblock_time']
                })
                
            return blocks
            
        except Exception as e:
            self.logger.error(f"Error getting active blocks: {str(e)}")
            return []
            
    def clean_expired_blocks(self):
        """
        Mark any expired blocks as unblocked
        
        Returns:
            List of IPs that were marked as unblocked
        """
        try:
            cursor = self.conn.cursor()
            
            # get current time
            current_time = datetime.now().timestamp()
            
            # find expired blocks
            cursor.execute(
                'SELECT ip FROM blocks WHERE is_blocked = 1 AND unblock_time < ?',
                (current_time,)
            )
            
            expired_ips = [row['ip'] for row in cursor.fetchall()]
            
            # mark expired blocks as unblocked
            if expired_ips:
                cursor.execute(
                    'UPDATE blocks SET is_blocked = 0 WHERE is_blocked = 1 AND unblock_time < ?',
                    (current_time,)
                )
                self.conn.commit()
                
            return expired_ips
            
        except Exception as e:
            self.logger.error(f"Error cleaning expired blocks: {str(e)}")
            self.conn.rollback()
            return []
    
    def get_blocks(self, ip: str = None, limit: int = 100) -> list:
        """
        Get block records from the database
        
        Args:
            ip: Optional IP address to filter by
            limit: Maximum number of records to return, default 100
            
        Returns:
            List of block records
        """
        try:
            cursor = self.conn.cursor()
            
            if ip:
                cursor.execute(
                    'SELECT * FROM blocks WHERE ip = ? ORDER BY timestamp DESC LIMIT ?',
                    (ip, limit)
                )
            else:
                cursor.execute(
                    'SELECT * FROM blocks ORDER BY timestamp DESC LIMIT ?',
                    (limit,)
                )
                
            return cursor.fetchall()
            
        except Exception as e:
            self.logger.error(f"Error getting block records: {str(e)}")
            return []
        
    def get_current_blocks(self) -> list:
        """
        Get currently blocked IPs based on the duration and timestamp
        
        Returns:
            List of currently blocked IPs
        """
        try:
            cursor = self.conn.cursor()

            cursor.execute('''
            SELECT * FROM blocks 
            WHERE is_blocked = 1
            ORDER BY timestamp DESC
            ''')
            
            return cursor.fetchall()
            
        except Exception as e:
            self.logger.error(f"Error getting current blocks: {str(e)}")
            return []
            
    def get_stats(self) -> dict:
        """
        Get stats about blocked IPs
        
        Returns:
            Dictionary with stats
        """
        try:
            cursor = self.conn.cursor()
            
            # Total blocks
            cursor.execute('SELECT COUNT(*) FROM blocks')
            total_blocks = cursor.fetchone()[0]
            
            # Currently active blocks
            cursor.execute('SELECT COUNT(*) FROM blocks WHERE is_blocked = 1')
            active_blocks = cursor.fetchone()[0]
            
            # Unique IPs
            cursor.execute('SELECT COUNT(DISTINCT ip) FROM blocks')
            unique_ips = cursor.fetchone()[0]
            
            # Top blocked IPs
            cursor.execute('''
            SELECT ip, COUNT(*) as count 
            FROM blocks 
            GROUP BY ip 
            ORDER BY count DESC 
            LIMIT 10
            ''')
            top_ips = cursor.fetchall()
            
            # Top rules
            cursor.execute('''
            SELECT rule_name, COUNT(*) as count 
            FROM blocks 
            GROUP BY rule_name 
            ORDER BY count DESC 
            LIMIT 10
            ''')
            top_rules = cursor.fetchall()
            
            return {
                'total_blocks': total_blocks,
                'active_blocks': active_blocks,
                'unique_ips': unique_ips,
                'top_ips': top_ips,
                'top_rules': top_rules
            }
            
        except Exception as e:
            self.logger.error(f"Error getting statistics: {str(e)}")
            return {
                'total_blocks': 0,
                'active_blocks': 0,
                'unique_ips': 0,
                'top_ips': [],
                'top_rules': []
            }
            
    def close(self):
        """Close the database connection"""
        if self.conn:
            self.conn.close()