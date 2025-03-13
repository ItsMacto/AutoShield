import subprocess
import logging
import threading
import time
import os
from typing import Dict, List, Set, Optional
from datetime import datetime, timedelta
from . import Blocks

class NFTablesManager:
    """
    Manages nftables rules for blocking IPs
    """
    def __init__(self, table_name="AutoShield", chain_name="block", db=None):
        """
        Initialize the nftables manager
        
        Args:
            table_name: Name of the nftables table
            chain_name: Name of the nftables chain
            db: Blocks database instance (will be created if None)
        """
        self.table_name = table_name
        self.chain_name = chain_name
        self.set_name = "blocklist"
        self.blocked_ips = {}  # IP: unblock time
        
        if db is None:
            db_path = os.path.join('/var/lib/autoshield', 'blocks.db')
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
            self.db = Blocks(db_path)
            self.logger = logging.getLogger('AutoShield.nftables')
            self.logger.info(f"Created default database at {db_path}")
        else:
            self.db = db
            self.logger = logging.getLogger('AutoShield.nftables')
        
        self.lock = threading.Lock()
        
        # setup for table, chain, and set
        self._setup()
        
        # restore previous blocks from database
        self._restore_blocks_from_db()
            
        # background thread to check for IPs to unblock
        self.running = True
        self.unblock_thread = threading.Thread(target=self._unblock_monitor)
        self.unblock_thread.daemon = True
        self.unblock_thread.start()
        
    def _setup(self):
        """Setup the nftables table, chain, and set"""
        try:
            # table
            self._run_command([
                'nft', 'add', 'table', 'inet', self.table_name
            ], check=False)
            
            # set for IP addresses
            self._run_command([
                'nft', 'add', 'set', 'inet', self.table_name, self.set_name, 
                '{', 'type', 'ipv4_addr', ';', '}'
            ], check=False)
            
            # chain
            self._run_command([
                'nft', 'add', 'chain', 'inet', self.table_name, self.chain_name, 
                '{', 'type', 'filter', 'hook', 'input', 'priority', '0', ';', 'policy', 'accept', ';', '}'
            ], check=False)
            
            # add rule to drop packets from blocked IPs
            try:
                result = self._run_command([
                    'nft', 'list', 'chain', 'inet', self.table_name, self.chain_name
                ])
                
                # add rule if not therre
                if self.set_name not in result.stdout:
                    self._run_command([
                        'nft', 'add', 'rule', 'inet', self.table_name, self.chain_name, 
                        'ip', 'saddr', '@', self.set_name, 'counter', 'drop'
                    ], check=False)
            except Exception as e:

                self._run_command([
                    'nft', 'add', 'rule', 'inet', self.table_name, self.chain_name, 
                    'ip', 'saddr', '@', self.set_name, 'counter', 'drop'
                ], check=False)
            
            self.logger.info(f"Successfully set up nftables table {self.table_name}, chain {self.chain_name}")
            
        except Exception as e:
            self.logger.error(f"Error setting up nftables: {str(e)}")
            raise
        
    def _restore_blocks_from_db(self):
        """Restore blocked IPs from the database"""
        try:
            # get current blocks from database
            current_blocks = self.db.get_current_blocks()
            
            # process each block
            for block in current_blocks:
                ip = block['ip']
                duration = block['duration']
                unblock_time = None
                
                # use unblock_time otherwise calculate it
                if 'unblock_time' in block and block['unblock_time']:
                    unblock_time = datetime.fromtimestamp(block['unblock_time'])
                else:

                    timestamp = datetime.strptime(block['timestamp'], '%Y-%m-%d %H:%M:%S')
                    unblock_time = timestamp + timedelta(seconds=duration)
                
                # skip if expired
                if unblock_time <= datetime.now():
                    self.db.mark_unblocked(ip)
                    continue
                
                self.blocked_ips[ip] = unblock_time
                
                # add to nftables
                try:
                    self._run_command([
                        'nft', 'add', 'element', 'inet', self.table_name, 
                        self.set_name, '{', ip, '}'
                    ], check=False)
                    self.logger.info(f"Restored block for IP {ip} from database")
                except Exception as e:
                    self.logger.error(f"Error restoring block for IP {ip}: {str(e)}")
                    
        except Exception as e:
            self.logger.error(f"Error restoring blocks from database: {str(e)}")
                 
    def block_ip(self, ip: str, duration: int, reason: Optional[Dict] = None):
        """
        Block an IP address
        
        Args:
            ip: IP address to block
            duration: Duration in seconds to block the IP
            reason: Optional dictionary with information about the block reason
        """
        with self.lock:
            # calculate unblock time
            unblock_time = datetime.now() + timedelta(seconds=duration)
            
            # check if already blocked with longer duration
            if ip in self.blocked_ips:
                existing_unblock_time = self.blocked_ips[ip]
                if existing_unblock_time and existing_unblock_time > unblock_time:
                    self.logger.info(f"IP {ip} already blocked with longer duration, keeping existing block")
                    return
            
            # add to database first 
            rule_name = reason.get('name', 'unknown') if reason else 'unknown'
            self.db.add_block(ip, rule_name, duration)
            
            self.blocked_ips[ip] = unblock_time
            
            try:
                # add to set
                self._run_command([
                    'nft', 'add', 'element', 'inet', self.table_name, 
                    self.set_name, '{', ip, '}'
                ], check=False)
                
                self.logger.info(f"Blocked IP {ip} until {unblock_time}")
                
                if reason:
                    self.logger.info(f"Block reason: {reason.get('name', 'N/A')}")
                    
            except Exception as e:
                self.logger.error(f"Error blocking IP {ip}: {str(e)}")
                
    def unblock_ip(self, ip: str):
        """
        Unblock an IP address
        
        Args:
            ip: IP address to unblock
        """
        with self.lock:
            if ip in self.blocked_ips:
                del self.blocked_ips[ip]
                
            try:
                # remove from set
                self._run_command([
                    'nft', 'delete', 'element', 'inet', self.table_name, 
                    self.set_name, '{', ip, '}'
                ], check=False)
                
                self.logger.info(f"Unblocked IP {ip}")
                
                # update database
                self.db.mark_unblocked(ip)
                    
            except Exception as e:
                self.logger.error(f"Error unblocking IP {ip}: {str(e)}")
                
    def is_blocked(self, ip: str) -> bool:
        """
        Check if an IP is currently blocked
        
        Args:
            ip: IP address to check
            
        Returns:
            True if the IP is blocked, False otherwise
        """
        with self.lock:
            # check if IP is in our blocked list
            if ip in self.blocked_ips:
                # check if its past the unblock time
                if datetime.now() > self.blocked_ips[ip]:
                    self.unblock_ip(ip)
                    return False
                return True
                
            # check nftables directly
            try:
                result = self._run_command([
                    'nft', 'get', 'element', 'inet', self.table_name, 
                    self.set_name, '{', ip, '}'
                ], check=False)
                
                # if blocked in nftables but not in our list, add it
                is_blocked = result.returncode == 0
                if is_blocked and ip not in self.blocked_ips:
                    # query database for block info
                    blocks = self.db.get_blocks(ip, 1)
                    if blocks and blocks[0]['is_blocked'] == 1:
                        # use unblock_time from database if available
                        if 'unblock_time' in blocks[0] and blocks[0]['unblock_time']:
                            self.blocked_ips[ip] = datetime.fromtimestamp(blocks[0]['unblock_time'])
                        else:
                            # no expiration time, permanent block
                            self.blocked_ips[ip] = None
                    else:
                        # not in database use default expiration (24h from now)
                        self.blocked_ips[ip] = datetime.now() + timedelta(hours=24)
                        self.logger.warning(f"IP {ip} found in nftables but not in database, added with 24h default")
                        
                return is_blocked
                
            except Exception:
                return False
                
    def _unblock_monitor(self):
        """Monitor thread to unblock IPs when their block time expires"""
        while self.running:
            now = datetime.now()
            ips_to_unblock = []
            
            # find IPs to unblock
            with self.lock:
                for ip, unblock_time in self.blocked_ips.items():
                    if unblock_time and now > unblock_time:
                        ips_to_unblock.append(ip)
            
            # unblock IPs
            for ip in ips_to_unblock:
                self.unblock_ip(ip)
                
            # clean expired blocks from database
            self.db.clean_expired_blocks()
                
            # sleep for a bit
            time.sleep(10)
    
    def _run_command(self, command: List[str], check=True) -> subprocess.CompletedProcess:
        """
        Run a shell command
        
        Args:
            command: Command and arguments to run
            check: Whether to check the return code
            
        Returns:
            CompletedProcess instance
        """
        self.logger.debug(f"Running command: {' '.join(command)}")
        return subprocess.run(
            command, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            text=True,
            check=check
        )
        
    def shutdown(self):
        """Shutdown the manager and clean up"""
        self.running = False
        if self.unblock_thread.is_alive():
            self.unblock_thread.join(timeout=1)