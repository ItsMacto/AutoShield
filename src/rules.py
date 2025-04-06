import logging
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Set, Any, Optional, Union, Callable

class RuleEngine:
    def __init__(self, config: Dict[str, Any], logger: Any, firewall: Any):
        """
        Initialize the rule engine
        
        Args:
            config: Config dict
            logger: Logger instance
            firewall: Firewall instance
        """
        self.config = config
        self.logger = logger
        self.firewall = firewall
        self.log = logging.getLogger('autoshield')
        
        # loading config
        self.threshold = config['rules']['threshold']
        self.time_window = config['rules']['time_window']
        self.block_duration = config['firewall']['block_duration']
        self.block_duration_multiplier = config['firewall']['block_duration_multiplier']
        self.max_block_duration = config['firewall']['max_block_duration']
        
        
        self.recent_attempts: Dict[str, List[datetime]] = {}
        self.scheduled_unblocks: Dict[str, datetime] = {}
        self.lock = threading.Lock()
        
        # creates a background thread for removing expired blocks
        self.unblock_thread = threading.Thread(target=self._check_expired_blocks, daemon=True)
        self.running = False
    
    def start(self) -> None:
        """
        Start the unblock thread
        """
        self.running = True
        self.unblock_thread.start()
        self.log.info("Rule engine started")
    
    def stop(self) -> None:
        """
        Stop the unblock thread
        """
        self.running = False
        if self.unblock_thread.is_alive():
            self.unblock_thread.join(timeout=5)
        self.log.info("Rule engine stopped")
    
    def process_attempt(self, ip: str, timestamp: datetime, details: str) -> None:
        """
        Process failed login attempt. Block if needed
        
        Args:
            ip: IP of the attempt
            timestamp: When the attempt happend
            details: Details about the attempt
        """

        self.logger.log_attempt(ip, timestamp, details)
        
        # Check if IP already blocked
        with self.lock:
            if ip in self.scheduled_unblocks:
                self.log.debug(f"Ignoring attempt from already blocked IP {ip}")
                return
        
        # Update local memory (recent_attempts)
        with self.lock:
            if ip not in self.recent_attempts:
                self.recent_attempts[ip] = []
            self.recent_attempts[ip].append(timestamp)
            
            # removes old attempts not in time window
            cutoff = timestamp - timedelta(minutes=self.time_window)
            self.recent_attempts[ip] = [t for t in self.recent_attempts[ip] if t >= cutoff]
        

        db_attempts = self.logger.get_recent_attempts(ip, self.time_window)
        
        with self.lock:
            all_timestamps = set(self.recent_attempts[ip]).union(set(db_attempts))
            recent_count = len(all_timestamps)
        
        block_count, last_block, _ = self.logger.get_block_history(ip)
        
        
        block_minutes = min(
            self.max_block_duration,
            self.block_duration * (self.block_duration_multiplier ** block_count)
        )
        
        self.log.debug(
            f"IP {ip}: {recent_count}/{self.threshold} recent attempts, "
            f"block history: {block_count}"
        )
        
        if recent_count >= self.threshold:
            self.log.info(
                f"Threshold met for IP {ip}: {recent_count} attempts in {self.time_window} minutes, "
            )
            self._block_ip(ip, timestamp, block_minutes)
    
    def _block_ip(self, ip: str, timestamp: datetime, block_minutes: float) -> None:
        """
        Block an IP address for a duration
        
        Args:
            ip: The IP to block
            timestamp: When the block is applied
            block_minutes: Lenght of the block in minutes
        """
        expiry_timestamp = timestamp + timedelta(minutes=block_minutes)
        
        if self.firewall.block_ip(ip):
            self.logger.log_block(ip, timestamp, expiry_timestamp)
            
            with self.lock:
                self.scheduled_unblocks[ip] = expiry_timestamp
    
    def _check_expired_blocks(self) -> None:
        """
        Background thread to check and remove expired blocks
        """
        while self.running:
            now = datetime.now()
            to_unblock = []
            
            with self.lock:
                for ip, expiry in list(self.scheduled_unblocks.items()):
                    if now >= expiry:
                        to_unblock.append(ip)
                        del self.scheduled_unblocks[ip]
            
            # unblock
            for ip in to_unblock:
                if self.firewall.unblock_ip(ip):
                    self.logger.log_unblock(ip, now)
            
            # check for missed blockss
            active_blocks = self.logger.get_active_blocks()
            for ip, expiry in active_blocks:
                if now >= expiry and ip not in self.scheduled_unblocks:
                    if self.firewall.unblock_ip(ip):
                        self.logger.log_unblock(ip, now)
            
            # sleep for a min before checking TODO: may be a better way idk
            for _ in range(60):
                if not self.running:
                    break
                threading.Event().wait(1)