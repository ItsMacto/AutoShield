import threading
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

class RuleEngine:
    """
    RuleEngine is responsible for:
      - Processing failed attempts and deciding when to block
      - Determining block durations based on config
      - Spawning a thread that periodically checks for expired blocks
    """
    def __init__(self, config: Dict[str, Any], logger, firewall):
        """
        Initialize RuleEngine
        
        Args:
            config: Dictionary loaded from config.yaml
            logger: Instance of Logger (src/logger.py)
            firewall: Instance of Firewall (src/firewall.py)
        """
        self.config = config
        self.logger = logger
        self.firewall = firewall

        self.log = logging.getLogger("autoshield")

        self.threshold = config["rules"]["threshold"]
        self.time_window = config["rules"]["time_window"]

        self.block_duration_minutes = config["firewall"]["block_duration"]
        self.block_duration_multiplier = config["firewall"]["block_duration_multiplier"]
        self.max_block_duration_minutes = config["firewall"]["max_block_duration"]

        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._background_expiry_check, daemon=True)

    def start(self) -> None:
        """
        Start any background processes needed by the rule engine.
        """
        self.log.info("Starting RuleEngine thread for block expiry checks.")
        self._thread.start()

    def stop(self) -> None:
        """
        Stop the background processes gracefully.
        """
        self.log.info("Stopping RuleEngine thread.")
        self._stop_event.set()
        self._thread.join()

    def process_attempt(self, ip: str, timestamp: datetime, details: str) -> None:
        """
        Process a single failed attempt. If the IP exceeds the threshold,
        calculate block duration and block it via the firewall.
        
        Args:
            ip: The IP address that made the failed attempt.
            timestamp: The datetime of the failed attempt.
            details: Additional details (log entry, etc.).
        """
        self.logger.log_attempt(ip, timestamp, details)

        recent_attempts = self.logger.get_recent_attempts(ip, self.time_window)
        attempt_count = len(recent_attempts)

        if attempt_count >= self.threshold:

            block_count, last_block_time, last_expiry = self.logger.get_block_history(ip)

            if block_count == 0 or (last_expiry and last_expiry < datetime.now()):

                new_block_duration = self._calculate_block_duration(block_count)
                block_start = datetime.now()
                block_end = block_start + timedelta(minutes=new_block_duration)

                blocked = self.firewall.block_ip(ip)
                if blocked:
                    self.logger.log_block(ip, block_start, block_end)

    def _calculate_block_duration(self, block_count: int) -> int:
        """
        Given how many times an IP has been blocked previously,
        compute how long the new block should be (in minutes).
        """
        base = self.block_duration_minutes
        multi = self.block_duration_multiplier
        max_dur = self.max_block_duration_minutes

        # Duration = base * (multi^(block_count)) 
        
        computed = base * (multi ** block_count)
        if computed > max_dur:
            computed = max_dur

        return computed

    def _background_expiry_check(self) -> None:
        """
        Background thread method that periodically checks for expired blocks
        and unblocks them in the firewall if needed.
        """
        self.log.info("RuleEngine expiry check thread started.")
        while not self._stop_event.is_set():
            try:
                active_blocks = self.logger.get_active_blocks()
                now = datetime.now()

                for ip, expiry_timestamp in active_blocks:
                    if now >= expiry_timestamp:
                        unblocked = self.firewall.unblock_ip(ip)
                        if unblocked:
                            self.logger.log_unblock(ip, now)
            except Exception as e:
                self.log.error(f"Error during block expiry check: {e}")


            self._stop_event.wait(10) #check every 10 seconds 

        self.log.info("RuleEngine expiry check thread exiting.")
