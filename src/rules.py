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

        # Monitoring thresholds
        self.threshold = config["rules"]["threshold"]
        self.time_window = config["rules"]["time_window"]

        # Block duration settings
        self.block_duration_minutes = config["firewall"]["block_duration"]
        self.block_duration_multiplier = config["firewall"]["block_duration_multiplier"]
        self.max_block_duration_minutes = config["firewall"]["max_block_duration"]

        # Thread control
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
        # 1. Log the attempt in our DB.
        self.logger.log_attempt(ip, timestamp, details)

        # 2. Check how many attempts in the last X minutes.
        recent_attempts = self.logger.get_recent_attempts(ip, self.time_window)
        attempt_count = len(recent_attempts)

        if attempt_count >= self.threshold:
            # Already above threshold, let's see if IP is currently blocked
            # or if we need to block it now.
            block_count, last_block_time, last_expiry = self.logger.get_block_history(ip)

            # If it's already within an active block, do nothing special here.
            # We'll rely on the expiration to handle unblocking.
            # But if it's not blocked, or the block is expired, block again.

            # We figure out the new block duration. The block_count helps
            # us do incremental blocking. If block_count=0, this is the first time.
            # If block_count=1 or more, multiply the base duration
            # but do not exceed max block duration.

            if block_count == 0 or (last_expiry and last_expiry < datetime.now()):
                # Need to block IP
                new_block_duration = self._calculate_block_duration(block_count)
                block_start = datetime.now()
                block_end = block_start + timedelta(minutes=new_block_duration)

                # Actually block
                blocked = self.firewall.block_ip(ip)
                if blocked:
                    # Log in DB
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
        # Because block_count is 0-based for the first block, we’ll do (block_count) if you want
        # repeated offense to ramp up. If you want the first block to remain just the base,
        # use block_count for exponent. Example: block_count = 2 => block_duration = base * (multi^2)
        # NOTE: Adjust logic if you prefer the very first block to be multiplied as well.
        
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
                        # This block has expired. Unblock in firewall, log the unblock event.
                        unblocked = self.firewall.unblock_ip(ip)
                        if unblocked:
                            self.logger.log_unblock(ip, now)
            except Exception as e:
                self.log.error(f"Error during block expiry check: {e}")

            # Sleep some interval, e.g., 60 seconds between checks
            time.sleep(60)

        self.log.info("RuleEngine expiry check thread exiting.")
