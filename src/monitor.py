import re
import logging
from systemd import journal
from datetime import datetime
from typing import Dict, Any, Callable, Pattern

class Monitor:
    def __init__(self, config: Dict[str, Any], event_callback: Callable[[str, datetime, str], None]):
        """
        Initialize the monitor from config and callback.

        Args:
            config: Configuration dictionary.
            event_callback: Function to call when a failed attempt is detected.
        """
        self.config = config
        self.event_callback = event_callback
        self.logger = logging.getLogger('autoshield')
        
        # Regular expression to extract IP addresses.
        self.IP_REGEX: Pattern[str] = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        
        # Set up the systemd journal reader.
        self.journal_reader = journal.Reader()
        self.journal_reader.this_boot()  # Restrict to this boot cycle.
        self.journal_reader.log_level(journal.LOG_INFO)  # Filter by INFO level and above.
        
        # Apply syslog identifier filters from the config.
        for identifier in self.config['monitoring']['syslog_identifiers']:
            self.journal_reader.add_match(SYSLOG_IDENTIFIER=identifier)
        
        # Move to the tail to start reading new entries.
        self.journal_reader.seek_tail()
        self.journal_reader.get_previous()  # Set the cursor to the last entry.
        
        self.logger.info("Monitor initialized")
    
    def start(self) -> None:
        """
        Start monitoring the journal for failed login attempts.
        """
        self.logger.info("Starting journal monitoring")
        try:
            while True:
                journal_events = self.journal_reader.wait(timeout=1)
                if journal_events == journal.APPEND:
                    for entry in self.journal_reader:
                        self._process_entry(entry)
        except KeyboardInterrupt:
            self.logger.info("Monitoring stopped by user")
        except Exception as e:
            self.logger.error(f"Monitoring error: {e}")
            raise
    
    def _process_entry(self, entry: Dict[str, Any]) -> None:
        """
        Process a journal entry to check for failed login attempts.

        Args:
            entry: A journal entry dictionary.
        """
        if 'MESSAGE' not in entry:
            return
        
        message = entry['MESSAGE']
        if isinstance(message, bytes):
            message = message.decode('utf-8', errors='ignore')
        
        # Check if the log message contains any of the configured keywords.
        is_failed_attempt = any(keyword in message for keyword in self.config['monitoring']['keywords'])
        
        if is_failed_attempt:
            ip_match = self.IP_REGEX.search(message)
            if ip_match:
                ip_address = ip_match.group(0)
                
                # Process the timestamp safely.
                if '_SOURCE_REALTIME_TIMESTAMP' in entry:
                    raw_timestamp = entry['_SOURCE_REALTIME_TIMESTAMP']
                    if isinstance(raw_timestamp, (int, float)):
                        timestamp = datetime.fromtimestamp(raw_timestamp / 1_000_000)
                    elif isinstance(raw_timestamp, datetime):
                        timestamp = raw_timestamp
                    else:
                        timestamp = datetime.now()
                else:
                    timestamp = datetime.now()
                
                details = str(entry)
                self.event_callback(ip_address, timestamp, details)
