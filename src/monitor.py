import re
import logging
from systemd import journal
from datetime import datetime
from typing import Dict, Any, Callable, Pattern, Optional, Union

class Monitor:
    def __init__(self, config: Dict[str, Any], event_callback: Callable[[str, datetime, str], None]):
        """
        Initialize the monitor freom config and callback
        
        Args:
            config: config dictionary
            event_callback: Function to call when a failed attempt is found. Passed to it from main 
        """
        self.config = config
        self.event_callback = event_callback
        self.logger = logging.getLogger('autoshield')
        
        # RE to get IP from journal
        self.IP_REGEX: Pattern[str] = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        
        # set up journal reader
        self.journal_reader = journal.Reader()
        self.journal_reader.this_boot() # looks just at this boot cycle
        self.journal_reader.log_level(journal.LOG_INFO) # filter for infor level or higher 
        
        # syslog identifier filters
        for identifier in self.config['monitoring']['syslog_identifiers']:
            self.journal_reader.add_match(SYSLOG_IDENTIFIER=identifier)
        
        # move to last to get new entries
        self.journal_reader.seek_tail()
        self.journal_reader.get_previous()  # get last entry to set cursor
        
        self.logger.info("Monitor initialized")
    
    def start(self) -> None:
        """
        Start monitoring the journal for failed logins
        """
        self.logger.info("Starting journal monitoring")
        
        try:
            # main monitoring loop
            while True:
                # wait for new journal entries
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
        Process a journal entry to check for failed logins
        
        Args:
            entry: Journal entry
        """
        if 'MESSAGE' not in entry:
            return
        
        # online said it may be in bytes and need to go to string so checking here 
        message = entry['MESSAGE']
        if isinstance(message, bytes):
            message = message.decode('utf-8', errors='ignore')
        

        is_failed_attempt = any(keyword in message for keyword in self.config['monitoring']['keywords'])
        
        if is_failed_attempt:
            ip_match = self.IP_REGEX.search(message)
            if ip_match:
                IP = ip_match.group(0)
                
                if '_SOURCE_REALTIME_TIMESTAMP' in entry:
                    TIMESTAMP = datetime.fromtimestamp(entry['_SOURCE_REALTIME_TIMESTAMP'] / 1000000)
                else:
                    TIMESTAMP = datetime.now()
                
                # details = f"Service: {entry.get('SYSLOG_IDENTIFIER', 'unknown')}, Message: {message}"
                DETAILS = str(entry)
                
                self.event_callback(IP, TIMESTAMP, DETAILS)