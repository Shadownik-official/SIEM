from typing import Dict, Any, List, Optional
import win32evtlog
import win32con
import win32security
import win32evtlogutil
import winerror
import threading
import time
from datetime import datetime, timedelta
import pythoncom
import win32com.client
import logging
from .base_collector import BaseCollector

class WindowsEventCollector(BaseCollector):
    """Windows Event Log collector"""
    
    def __init__(
        self,
        kafka_brokers: List[str],
        event_logs: List[str] = ['System', 'Application', 'Security'],
        query_interval: int = 10,
        batch_size: int = 100,
        batch_timeout: int = 5
    ):
        super().__init__(kafka_brokers, batch_size=batch_size, batch_timeout=batch_timeout)
        
        self.event_logs = event_logs
        self.query_interval = query_interval
        self.running = False
        self.collection_threads = {}
        self.last_read_times = {}
        
        # Initialize WMI
        pythoncom.CoInitialize()
        self.wmi = win32com.client.GetObject("winmgmts:\\\\.")
    
    def start(self):
        """Start collecting Windows events"""
        if self.running:
            return
        
        self.running = True
        self.logger.info("Starting Windows event collection")
        
        # Start collection threads for each event log
        for log_name in self.event_logs:
            thread = threading.Thread(
                target=self._collect_events,
                args=(log_name,),
                daemon=True
            )
            self.collection_threads[log_name] = thread
            thread.start()
    
    def stop(self):
        """Stop collecting Windows events"""
        self.running = False
        
        # Wait for collection threads to stop
        for thread in self.collection_threads.values():
            thread.join(timeout=5.0)
        
        self.collection_threads.clear()
        self.logger.info("Stopped Windows event collection")
    
    def get_status(self) -> Dict[str, Any]:
        """Get collector status"""
        return {
            'running': self.running,
            'event_logs': self.event_logs,
            'threads': {
                name: thread.is_alive()
                for name, thread in self.collection_threads.items()
            },
            'last_read_times': self.last_read_times
        }
    
    def _collect_events(self, log_name: str):
        """Collect events from a specific Windows event log"""
        handle = None
        try:
            # Open event log
            handle = win32evtlog.OpenEventLog(None, log_name)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            while self.running:
                try:
                    events = win32evtlog.ReadEventLog(
                        handle,
                        flags,
                        0
                    )
                    
                    for event in events:
                        # Convert and submit event
                        event_dict = self._convert_event(event, log_name)
                        if event_dict:
                            self.submit_event(event_dict)
                    
                    # Update last read time
                    self.last_read_times[log_name] = datetime.utcnow().isoformat()
                    
                except win32evtlog.error as e:
                    if e.winerror == winerror.ERROR_HANDLE_EOF:
                        # No more events, wait before next query
                        time.sleep(self.query_interval)
                    else:
                        self.logger.error(f"Error reading {log_name} event log: {str(e)}")
                        time.sleep(self.query_interval)
                
                except Exception as e:
                    self.logger.error(f"Unexpected error reading {log_name} event log: {str(e)}")
                    time.sleep(self.query_interval)
        
        finally:
            if handle:
                win32evtlog.CloseEventLog(handle)
    
    def _convert_event(self, event, log_name: str) -> Optional[Dict[str, Any]]:
        """Convert Windows event to SIEM format"""
        try:
            # Get event category and type strings
            category = str(event.EventCategory)
            event_type = {
                win32con.EVENTLOG_AUDIT_SUCCESS: 'audit_success',
                win32con.EVENTLOG_AUDIT_FAILURE: 'audit_failure',
                win32con.EVENTLOG_INFORMATION_TYPE: 'information',
                win32con.EVENTLOG_WARNING_TYPE: 'warning',
                win32con.EVENTLOG_ERROR_TYPE: 'error'
            }.get(event.EventType, 'unknown')
            
            # Map severity based on event type
            severity = {
                'audit_failure': 'high',
                'error': 'high',
                'warning': 'medium',
                'information': 'low',
                'audit_success': 'low'
            }.get(event_type, 'low')
            
            # Get computer name and source
            computer_name = event.ComputerName or 'unknown'
            source_name = event.SourceName or 'unknown'
            
            # Convert event data
            event_data = self._get_event_data(event)
            
            # Create event dictionary
            event_dict = {
                'timestamp': self._convert_time(event.TimeGenerated),
                'source': {
                    'type': 'windows_event',
                    'log_name': log_name,
                    'computer': computer_name,
                    'source_name': source_name
                },
                'event_id': event.EventID & 0xFFFF,  # Mask off qualifiers
                'event_type': event_type,
                'category': category,
                'severity': severity,
                'record_number': event.RecordNumber,
                'message': event.StringInserts[0] if event.StringInserts else '',
                'raw_data': event_data
            }
            
            return event_dict
        
        except Exception as e:
            self.logger.error(f"Error converting event: {str(e)}")
            return None
    
    def _get_event_data(self, event) -> Dict[str, Any]:
        """Extract event data"""
        data = {}
        
        try:
            if event.StringInserts:
                data['string_inserts'] = list(event.StringInserts)
            
            if event.Sid:
                try:
                    sid = win32security.ConvertSidToStringSid(event.Sid)
                    name, domain, type = win32security.LookupAccountSid(None, event.Sid)
                    data['user'] = {
                        'sid': sid,
                        'name': name,
                        'domain': domain
                    }
                except Exception as e:
                    self.logger.debug(f"Error getting user info: {str(e)}")
                    data['user'] = {'sid': str(event.Sid)}
            
            # Get additional data from WMI
            try:
                query = f"SELECT * FROM Win32_NTLogEvent WHERE RecordNumber = {event.RecordNumber}"
                wmi_events = self.wmi.ExecQuery(query)
                for wmi_event in wmi_events:
                    data['wmi'] = {
                        'message': wmi_event.Message,
                        'category_string': wmi_event.CategoryString,
                        'log_file': wmi_event.Logfile,
                        'source_name': wmi_event.SourceName,
                        'type': wmi_event.Type,
                        'user': wmi_event.User
                    }
                    break
            except Exception as e:
                self.logger.debug(f"Error getting WMI data: {str(e)}")
        
        except Exception as e:
            self.logger.error(f"Error extracting event data: {str(e)}")
        
        return data
    
    @staticmethod
    def _convert_time(time_generated) -> str:
        """Convert Windows time to ISO format"""
        return datetime.fromtimestamp(time_generated).isoformat()
