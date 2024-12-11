"""
Log Collector Service for SIEM system.
Handles collection and processing of logs from various sources.
"""
from typing import List, Dict, Any, Optional
import asyncio
import aiologstash
import logging
import json
import re
from pathlib import Path
from datetime import datetime
from ..models.event import Event, EventCategory, EventThreatLevel
from ..database import get_db
from ..core.exceptions import LogCollectionError

class LogCollector:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.collectors = {}
        self.parsers = {}
        self.running = False
        self.setup_logging()
        self.initialize_collectors()

    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=self.config.get('log_level', 'INFO'),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def initialize_collectors(self):
        """Initialize configured log collectors"""
        for collector_config in self.config.get('collectors', []):
            collector_type = collector_config.get('type')
            if collector_type == 'file':
                self.collectors[collector_config['name']] = FileLogCollector(collector_config)
            elif collector_type == 'syslog':
                self.collectors[collector_config['name']] = SyslogCollector(collector_config)
            elif collector_type == 'winlog':
                self.collectors[collector_config['name']] = WindowsEventCollector(collector_config)
            elif collector_type == 'api':
                self.collectors[collector_config['name']] = APILogCollector(collector_config)

    async def start(self):
        """Start all configured collectors"""
        if self.running:
            return

        self.running = True
        tasks = []
        
        for name, collector in self.collectors.items():
            self.logger.info(f"Starting collector: {name}")
            tasks.append(asyncio.create_task(collector.collect()))

        try:
            await asyncio.gather(*tasks)
        except Exception as e:
            self.logger.error(f"Error in collectors: {str(e)}")
            raise LogCollectionError(f"Collector error: {str(e)}")

    async def stop(self):
        """Stop all collectors"""
        self.running = False
        for collector in self.collectors.values():
            await collector.stop()

class BaseLogCollector:
    """Base class for log collectors"""
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.name = config['name']
        self.enabled = config.get('enabled', True)
        self.logger = logging.getLogger(f"{__name__}.{self.name}")
        self.running = False

    async def collect(self):
        """Collect logs from source"""
        raise NotImplementedError()

    async def stop(self):
        """Stop collecting logs"""
        self.running = False

    async def process_log(self, log_entry: Dict[str, Any]) -> Optional[Event]:
        """Process a log entry into an Event"""
        try:
            # Basic event creation
            event = Event(
                source=self.name,
                raw_event_data=log_entry,
                timestamp=datetime.utcnow()
            )

            # Enhance event with parsed data
            parsed_data = self.parse_log_entry(log_entry)
            if parsed_data:
                event.source_ip = parsed_data.get('source_ip')
                event.destination_ip = parsed_data.get('destination_ip')
                event.category = self.determine_category(parsed_data)
                event.threat_level = self.determine_threat_level(parsed_data)
                event.description = parsed_data.get('description')

            return event
        except Exception as e:
            self.logger.error(f"Error processing log entry: {str(e)}")
            return None

    def parse_log_entry(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Parse log entry based on configured patterns"""
        raise NotImplementedError()

    def determine_category(self, parsed_data: Dict[str, Any]) -> EventCategory:
        """Determine event category based on parsed data"""
        # Implement basic category detection logic
        return EventCategory.SYSTEM_ANOMALY

    def determine_threat_level(self, parsed_data: Dict[str, Any]) -> EventThreatLevel:
        """Determine threat level based on parsed data"""
        # Implement basic threat level detection logic
        return EventThreatLevel.INFORMATIONAL

class FileLogCollector(BaseLogCollector):
    """Collector for file-based logs"""
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.path = Path(config['path'])
        self.pattern = config.get('pattern', '.*')
        self.position = {}

    async def collect(self):
        """Collect logs from file"""
        self.running = True
        while self.running:
            try:
                if self.path.exists():
                    current_size = self.path.stat().st_size
                    last_position = self.position.get(str(self.path), 0)

                    if current_size > last_position:
                        with open(self.path, 'r') as f:
                            f.seek(last_position)
                            for line in f:
                                if not self.running:
                                    break
                                try:
                                    log_entry = json.loads(line.strip())
                                    event = await self.process_log(log_entry)
                                    if event:
                                        await self.store_event(event)
                                except json.JSONDecodeError:
                                    # Handle non-JSON logs
                                    log_entry = {'raw': line.strip()}
                                    event = await self.process_log(log_entry)
                                    if event:
                                        await self.store_event(event)

                            self.position[str(self.path)] = f.tell()

                await asyncio.sleep(1)
            except Exception as e:
                self.logger.error(f"Error collecting logs: {str(e)}")
                await asyncio.sleep(5)

    def parse_log_entry(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Parse log entry using configured patterns"""
        if 'raw' in log_entry:
            # Parse raw log line using regex patterns
            for pattern in self.config.get('patterns', []):
                match = re.search(pattern['regex'], log_entry['raw'])
                if match:
                    return {
                        'source_ip': match.group('source_ip') if 'source_ip' in pattern['regex'] else None,
                        'destination_ip': match.group('dest_ip') if 'dest_ip' in pattern['regex'] else None,
                        'description': match.group('description') if 'description' in pattern['regex'] else None
                    }
        return log_entry

class SyslogCollector(BaseLogCollector):
    """Collector for syslog messages"""
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.host = config.get('host', '0.0.0.0')
        self.port = config.get('port', 514)
        self.transport = None

    async def collect(self):
        """Collect logs from syslog"""
        self.running = True
        try:
            server = await aiologstash.create_tcp_server(
                self.host,
                self.port,
                self.handle_syslog
            )
            self.transport = server
            while self.running:
                await asyncio.sleep(1)
        except Exception as e:
            self.logger.error(f"Error in syslog collector: {str(e)}")
        finally:
            if self.transport:
                self.transport.close()

    async def handle_syslog(self, data: Dict[str, Any]):
        """Handle incoming syslog message"""
        try:
            event = await self.process_log(data)
            if event:
                await self.store_event(event)
        except Exception as e:
            self.logger.error(f"Error handling syslog message: {str(e)}")

class WindowsEventCollector(BaseLogCollector):
    """Collector for Windows Event Logs"""
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.channels = config.get('channels', ['Security'])
        self.query = config.get('query', '*')

    async def collect(self):
        """Collect Windows Event Logs"""
        if not sys.platform.startswith('win'):
            self.logger.error("Windows Event Collector can only run on Windows")
            return

        self.running = True
        import win32evtlog
        import win32evtlogutil
        import win32con
        import win32security

        while self.running:
            try:
                for channel in self.channels:
                    handle = win32evtlog.OpenEventLog(None, channel)
                    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                    events = win32evtlog.ReadEventLog(handle, flags, 0)

                    for event in events:
                        if not self.running:
                            break

                        event_dict = {
                            'Channel': channel,
                            'EventID': event.EventID,
                            'EventType': event.EventType,
                            'SourceName': event.SourceName,
                            'TimeGenerated': event.TimeGenerated.Format(),
                            'StringInserts': event.StringInserts
                        }

                        processed_event = await self.process_log(event_dict)
                        if processed_event:
                            await self.store_event(processed_event)

                    win32evtlog.CloseEventLog(handle)
                await asyncio.sleep(1)
            except Exception as e:
                self.logger.error(f"Error collecting Windows events: {str(e)}")
                await asyncio.sleep(5)

class APILogCollector(BaseLogCollector):
    """Collector for API-based log sources"""
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.endpoint = config['endpoint']
        self.method = config.get('method', 'GET')
        self.headers = config.get('headers', {})
        self.interval = config.get('interval', 60)

    async def collect(self):
        """Collect logs from API endpoint"""
        self.running = True
        async with aiohttp.ClientSession() as session:
            while self.running:
                try:
                    async with session.request(
                        self.method,
                        self.endpoint,
                        headers=self.headers
                    ) as response:
                        if response.status == 200:
                            data = await response.json()
                            for log_entry in data:
                                if not self.running:
                                    break
                                event = await self.process_log(log_entry)
                                if event:
                                    await self.store_event(event)
                except Exception as e:
                    self.logger.error(f"Error collecting API logs: {str(e)}")

                await asyncio.sleep(self.interval)

    async def store_event(self, event: Event):
        """Store processed event in database"""
        try:
            db = next(get_db())
            db.add(event)
            db.commit()
        except Exception as e:
            self.logger.error(f"Error storing event: {str(e)}")
            db.rollback()
