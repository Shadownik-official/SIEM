import csv
import os
from datetime import datetime

class EventReporting:
    def __init__(self, output_file):
        self.output_file = output_file

    def report_event(self, event_type, event_description, timestamp):
        event_data = {
            'event_type': event_type,
            'event_description': event_description,
            'timestamp': timestamp
        }

        with open(self.output_file, mode='a', newline='') as csvfile:
            fieldnames = ['event_type', 'event_description', 'timestamp']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            if not os.path.exists(self.output_file):
                writer.writeheader()

            writer.writerow(event_data)

if __name__ == '__main__':
    event_reporting = EventReporting('events.csv')

    event_type = 'Unauthorized Access'
    event_description = 'User xyz attempted to access file /path/to/file'
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    event_reporting.report_event(event_type, event_description, timestamp)