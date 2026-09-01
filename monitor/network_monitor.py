import psutil
import time
import logging
from config import config

class NetworkMonitor:
    def __init__(self):
        self.config = config
        self.logger = logging.getLogger(__name__)

    def get_interface_info(self):
        net_if_addrs = psutil.net_if_addrs()
        return {interface: info for interface, info in net_if_addrs.items() if 'en' in interface or 'eth' in interface}

    def monitor_network_traffic(self):
        self.logger.info("Starting network traffic monitoring")
        interface_info = self.get_interface_info()
        prev_bytes_sent = {interface: info.bytes_sent for interface, info in interface_info.items()}
        prev_bytes_recv = {interface: info.bytes_recv for interface, info in interface_info.items()}

        while True:
            time.sleep(self.config['monitoring_interval'])
            current_interface_info = self.get_interface_info()
            current_bytes_sent = {interface: info.bytes_sent for interface, info in current_interface_info.items()}
            current_bytes_recv = {interface: info.bytes_recv for interface, info in current_interface_info.items()}

            for interface in current_interface_info:
                bytes_sent_diff = current_bytes_sent[interface] - prev_bytes_sent[interface]
                bytes_recv_diff = current_bytes_recv[interface] - prev_bytes_recv[interface]
                self.logger.info(f"Interface: {interface}, Bytes Sent: {bytes_sent_diff}, Bytes Received: {bytes_recv_diff}")

            prev_bytes_sent = current_bytes_sent
            prev_bytes_recv = current_bytes_recv

if __name__ == "__main__":
    monitor = NetworkMonitor()
    monitor.monitor_network_traffic()