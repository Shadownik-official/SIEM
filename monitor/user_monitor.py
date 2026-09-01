import psutil
import time
from utils.logging import log

def monitor_user_activity():
    """
    Monitors user activity on the system.

    Returns:
        dict: A dictionary containing user activity statistics.
    """
    user_activity = {}

    while True:
        # Get user information
        users = psutil.users()

        # Initialize user activity statistics
        for user in users:
            user_activity[user.name] = {
                'cpu_percent': 0,
                'memory_percent': 0,
                'disk_usage': 0,
                'disk_io_count': 0,
                'network_bytes_sent': 0,
                'network_bytes_recv': 0,
                'uptime': 0
            }

        # Calculate user activity statistics
        for user in users:
            # Get CPU usage
            cpu_percent = psutil.cpu_percent(interval=1, percpu=True)
            user_activity[user.name]['cpu_percent'] = sum(cpu_percent) / len(cpu_percent)

            # Get memory usage
            memory_info = psutil.Process(user.pid).memory_info()
            memory_percent = memory_info.rss / psutil.virtual_memory().total * 100
            user_activity[user.name]['memory_percent'] = memory_percent

            # Get disk usage
            disk_usage = psutil.disk_usage(user.root_dir)
            user_activity[user.name]['disk_usage'] = disk_usage.percent

            # Get disk I/O count
            disk_io_stats = psutil.disk_io_counters(perdisk=False)
            user_activity[user.name]['disk_io_count'] = disk_io_stats.read_count + disk_io_stats.write_count

            # Get network usage
            network_stats = psutil.net_io_counters(pernic=False)
            user_activity[user.name]['network_bytes_sent'] = network_stats.bytes_sent
            user_activity[user.name]['network_bytes_recv'] = network_stats.bytes_recv

            # Get uptime
            user_activity[user.name]['uptime'] = time.time() - user.started

        # Log user activity statistics
        log(user_activity)

        # Sleep for a while before monitoring again
        time.sleep(60)

if __name__ == '__main__':
    monitor_user_activity()