import requests
import time
from utils.logging import log

# Configuration settings
THIRD_PARTY_URLS = [
    "https://www.google.com",
    "https://www.microsoft.com",
    "https://www.github.com"
]
MONITOR_INTERVAL = 60  # seconds

def monitor_third_party_services():
    """
    Continuously monitor third-party services for availability and response time.
    """
    while True:
        for url in THIRD_PARTY_URLS:
            try:
                start_time = time.time()
                response = requests.get(url, timeout=5)
                end_time = time.time()
                response_time = end_time - start_time

                if response.status_code == 200:
                    log.info(f"{url} is available with response time {response_time:.2f} seconds")
                else:
                    log.warning(f"{url} is not available (status code {response.status_code})")
            except requests.exceptions.RequestException as e:
                log.error(f"Error monitoring {url}: {e}")

        time.sleep(MONITOR_INTERVAL)