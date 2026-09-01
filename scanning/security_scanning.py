import os
import subprocess
import json
from typing import List, Tuple

import utils.logging as logging
import utils.machine_learning as machine_learning
import utils.threat_intelligence as threat_intelligence

class SecurityScanning:
    def __init__(self, scanning_interval: int):
        self.scanning_interval = scanning_interval
        self.log = logging.Logger('security_scanning')

    def scan_vulnerabilities(self, targets: List[str]) -> Tuple[str, str]:
        vulnerabilities = []
        vulnerable_packages = []

        for target in targets:
            self.log.info(f'Scanning vulnerabilities for {target}')

            scan_output = subprocess.check_output(f'trivy --quiet --no-progress --format json --output {target}', shell=True)
            scan_result = json.loads(scan_output)

            if len(scan_result) > 0:
                for image in scan_result:
                    for vulnerability in image['Vulnerabilities']:
                        vulnerabilities.append(f'{vulnerability["VulnerabilityID"]}: {vulnerability["PkgName"]} ({vulnerability["InstalledVersion"]})')
                        vulnerable_packages.append(f'{vulnerability["VulnerabilityID"]}: {vulnerability["PkgName"]} ({vulnerability["InstalledVersion"]})')

        return vulnerabilities, vulnerable_packages

    def run(self):
        targets = ['target1', 'target2', 'target3']

        while True:
            self.log.info('Starting security scanning')

            vulnerabilities, vulnerable_packages = self.scan_vulnerabilities(targets)

            self.log.info('Security scanning completed')

            machine_learning.update_vulnerability_data(vulnerable_packages)
            threat_intelligence.update_vulnerability_data(vulnerable_packages)

            self.log.info('Waiting for the next scanning interval')

            import time
            time.sleep(self.scanning_interval)


if __name__ == '__main__':
    scanning = SecurityScanning(scanning_interval=3600)
    scanning.run()