"""
Test runner for SIEM system
Executes all unit tests and integration tests
"""
import unittest
import sys
import os
import coverage
import logging
from datetime import datetime

def setup_logging():
    """Set up logging for test execution"""
    log_dir = 'logs'
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
        
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = os.path.join(log_dir, f'test_run_{timestamp}.log')
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger(__name__)

def run_tests():
    """Run all test suites and generate coverage report"""
    logger = setup_logging()
    logger.info("Starting SIEM test suite execution")
    
    # Start coverage monitoring
    cov = coverage.Coverage()
    cov.start()
    
    # Discover and run tests
    loader = unittest.TestLoader()
    start_dir = os.path.join(os.path.dirname(__file__), 'tests')
    suite = loader.discover(start_dir, pattern='test_*.py')
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Stop coverage monitoring
    cov.stop()
    cov.save()
    
    # Generate coverage report
    logger.info("Generating coverage report...")
    cov.report()
    
    # Generate HTML coverage report
    coverage_dir = 'coverage_report'
    if not os.path.exists(coverage_dir):
        os.makedirs(coverage_dir)
    cov.html_report(directory=coverage_dir)
    
    # Log test results
    logger.info(f"Tests Run: {result.testsRun}")
    logger.info(f"Failures: {len(result.failures)}")
    logger.info(f"Errors: {len(result.errors)}")
    logger.info(f"Skipped: {len(result.skipped)}")
    
    # Return appropriate exit code
    return len(result.failures) + len(result.errors)

if __name__ == '__main__':
    sys.exit(run_tests())
