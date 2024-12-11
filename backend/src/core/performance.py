import time
import functools
import logging
from typing import Any, Callable

class PerformanceMonitor:
    """
    Performance monitoring and tracking utility for SIEM components
    """
    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger('performance_monitor')
    
    def track_performance(self, func: Callable) -> Callable:
        """
        Decorator to track function performance
        
        :param func: Function to monitor
        :return: Wrapped function with performance tracking
        """
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                end_time = time.time()
                
                # Log performance metrics
                execution_time = end_time - start_time
                self.logger.info(
                    f"Performance: {func.__name__} "
                    f"executed in {execution_time:.4f} seconds"
                )
                
                return result
            except Exception as e:
                end_time = time.time()
                execution_time = end_time - start_time
                self.logger.error(
                    f"Performance Error: {func.__name__} "
                    f"failed after {execution_time:.4f} seconds. Error: {e}"
                )
                raise
        
        return wrapper
    
    def measure_execution_time(self, func: Callable) -> float:
        """
        Measure pure execution time of a function
        
        :param func: Function to measure
        :return: Execution time in seconds
        """
        start_time = time.time()
        func()
        return time.time() - start_time
    
    def log_resource_usage(self):
        """
        Log system resource usage
        """
        try:
            import psutil
            
            cpu_percent = psutil.cpu_percent()
            memory = psutil.virtual_memory()
            
            self.logger.info(
                f"System Resources: "
                f"CPU: {cpu_percent}%, "
                f"Memory: {memory.percent}% used"
            )
        except ImportError:
            self.logger.warning("psutil not available for resource monitoring")

# Global performance monitor instance
performance_monitor = PerformanceMonitor()
