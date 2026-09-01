import logging
import os

def setup_logging(log_file=None, log_level=logging.INFO):
    """
    Set up logging for the SIEM tool.

    Parameters:
    log_file (str): The name of the log file. If None, logging will be done to the console.
    log_level (int): The logging level.
    """
    # Create a custom logger
    logger = logging.getLogger()
    logger.setLevel(log_level)

    # Create a console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)

    # Create a file handler
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(log_level)

        # Format the log messages
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)

        # Add the file handler to the logger
        logger.addHandler(file_handler)

    # Format the log messages
    formatter = logging.Formatter('%(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)

    # Add the console handler to the logger
    logger.addHandler(console_handler)

def log_event(event, log_level=logging.INFO):
    """
    Log a security event.

    Parameters:
    event (str): The security event to log.
    log_level (int): The logging level.
    """
    logging.log(log_level, event)

def log_exception(e, log_level=logging.ERROR):
    """
    Log an exception.

    Parameters:
    e (Exception): The exception to log.
    log_level (int): The logging level.
    """
    logging.log(log_level, f'Exception: {str(e)}')

def log_debug(message):
    """
    Log a debug message.

    Parameters:
    message (str): The debug message to log.
    """
    logging.debug(message)

def log_info(message):
    """
    Log an info message.

    Parameters:
    message (str): The info message to log.
    """
    logging.info(message)

def log_warning(message):
    """
    Log a warning message.

    Parameters:
    message (str): The warning message to log.
    """
    logging.warning(message)

def log_error(message):
    """
    Log an error message.

    Parameters:
    message (str): The error message to log.
    """
    logging.error(message)

def log_critical(message):
    """
    Log a critical message.

    Parameters:
    message (str): The critical message to log.
    """
    logging.critical(message)