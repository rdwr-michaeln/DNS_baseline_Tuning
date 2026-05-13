import configParser
import os
import logging
from logging.handlers import RotatingFileHandler

LEVELS = {
    'DEBUG': logging.DEBUG,
    'INFO': logging.INFO,
    'WARNING': logging.WARNING,
    'ERROR': logging.ERROR,
    'CRITICAL': logging.CRITICAL
}

class LogManager:
    def __init__(self, name):
        self.log_level = configParser.log_level
        self.log_directory = configParser.log_path
        self.log_filename = configParser.log_filename
        self.max_log_size = configParser.log_max_size_kb * 1024
        self.backup_count = configParser.log_backup_count
        self.name = name
        if self.log_level not in LEVELS:
            print(f'Log severity does not exist: {self.log_level}')
            exit(1)

        log_level_parsed = LEVELS[self.log_level]

        # Create a logger with the provided name
        self.logger = logging.getLogger(name)
        self.logger.setLevel(log_level_parsed)

        # Create a console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level_parsed)

        # Ensure the log directory exists
        os.makedirs(self.log_directory, exist_ok=True)

        # Create a file handler
        file_handler = RotatingFileHandler(
            f"{self.log_directory}/{self.log_filename}",
            mode="a",
            maxBytes=self.max_log_size,
            backupCount=self.backup_count
        )
        file_handler.setLevel(log_level_parsed)

        # Create a formatter and add it to the handlers
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(formatter)
        file_handler.setFormatter(formatter)

        # Add the handlers to the logger
        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)
    
    def get_logger(self):
        return self.logger