import logging
import os
from datetime import datetime

def setup_logger(name: str, level: str = "INFO") -> logging.Logger:
    """Configure un logger structuré."""
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))
    
    # Handler console
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_format = logging.Formatter('[%(asctime)s] [%(name)s] %(levelname)s: %(message)s', datefmt='%H:%M:%S')
    console_handler.setFormatter(console_format)
    logger.addHandler(console_handler)
    
    # Handler fichier (optionnel)
    log_dir = os.getenv("LOG_DIR", "logs")
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    file_handler = logging.FileHandler(os.path.join(log_dir, f"{name}_{datetime.now().strftime('%Y%m%d')}.log"))
    file_handler.setLevel(logging.DEBUG)
    file_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_format)
    logger.addHandler(file_handler)
    
    return logger
