# log_config.py

import os
import logging
from logging.handlers import TimedRotatingFileHandler

def get_logger():
    # Define o diretório de logs e o arquivo de log
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, 'gtr.log')

    # Cria o logger
    logger = logging.getLogger('gtr')
    logger.setLevel(logging.INFO)

    # Remove handlers existentes para evitar duplicidade
    if logger.hasHandlers():
        logger.handlers.clear()

    # Cria o handler de rotação diária
    handler = TimedRotatingFileHandler(
        filename=log_file,
        when='midnight',
        interval=1,
        backupCount=30,
        encoding='utf-8',
        utc=False
    )
    handler.suffix = "%Y-%m-%d"

    # Define o formato do log
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    handler.setFormatter(formatter)

    # Adiciona o handler ao logger
    logger.addHandler(handler)

    return logger
