# log_config.py

import os
import logging

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

    # Cria um handler simples sem rotação
    handler = logging.FileHandler(log_file, encoding='utf-8')
    
    # Define o formato do log
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    handler.setFormatter(formatter)

    # Adiciona o handler ao logger
    logger.addHandler(handler)

    return logger
