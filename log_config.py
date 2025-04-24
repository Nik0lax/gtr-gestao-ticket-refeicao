# log_config.py

import os
import logging
from logging.handlers import TimedRotatingFileHandler

def logger(name='gtr', log_dir=None, backup_count=30):
    # 1. Cria a pasta de logs
    if log_dir is None:
        log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
    os.makedirs(log_dir, exist_ok=True)

    # 2. Configura o handler para rotacionar à meia-noite, mantendo 30 backups
    log_file = os.path.join(log_dir, f'{name}.log')
    handler = TimedRotatingFileHandler(
        filename=log_file,
        when='midnight',      # rotaciona todo dia à 00:00
        interval=1,           # intervalo de 1 dia
        backupCount=backup_count,
        encoding='utf-8',
        utc=False
    )
    handler.suffix = "%Y-%m-%d"  # sufixo de data para os arquivos rotacionados

    # 3. Formato: timestamp, nível e nome do logger
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    handler.setFormatter(logging.Formatter(fmt))

    # 4. Cria e retorna o logger configurado
    log = logging.getLogger(name)
    log.setLevel(logging.INFO)

    # Evita múltiplos handlers duplicados
    if not log.hasHandlers():
        log.addHandler(handler)

    return log
