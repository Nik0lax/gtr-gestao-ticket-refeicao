import logging
from logging.handlers import RotatingFileHandler
import os
from datetime import datetime

# Criar diretório para armazenar logs, caso não exista
log_dir = 'logs'
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# Definir o formato do log
log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# Definir o nome do arquivo de log com a data atual
log_file = os.path.join(log_dir, f'gtr_{datetime.now().strftime("%Y-%m-%d")}.log')

# Criar um handler para salvar os logs em arquivo, com rotação de logs a cada 10MB
file_handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=7)
file_handler.setFormatter(log_formatter)

# Criar um handler para console
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)

# Configurar o logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(file_handler)
logger.addHandler(console_handler)

print(f"Logs serão gravados em: {log_file}")
