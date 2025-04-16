import logging
from logging.handlers import RotatingFileHandler
import os

# Criar diretório para armazenar logs, caso não exista
if not os.path.exists('logs'):
    os.makedirs('logs')

# Definir o formato do log
log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# Criar um handler para salvar os logs em arquivo, com rotação de logs a cada 10MB
log_file = 'logs/gtr.log'
file_handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=7)
file_handler.setFormatter(log_formatter)

# Configurar o logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)  # Registrar apenas INFO para registrar passos do usuário
logger.addHandler(file_handler)

# Adicionar um handler para mostrar os logs também no console
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)
logger.addHandler(console_handler)
