import logging
from logging.handlers import TimedRotatingFileHandler
import os

# Criar diretório para armazenar logs, caso não exista
log_dir = 'logs'
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# Definir o nome base do arquivo de log (sem a data)
log_file_base = os.path.join(log_dir, 'gtr.log')

# Criar um handler que rotaciona os arquivos diariamente à meia-noite
file_handler = TimedRotatingFileHandler(
    log_file_base,
    when='midnight',
    interval=1,
    backupCount=7,
    encoding='utf-8',
    utc=False  # Usa horário local; coloque True se preferir UTC
)

# Nome do arquivo rotacionado incluirá a data no final, ex: gtr.log.2025-04-22
file_handler.suffix = "%Y-%m-%d"

# Formato do log
log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(log_formatter)

# Handler para o console
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)

# Configurar o logger principal
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(file_handler)
logger.addHandler(console_handler)

print(f"Logs diários serão gravados em: {log_file_base}")
