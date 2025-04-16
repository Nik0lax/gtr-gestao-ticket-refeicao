import shutil
from datetime import datetime
import schedule
import time
from threading import Thread
import os

def backup_logs():
    # Obtém a data atual para o nome do arquivo de backup
    data_atual = datetime.now().strftime('%Y-%m-%d')
    arquivo_log = 'logs/gtr.log'
    arquivo_backup = f'logs/gtr_{data_atual}.log'

    # Renomeia o arquivo de log atual
    if os.path.exists(arquivo_log):
        shutil.copy(arquivo_log, arquivo_backup)
        open(arquivo_log, 'w').close()  # Limpa o arquivo de log atual
        print(f"Backup do log realizado: {arquivo_backup}")

# Agendar o backup para rodar às 23:59 de todos os dias
schedule.every().day.at("23:59").do(backup_logs)

def run_scheduler():
    while True:
        schedule.run_pending()
        time.sleep(1)

# Rodar o agendador em uma thread separada
def start_log_backup():
    thread = Thread(target=run_scheduler)
    thread.daemon = True
    thread.start()
