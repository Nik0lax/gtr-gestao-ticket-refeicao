import shutil
from datetime import datetime
import schedule
import time
from threading import Thread
import os

def backup_logs():
    data_atual = datetime.now().strftime('%Y-%m-%d')
    arquivo_log = 'logs/gtr.log'
    arquivo_backup = f'logs/gtr_{data_atual}.log'

    if os.path.exists(arquivo_log):
        try:
            # Copia o log original para um novo arquivo com data
            shutil.copy2(arquivo_log, arquivo_backup)
            print(f"Backup do log realizado com sucesso: {arquivo_backup}")

            # Limpa o conteúdo do arquivo original sem apagar o arquivo
            with open(arquivo_log, 'w'):
                pass
            print(f"Log original limpo após o backup.")
        except Exception as e:
            print(f"Erro ao realizar backup do log: {e}")

# Agendar o backup para rodar às 23:59 todos os dias
schedule.every().day.at("23:59").do(backup_logs)

def run_scheduler():
    while True:
        schedule.run_pending()
        time.sleep(1)

def start_log_backup():
    thread = Thread(target=run_scheduler)
    thread.daemon = True
    thread.start()
