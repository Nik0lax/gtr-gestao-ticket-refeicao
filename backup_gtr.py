"""GTR — backup e restauração (independente de infraestrutura).

Não depende de mysqldump nem de ferramentas do sistema: usa só Python e a conexão do próprio GTR,
então funciona igual em instalação nativa ou Docker, com MariaDB ou MySQL.

Formato do arquivo (.zip):
  manifest.json   — formato, data, banco, linhas por tabela, SHA-256 do banco.sql, arquivos
  banco.sql       — SQL padrão (DROP/CREATE + INSERT), importável também com `mysql -u ... banco < banco.sql`
  arquivos/<nome>/...  — arquivos enviados ao sistema (fotos do cardápio)
Os segredos (instance/secret_key, certificados) NÃO entram no backup.
"""
import hashlib
import io
import json
import os
import zipfile
from datetime import datetime

import MySQLdb
import MySQLdb.cursors

FORMATO = 1
LOTE_INSERT = 500


def _conectar(cfg):
    return MySQLdb.connect(host=cfg['host'], user=cfg['user'], passwd=cfg['password'], db=cfg['db'],
                           port=int(cfg.get('port') or 3306), charset='utf8mb4', use_unicode=True)


def _sql_valor(conn, v):
    if v is None:
        return 'NULL'
    if isinstance(v, (bytes, bytearray)):
        return '0x' + bytes(v).hex() if v else "''"
    lit = conn.literal(v)
    return lit.decode('utf-8') if isinstance(lit, bytes) else str(lit)


def gerar_backup(cfg, destino, pastas=None, meta=None, progresso=None):
    """Gera o .zip em `destino` (grava em .parcial e renomeia no fim). Retorna o manifest."""
    pastas = pastas or {}
    parcial = destino + '.parcial'
    conn = _conectar(cfg)
    tabelas = {}
    sha = hashlib.sha256()
    try:
        cur = conn.cursor()
        cur.execute("SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        cur.execute("START TRANSACTION WITH CONSISTENT SNAPSHOT")      # foto consistente, sem travar o sistema
        cur.execute("SELECT VERSION()")
        versao_srv = cur.fetchone()[0]
        cur.execute("SHOW FULL TABLES WHERE Table_type = 'BASE TABLE'")
        nomes = sorted(r[0] for r in cur.fetchall())
        with zipfile.ZipFile(parcial, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=True) as z:
            with z.open('banco.sql', 'w', force_zip64=True) as fsql:
                def w(txt):
                    b = (txt + '\n').encode('utf-8')
                    sha.update(b)
                    fsql.write(b)
                w(f"-- GTR backup · banco `{cfg['db']}` · {datetime.now():%d/%m/%Y %H:%M:%S} · servidor {versao_srv}")
                w("SET NAMES utf8mb4;")
                w("SET FOREIGN_KEY_CHECKS=0;")
                w("SET UNIQUE_CHECKS=0;")
                w("SET SQL_MODE='NO_AUTO_VALUE_ON_ZERO';")
                for i, t in enumerate(nomes):
                    if progresso:
                        progresso(f"Tabela {t} ({i + 1}/{len(nomes)})")
                    cur.execute(f"SHOW CREATE TABLE `{t}`")
                    w("")
                    w(f"DROP TABLE IF EXISTS `{t}`;")
                    w(cur.fetchone()[1] + ";")
                    ss = conn.cursor(MySQLdb.cursors.SSCursor)
                    ss.execute(f"SELECT * FROM `{t}`")
                    cols = ', '.join(f"`{d[0]}`" for d in ss.description)
                    n = 0
                    while True:
                        lote = ss.fetchmany(LOTE_INSERT)
                        if not lote:
                            break
                        vals = ','.join('(' + ','.join(_sql_valor(conn, v) for v in row) + ')' for row in lote)
                        w(f"INSERT INTO `{t}` ({cols}) VALUES {vals};")
                        n += len(lote)
                    ss.close()
                    tabelas[t] = n
                w("")
                w("SET FOREIGN_KEY_CHECKS=1;")
                w("SET UNIQUE_CHECKS=1;")
            cur.execute("COMMIT")
            arquivos = {}
            for nome, pasta in pastas.items():
                qtd = 0
                if pasta and os.path.isdir(pasta):
                    if progresso:
                        progresso(f"Arquivos: {nome}")
                    for raiz, _dirs, fs in os.walk(pasta):
                        for f in fs:
                            caminho = os.path.join(raiz, f)
                            rel = os.path.relpath(caminho, pasta).replace(os.sep, '/')
                            z.write(caminho, f"arquivos/{nome}/{rel}")
                            qtd += 1
                arquivos[nome] = qtd
            manifest = {'sistema': 'GTR', 'formato': FORMATO, 'gerado_em': datetime.now().isoformat(timespec='seconds'),
                        'banco': cfg['db'], 'servidor': versao_srv, 'tabelas': tabelas,
                        'linhas': sum(tabelas.values()), 'sha256_banco': sha.hexdigest(), 'arquivos': arquivos,
                        **(meta or {})}
            z.writestr('manifest.json', json.dumps(manifest, ensure_ascii=False, indent=2))
        os.replace(parcial, destino)
        return manifest
    except Exception:
        try:
            os.remove(parcial)
        except OSError:
            pass
        raise
    finally:
        conn.close()


def ler_manifest(caminho):
    with zipfile.ZipFile(caminho) as z:
        return json.loads(z.read('manifest.json').decode('utf-8'))


def verificar_backup(caminho):
    """Confere se o arquivo é um backup do GTR íntegro. Retorna (ok, manifest_ou_None, mensagem)."""
    try:
        with zipfile.ZipFile(caminho) as z:
            nomes = set(z.namelist())
            if 'manifest.json' not in nomes or 'banco.sql' not in nomes:
                return False, None, "Não é um backup do GTR (faltam manifest.json ou banco.sql)."
            m = json.loads(z.read('manifest.json').decode('utf-8'))
            if m.get('sistema') != 'GTR' or m.get('formato') != FORMATO:
                return False, m, "Formato de backup não reconhecido por esta versão do GTR."
            sha = hashlib.sha256()
            with z.open('banco.sql') as f:
                for bloco in iter(lambda: f.read(1024 * 1024), b''):
                    sha.update(bloco)
            if sha.hexdigest() != m.get('sha256_banco'):
                return False, m, "Arquivo corrompido: a verificação (SHA-256) do banco não confere."
            return True, m, "Backup íntegro."
    except zipfile.BadZipFile:
        return False, None, "Arquivo .zip inválido ou corrompido."
    except Exception as e:
        return False, None, f"Não foi possível ler o arquivo: {e}"


def _comandos_sql(fbin):
    """Lê o banco.sql comando a comando (cada comando termina numa linha que acaba em ';')."""
    buf = []
    for linha in io.TextIOWrapper(fbin, encoding='utf-8'):
        if not buf and (not linha.strip() or linha.startswith('--')):
            continue
        buf.append(linha)
        if linha.rstrip().endswith(';'):
            yield ''.join(buf).strip()
            buf = []
    if buf and ''.join(buf).strip():
        yield ''.join(buf).strip()


TABELAS_NAO_RESTAURAR = {'gtr_backups'}     # histórico de backups: é do servidor, não do backup


def _tabela_do_comando(cmd):
    """Nome da tabela de um DROP/CREATE/INSERT gerado por gerar_backup (None para SET etc.)."""
    for ini in ('DROP TABLE IF EXISTS `', 'CREATE TABLE `', 'INSERT INTO `'):
        if cmd.startswith(ini):
            return cmd[len(ini):cmd.index('`', len(ini))]
    return None


def restaurar_backup(cfg, caminho, pastas=None, progresso=None, pular=TABELAS_NAO_RESTAURAR):
    """Restaura banco e arquivos de um backup já verificado. Retorna {'comandos', 'tabelas', 'arquivos', 'divergentes'}."""
    pastas = pastas or {}
    m = ler_manifest(caminho)
    conn = _conectar(cfg)
    n_cmd = 0
    try:
        cur = conn.cursor()
        cur.execute("SET SESSION lock_wait_timeout = 60")   # tabela presa por outra conexão: falha (e desfaz), não trava
        with zipfile.ZipFile(caminho) as z:
            with z.open('banco.sql') as f:
                for cmd in _comandos_sql(f):
                    if _tabela_do_comando(cmd) in pular:
                        continue
                    cur.execute(cmd)            # sem parâmetros: o MySQLdb não interpreta "%"
                    n_cmd += 1
                    if progresso and n_cmd % 200 == 0:
                        progresso(f"Banco: {n_cmd} comandos aplicados")
            conn.commit()
            n_arq = 0
            for nome, pasta in pastas.items():
                prefixo = f"arquivos/{nome}/"
                for info in z.infolist():
                    if not info.filename.startswith(prefixo) or info.is_dir():
                        continue
                    rel = info.filename[len(prefixo):]
                    destino = os.path.realpath(os.path.join(pasta, rel))
                    if not destino.startswith(os.path.realpath(pasta) + os.sep):   # proteção contra "../"
                        continue
                    os.makedirs(os.path.dirname(destino), exist_ok=True)
                    with z.open(info) as src, open(destino, 'wb') as dst:
                        dst.write(src.read())
                    n_arq += 1
            if progresso:
                progresso("Conferindo as tabelas restauradas")
        divergentes = {}
        for t, esperado in m.get('tabelas', {}).items():
            if t in pular:
                continue
            cur.execute(f"SELECT COUNT(*) FROM `{t}`")
            atual = cur.fetchone()[0]
            if atual != esperado:
                divergentes[t] = (esperado, atual)
        return {'comandos': n_cmd, 'tabelas': len(m.get('tabelas', {})), 'arquivos': n_arq, 'divergentes': divergentes}
    finally:
        conn.close()


# ─── Executor em processo separado ───────────────────────────────────────────
# O servidor web só registra o pedido e inicia este processo (python backup_gtr.py <acao> <id>).
# Rodando fora dos workers do gunicorn, o backup/restauração não morre se um worker for reiniciado,
# e a restauração liga o "modo manutenção" (arquivo-sinal) para nenhuma tela segurar tabelas no meio.
ARQ_MANUTENCAO = '.restauracao_em_andamento.json'


def _cfg_env():
    return {'host': os.environ['GTR_DB_HOST'], 'user': os.environ['GTR_DB_USER'], 'password': os.environ['GTR_DB_PASSWORD'],
            'db': os.environ['GTR_DB_NAME'], 'port': int(os.environ.get('GTR_DB_PORT') or 3306)}


def _sql(cfg, q, p=(), um=False, todos=False):
    conn = _conectar(cfg)
    try:
        cur = conn.cursor()
        cur.execute(q, p)
        r = cur.fetchone() if um else (cur.fetchall() if todos else cur.lastrowid)
        conn.commit()
        return r
    finally:
        conn.close()


def _config(cfg, chave, padrao):
    try:
        r = _sql(cfg, "SELECT valor FROM configuracoes_sistema WHERE chave=%s", (chave,), um=True)
        return r[0] if r else padrao
    except Exception:
        return padrao


def _gerar(cfg, bid, tipo, por, pasta_bk, pastas, log):
    nome = f"gtr_{cfg['db']}_{datetime.now():%Y%m%d_%H%M%S}_{tipo}.zip"
    etapa = lambda t: _sql(cfg, "UPDATE gtr_backups SET etapa=%s WHERE id=%s", (t[:200], bid))
    m = gerar_backup(cfg, os.path.join(pasta_bk, nome), pastas, progresso=etapa,
                     meta={'tipo': tipo, 'por': por, 'instituicao': _config(cfg, 'nome_instituicao', '')})
    tam = os.path.getsize(os.path.join(pasta_bk, nome))
    _sql(cfg, """UPDATE gtr_backups SET status='ok', arquivo=%s, tamanho=%s, tabelas=%s, linhas=%s, arquivos=%s,
                 etapa='Concluído', concluido_em=NOW() WHERE id=%s""",
         (nome, tam, len(m['tabelas']), m['linhas'], sum(m['arquivos'].values()), bid))
    log.info(f"Backup {tipo} concluído: {nome} ({tam} bytes, {m['linhas']} linhas) por {por}.")
    return nome


def _retencao(cfg, pasta_bk):
    try:
        n = max(int(_config(cfg, 'backup_retencao', '14')), 1)
    except ValueError:
        n = 14
    for bid, arq in _sql(cfg, """SELECT id, arquivo FROM gtr_backups WHERE tipo='automatico' AND status='ok' AND excluido=0
                                 ORDER BY iniciado_em DESC LIMIT 100000 OFFSET %s""", (n,), todos=True):
        try:
            os.remove(os.path.join(pasta_bk, arq))
        except OSError:
            pass
        _sql(cfg, "UPDATE gtr_backups SET excluido=1, etapa='Removido pela retenção' WHERE id=%s", (bid,))


def executar(acao, bid):
    """Ponto de entrada do processo separado. acao: 'backup' | 'restaurar'. bid: linha em gtr_backups."""
    import logging, sys, time as _t
    try:
        from log_config import get_logger
        log = get_logger()
    except Exception:
        logging.basicConfig(level=logging.INFO)
        log = logging.getLogger('gtr_backup')
    cfg = _cfg_env()
    pasta_bk = os.environ['GTR_BACKUP_DIR']
    pastas = json.loads(os.environ.get('GTR_BACKUP_PASTAS') or '{}')
    tipo, por, origem = _sql(cfg, "SELECT tipo, por, origem_id FROM gtr_backups WHERE id=%s", (bid,), um=True)
    _sql(cfg, "UPDATE gtr_backups SET pid=%s WHERE id=%s", (os.getpid(), bid))
    trava = _conectar(cfg)
    tc = trava.cursor()
    tc.execute("SELECT GET_LOCK(%s, 0)", (f"gtr_backup_{cfg['db']}",))
    if (tc.fetchone() or [0])[0] != 1:
        _sql(cfg, "UPDATE gtr_backups SET status='erro', mensagem='Já havia outro backup ou restauração em andamento.', concluido_em=NOW() WHERE id=%s", (bid,))
        trava.close()
        return 1
    flag = os.path.join(pasta_bk, ARQ_MANUTENCAO)
    try:
        if acao == 'backup':
            _gerar(cfg, bid, tipo, por, pasta_bk, pastas, log)
            if tipo == 'automatico':
                _retencao(cfg, pasta_bk)
            return 0
        # ── restauração ──
        arq = _sql(cfg, "SELECT arquivo FROM gtr_backups WHERE id=%s", (origem,), um=True)[0]
        caminho = os.path.join(pasta_bk, arq)
        ok, _m, msg = verificar_backup(caminho)
        if not ok:
            raise RuntimeError(msg)
        etapa = lambda t: _sql(cfg, "UPDATE gtr_backups SET etapa=%s WHERE id=%s", (t[:200], bid))
        etapa("Fazendo backup de segurança do estado atual")
        sid = _sql(cfg, "INSERT INTO gtr_backups (tipo, por, iniciado_em, etapa, pid) VALUES ('seguranca',%s,NOW(),'Iniciando',%s)", (por, os.getpid()))
        try:
            seg = _gerar(cfg, sid, 'seguranca', por, pasta_bk, pastas, log)
        except Exception as e:
            _sql(cfg, "UPDATE gtr_backups SET status='erro', mensagem=%s, concluido_em=NOW() WHERE id=%s", (str(e)[:2000], sid))
            raise RuntimeError(f"O backup de segurança falhou; nada foi restaurado. ({e})")
        # modo manutenção: o sistema recusa as telas e espera as requisições em curso terminarem
        with open(flag, 'w') as fh:
            json.dump({'pid': os.getpid(), 'id': bid, 'seguranca': seg, 'inicio': datetime.now().isoformat(timespec='seconds')}, fh)
        etapa("Sistema em manutenção; aguardando as telas abertas terminarem")
        _t.sleep(8)
        try:
            r = restaurar_backup(cfg, caminho, pastas, progresso=etapa)
        except Exception as e:
            log.error(f"Restauração falhou ({e}); voltando ao backup de segurança {seg}.")
            etapa("Falhou — voltando ao estado anterior (backup de segurança)")
            try:
                restaurar_backup(cfg, os.path.join(pasta_bk, seg), pastas)
            except Exception as e2:
                raise RuntimeError(f"A restauração falhou ({e}) e a volta automática também ({e2}). "
                                   f"RESTAURE MANUALMENTE o backup de segurança {seg}.")
            raise RuntimeError(f"A restauração falhou ({e}). O sistema voltou automaticamente ao estado anterior "
                               f"(backup de segurança {seg}); nada foi alterado.")
        msg = (f"Restaurado de {arq}: {r['tabelas']} tabelas, {r['arquivos']} arquivo(s). "
               f"Backup de segurança do estado anterior: {seg}.")
        if r['divergentes']:
            msg += f" ATENÇÃO — contagem diferente em: {r['divergentes']}."
        _sql(cfg, "UPDATE gtr_backups SET status=%s, arquivo=%s, etapa='Concluído', mensagem=%s, concluido_em=NOW() WHERE id=%s",
             ('erro' if r['divergentes'] else 'ok', arq, msg, bid))
        log.warning(f"RESTAURAÇÃO de backup por {por}: {msg}")
        return 0
    except Exception as e:
        log.error(f"Falha no {'backup ' + tipo if acao == 'backup' else 'restauração'} (id {bid}): {e}")
        _sql(cfg, "UPDATE gtr_backups SET status='erro', mensagem=%s, concluido_em=NOW() WHERE id=%s", (str(e)[:2000], bid))
        return 1
    finally:
        try:
            if os.path.exists(flag) and json.load(open(flag)).get('pid') == os.getpid():
                os.remove(flag)
        except Exception:
            pass
        trava.close()


if __name__ == '__main__':
    import sys
    sys.exit(executar(sys.argv[1], int(sys.argv[2])))
