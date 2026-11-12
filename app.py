from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from flask_mysqldb import MySQL
from datetime import datetime, date, time
from io import BytesIO, StringIO
from werkzeug.security import generate_password_hash, check_password_hash
import pdfkit
import os
import MySQLdb
import pandas as pd

from log_config import get_logger


def _carregar_env(caminho=os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')):
    """Lê o .env (CHAVE=valor por linha) para os.environ. Senhas, IPs e endereços de cada unidade ficam lá,
    fora do código e do Git (modelo: .env.example). Variável já definida no ambiente (systemd, Docker) prevalece."""
    try:
        with open(caminho, encoding='utf-8') as fh:
            for linha in fh:
                linha = linha.strip()
                if not linha or linha.startswith('#') or '=' not in linha:
                    continue
                chave, valor = linha.split('=', 1)
                valor = valor.strip()
                if len(valor) >= 2 and valor[0] == valor[-1] and valor[0] in '"\'':
                    valor = valor[1:-1]
                os.environ.setdefault(chave.strip(), valor)
    except FileNotFoundError:
        pass


_carregar_env()

##################################CONFIGS##################################
logger = get_logger()

app = Flask(__name__)
import time as time_mod


def _carregar_secret_key():
    """Chave que assina o cookie de sessão. Quem a conhece consegue se passar por qualquer usuário,
    então ela NUNCA fica no código: vem da variável SECRET_KEY ou de um arquivo gerado uma única vez
    (instance/secret_key, permissão 600, fora do Git). Trocar a chave desloga todo mundo."""
    import secrets
    chave = (os.environ.get('SECRET_KEY') or '').strip()
    if chave and len(chave) >= 32 and chave.lower() not in ('gtr', 'secret', 'changeme'):
        return chave
    if chave:
        logger.error("SECRET_KEY recebida é fraca (menos de 32 caracteres) e foi ignorada; usando a chave do arquivo.")
    caminho = os.environ.get('SECRET_KEY_FILE') or os.path.join(app.root_path, 'instance', 'secret_key')
    os.makedirs(os.path.dirname(caminho), mode=0o700, exist_ok=True)
    try:   # criação atômica: com vários workers do gunicorn, só um gera e todos usam a mesma
        fd = os.open(caminho, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(secrets.token_hex(32))
        logger.info(f"Nova chave de sessão gerada em {caminho}.")
    except FileExistsError:
        pass
    for _ in range(50):
        with open(caminho) as f:
            chave = f.read().strip()
        if len(chave) >= 32:
            return chave
        time_mod.sleep(0.05)   # outro worker ainda está gravando
    raise RuntimeError(f"Não foi possível ler a chave de sessão em {caminho}.")


app.secret_key = _carregar_secret_key()
app.config.update(
    # nome novo: cookies antigos (assinados com a chave velha) são ignorados. A instância HTTPS usa outro nome,
    # porque cookie não separa por porta e um cookie Secure travaria o login da instância HTTP no mesmo navegador.
    SESSION_COOKIE_NAME=os.environ.get('SESSION_COOKIE_NAME', 'gtr_sessao'),
    SESSION_COOKIE_HTTPONLY=True,              # JavaScript da página não lê o cookie
    SESSION_COOKIE_SAMESITE='Lax',             # outro site não envia o cookie em POST para o GTR
    SESSION_COOKIE_SECURE=os.environ.get('SESSION_COOKIE_SECURE', '0') == '1',   # 1 onde só há HTTPS
)
# minutos sem uso até a sessão expirar (perfis de totem não expiram; o totem da dispensa tem regra própria)
SESSAO_INATIVIDADE_MIN = int(os.environ.get('SESSAO_INATIVIDADE_MIN', '60'))
logger.info("🚀 Aplicação iniciada.")


# ─── CSRF: todo POST precisa do token secreto da sessão ──────────────────────
# Impede que outra página (inclusive de outro sistema no mesmo servidor, como o GLPI — para o navegador
# é o "mesmo site", então o SameSite do cookie não basta) dispare ações no GTR com a sessão de quem está logado.
# O token vai sozinho em todo <form method="post"> das páginas HTML (_csrf_injetar) e, nas chamadas
# fetch(), no cabeçalho X-CSRF-Token lido de <meta name="csrf-token">.
import hmac as _hmac
import re as _re_csrf
import secrets as _secrets
CSRF_CAMPO = 'csrf_token'
CSRF_CABECALHO = 'X-CSRF-Token'
_RE_FORM_POST = _re_csrf.compile(r'(<form\b[^>]*\bmethod\s*=\s*["\']?post["\']?[^>]*>)', _re_csrf.I)


def csrf_token():
    tok = session.get('_csrf')
    if not tok:
        tok = session['_csrf'] = _secrets.token_urlsafe(32)
    return tok


@app.context_processor
def _injetar_csrf():
    return {'csrf_token': csrf_token}


@app.before_request
def _checar_csrf():
    if request.method in ('GET', 'HEAD', 'OPTIONS'):
        return None
    enviado = request.headers.get(CSRF_CABECALHO) or request.form.get(CSRF_CAMPO, '')
    esperado = session.get('_csrf', '')
    if esperado and enviado and _hmac.compare_digest(str(enviado), str(esperado)):
        return None
    auditar(forcar=True, resultado='negado', motivo='CSRF: ' + ('sem token' if not enviado else 'token inválido'),
            detalhes={'origem': request.headers.get('Origin') or request.referrer or ''})
    logger.warning(f"CSRF: POST recusado em {request.path} ({'sem token' if not enviado else 'token inválido'}; "
                   f"IP {request.remote_addr}; usuário {session.get('usuario_nome', '-')}; origem {request.headers.get('Origin') or request.referrer or '-'}).")
    quer_json = (request.endpoint in ROTAS_JSON or request.headers.get(CSRF_CABECALHO) is not None
                 or 'application/json' in (request.headers.get('Accept') or ''))
    if quer_json:
        return {'ok': False, 'tipo': 'csrf', 'erro': 'A página estava desatualizada. Recarregue a tela e tente de novo.'}, 400
    flash("A página estava desatualizada e a ação não foi feita. Confira os dados e tente de novo.", "error")
    # volta para a própria página (só se a origem for o próprio GTR), que já carrega com um token novo
    ref = request.referrer or ''
    if ref.startswith(request.host_url):
        return redirect(ref)
    return redirect('/')


@app.after_request
def _csrf_injetar(response):
    """Coloca o campo oculto do token em todo formulário POST e a <meta> para o JavaScript."""
    if response.direct_passthrough or response.status_code >= 300 or \
            not (response.mimetype == 'text/html'):
        return response
    corpo = response.get_data(as_text=True)
    tem_form = _RE_FORM_POST.search(corpo) is not None
    tem_meta = 'name="csrf-token"' in corpo
    if not tem_form and not tem_meta:
        return response
    tok = csrf_token()
    campo = f'<input type="hidden" name="{CSRF_CAMPO}" value="{tok}">'
    if tem_form:
        corpo = _RE_FORM_POST.sub(lambda m: m.group(1) + campo, corpo)
    if not tem_meta and '</head>' in corpo:
        corpo = corpo.replace('</head>', f'<meta name="csrf-token" content="{tok}">\n</head>', 1)
    response.set_data(corpo)
    return response

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

def validar_cpf(cpf):
    import re
    cpf = re.sub(r'\D', '', cpf)
    if len(cpf) != 11 or cpf == cpf[0] * 11:
        return False
    for i in range(9, 11):
        soma = sum(int(cpf[j]) * ((i + 1) - j) for j in range(i))
        digito = ((soma * 10) % 11) % 10
        if digito != int(cpf[i]):
            return False
    return True

_PARTICULAS_NOME = {'DE', 'DA', 'DO', 'DAS', 'DOS', 'E'}

def nome_completo_valido(nome):
    """Exige nome e sobrenome: ao menos 2 palavras com 2+ letras, sem contar partículas (de, da, do...)."""
    palavras = [p for p in (nome or '').upper().split() if p not in _PARTICULAS_NOME]
    validas = [p for p in palavras if sum(ch.isalpha() for ch in p) >= 2]
    return len(validas) >= 2

def get_usuario_logado():
    return session.get('usuario_nome', 'Usuário não autenticado')

def requer_admin():
    """Mantida por compatibilidade: a permissão agora é checada de forma central
    (perfis configuráveis, ver _checar_permissao). Se a rota foi alcançada, já foi autorizada."""
    return False

def get_dashboard_data(data_inicio=None, data_fim=None):
    from datetime import date, timedelta
    cursor = mysql.connection.cursor()
    filtro_ativo = bool(data_inicio and data_fim)

    # KPIs estáticos (sempre referentes ao dia/banco completo)
    cursor.execute("SELECT COUNT(*) FROM emissoes_senha WHERE DATE(data_hora) = CURDATE()")
    total_hoje = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM colaboradores")
    total_colaboradores = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM departamentos")
    total_departamentos = cursor.fetchone()[0]
    cursor.execute("SELECT MAX(data_hora) FROM emissoes_senha")
    ultima_emissao = cursor.fetchone()[0]

    if filtro_ativo:
        # KPI período filtrado
        cursor.execute("SELECT COUNT(*) FROM emissoes_senha WHERE DATE(data_hora) BETWEEN %s AND %s",
                       (data_inicio, data_fim))
        kpi_valor_periodo = cursor.fetchone()[0]
        kpi_label_periodo = "Senhas no Período"

        # Gráfico de barras: diário no período
        cursor.execute("""
            SELECT DATE(data_hora), COUNT(*) FROM emissoes_senha
            WHERE DATE(data_hora) BETWEEN %s AND %s
            GROUP BY DATE(data_hora) ORDER BY DATE(data_hora)
        """, (data_inicio, data_fim))
        rows_grafico = cursor.fetchall()
        dias_map = {r[0]: r[1] for r in rows_grafico}
        labels_grafico, valores_grafico = [], []
        delta = (data_fim - data_inicio).days
        for i in range(delta + 1):
            d = data_inicio + timedelta(days=i)
            labels_grafico.append(d.strftime('%d/%m'))
            valores_grafico.append(dias_map.get(d, 0))
        titulo_grafico = f"Emissões por dia ({data_inicio.strftime('%d/%m')} a {data_fim.strftime('%d/%m/%Y')})"
        titulo_pizza   = "Top Departamentos (período)"

        # Top 5 departamentos no período
        cursor.execute("""
            SELECT departamento, COUNT(*) FROM emissoes_senha
            WHERE DATE(data_hora) BETWEEN %s AND %s
            GROUP BY departamento ORDER BY 2 DESC LIMIT 5
        """, (data_inicio, data_fim))
    else:
        # KPI mês corrente
        cursor.execute("SELECT COUNT(*) FROM emissoes_senha WHERE MONTH(data_hora)=MONTH(CURDATE()) AND YEAR(data_hora)=YEAR(CURDATE())")
        kpi_valor_periodo = cursor.fetchone()[0]
        kpi_label_periodo = "Senhas no Mês"

        # Gráfico de barras: últimos 7 dias
        cursor.execute("""
            SELECT DATE(data_hora), COUNT(*) FROM emissoes_senha
            WHERE data_hora >= CURDATE() - INTERVAL 6 DAY
            GROUP BY DATE(data_hora) ORDER BY DATE(data_hora)
        """)
        rows_grafico = cursor.fetchall()
        hoje = date.today()
        dias_map = {r[0]: r[1] for r in rows_grafico}
        labels_grafico, valores_grafico = [], []
        for i in range(6, -1, -1):
            d = hoje - timedelta(days=i)
            labels_grafico.append(d.strftime('%d/%m'))
            valores_grafico.append(dias_map.get(d, 0))
        titulo_grafico = "Emissões — Últimos 7 dias"
        titulo_pizza   = "Top Departamentos (mês)"

        # Top 5 departamentos no mês
        cursor.execute("""
            SELECT departamento, COUNT(*) FROM emissoes_senha
            WHERE MONTH(data_hora)=MONTH(CURDATE()) AND YEAR(data_hora)=YEAR(CURDATE())
            GROUP BY departamento ORDER BY 2 DESC LIMIT 5
        """)

    rows_deps = cursor.fetchall()
    cursor.close()

    return {
        'total_hoje':          total_hoje,
        'kpi_valor_periodo':   kpi_valor_periodo,
        'kpi_label_periodo':   kpi_label_periodo,
        'total_colaboradores': total_colaboradores,
        'total_departamentos': total_departamentos,
        'ultima_emissao':      ultima_emissao.strftime('%d/%m/%Y %H:%M') if ultima_emissao else 'N/A',
        'filtro_ativo':        filtro_ativo,
        'dash_inicio':         data_inicio.strftime('%Y-%m-%d') if data_inicio else '',
        'dash_fim':            data_fim.strftime('%Y-%m-%d') if data_fim else '',
        'labels_grafico':      labels_grafico,
        'valores_grafico':     valores_grafico,
        'titulo_grafico':      titulo_grafico,
        'titulo_pizza':        titulo_pizza,
        'labels_deps':         [r[0] for r in rows_deps],
        'valores_deps':        [r[1] for r in rows_deps],
    }

def _variacao_pct(atual, anterior):
    if not anterior:
        return None
    return round((atual - anterior) * 100.0 / anterior, 1)


def get_dashboard_extras():
    """Indicadores adicionais do painel administrativo (layout novo)."""
    from datetime import timedelta
    hoje = date.today()
    ontem = hoje - timedelta(days=1)
    inicio_mes = hoje.replace(day=1)
    fim_mes_ant = inicio_mes - timedelta(days=1)
    inicio_mes_ant = fim_mes_ant.replace(day=1)
    # mesmo dia do mês anterior (limitado ao último dia daquele mês)
    corte_mes_ant = fim_mes_ant.replace(day=min(hoje.day, fim_mes_ant.day))

    t = get_turnos()
    faixas = {'cafe': None, 'almoco': None, 'janta': None}
    _ref = sql_refeicao(t)
    case_turnos = ", ".join(f"SUM({_ref} = '{k}')" for k in faixas)

    cur = mysql.connection.cursor()

    def um(sql, params=()):
        cur.execute(sql, params)
        return cur.fetchone()[0] or 0

    total_hoje  = um("SELECT COUNT(*) FROM emissoes_senha WHERE DATE(data_hora) = %s", (hoje,))
    total_ontem = um("SELECT COUNT(*) FROM emissoes_senha WHERE DATE(data_hora) = %s", (ontem,))
    visit_hoje  = um("SELECT COUNT(*) FROM emissoes_senha WHERE DATE(data_hora) = %s AND cargo = 'VISITANTE'", (hoje,))
    total_mes   = um("SELECT COUNT(*) FROM emissoes_senha WHERE DATE(data_hora) BETWEEN %s AND %s", (inicio_mes, hoje))
    total_mes_ant_parcial = um("SELECT COUNT(*) FROM emissoes_senha WHERE DATE(data_hora) BETWEEN %s AND %s",
                               (inicio_mes_ant, corte_mes_ant))
    media_30 = um("""SELECT COUNT(*) / 30 FROM emissoes_senha
                     WHERE DATE(data_hora) BETWEEN %s AND %s""",
                  (hoje - timedelta(days=30), ontem))
    media_30 = int(round(float(media_30)))

    # Turnos: hoje e mês corrente
    cur.execute(f"SELECT {case_turnos} FROM emissoes_senha WHERE DATE(data_hora) = %s", (hoje,))
    turnos_hoje = dict(zip(faixas.keys(), [int(v or 0) for v in cur.fetchone()]))
    cur.execute(f"SELECT {case_turnos} FROM emissoes_senha WHERE DATE(data_hora) BETWEEN %s AND %s",
                (inicio_mes, hoje))
    turnos_mes = dict(zip(faixas.keys(), [int(v or 0) for v in cur.fetchone()]))

    # Série dos últimos 14 dias (mini gráfico)
    cur.execute("""SELECT DATE(data_hora), COUNT(*) FROM emissoes_senha
                   WHERE DATE(data_hora) BETWEEN %s AND %s GROUP BY DATE(data_hora)""",
                (hoje - timedelta(days=13), hoje))
    mapa = {r[0]: r[1] for r in cur.fetchall()}
    serie_14 = [{'dia': (hoje - timedelta(days=i)).strftime('%d/%m'),
                 'valor': mapa.get(hoje - timedelta(days=i), 0)} for i in range(13, -1, -1)]

    # Top departamentos do mês
    cur.execute("""SELECT departamento, COUNT(*) FROM emissoes_senha
                   WHERE DATE(data_hora) BETWEEN %s AND %s
                   GROUP BY departamento ORDER BY 2 DESC LIMIT 6""", (inicio_mes, hoje))
    top_deps = [{'nome': r[0], 'total': r[1]} for r in cur.fetchall()]

    # Últimas emissões
    cur.execute("""SELECT nome, departamento, cargo, data_hora, numero_senha, tipo_refeicao
                   FROM emissoes_senha ORDER BY id DESC LIMIT 8""")
    ultimas = [{'nome': r[0], 'departamento': r[1], 'visitante': r[2] == 'VISITANTE',
                'hora': r[3].strftime('%d/%m %H:%M') if r[3] else '', 'numero': r[4],
                'tipo': r[5]} for r in cur.fetchall()]
    # Cardápio ativo de hoje
    cur.execute("""SELECT tipo_refeicao, descricao FROM cardapios
                   WHERE ativo = 1 AND data_cardapio = %s
                   ORDER BY FIELD(tipo_refeicao,'Café da Manhã','Almoço','Jantar')""", (hoje,))
    cardapio_hoje = [{'tipo': r[0], 'descricao': (r[1] or '').strip().split('\n')[0].strip()}
                     for r in cur.fetchall()]
    custos = get_custos_refeicao()

    def custo_colab(ini, fim):
        cur.execute(f"SELECT {case_turnos} FROM emissoes_senha WHERE DATE(data_hora) BETWEEN %s AND %s", (ini, fim))
        cont = dict(zip(faixas.keys(), [int(v or 0) for v in cur.fetchone()]))
        return float(sum(cont[k] * custos.get(k, {}).get('custo_unitario', 0) for k in cont))

    def custo_pacientes(ini, fim):
        # mesmo critério do relatório financeiro da dispensa: só itens entregues,
        # valor congelado na entrega, pela data da prescrição
        try:
            return float(um("""SELECT SUM(i.valor_unitario) FROM dispensa_itens i
                              JOIN dispensa_pacientes p ON p.id = i.paciente_id
                              WHERE i.status = 'entregue' AND p.data_prescricao BETWEEN %s AND %s""",
                           (ini, fim)))
        except Exception:
            return 0.0

    # Refeições de pacientes do dia (pela data da prescrição)
    pac_hoje = {'liberadas': 0, 'previstas': 0, 'pendentes': 0, 'ontem': 0}
    try:
        cur.execute("""SELECT p.data_prescricao,
                                SUM(i.status = 'entregue'), COUNT(*), SUM(i.status = 'pendente')
                         FROM dispensa_itens i JOIN dispensa_pacientes p ON p.id = i.paciente_id
                         WHERE p.data_prescricao IN (%s, %s) GROUP BY p.data_prescricao""", (hoje, ontem))
        for dt, entregues, total, pend in cur.fetchall():
            if dt == hoje:
                pac_hoje.update(liberadas=int(entregues or 0), previstas=int(total or 0), pendentes=int(pend or 0))
            else:
                pac_hoje['ontem'] = int(entregues or 0)
    except Exception:
        pass
    pac_hoje['var'] = _variacao_pct(pac_hoje['liberadas'], pac_hoje['ontem'])

    inicio_semana = hoje - timedelta(days=hoje.weekday())   # segunda-feira
    periodos = {'dia': (hoje, hoje), 'semana': (inicio_semana, hoje), 'mes': (inicio_mes, hoje)}
    custos_periodo = {}
    for chave, (ini, fim) in periodos.items():
        c, p = custo_colab(ini, fim), custo_pacientes(ini, fim)
        custos_periodo[chave] = {'colab': c, 'pacientes': p, 'total': c + p,
                                 'faixa': hoje.strftime('%d/%m') if ini == fim
                                          else f"{ini.strftime('%d/%m')} a {fim.strftime('%d/%m')}"}
    cur.close()
    custo_mes = custos_periodo['mes']['colab']
    custo_hoje = custos_periodo['dia']['colab']

    max_serie = max([d['valor'] for d in serie_14] + [1])
    for d in serie_14:
        d['nivel'] = round(d['valor'] * 6 / max_serie) if d['valor'] else 0

    return {
        'hoje_str':        hoje.strftime('%d/%m/%Y'),
        'total_hoje':      total_hoje,
        'total_ontem':     total_ontem,
        'var_hoje':        _variacao_pct(total_hoje, total_ontem),
        'colab_hoje':      total_hoje - visit_hoje,
        'visit_hoje':      visit_hoje,
        'total_mes':       total_mes,
        'var_mes':         _variacao_pct(total_mes, total_mes_ant_parcial),
        'media_30':        media_30,
        'meta_pct':        min(round(total_hoje * 100 / media_30), 100) if media_30 else 0,
        'turnos_hoje':     turnos_hoje,
        'turnos_mes':      turnos_mes,
        'custo_mes':       custo_mes,
        'custo_hoje':      custo_hoje,
        'custos_periodo':  custos_periodo,
        'pac_hoje':        pac_hoje,
        'serie_14':        serie_14,
        'top_deps':        top_deps,
        'top_deps_max':    max([d['total'] for d in top_deps] + [1]),
        'ultimas':         ultimas,
        'cardapio_hoje':   cardapio_hoje,
    }


def moeda_br(valor):
    s = f"{valor:,.2f}"
    return s.replace(',', 'X').replace('.', ',').replace('X', '.')

app.jinja_env.filters['moeda_br'] = moeda_br
app.jinja_env.filters['milhar_br'] = lambda v: f"{int(v):,}".replace(',', '.')


config_pdf = pdfkit.configuration(wkhtmltopdf='/usr/bin/wkhtmltopdf')


PDF_LINHAS_WEASYPRINT = 2000   # acima disso (relatórios enormes) usa o modo híbrido, que é ~7x mais rápido


def gerar_pdf(html):
    """Gera o PDF de qualquer relatório do GTR com cabeçalho e rodapé padrão em todas as páginas
    e "Página X de Y" (ver templates/_relatorio_padrao.html).
    Até PDF_LINHAS_WEASYPRINT linhas de tabela: WeasyPrint puro (repete os títulos das colunas em cada página).
    Acima disso, híbrido por desempenho: o conteúdo é diagramado pelo wkhtmltopdf (rápido mesmo com milhares de
    linhas, mas o Qt instalado não suporta cabeçalho/rodapé nem repete títulos de coluna) e o cabeçalho/rodapé de
    cada página é gerado pelo WeasyPrint e sobreposto página a página (pypdf). Em ambos, linha de tabela não se parte."""
    import re, weasyprint
    from pypdf import PdfReader, PdfWriter
    m_pag = re.search(r'<!--GTR-PAGINA-INI (\w+)-->(.*?)<!--GTR-PAGINA-FIM-->', html, re.S)
    m_cab = re.search(r'<!--GTR-CAB-INI-->(.*?)<!--GTR-CAB-FIM-->', html, re.S)
    if not (m_pag and m_cab):   # relatório sem o padrão: só o conteúdo
        return pdfkit.from_string(html, False, configuration=config_pdf, options={'encoding': 'UTF-8', 'quiet': ''})
    if html.count('<tr') <= PDF_LINHAS_WEASYPRINT:
        # caso normal: tudo no WeasyPrint (cabeçalho/rodapé nativos e títulos das colunas repetidos em cada página)
        return weasyprint.HTML(string=html, base_url=app.root_path).write_pdf()
    orient = 'Landscape' if m_pag.group(1) == 'landscape' else 'Portrait'
    corpo = html.replace(m_pag.group(0), '').replace(m_cab.group(0), '')
    pdf_corpo = pdfkit.from_string(corpo, False, configuration=config_pdf, options={
        'encoding': 'UTF-8', 'quiet': '', 'page-size': 'A4', 'orientation': orient,
        'margin-top': '30mm', 'margin-bottom': '17mm', 'margin-left': '11mm', 'margin-right': '11mm'})
    leitor = PdfReader(BytesIO(pdf_corpo))
    n = len(leitor.pages)
    moldura = ('<!DOCTYPE html><html><head><meta charset="UTF-8">' + m_pag.group(2) + '</head><body>'
               + m_cab.group(1) + '<div></div>' + '<div style="break-before: page"></div>' * (n - 1) + '</body></html>')
    paginas = PdfReader(BytesIO(weasyprint.HTML(string=moldura, base_url=app.root_path).write_pdf())).pages
    saida = PdfWriter()
    for i, pag in enumerate(leitor.pages):
        if i < len(paginas):
            pag.merge_page(paginas[i])
        saida.add_page(pag)
    buf = BytesIO()
    saida.write(buf)
    return buf.getvalue()


app.jinja_env.globals['relatorio_emitido_em'] = lambda: datetime.now().strftime('%d/%m/%Y %H:%M')
app.jinja_env.globals['usuario_relatorio'] = lambda: (get_usuario_logado() if has_request_context() else '') or '—'

# ─── GRUPOS ───────────────────────────────────────────────────────────────────

_GRUPOS_PADRAO = ['Produtivos', 'Auxiliares', 'Administrativos', 'Não Operacional']

def init_grupos_table():
    cur = mysql.connection.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS grupos (
            id   INT AUTO_INCREMENT PRIMARY KEY,
            nome VARCHAR(100) NOT NULL UNIQUE
        )
    """)
    cur.execute("SELECT COUNT(*) FROM grupos")
    if cur.fetchone()[0] == 0:
        for nome in _GRUPOS_PADRAO:
            try:
                cur.execute("INSERT INTO grupos (nome) VALUES (%s)", (nome,))
            except Exception:
                pass
    mysql.connection.commit()
    cur.close()

def get_grupos():
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, nome FROM grupos ORDER BY id")
    grupos = cur.fetchall()
    cur.close()
    return grupos

# ─── HISTÓRICO DE CUSTOS ──────────────────────────────────────────────────────

def init_custos_historico_table():
    cur = mysql.connection.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS custos_historico (
            id             INT AUTO_INCREMENT PRIMARY KEY,
            tipo_refeicao  VARCHAR(20)   NOT NULL,
            descricao      VARCHAR(100),
            custo_unitario DECIMAL(10,2) NOT NULL,
            vigente_desde  DATETIME      NOT NULL,
            alterado_por   VARCHAR(100)
        )
    """)
    cur.execute("SELECT COUNT(*) FROM custos_historico")
    if cur.fetchone()[0] == 0:
        cur.execute("SELECT tipo_refeicao, descricao, custo_unitario FROM custos_refeicao")
        for tipo, desc, custo in cur.fetchall():
            if custo and float(custo) > 0:
                cur.execute("""
                    INSERT INTO custos_historico
                        (tipo_refeicao, descricao, custo_unitario, vigente_desde, alterado_por)
                    VALUES (%s, %s, %s, NOW(), %s)
                """, (tipo, desc, custo, 'sistema (registro inicial)'))
    mysql.connection.commit()
    cur.close()


def get_custos_na_data(data_ref):
    """Retorna {tipo: {descricao, custo_unitario, ativo}} com o custo vigente na data_ref."""
    try:
        cur = mysql.connection.cursor()
        result = {}
        for tipo in ['cafe', 'almoco', 'janta']:
            cur.execute("""
                SELECT custo_unitario, descricao
                FROM custos_historico
                WHERE tipo_refeicao = %s AND vigente_desde <= %s
                ORDER BY vigente_desde DESC
                LIMIT 1
            """, (tipo, data_ref))
            row = cur.fetchone()
            if row:
                result[tipo] = {'custo_unitario': float(row[0]), 'descricao': row[1], 'ativo': True}
        cur.close()
        if result:
            return result
    except Exception:
        pass
    return get_custos_refeicao()

app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST') or 'localhost'
app.config['MYSQL_PORT'] = int(os.getenv('MYSQL_PORT') or 3306)
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER') or 'gtruser'
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD') or ''
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB') or 'gtr'
if not app.config['MYSQL_PASSWORD']:
    raise RuntimeError("MYSQL_PASSWORD não definida. Copie .env.example para .env e preencha os dados do banco.")
# endereço HTTPS do GTR nesta unidade (o totem de dispensa indica quando a câmera exige conexão segura)
app.jinja_env.globals['gtr_url_https'] = (os.getenv('GTR_URL_HTTPS') or '').rstrip('/')
mysql = MySQL(app)


from contextlib import contextmanager


@contextmanager
def trava_emissao():
    """Uma emissão de senha por vez (vale para todos os workers do gunicorn).
    Evita que dois pedidos simultâneos (clique duplo) passem juntos pela checagem do limite
    e gravem senhas em dobro ou com o mesmo número. Rende True se conseguiu a trava.
    Usa cursor próprio: a rota pode fechar o dela antes de sair do bloco."""
    nome = f"gtr_emissao_senha_{app.config['MYSQL_DB']}"   # o servidor MySQL é compartilhado entre bancos
    cur = mysql.connection.cursor()
    cur.execute("SELECT GET_LOCK(%s, 10)", (nome,))
    ok = (cur.fetchone() or [0])[0] == 1
    # encerra a transação aberta: as consultas seguintes enxergam o que outro worker acabou de gravar
    mysql.connection.commit()
    try:
        yield ok
    finally:
        if ok:
            cur.execute("SELECT RELEASE_LOCK(%s)", (nome,))
            cur.fetchall()
        cur.close()

##################################APP##################################

@app.route('/favicon.ico')
def favicon():
    return app.send_static_file('favicon.ico')


@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        init_perfis()
        init_seguranca()
        usuario = request.form.get('usuario', '')
        senha = request.form.get('senha', '')
        login_norm, ip = _login_normalizado(usuario), _ip_cliente()
        bloqueio = _bloqueio_ativo(login_norm, ip)
        if bloqueio:
            # bloqueado: a senha nem é conferida (nem a certa libera antes do prazo)
            _registrar_tentativa(login_norm, ip, False, 'bloqueado')
            auditar(usuario=login_norm, alvo=login_norm, resultado='negado', motivo=f'{bloqueio[0]} bloqueado')
            logger.warning(f"Login barrado: {bloqueio[0]} bloqueado (usuário '{login_norm}', IP {ip}).")
            flash(_msg_bloqueio(bloqueio[1]))
            return render_template('login.html', nome_instituicao=get_instituicao())
        cur = mysql.connection.cursor()
        cur.execute("""SELECT id, nome, senha, perfil, perfil_id, trocar_senha, COALESCE(senha_alterada_em, criado_em), usuario
                       FROM usuarios WHERE usuario = %s AND status = TRUE""", (usuario,))
        logger.info(f"Consultando se o {usuario} existe no banco de dados...")
        usuario_db = cur.fetchone()
        cur.close()
        if usuario_db:
            id, nome, senha_armazenada, perfil, perfil_id, trocar_flag, alterada_em, login_db = usuario_db
            # só hash: senhas legadas em texto puro já foram convertidas (init_politica_senha)
            if _eh_hash(senha_armazenada):
                senha_ok = check_password_hash(senha_armazenada, senha)
            else:
                logger.error(f"Usuário '{usuario}' com senha fora do formato de hash: login recusado.")
                check_password_hash(_HASH_FANTASMA, senha)
                senha_ok = False
        else:
            check_password_hash(_HASH_FANTASMA, senha)   # mesmo tempo de resposta de um usuário que existe
            senha_ok = False
        if senha_ok:
            _registrar_tentativa(login_norm, ip, True, 'ok')
            auditar(alvo=login_norm, resultado='ok')
            perfil_obj = _carregar_perfil(perfil_id) if perfil_id else None
            if not perfil_obj or not perfil_obj['ativo']:
                logger.info(f"{usuario}: login recusado (perfil inexistente ou inativo).")
                flash("Seu perfil de acesso está inativo ou não foi definido. Procure o administrador.")
                return render_template('login.html', nome_instituicao=get_instituicao())
            session.clear()
            session.update({'usuario_id': id, 'usuario_nome': nome, 'usuario_perfil': perfil_obj['chave'] or perfil,
                            'perfil_id': perfil_obj['id'], 'ult': time_mod.time()})
            g.pop('perfil', None)
            g.setdefault('audit', {})['quem'] = _audit_sessao()   # quem entrou
            logger.info(f"{usuario} logou com sucesso! (perfil {perfil_obj['nome']})")
            motivo = _motivo_troca(trocar_flag, senha, login_db, alterada_em)
            if motivo:
                session['trocar_senha'] = motivo
                auditar(detalhes={'troca_obrigatoria': motivo})
                logger.info(f"{usuario}: troca de senha obrigatória (motivo: {motivo}).")
                return redirect(url_for('minha_senha'))
            return redirect(pagina_inicial() or url_for('inicio_perfil'))
        else:
            logger.info(f"Login sem sucesso: usuário '{login_norm}', IP {ip}.")
            bloqueou, restantes = _registrar_falha(login_norm, ip)
            auditar(usuario=login_norm, alvo=login_norm, resultado='erro',
                    motivo='usuário ou senha incorretos' + ('; acesso bloqueado' if bloqueou else ''))
            if bloqueou:
                flash(_msg_bloqueio(seg_params()['seg_login_bloqueio_min']))
            elif restantes <= 2:
                flash(f"Usuário ou senha incorretos. Restam {restantes} tentativa{'s' if restantes != 1 else ''} "
                      f"antes do bloqueio temporário do acesso.")
            else:
                flash("Usuário ou senha incorretos.")
    return render_template('login.html', nome_instituicao=get_instituicao())


@app.route('/admin')
def admin():
    if 'usuario_id' not in session:
        return redirect('/')
    if requer_admin():
        flash("Acesso restrito a administradores.", "error")
        return redirect('/usuario')
    usuario_logado = get_usuario_logado()
    dashboard_data = get_dashboard_data()
    dash = get_dashboard_extras()
    return render_template('menu_admin.html', module=None, usuario=usuario_logado,
                           dashboard_data=dashboard_data, dash=dash,
                           nome_instituicao=get_instituicao())


@app.route('/usuario')
def usuario():
    """Endereço antigo do painel do perfil "usuário": agora todos usam o painel novo."""
    if 'usuario_id' not in session:
        return redirect('/')
    return redirect(pagina_inicial() or url_for('inicio_perfil'))


@app.route('/emissao_senha', methods=['GET', 'POST'])
def emissao_senha():
    return render_template('emissao_senha.html', tipo_senha='menu')


@app.route('/emissao_senha_tablet', methods=['GET', 'POST'])
def emissao_senha_tablet():
    return render_template('emissao_senha_tablet.html', tipo_senha='menu')


# ─── COLABORADORES ────────────────────────────────────────────────────────────

@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if 'usuario_id' not in session:
        return redirect('/')

    perfil = session.get('usuario_perfil', '')

    if request.method == 'POST' and requer_admin():
        flash("Acesso restrito a administradores.", "error")
        return redirect('/usuario')

    usuario_logado = get_usuario_logado()
    logger.info(f"{usuario_logado} acessou a tela de cadastro de colaborador")

    search = request.args.get('search', '').strip()
    filtro_escala = request.args.get('escala', '').strip()      # '' = todas | 'sem' | id
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page

    init_escalas()
    cur = mysql.connection.cursor()

    where, params = ["1=1"], []
    if search:
        logger.info(f"{usuario_logado} pesquisou colaborador: '{search}'")
        where.append("(c.nome LIKE %s OR c.cpf LIKE %s)"); params += [f"%{search}%", f"%{search}%"]
    if filtro_escala == 'sem':
        where.append("c.escala_id IS NULL")
    elif filtro_escala.isdigit():
        where.append("c.escala_id = %s"); params.append(int(filtro_escala))
    sql_where = " AND ".join(where)
    cur.execute(f"SELECT COUNT(*) FROM colaboradores c WHERE {sql_where}", params)

    total_colaboradores = cur.fetchone()[0]
    total_pages = max((total_colaboradores + per_page - 1) // per_page, 1)

    # (id, nome, cpf, cargo, departamento, tipo antigo, escala_id, nome da escala)
    cur.execute(f"""SELECT c.id, c.nome, c.cpf, c.cargo, c.departamento, c.tipo, c.escala_id, e.nome
                    FROM colaboradores c LEFT JOIN escalas e ON e.id = c.escala_id
                    WHERE {sql_where} ORDER BY c.nome LIMIT %s OFFSET %s""", params + [per_page, offset])

    colaboradores = cur.fetchall()
    cur.execute("SELECT COUNT(*) FROM colaboradores WHERE escala_id IS NULL")
    sem_escala = cur.fetchone()[0]
    cur.execute("SELECT nome FROM departamentos ORDER BY nome")
    departamentos = [row[0] for row in cur.fetchall()]
    cur.close()

    if request.method == 'POST':
        nome = request.form['nome'].strip().upper()
        cpf = request.form['cpf'].strip()
        cargo = request.form['cargo'].strip().upper()
        departamento = request.form['departamento'].strip()
        escala_id = request.form.get('escala_id', type=int)

        if not all([nome, cpf, cargo, departamento, escala_id]):
            flash("Todos os campos são obrigatórios.", "error")
            return redirect(url_for('cadastro'))
        if not validar_cpf(cpf):
            flash("CPF inválido. Verifique os dígitos.", "error")
            return redirect(url_for('cadastro'))

        cur = mysql.connection.cursor()
        cur.execute("SELECT id FROM colaboradores WHERE cpf = %s", (cpf,))
        if cur.fetchone():
            flash("Esse CPF já está cadastrado.", "error")
            cur.close()
            return redirect(url_for('cadastro'))

        try:
            cur.execute("INSERT INTO colaboradores (nome, cpf, cargo, departamento, tipo, escala_id) "
                        "VALUES (%s,%s,%s,%s,1,%s)", (nome, cpf, cargo, departamento, escala_id))
            mysql.connection.commit()
            logger.info(f"{usuario_logado} cadastrou colaborador {nome}.")
            flash("Colaborador cadastrado com sucesso!", "success")
        except Exception as e:
            mysql.connection.rollback()
            flash(f"Erro ao cadastrar colaborador: {str(e)}", "error")
        finally:
            cur.close()
        return redirect(url_for('cadastro'))

    tmpl = 'menu_admin.html'
    return render_template(tmpl, colaboradores=colaboradores, departamentos=departamentos,
                           page=page, total_pages=total_pages, search=search,
                           escalas=listar_escalas(), filtro_escala=filtro_escala, sem_escala=sem_escala,
                           module='cadastro', usuario=usuario_logado)


@app.route('/editar_colaborador/<int:colaborador_id>', methods=['POST'])
def editar_colaborador(colaborador_id):
    if 'usuario_id' not in session or requer_admin():
        return redirect('/')
    usuario_logado = get_usuario_logado()
    nome = request.form['nome'].strip().upper()
    cargo = request.form['cargo'].strip().upper()
    departamento = request.form['departamento'].strip()
    escala_id = request.form.get('escala_id', type=int)
    if not escala_id:
        flash("Selecione a escala do colaborador.", "error")
        return redirect(url_for('cadastro'))
    try:
        cur = mysql.connection.cursor()
        cur.execute("UPDATE colaboradores SET nome=%s, cargo=%s, departamento=%s, escala_id=%s WHERE id=%s",
                    (nome, cargo, departamento, escala_id, colaborador_id))
        mysql.connection.commit()
        cur.close()
        logger.info(f"{usuario_logado} editou colaborador ID {colaborador_id}.")
        flash("Colaborador atualizado com sucesso!", "success")
    except Exception as e:
        mysql.connection.rollback()
        flash("Erro ao atualizar colaborador.", "error")
    return redirect(url_for('cadastro'))


@app.route('/excluir_colaborador/<int:colaborador_id>', methods=['POST'])
def excluir_colaborador(colaborador_id):
    if 'usuario_id' not in session or requer_admin():
        return redirect('/')
    usuario_logado = get_usuario_logado()
    try:
        cur = mysql.connection.cursor()
        cur.execute("DELETE FROM colaboradores WHERE id = %s", (colaborador_id,))
        mysql.connection.commit()
        cur.close()
        logger.info(f"{usuario_logado} excluiu colaborador ID {colaborador_id}")
        flash("Colaborador excluído com sucesso.", "success")
    except Exception as e:
        mysql.connection.rollback()
        flash("Erro ao excluir colaborador.", "error")
    return redirect(url_for('cadastro'))


# ─── ESCALAS DE TRABALHO (direito a refeição do colaborador) ─────────────────
# Cada escala diz quantas senhas de cada refeição o colaborador pode emitir por dia
# (0 = sem direito) e, opcionalmente, um máximo no dia. Colaborador sem escala segue
# a regra antiga ("refeições por dia", coluna colaboradores.tipo) até receber uma.

REFEICOES_COLAB = [('cafe', 'Café da manhã', 'fa-mug-hot'), ('almoco', 'Almoço', 'fa-utensils'),
                   ('janta', 'Jantar', 'fa-moon')]
REFEICAO_NOME = {k: n for k, n, _ in REFEICOES_COLAB}
_CARDAPIO_PARA_REFEICAO = {'CAFÉ DA MANHÃ': 'cafe', 'ALMOÇO': 'almoco', 'JANTAR': 'janta'}
ESCALA_QTD_MAX = 3
_ESCALAS_PADRAO = [   # nome, café, almoço, jantar  (pedido da direção, 06/11/2026)
    ('12h diurno (12x36 / 12x60)',  1, 1, 0),
    ('12h noturno (12x36 / 12x60)', 1, 0, 1),
    ('8h (Seg a Sex)',              0, 1, 0),
    ('9h (Seg a Qui)',              0, 1, 0),
    ('6h (Seg a Sex / Seg a Sáb)',  0, 0, 0),
]
_escalas_ok = False


def init_escalas():
    global _escalas_ok
    if _escalas_ok:
        return
    cur = mysql.connection.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS escalas (
            id         INT AUTO_INCREMENT PRIMARY KEY,
            nome       VARCHAR(80) NOT NULL,
            cafe       TINYINT UNSIGNED NOT NULL DEFAULT 0 COMMENT 'Senhas de café por dia (0 = sem direito)',
            almoco     TINYINT UNSIGNED NOT NULL DEFAULT 0,
            janta      TINYINT UNSIGNED NOT NULL DEFAULT 0,
            max_dia    TINYINT UNSIGNED DEFAULT NULL COMMENT 'Máximo de senhas no dia; NULL = soma das refeições',
            criado_em  TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uk_escala_nome (nome)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    """)
    cur.execute("ALTER TABLE colaboradores ADD COLUMN IF NOT EXISTS escala_id INT DEFAULT NULL "
                "COMMENT 'Escala de trabalho; NULL = regra antiga (coluna tipo)'")
    cur.execute("SELECT COUNT(*) FROM escalas")
    if cur.fetchone()[0] == 0:
        for nome, c, a, j in _ESCALAS_PADRAO:
            cur.execute("INSERT INTO escalas (nome, cafe, almoco, janta) VALUES (%s,%s,%s,%s)", (nome, c, a, j))
    mysql.connection.commit()
    cur.close()
    _escalas_ok = True


def listar_escalas(com_contagem=False):
    init_escalas()
    cur = mysql.connection.cursor()
    cur.execute("""SELECT e.id, e.nome, e.cafe, e.almoco, e.janta, e.max_dia,
                          (SELECT COUNT(*) FROM colaboradores c WHERE c.escala_id = e.id)
                   FROM escalas e ORDER BY e.nome""")
    lista = []
    for r in cur.fetchall():
        e = {'id': r[0], 'nome': r[1], 'cafe': r[2], 'almoco': r[3], 'janta': r[4], 'max_dia': r[5],
             'colaboradores': r[6]}
        e['soma'] = e['cafe'] + e['almoco'] + e['janta']
        e['limite_dia'] = min(e['max_dia'], e['soma']) if e['max_dia'] is not None else e['soma']
        e['resumo'] = ', '.join((REFEICAO_NOME[k] if e[k] == 1 else f"{e[k]}× {REFEICAO_NOME[k]}")
                                for k in ('cafe', 'almoco', 'janta') if e[k]) or 'Sem direito a refeição'
        lista.append(e)
    cur.close()
    return lista


def classificar_refeicao(h, t):
    """REGRA ÚNICA de classificação de uma senha pelo horário (emissão, relatórios e painel).
    Café e almoço pelos Horários de turno, com o minuto final inteiro (até :59 s);
    qualquer outro horário — jantar, madrugada ou fora de turno — conta como Jantar."""
    if t['turno_cafe_ini'] <= h <= t['turno_cafe_fim'].replace(second=59, microsecond=999999):
        return 'cafe'
    if t['turno_almoco_ini'] <= h <= t['turno_almoco_fim'].replace(second=59, microsecond=999999):
        return 'almoco'
    return 'janta'


def sql_refeicao(t, coluna='data_hora'):
    """A mesma regra de classificar_refeicao em SQL: expressão que vale 'cafe' | 'almoco' | 'janta'.
    Os horários vêm de get_turnos() (objetos time), então o texto montado é seguro."""
    f = lambda k, seg: t[k].strftime('%H:%M:') + seg
    return (f"(CASE WHEN TIME({coluna}) BETWEEN '{f('turno_cafe_ini', '00')}' AND '{f('turno_cafe_fim', '59')}' THEN 'cafe' "
            f"WHEN TIME({coluna}) BETWEEN '{f('turno_almoco_ini', '00')}' AND '{f('turno_almoco_fim', '59')}' THEN 'almoco' "
            f"ELSE 'janta' END)")


def refeicao_por_horario(momento=None):
    """Refeição do horário (ver classificar_refeicao)."""
    return classificar_refeicao((momento or datetime.now()).time(), get_turnos())


def refeicao_do_cardapio(tipo_refeicao):
    """'Almoço' -> 'almoco' (None para tipos fora de café/almoço/jantar)."""
    return _CARDAPIO_PARA_REFEICAO.get((tipo_refeicao or '').strip().upper())


def cardapios_do_horario(cur):
    """Modo com cardápio: só os cardápios ativos de hoje da refeição do horário atual.
    Assim a refeição escolhida no totem é sempre a mesma que os relatórios vão contar."""
    agora = refeicao_por_horario()
    cur.execute("""SELECT id, tipo_refeicao, descricao, foto FROM cardapios
                   WHERE ativo = 1 AND data_cardapio = CURDATE()
                   ORDER BY FIELD(tipo_refeicao,'Café da Manhã','Almoço','Jantar'), id""")
    return [{'id': r[0], 'tipo_refeicao': r[1], 'descricao': r[2], 'foto': r[3]}
            for r in cur.fetchall() if refeicao_do_cardapio(r[1]) == agora]


app.jinja_env.globals['refeicao_agora'] = lambda: REFEICAO_NOME[refeicao_por_horario()]


def msg_cardapio_fora_do_horario():
    return (f"Este cardápio não é o da refeição deste horário (agora: {REFEICAO_NOME[refeicao_por_horario()]}). "
            "Escolha de novo.")


def checar_direito_refeicao(cur, cpf, escala_id, limite_antigo, refeicao):
    """Confere se o colaborador pode emitir a senha desta refeição hoje.
    Retorna None se pode, ou a mensagem para o totem. Chamar DENTRO de trava_emissao()."""
    hoje = date.today()
    cur.execute("SELECT data_hora, tipo_refeicao FROM emissoes_senha WHERE cpf=%s AND DATE(data_hora)=%s",
                (cpf, hoje))
    emitidas = cur.fetchall()
    if not escala_id:                                   # regra antiga: só a quantidade no dia
        if len(emitidas) >= (limite_antigo or 1):
            return "Você atingiu o limite diário de emissões."
        return None
    cur.execute("SELECT nome, cafe, almoco, janta, max_dia FROM escalas WHERE id=%s", (escala_id,))
    e = cur.fetchone()
    if not e:
        return "Sua escala de trabalho não foi encontrada. Procure o administrador."
    nome, qtd = e[0], {'cafe': e[1], 'almoco': e[2], 'janta': e[3]}
    limite_dia = sum(qtd.values()) if e[4] is None else min(e[4], sum(qtd.values()))
    rotulo = REFEICAO_NOME[refeicao]
    if limite_dia == 0:
        return f"A escala {nome} não dá direito a refeição."
    if qtd[refeicao] == 0:
        return f"A escala {nome} não dá direito ao {rotulo.lower()}."
    t = get_turnos()
    desta = sum(1 for dh, _tr in emitidas if classificar_refeicao(dh.time(), t) == refeicao)
    if desta >= qtd[refeicao]:
        return (f"Você já emitiu a senha do {rotulo.lower()} hoje." if qtd[refeicao] == 1
                else f"Você já emitiu as {qtd[refeicao]} senhas de {rotulo.lower()} de hoje.")
    if len(emitidas) >= limite_dia:
        return f"Você atingiu o limite de {limite_dia} refeição(ões) por dia da sua escala."
    return None


def _ler_escala_form(prefixo=''):
    """Lê nome/quantidades/máximo do formulário. Retorna (dados, erro)."""
    nome = ' '.join((request.form.get(prefixo + 'nome') or '').split())
    if not nome or len(nome) > 80:
        return None, "Informe o nome da escala (até 80 caracteres)."
    dados = {'nome': nome}
    try:
        for k, _, _ in REFEICOES_COLAB:
            dados[k] = int(request.form.get(prefixo + k) or 0)
            if not 0 <= dados[k] <= ESCALA_QTD_MAX:
                raise ValueError
        m = (request.form.get(prefixo + 'max_dia') or '').strip()
        dados['max_dia'] = int(m) if m else None
        if dados['max_dia'] is not None and not 0 <= dados['max_dia'] <= ESCALA_QTD_MAX * 3:
            raise ValueError
    except ValueError:
        return None, "Quantidades inválidas."
    return dados, None


@app.route('/admin/escalas', methods=['GET', 'POST'])
def escalas():
    if 'usuario_id' not in session:
        return redirect('/')
    usuario_logado = get_usuario_logado()
    init_escalas()
    if request.method == 'POST':
        dados, erro = _ler_escala_form()
        if erro:
            flash(erro, "error")
            return redirect(url_for('escalas'))
        cur = mysql.connection.cursor()
        try:
            cur.execute("INSERT INTO escalas (nome, cafe, almoco, janta, max_dia) VALUES (%s,%s,%s,%s,%s)",
                        (dados['nome'], dados['cafe'], dados['almoco'], dados['janta'], dados['max_dia']))
            mysql.connection.commit()
            logger.info(f"{usuario_logado} cadastrou a escala {dados['nome']}.")
            flash(f"Escala \"{dados['nome']}\" cadastrada.", "success")
        except MySQLdb.IntegrityError:
            mysql.connection.rollback()
            flash("Já existe uma escala com esse nome.", "error")
        finally:
            cur.close()
        return redirect(url_for('escalas'))

    _limpar_previas(ESCALAS_TMP_FOLDER)
    lista = listar_escalas()
    editar = request.args.get('editar', type=int)
    cur = mysql.connection.cursor()
    cur.execute("SELECT COUNT(*) FROM colaboradores WHERE escala_id IS NULL")
    sem_escala = cur.fetchone()[0]
    cur.execute("""SELECT cargo, COUNT(*) FROM colaboradores WHERE escala_id IS NULL
                   GROUP BY cargo ORDER BY 2 DESC, cargo LIMIT 12""")
    sem_por_cargo = cur.fetchall()
    cur.execute("SELECT nome FROM departamentos ORDER BY nome")
    departamentos = [r[0] for r in cur.fetchall()]

    # Aplicar em lote — passo 1: filtro (GET) → lista para marcar quem recebe a escala
    lote = None
    if request.args.get('lote') == '1':
        dep = (request.args.get('lote_dep') or '').strip()
        cargo = ' '.join((request.args.get('lote_cargo') or '').split()).upper()
        so_sem = request.args.get('lote_sem') == '1'
        lote = {'departamento': dep, 'cargo': cargo, 'so_sem_escala': so_sem, 'linhas': [], 'erro': None}
        if not dep and not cargo:
            lote['erro'] = "Filtre por departamento e/ou cargo."
        else:
            where, params = ["1=1"], []
            if dep:
                where.append("c.departamento = %s"); params.append(dep)
            if cargo:
                where.append("UPPER(c.cargo) LIKE %s"); params.append(f"%{cargo}%")
            if so_sem:
                where.append("c.escala_id IS NULL")
            cur.execute(f"""SELECT c.id, c.nome, c.cargo, c.departamento, e.nome, c.escala_id
                            FROM colaboradores c LEFT JOIN escalas e ON e.id = c.escala_id
                            WHERE {' AND '.join(where)} ORDER BY c.cargo, c.nome""", params)
            lote['linhas'] = [{'id': r[0], 'nome': r[1], 'cargo': r[2], 'departamento': r[3],
                               'escala_atual': r[4]} for r in cur.fetchall()]
    cur.close()
    return render_template('menu_admin.html', module='escalas', usuario=usuario_logado,
                           escalas=lista, escala_edit=next((e for e in lista if e['id'] == editar), None),
                           sem_escala=sem_escala, sem_por_cargo=sem_por_cargo, departamentos=departamentos,
                           refeicoes_colab=REFEICOES_COLAB, qtd_max=ESCALA_QTD_MAX, lote=lote,
                           imp=_carregar_previa_escalas(request.args.get('imp')))


@app.route('/admin/escalas/<int:escala_id>/editar', methods=['POST'])
def escala_editar(escala_id):
    if 'usuario_id' not in session:
        return redirect('/')
    dados, erro = _ler_escala_form()
    if erro:
        flash(erro, "error")
        return redirect(url_for('escalas', editar=escala_id))
    cur = mysql.connection.cursor()
    try:
        cur.execute("UPDATE escalas SET nome=%s, cafe=%s, almoco=%s, janta=%s, max_dia=%s WHERE id=%s",
                    (dados['nome'], dados['cafe'], dados['almoco'], dados['janta'], dados['max_dia'], escala_id))
        mysql.connection.commit()
        logger.info(f"{get_usuario_logado()} alterou a escala {escala_id} ({dados['nome']}).")
        flash(f"Escala \"{dados['nome']}\" atualizada. A regra nova vale nas próximas emissões.", "success")
    except MySQLdb.IntegrityError:
        mysql.connection.rollback()
        flash("Já existe uma escala com esse nome.", "error")
        return redirect(url_for('escalas', editar=escala_id))
    finally:
        cur.close()
    return redirect(url_for('escalas'))


@app.route('/admin/escalas/<int:escala_id>/excluir', methods=['POST'])
def escala_excluir(escala_id):
    if 'usuario_id' not in session:
        return redirect('/')
    cur = mysql.connection.cursor()
    cur.execute("SELECT COUNT(*) FROM colaboradores WHERE escala_id=%s", (escala_id,))
    n = cur.fetchone()[0]
    if n:
        cur.close()
        flash(f"Esta escala tem {n} colaborador(es). Mude-os de escala antes de excluir.", "error")
        return redirect(url_for('escalas'))
    cur.execute("DELETE FROM escalas WHERE id=%s", (escala_id,))
    mysql.connection.commit()
    cur.close()
    logger.info(f"{get_usuario_logado()} excluiu a escala {escala_id}.")
    flash("Escala excluída.", "success")
    return redirect(url_for('escalas'))


@app.route('/admin/escalas/lote', methods=['POST'])
def escalas_lote():
    """Aplicar em lote — passo 2: grava a escala nos colaboradores marcados na lista."""
    if 'usuario_id' not in session:
        return redirect('/')
    init_escalas()
    escala_id = request.form.get('escala_id', type=int)
    volta = {k: request.form.get(k) or None for k in ('lote', 'lote_dep', 'lote_cargo', 'lote_sem')}
    ids = sorted({int(i) for i in request.form.getlist('colab_id') if i.isdigit()})
    cur = mysql.connection.cursor()
    cur.execute("SELECT nome FROM escalas WHERE id=%s", (escala_id,))
    r = cur.fetchone()
    if not r or not ids:
        cur.close()
        flash("Escolha a escala e marque ao menos um colaborador." if r else "Escolha a escala a aplicar.", "error")
        return redirect(url_for('escalas', **volta) + '#lote')
    nome_escala = r[0]
    fmt = ','.join(['%s'] * len(ids))
    cur.execute(f"SELECT id, nome FROM colaboradores WHERE id IN ({fmt}) AND (escala_id IS NULL OR escala_id <> %s)",
                ids + [escala_id])
    alvo = cur.fetchall()
    if alvo:
        fmt = ','.join(['%s'] * len(alvo))
        cur.execute(f"UPDATE colaboradores SET escala_id=%s WHERE id IN ({fmt})", [escala_id] + [a[0] for a in alvo])
        mysql.connection.commit()
    cur.close()
    auditar(alvo=nome_escala, detalhes={'colaboradores_alterados': len(alvo),
                                        'colaboradores': [a[1] for a in alvo][:200]})
    logger.info(f"{get_usuario_logado()} aplicou a escala {nome_escala} a {len(alvo)} colaborador(es) em lote.")
    flash(f"Escala \"{nome_escala}\" aplicada a {len(alvo)} colaborador(es).", "success")
    return redirect(url_for('escalas', **volta) + '#lote')


# ── Importação de escalas por CSV (RH) ──────────────────────────────────────
ESCALAS_TMP_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads', 'escalas_tmp')
ESCALAS_CSV_MAX_BYTES = 10 * 1024 * 1024   # 10 MB


def _so_digitos_cpf(v):
    d = ''.join(ch for ch in str(v or '') if ch.isdigit())
    return d.zfill(11) if 0 < len(d) <= 11 else d      # Excel costuma comer o zero da frente


@app.route('/admin/escalas/modelo.csv')
def escalas_modelo_csv():
    """Modelo para o RH: todos os colaboradores, já com a escala atual. Basta preencher a coluna escala."""
    if 'usuario_id' not in session:
        return redirect('/')
    init_escalas()
    cur = mysql.connection.cursor()
    cur.execute("""SELECT c.cpf, c.nome, c.cargo, c.departamento, e.nome
                   FROM colaboradores c LEFT JOIN escalas e ON e.id = c.escala_id
                   ORDER BY c.departamento, c.nome""")
    linhas = cur.fetchall()
    cur.close()
    out = StringIO()
    w = _csv.writer(out, delimiter=';', lineterminator='\r\n')
    w.writerow(['cpf', 'nome', 'cargo', 'departamento', 'escala'])
    for cpf, nome, cargo, dep, esc in linhas:
        w.writerow([cpf, nome, cargo or '', dep or '', esc or ''])
    auditar(forcar=True, detalhes={'colaboradores_no_modelo': len(linhas)})
    logger.info(f"{get_usuario_logado()} baixou o modelo de escalas ({len(linhas)} colaboradores).")
    return send_file(BytesIO(out.getvalue().encode('utf-8-sig')), mimetype='text/csv', as_attachment=True,
                     download_name=f"escalas_colaboradores_{date.today().strftime('%Y%m%d')}.csv")


def _ler_csv_escalas(conteudo):
    """Retorna (linhas, erro_geral). Cada linha: dict com status alterar|igual|vazio|erro."""
    texto = None
    for enc in ('utf-8-sig', 'cp1252', 'latin-1'):
        try:
            texto = conteudo.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    if not texto or not texto.strip():
        return [], "O arquivo está vazio ou não pôde ser lido."
    amostra = texto[:4096]
    try:
        sep = _csv.Sniffer().sniff(amostra, delimiters=';,\t').delimiter
    except _csv.Error:
        sep = max([';', ',', '\t'], key=lambda c: amostra.count(c))
    leitor = _csv.reader(StringIO(texto), delimiter=sep)
    cab = [_norm_col(c) for c in next(leitor, [])]
    if 'cpf' not in cab or 'escala' not in cab:
        return [], ("O arquivo precisa das colunas cpf e escala (use o modelo). "
                    f"Colunas encontradas: {', '.join(c for c in cab if c) or 'nenhuma'}.")
    i_cpf, i_esc = cab.index('cpf'), cab.index('escala')
    i_nome = cab.index('nome') if 'nome' in cab else None

    cur = mysql.connection.cursor()
    cur.execute("SELECT id, nome FROM escalas")
    escalas_map = {}
    for eid, enome in cur.fetchall():
        escalas_map[_norm_col(enome)] = (eid, enome)
        escalas_map[str(eid)] = (eid, enome)
    cur.execute("""SELECT c.id, c.cpf, c.nome, c.escala_id, e.nome FROM colaboradores c
                   LEFT JOIN escalas e ON e.id = c.escala_id""")
    colabs = {_so_digitos_cpf(r[1]): r for r in cur.fetchall()}
    cur.close()

    linhas, por_cpf = [], {}
    for n, row in enumerate(leitor, start=2):
        if not any((c or '').strip() for c in row):
            continue
        cel = lambda i: (row[i].strip() if i is not None and i < len(row) else '')
        cpf_txt, esc_txt = cel(i_cpf), ' '.join(cel(i_esc).split())
        l = {'linha': n, 'cpf': cpf_txt, 'nome': cel(i_nome), 'escala_atual': None, 'escala_nova': esc_txt,
             'escala_id': None, 'colab_id': None, 'status': 'erro', 'motivo': ''}
        dig = _so_digitos_cpf(cpf_txt)
        colab = colabs.get(dig)
        if not colab:     # o cadastro manda: CPF antigo com dígito errado mas cadastrado é aceito
            l['motivo'] = ('CPF não cadastrado em Colaboradores'
                           if len(dig) == 11 and validar_cpf(f"{dig[:3]}.{dig[3:6]}.{dig[6:9]}-{dig[9:]}")
                           else 'CPF inválido')
        else:
            l.update(colab_id=colab[0], nome=colab[2], escala_atual=colab[4])
            if not esc_txt:
                l.update(status='vazio', motivo='Escala em branco — mantém a atual')
            elif _norm_col(esc_txt) not in escalas_map:
                l['motivo'] = f'Escala "{esc_txt}" não existe'
            else:
                eid, enome = escalas_map[_norm_col(esc_txt)]
                l.update(escala_id=eid, escala_nova=enome)
                l.update(status='igual', motivo='Já está nesta escala') if colab[3] == eid else \
                    l.update(status='alterar', motivo='')
        if l['colab_id'] and l['status'] in ('alterar', 'igual'):
            ant = por_cpf.get(l['colab_id'])
            if ant and ant['escala_id'] != l['escala_id']:
                for x in (ant, l):
                    x.update(status='erro', motivo='CPF repetido no arquivo com escalas diferentes')
            elif ant:
                l.update(status='vazio', motivo=f"Repetido (igual à linha {ant['linha']})")
            else:
                por_cpf[l['colab_id']] = l
        linhas.append(l)
    if not linhas:
        return [], "O arquivo não tem nenhuma linha de colaborador."
    return linhas, None


@app.route('/admin/escalas/importar', methods=['POST'])
def escalas_importar():
    """Passo 1: lê o CSV e guarda uma prévia temporária. Nada é gravado nos colaboradores."""
    if 'usuario_id' not in session:
        return redirect('/')
    init_escalas()
    arq = request.files.get('arquivo_csv')
    if not arq or not arq.filename:
        flash("Escolha o arquivo CSV.", "error")
        return redirect(url_for('escalas') + '#importar')
    if not arq.filename.lower().endswith(('.csv', '.txt')):
        flash("Envie um arquivo .csv (no Excel: Salvar como › CSV).", "error")
        return redirect(url_for('escalas') + '#importar')
    conteudo = arq.read(ESCALAS_CSV_MAX_BYTES + 1)
    if len(conteudo) > ESCALAS_CSV_MAX_BYTES:
        flash(f"Arquivo grande demais (máximo {ESCALAS_CSV_MAX_BYTES // (1024 * 1024)} MB).", "error")
        return redirect(url_for('escalas') + '#importar')
    linhas, erro = _ler_csv_escalas(conteudo)
    if erro:
        flash(erro, "error")
        return redirect(url_for('escalas') + '#importar')
    os.makedirs(ESCALAS_TMP_FOLDER, exist_ok=True)
    agora_ts = datetime.now().timestamp()
    for f in os.listdir(ESCALAS_TMP_FOLDER):                 # prévias com mais de 2 h
        fp = os.path.join(ESCALAS_TMP_FOLDER, f)
        if f.endswith('.json') and agora_ts - os.path.getmtime(fp) > 7200:
            os.remove(fp)
    token = _uuid.uuid4().hex
    with open(os.path.join(ESCALAS_TMP_FOLDER, token + '.json'), 'w', encoding='utf-8') as f:
        _json.dump({'usuario_id': session.get('usuario_id'), 'arquivo': secure_filename(arq.filename) or 'arquivo.csv',
                    'linhas': linhas}, f, ensure_ascii=False)
    return redirect(url_for('escalas', imp=token) + '#importar')


def _carregar_previa_escalas(token):
    if not token or not _re.fullmatch(r'[0-9a-f]{32}', token):
        return None
    caminho = os.path.join(ESCALAS_TMP_FOLDER, token + '.json')
    if not os.path.exists(caminho):
        return None
    with open(caminho, encoding='utf-8') as f:
        dados = _json.load(f)
    if dados.get('usuario_id') != session.get('usuario_id'):   # prévia é de quem enviou
        return None
    dados['token'] = token
    cont = {'alterar': 0, 'igual': 0, 'vazio': 0, 'erro': 0}
    for l in dados['linhas']:
        cont[l['status']] += 1
    dados['cont'] = cont
    dados['total'] = len(dados['linhas'])
    return dados


@app.route('/admin/escalas/importar/confirmar', methods=['POST'])
def escalas_importar_confirmar():
    """Passo 2: grava as escalas das linhas 'alterar' da prévia."""
    if 'usuario_id' not in session:
        return redirect('/')
    token = request.form.get('token', '')
    dados = _carregar_previa_escalas(token)
    if not dados:
        flash("Prévia expirada. Envie o arquivo novamente.", "error")
        return redirect(url_for('escalas') + '#importar')
    alvo = [l for l in dados['linhas'] if l['status'] == 'alterar']
    cur = mysql.connection.cursor()
    cur.execute("SELECT id FROM escalas")
    validas = {r[0] for r in cur.fetchall()}
    feitos = 0
    for l in alvo:
        if l['escala_id'] in validas:
            cur.execute("UPDATE colaboradores SET escala_id=%s WHERE id=%s", (l['escala_id'], l['colab_id']))
            feitos += cur.rowcount
    mysql.connection.commit()
    cur.close()
    os.remove(os.path.join(ESCALAS_TMP_FOLDER, token + '.json'))
    resumo = {}
    for l in alvo:
        resumo[l['escala_nova']] = resumo.get(l['escala_nova'], 0) + 1
    auditar(detalhes={'arquivo': dados['arquivo'], 'colaboradores_alterados': feitos, 'por_escala': resumo,
                      'ignorados_erro': dados['cont']['erro']})
    logger.info(f"{get_usuario_logado()} importou escalas por CSV ({dados['arquivo']}): {feitos} alterado(s).")
    flash(f"Importação concluída: {feitos} colaborador(es) com escala atualizada.", "success")
    return redirect(url_for('escalas') + '#importar')


# ─── USUÁRIOS ─────────────────────────────────────────────────────────────────

@app.route('/cadastro_usuario', methods=['GET', 'POST'])
def cadastro_usuario():
    if 'usuario_id' not in session:
        return redirect('/')
    if requer_admin():
        flash("Acesso restrito a administradores.", "error")
        return redirect('/usuario')

    usuario_logado = get_usuario_logado()
    logger.info(f"{usuario_logado} acessou a tela de cadastro de usuário")

    init_perfis()
    cur = mysql.connection.cursor()
    init_seguranca()
    cur.execute("""SELECT u.id, u.nome, u.usuario, COALESCE(p.nome, u.perfil), u.status, u.perfil_id, u.trocar_senha
                   FROM usuarios u LEFT JOIN perfis p ON p.id = u.perfil_id ORDER BY u.nome ASC""")
    usuarios = cur.fetchall()
    cur.close()

    if request.method == 'POST':
        nome = request.form['nome'].strip().upper()
        usuario_form = request.form['usuario'].strip()
        senha = request.form['senha'].strip()
        perfil_id = request.form.get('perfil_id', '').strip()
        perfil_obj = _carregar_perfil(int(perfil_id)) if perfil_id.isdigit() else None

        if not all([nome, usuario_form, senha]) or not perfil_obj:
            flash("Todos os campos são obrigatórios.", "error")
            return redirect(url_for('cadastro_usuario'))
        erros_senha = validar_senha(senha, usuario_form)
        if erros_senha:
            flash(msg_senha_invalida(erros_senha), "error")
            return redirect(url_for('cadastro_usuario'))
        trocar = 1 if request.form.get('trocar_senha') else 0
        perfil = perfil_obj['chave'] or f"perfil_{perfil_obj['id']}"

        cur = mysql.connection.cursor()
        cur.execute("SELECT id FROM usuarios WHERE usuario = %s", (usuario_form,))
        if cur.fetchone():
            flash("Esse nome de usuário já está cadastrado.", "error")
            cur.close()
            return redirect(url_for('cadastro_usuario'))

        try:
            cur.execute("""INSERT INTO usuarios (nome, usuario, senha, perfil, perfil_id, status, criado_em, trocar_senha, senha_alterada_em)
                           VALUES (%s,%s,%s,%s,%s,1,NOW(),%s,NOW())""",
                        (nome, usuario_form, generate_password_hash(senha), perfil, perfil_obj['id'], trocar))
            mysql.connection.commit()
            logger.info(f"{usuario_logado} cadastrou usuário '{usuario_form}'.")
            flash("Usuário cadastrado com sucesso!", "success")
        except Exception as e:
            mysql.connection.rollback()
            flash(f"Erro ao cadastrar usuário: {str(e)}", "error")
        finally:
            cur.close()
        return redirect(url_for('cadastro_usuario'))

    return render_template('menu_admin.html', usuarios=usuarios, module='cadastro_usuario', usuario=usuario_logado,
                           perfis_select=_perfis_para_select(), regras_senha=regras_senha(), pol_senha=politica_senha())


@app.route('/editar_usuario/<int:usuario_id>', methods=['POST'])
def editar_usuario(usuario_id):
    if 'usuario_id' not in session or requer_admin():
        return redirect('/')
    usuario_logado = get_usuario_logado()

    novo_nome    = request.form.get('nome', '').strip().upper()
    novo_login   = request.form.get('usuario_login', '').strip()
    novo_perfil_id = request.form.get('perfil_id', '').strip()
    nova_senha   = request.form.get('nova_senha', '').strip()
    perfil_obj = _carregar_perfil(int(novo_perfil_id)) if novo_perfil_id.isdigit() else None

    if not all([novo_nome, novo_login]) or not perfil_obj:
        flash("Nome, usuário e perfil são obrigatórios.", "error")
        return redirect(url_for('cadastro_usuario'))
    novo_perfil = perfil_obj['chave'] or f"perfil_{perfil_obj['id']}"
    if nova_senha:
        erros_senha = validar_senha(nova_senha, novo_login)
        if erros_senha:
            flash(msg_senha_invalida(erros_senha), "error")
            return redirect(url_for('cadastro_usuario'))
    # quem redefine a senha de OUTRA pessoa normalmente exige a troca no próximo acesso
    trocar = 1 if (request.form.get('trocar_senha') and usuario_id != session.get('usuario_id')) else 0

    if usuario_id == session.get('usuario_id') and perfil_obj['id'] != session.get('perfil_id'):
        flash("Você não pode alterar o próprio perfil.", "error")
        return redirect(url_for('cadastro_usuario'))

    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT id FROM usuarios WHERE usuario = %s AND id != %s", (novo_login, usuario_id))
        if cur.fetchone():
            flash("Esse nome de usuário já está em uso.", "error")
            cur.close()
            return redirect(url_for('cadastro_usuario'))

        # não deixar o sistema sem nenhum Administrador ativo
        cur.execute("""SELECT COUNT(*) FROM usuarios u JOIN perfis p ON p.id = u.perfil_id
                       WHERE p.protegido = 1 AND u.status = 1 AND u.id <> %s""", (usuario_id,))
        outros_admins = cur.fetchone()[0]
        cur.execute("SELECT p.protegido FROM usuarios u LEFT JOIN perfis p ON p.id = u.perfil_id WHERE u.id=%s", (usuario_id,))
        era_admin = bool((cur.fetchone() or [0])[0])
        if era_admin and not perfil_obj['protegido'] and outros_admins == 0:
            cur.close()
            flash("Este é o último Administrador ativo. Cadastre outro antes de mudar o perfil dele.", "error")
            return redirect(url_for('cadastro_usuario'))
        if nova_senha:
            cur.execute("""UPDATE usuarios SET nome=%s, usuario=%s, perfil=%s, perfil_id=%s, senha=%s,
                                  trocar_senha=%s, senha_alterada_em=NOW() WHERE id=%s""",
                        (novo_nome, novo_login, novo_perfil, perfil_obj['id'], generate_password_hash(nova_senha), trocar, usuario_id))
        else:
            cur.execute("UPDATE usuarios SET nome=%s, usuario=%s, perfil=%s, perfil_id=%s WHERE id=%s",
                        (novo_nome, novo_login, novo_perfil, perfil_obj['id'], usuario_id))
        mysql.connection.commit()
        cur.close()
        msg = f"Usuário '{novo_login}' atualizado." + (" Senha redefinida." if nova_senha else "") + \
            (" Troca obrigatória no próximo acesso." if nova_senha and trocar else "")
        logger.info(f"{usuario_logado} editou usuário ID {usuario_id}: {msg}")
        flash("Usuário atualizado com sucesso!" + (" Senha redefinida." if nova_senha else "")
              + (" A pessoa vai criar uma senha nova no próximo acesso." if nova_senha and trocar else ""), "success")
    except Exception:
        mysql.connection.rollback()
        flash("Erro ao atualizar usuário.", "error")
    return redirect(url_for('cadastro_usuario'))


@app.route('/excluir_usuario/<int:usuario_id>', methods=['POST'])
def excluir_usuario(usuario_id):
    if 'usuario_id' not in session or requer_admin():
        return redirect('/')
    usuario_logado = get_usuario_logado()
    if usuario_id == session.get('usuario_id'):
        flash("Você não pode excluir o próprio usuário.", "error")
        return redirect(url_for('cadastro_usuario'))
    try:
        cur = mysql.connection.cursor()
        cur.execute("DELETE FROM usuarios WHERE id = %s", (usuario_id,))
        mysql.connection.commit()
        cur.close()
        logger.info(f"{usuario_logado} excluiu usuário ID {usuario_id}")
        flash("Usuário excluído com sucesso.", "success")
    except Exception as e:
        mysql.connection.rollback()
        flash("Erro ao excluir usuário.", "error")
    return redirect(url_for('cadastro_usuario'))


# ─── DEPARTAMENTOS (CRUD COMPLETO) ────────────────────────────────────────────

@app.route('/departamentos', methods=['GET', 'POST'])
def departamentos():
    if 'usuario_id' not in session:
        return redirect('/')

    perfil = session.get('usuario_perfil', '')

    if request.method == 'POST' and requer_admin():
        flash("Acesso restrito a administradores.", "error")
        return redirect('/usuario')

    usuario_logado = get_usuario_logado()
    logger.info(f"{usuario_logado} acessou a tela de departamentos")
    init_grupos_table()

    if request.method == 'POST':
        nome  = request.form['nome'].strip().upper()
        grupo = request.form.get('grupo', '').strip()
        if not nome:
            flash("O nome do departamento é obrigatório.", "error")
            return redirect(url_for('departamentos'))

        cur = mysql.connection.cursor()
        cur.execute("SELECT id FROM departamentos WHERE nome = %s", (nome,))
        if cur.fetchone():
            flash("Esse departamento já está cadastrado.", "error")
            cur.close()
            return redirect(url_for('departamentos'))

        try:
            cur.execute("INSERT INTO departamentos (nome, grupo) VALUES (%s, %s)", (nome, grupo))
            mysql.connection.commit()
            logger.info(f"{usuario_logado} cadastrou departamento '{nome}' (grupo: {grupo or 'nenhum'}).")
            flash("Departamento cadastrado com sucesso!", "success")
        except Exception as e:
            mysql.connection.rollback()
            flash(f"Erro ao cadastrar departamento: {str(e)}", "error")
        finally:
            cur.close()
        return redirect(url_for('departamentos'))

    search = request.args.get('search', '').strip()
    cur = mysql.connection.cursor()
    if search:
        cur.execute("""
            SELECT d.id, d.nome, d.grupo,
                (SELECT COUNT(*) FROM colaboradores c WHERE c.departamento = d.nome) AS total_colab
            FROM departamentos d WHERE d.nome LIKE %s ORDER BY d.nome
        """, (f"%{search}%",))
    else:
        cur.execute("""
            SELECT d.id, d.nome, d.grupo,
                (SELECT COUNT(*) FROM colaboradores c WHERE c.departamento = d.nome) AS total_colab
            FROM departamentos d ORDER BY d.nome
        """)
    lista_departamentos = cur.fetchall()
    cur.close()

    tmpl = 'menu_admin.html'
    return render_template(tmpl, lista_departamentos=lista_departamentos,
                           grupos=get_grupos(), search=search,
                           module='departamentos', usuario=usuario_logado)


@app.route('/editar_departamento/<int:dep_id>', methods=['POST'])
def editar_departamento(dep_id):
    if 'usuario_id' not in session or requer_admin():
        return redirect('/')
    usuario_logado = get_usuario_logado()
    novo_nome = request.form['nome'].strip().upper()
    novo_grupo = request.form.get('grupo', '').strip()
    if not novo_nome:
        flash("Nome do departamento não pode ser vazio.", "error")
        return redirect(url_for('departamentos'))
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT nome FROM departamentos WHERE id = %s", (dep_id,))
        row = cur.fetchone()
        if row:
            nome_antigo = row[0]
            cur.execute("UPDATE departamentos SET nome = %s, grupo = %s WHERE id = %s", (novo_nome, novo_grupo, dep_id))
            cur.execute("UPDATE colaboradores SET departamento = %s WHERE departamento = %s", (novo_nome, nome_antigo))
            mysql.connection.commit()
            logger.info(f"{usuario_logado} renomeou departamento '{nome_antigo}' -> '{novo_nome}'.")
            flash("Departamento atualizado com sucesso!", "success")
        cur.close()
    except Exception as e:
        mysql.connection.rollback()
        flash("Erro ao atualizar departamento.", "error")
    return redirect(url_for('departamentos'))


@app.route('/excluir_departamento/<int:dep_id>', methods=['POST'])
def excluir_departamento(dep_id):
    if 'usuario_id' not in session or requer_admin():
        return redirect('/')
    usuario_logado = get_usuario_logado()
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT nome FROM departamentos WHERE id = %s", (dep_id,))
        row = cur.fetchone()
        if not row:
            flash("Departamento não encontrado.", "error")
            cur.close()
            return redirect(url_for('departamentos'))
        nome_dep = row[0]
        cur.execute("SELECT COUNT(*) FROM colaboradores WHERE departamento = %s", (nome_dep,))
        total = cur.fetchone()[0]
        if total > 0:
            flash(f"Não é possível excluir: {total} colaborador(es) vinculado(s) a este departamento.", "error")
            cur.close()
            return redirect(url_for('departamentos'))
        cur.execute("DELETE FROM departamentos WHERE id = %s", (dep_id,))
        mysql.connection.commit()
        cur.close()
        logger.info(f"{usuario_logado} excluiu departamento '{nome_dep}'.")
        flash("Departamento excluído com sucesso.", "success")
    except Exception as e:
        mysql.connection.rollback()
        flash("Erro ao excluir departamento.", "error")
    return redirect(url_for('departamentos'))


@app.route('/admin/grupos', methods=['GET', 'POST'])
def admin_grupos():
    if 'usuario_id' not in session or requer_admin():
        return redirect('/')
    usuario_logado = get_usuario_logado()
    init_grupos_table()

    if request.method == 'POST':
        nome = request.form.get('nome', '').strip()
        if not nome:
            flash("O nome do grupo é obrigatório.", "error")
            return redirect(url_for('admin_grupos'))
        try:
            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO grupos (nome) VALUES (%s)", (nome,))
            mysql.connection.commit()
            cur.close()
            logger.info(f"{usuario_logado} criou grupo '{nome}'.")
            flash(f"Grupo '{nome}' criado com sucesso!", "success")
        except Exception:
            mysql.connection.rollback()
            flash("Esse grupo já existe ou ocorreu um erro.", "error")
        return redirect(url_for('admin_grupos'))

    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT g.id, g.nome,
               COUNT(d.id) AS total_deps
        FROM grupos g
        LEFT JOIN departamentos d ON d.grupo = g.nome
        GROUP BY g.id, g.nome
        ORDER BY g.id
    """)
    lista_grupos = cur.fetchall()
    cur.close()

    return render_template('menu_admin.html', lista_grupos=lista_grupos,
                           module='grupos', usuario=usuario_logado)


@app.route('/admin/grupos/editar/<int:grupo_id>', methods=['POST'])
def editar_grupo(grupo_id):
    if 'usuario_id' not in session or requer_admin():
        return redirect('/')
    usuario_logado = get_usuario_logado()
    novo_nome = request.form.get('nome', '').strip()
    if not novo_nome:
        flash("O nome do grupo não pode ser vazio.", "error")
        return redirect(url_for('admin_grupos'))
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT nome FROM grupos WHERE id = %s", (grupo_id,))
        row = cur.fetchone()
        if row:
            nome_antigo = row[0]
            cur.execute("UPDATE grupos SET nome = %s WHERE id = %s", (novo_nome, grupo_id))
            cur.execute("UPDATE departamentos SET grupo = %s WHERE grupo = %s", (novo_nome, nome_antigo))
            mysql.connection.commit()
            logger.info(f"{usuario_logado} renomeou grupo '{nome_antigo}' -> '{novo_nome}'.")
            flash("Grupo atualizado com sucesso!", "success")
        cur.close()
    except Exception:
        mysql.connection.rollback()
        flash("Erro ao atualizar grupo.", "error")
    return redirect(url_for('admin_grupos'))


@app.route('/admin/grupos/excluir/<int:grupo_id>', methods=['POST'])
def excluir_grupo(grupo_id):
    if 'usuario_id' not in session or requer_admin():
        return redirect('/')
    usuario_logado = get_usuario_logado()
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT nome FROM grupos WHERE id = %s", (grupo_id,))
        row = cur.fetchone()
        if not row:
            flash("Grupo não encontrado.", "error")
            cur.close()
            return redirect(url_for('admin_grupos'))
        nome_grupo = row[0]
        cur.execute("SELECT COUNT(*) FROM departamentos WHERE grupo = %s", (nome_grupo,))
        total = cur.fetchone()[0]
        if total > 0:
            flash(f"Não é possível excluir: {total} departamento(s) vinculado(s) a este grupo.", "error")
            cur.close()
            return redirect(url_for('admin_grupos'))
        cur.execute("DELETE FROM grupos WHERE id = %s", (grupo_id,))
        mysql.connection.commit()
        cur.close()
        logger.info(f"{usuario_logado} excluiu grupo '{nome_grupo}'.")
        flash("Grupo excluído com sucesso.", "success")
    except Exception:
        mysql.connection.rollback()
        flash("Erro ao excluir grupo.", "error")
    return redirect(url_for('admin_grupos'))


# ─── RELATÓRIOS ───────────────────────────────────────────────────────────────

@app.route('/relatorio/total', methods=['GET', 'POST'])
def relatorio_totalEmissao():
    if 'usuario_id' not in session:
        return redirect('/')
    usuario_logado = get_usuario_logado()
    perfil = session.get('usuario_perfil', 'desconhecido')
    logger.info(f"{usuario_logado} acessou relatório total de senhas emitidas")

    if request.method == 'POST':
        try:
            data_inicio = datetime.strptime(request.form.get('data_inicial'), "%Y-%m-%d").date()
            data_fim    = datetime.strptime(request.form.get('data_final'),   "%Y-%m-%d").date()
        except ValueError:
            flash("Datas inválidas.", "error")
            return redirect(url_for('relatorio_totalEmissao'))

        if data_fim < data_inicio:
            flash("A data final não pode ser anterior à data inicial.", "error")
            return redirect(url_for('relatorio_totalEmissao'))

        cursor = mysql.connection.cursor()

        def q(sql, params=()):
            cursor.execute(sql, params)
            return cursor.fetchone()[0]

        t = get_turnos()
        REF = sql_refeicao(t)

        def count_colab(refeicao):
            cursor.execute(
                f"SELECT COUNT(*) FROM emissoes_senha WHERE {REF} = %s "
                "AND cargo != %s AND DATE(data_hora) BETWEEN %s AND %s",
                (refeicao, 'VISITANTE', data_inicio, data_fim)
            )
            return cursor.fetchone()[0]

        def count_visit(refeicao):
            cursor.execute(
                f"SELECT COUNT(*) FROM emissoes_senha WHERE {REF} = %s "
                "AND cargo = %s AND DATE(data_hora) BETWEEN %s AND %s",
                (refeicao, 'VISITANTE', data_inicio, data_fim)
            )
            return cursor.fetchone()[0]

        total_senhas      = q("SELECT COUNT(*) FROM emissoes_senha WHERE DATE(data_hora) BETWEEN %s AND %s", (data_inicio, data_fim))
        total_visitantes  = q("SELECT COUNT(*) FROM emissoes_senha WHERE cargo = %s  AND DATE(data_hora) BETWEEN %s AND %s", ('VISITANTE', data_inicio, data_fim))
        total_colaborador = q("SELECT COUNT(*) FROM emissoes_senha WHERE cargo != %s AND DATE(data_hora) BETWEEN %s AND %s", ('VISITANTE', data_inicio, data_fim))

        cafe_colab   = count_colab('cafe')
        cafe_visit   = count_visit('cafe')
        almoco_colab = count_colab('almoco')
        almoco_visit = count_visit('almoco')
        janta_colab  = count_colab('janta')
        janta_visit  = count_visit('janta')

        # breakdown por departamento com contagem por turno numa única query
        cursor.execute(
            f"""SELECT departamento,
                      SUM({REF} = 'cafe') AS cafe,
                      SUM({REF} = 'almoco') AS almoco,
                      SUM({REF} = 'janta') AS janta,
                      COUNT(*) AS total
               FROM emissoes_senha
               WHERE DATE(data_hora) BETWEEN %s AND %s
               GROUP BY departamento
               ORDER BY total DESC""",
            (data_inicio, data_fim)
        )
        lista_departamentos = [
            {"nome": n, "cafe": int(c or 0), "almoco": int(a or 0), "janta": int(j or 0), "quantidade": int(t)}
            for n, c, a, j, t in cursor.fetchall()
        ]
        cursor.close()

        dados = {
            "total_senhas":      total_senhas,
            "total_visitantes":  total_visitantes,
            "total_colaborador": total_colaborador,
            "cafe_colab":        cafe_colab,
            "cafe_visit":        cafe_visit,
            "almoco_colab":      almoco_colab,
            "almoco_visit":      almoco_visit,
            "janta_colab":       janta_colab,
            "janta_visit":       janta_visit,
            "cafe_total":        cafe_colab   + cafe_visit,
            "almoco_total":      almoco_colab + almoco_visit,
            "janta_total":       janta_colab  + janta_visit,
        }
        periodo = f"{data_inicio.strftime('%d/%m/%Y')} a {data_fim.strftime('%d/%m/%Y')}"
        agora   = datetime.now().strftime('%d/%m/%Y %H:%M')
        turnos_label = {
            'cafe_ini':   t['turno_cafe_ini'].strftime('%Hh%M'),
            'cafe_fim':   t['turno_cafe_fim'].strftime('%Hh%M'),
            'almoco_ini': t['turno_almoco_ini'].strftime('%Hh%M'),
            'almoco_fim': t['turno_almoco_fim'].strftime('%Hh%M'),
            'janta_ini':  t['turno_janta_ini'].strftime('%Hh%M'),
            'janta_fim':  t['turno_janta_fim'].strftime('%Hh%M'),
        }

        html = render_template(
            'relatorio_totalEmissao.html',
            dados=dados,
            lista_departamentos=lista_departamentos,
            periodo=periodo,
            agora=agora,
            turnos=turnos_label,
            nome_instituicao=get_instituicao(),
        )
        pdf = gerar_pdf(html)
        logger.info(f"{usuario_logado} emitiu relatório total ({periodo}).")
        return send_file(BytesIO(pdf), download_name='relatorio_totalEmissao.pdf', as_attachment=True)

    tmpl = 'menu_admin.html'
    return render_template(tmpl, modulo='relatorio_totalEmissao', usuario=usuario_logado)


@app.route('/relatorio/diario', methods=['GET', 'POST'])
def relatorio_emissaoDiaria():
    if 'usuario_id' not in session:
        return redirect('/')
    usuario_logado = get_usuario_logado()
    perfil = session.get('usuario_perfil', 'desconhecido')
    logger.info(f"{usuario_logado} acessou relatório de emissões diárias")

    if request.method == 'POST':
        try:
            data_ini = datetime.strptime(request.form.get('data_inicio'), "%Y-%m-%d").date()
            data_final = datetime.strptime(request.form.get('data_fim'), "%Y-%m-%d").date()
            if data_ini > data_final:
                flash("A data inicial não pode ser maior que a final.")
                return redirect(url_for('relatorio_emissaoDiaria'))
        except ValueError:
            flash("Datas inválidas.")
            return redirect(url_for('relatorio_emissaoDiaria'))

        tipo_relatorio = request.form.get('tipo_relatorio')
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT numero_senha,cpf,nome,cargo,departamento,data_hora FROM emissoes_senha WHERE DATE(data_hora) BETWEEN %s AND %s ORDER BY data_hora ASC", (data_ini, data_final))
        results = cursor.fetchall()
        colunas = [d[0] for d in cursor.description]
        registros = [dict(zip(colunas, r)) for r in results]
        cursor.close()

        periodo = f"{data_ini.strftime('%d/%m/%Y')} até {data_final.strftime('%d/%m/%Y')}"
        agora = datetime.now().strftime('%d/%m/%Y %H:%M')

        if tipo_relatorio == 'excel':
            df = pd.DataFrame(registros)
            output = BytesIO()
            with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                wb = writer.book
                ws = wb.add_worksheet("Relatório"); writer.sheets['Relatório'] = ws
                bold = wb.add_format({'bold': True})
                ws.write('A1','Relatório de Emissões Diárias', bold)
                ws.write('A3','Período:', bold); ws.write('B3', periodo)
                ws.write('A4','Gerado em:', bold); ws.write('B4', agora)
                df.to_excel(writer, sheet_name='Relatório', startrow=6, index=False)
                for i, col in enumerate(df.columns):
                    ws.set_column(i, i, max(df[col].astype(str).map(len).max(), len(col)) + 2)
            output.seek(0)
            logger.info(f"{usuario_logado} emitiu relatório diário (EXCEL).")
            return send_file(output, download_name='relatorio_emissoesDiarias.xlsx', as_attachment=True)
        else:
            html = render_template('relatorio_emissoesDiarias.html', registros=registros, periodo=periodo, agora=agora,
                                       nome_instituicao=get_instituicao())
            pdf = gerar_pdf(html)
            logger.info(f"{usuario_logado} emitiu relatório diário (PDF).")
            return send_file(BytesIO(pdf), download_name='relatorio_emissoesDiarias.pdf', as_attachment=True)

    tmpl = 'menu_admin.html'
    return render_template(tmpl, modulo='relatorio_emissaoDiaria', usuario=usuario_logado)


@app.route('/relatorio/totalVisitantes', methods=['GET', 'POST'])
def relatorio_totalVisitantes():
    if 'usuario_id' not in session:
        return redirect('/')
    usuario_logado = get_usuario_logado()
    perfil = session.get('usuario_perfil', 'desconhecido')

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT nome FROM localizacoes ORDER BY nome ASC")
    localizacoes = [r[0] for r in cursor.fetchall()]
    cursor.close()

    if request.method == 'POST':
        try:
            data_inicial = datetime.strptime(request.form.get('data_inicial'), "%Y-%m-%d")
            data_final = datetime.strptime(request.form.get('data_final'), "%Y-%m-%d")
        except ValueError:
            flash("Datas inválidas.")
            return redirect(url_for('relatorio_totalVisitantes'))
        if data_final < data_inicial:
            flash("Data final não pode ser anterior à inicial.")
            return redirect(url_for('relatorio_totalVisitantes'))

        departamento = request.form.get('departamento') or ''
        todas = departamento == 'TODAS'
        if not todas and departamento not in localizacoes:
            flash("Selecione uma localização válida.")
            return redirect(url_for('relatorio_totalVisitantes'))
        rotulo_local = 'Todas as localizações' if todas else departamento
        tipo_relatorio = request.form.get('tipo_relatorio')
        dt_inicio = datetime.combine(data_inicial, time(0, 0))
        dt_fim = datetime.combine(data_final, time(23, 59, 59))

        # Apenas senhas de visitante (cargo = VISITANTE); a localização fica gravada em "departamento"
        sql = ("SELECT numero_senha,cpf,nome,cargo,departamento,data_hora FROM emissoes_senha "
               "WHERE data_hora BETWEEN %s AND %s AND cargo = 'VISITANTE'")
        params = [dt_inicio, dt_fim]
        if not todas:
            sql += " AND departamento = %s"
            params.append(departamento)
        sql += " ORDER BY data_hora ASC"
        cursor = mysql.connection.cursor()
        cursor.execute(sql, params)
        registros = [dict(zip([d[0] for d in cursor.description], r)) for r in cursor.fetchall()]
        cursor.close()

        t = get_turnos()
        def turno(h):
            return classificar_refeicao(h, t)

        total_geral = len(registros)
        totais = {'cafe': 0, 'almoco': 0, 'janta': 0}
        por_local = {}
        for r in registros:
            k = turno(r['data_hora'].time())
            totais[k] += 1
            loc = por_local.setdefault(r['departamento'], {'nome': r['departamento'], 'cafe': 0, 'almoco': 0, 'janta': 0, 'total': 0})
            loc[k] += 1
            loc['total'] += 1
        lista_locais = sorted(por_local.values(), key=lambda x: (-x['total'], x['nome']))
        total_cafe, total_almoco, total_janta = totais['cafe'], totais['almoco'], totais['janta']

        periodo = f"{data_inicial.strftime('%d/%m/%Y')} até {data_final.strftime('%d/%m/%Y')}"
        agora = datetime.now().strftime('%d/%m/%Y %H:%M')
        turnos_fmt = {k.replace('turno_', ''): v.strftime('%Hh%M') for k, v in t.items()}
        logger.info(f"{usuario_logado} emitiu relatório de visitantes ({rotulo_local}, {tipo_relatorio}).")

        if tipo_relatorio == 'excel':
            df = pd.DataFrame(registros)
            output = BytesIO()
            with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                wb = writer.book; ws = wb.add_worksheet("Relatório"); writer.sheets['Relatório'] = ws
                bold = wb.add_format({'bold': True})
                ws.write('A1','Relatório Total por Tipo de Visitantes', bold)
                ws.write('A3','Localização:', bold); ws.write('B3', rotulo_local)
                ws.write('A4','Período:', bold); ws.write('B4', periodo)
                ws.write('A6','Total Café:', bold); ws.write('B6', total_cafe)
                ws.write('A7','Total Almoço:', bold); ws.write('B7', total_almoco)
                ws.write('A8','Total Jantar:', bold); ws.write('B8', total_janta)
                ws.write('A9','Total Geral:', bold); ws.write('B9', total_geral)
                linha = 10
                if todas and lista_locais:
                    ws.write(linha, 0, 'Por localização', bold); linha += 1
                    for col, titulo in enumerate(['Localização', 'Café', 'Almoço', 'Jantar', 'Total']):
                        ws.write(linha, col, titulo, bold)
                    for loc in lista_locais:
                        linha += 1
                        ws.write_row(linha, 0, [loc['nome'], loc['cafe'], loc['almoco'], loc['janta'], loc['total']])
                    linha += 2
                if registros:
                    df.to_excel(writer, sheet_name='Relatório', startrow=linha, index=False)
                    for i, col in enumerate(df.columns):
                        ws.set_column(i, i, max(df[col].astype(str).map(len).max(), len(col)) + 2)
            output.seek(0)
            return send_file(output, download_name='relatorio_totalVisitantes.xlsx', as_attachment=True)
        else:
            html = render_template('relatorio_totalVisitantes.html', registros=registros,
                                   periodo=periodo, agora=agora, localizacao=rotulo_local, todas=todas,
                                   total_cafe=total_cafe, total_almoco=total_almoco,
                                   total_janta=total_janta, total_geral=total_geral,
                                   lista_locais=lista_locais, turnos=turnos_fmt,
                                   nome_instituicao=get_instituicao())
            pdf = gerar_pdf(html)
            return send_file(BytesIO(pdf), download_name='relatorio_totalVisitantes.pdf', as_attachment=True)

    tmpl = 'menu_admin.html'
    return render_template(tmpl, modulo='relatorio_totalVisitantes', usuario=usuario_logado, localizacoes=localizacoes)


@app.route('/relatorio/totalDepartamento', methods=['GET', 'POST'])
def relatorio_totalDepartamento():
    if 'usuario_id' not in session:
        return redirect('/')
    usuario_logado = get_usuario_logado()
    perfil = session.get('usuario_perfil', 'desconhecido')

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT nome FROM departamentos ORDER BY nome ASC")
    departamentos = [r[0] for r in cursor.fetchall()]
    cursor.close()

    if request.method == 'POST':
        try:
            data_inicial = datetime.strptime(request.form.get('data_inicial'), "%Y-%m-%d")
            data_final = datetime.strptime(request.form.get('data_final'), "%Y-%m-%d")
        except ValueError:
            flash("Datas inválidas.")
            return redirect(url_for('relatorio_totalDepartamento'))
        if data_final < data_inicial:
            flash("Data final não pode ser anterior à data inicial.")
            return redirect(url_for('relatorio_totalDepartamento'))

        departamento = request.form.get('departamento')
        tipo_relatorio = request.form.get('tipo_relatorio')
        dt_inicio = datetime.combine(data_inicial, time(0, 0))
        dt_fim = datetime.combine(data_final, time(23, 59, 59))

        cursor = mysql.connection.cursor()
        if departamento == 'TODOS':
            cursor.execute("SELECT numero_senha,cpf,nome,cargo,departamento,data_hora FROM emissoes_senha WHERE data_hora BETWEEN %s AND %s ORDER BY data_hora ASC", (dt_inicio, dt_fim))
        else:
            cursor.execute("SELECT numero_senha,cpf,nome,cargo,departamento,data_hora FROM emissoes_senha WHERE data_hora BETWEEN %s AND %s AND departamento=%s ORDER BY data_hora ASC", (dt_inicio, dt_fim, departamento))

        registros = [dict(zip([d[0] for d in cursor.description], r)) for r in cursor.fetchall()]
        cursor.close()

        t = get_turnos()
        total_geral = len(registros)
        totais = {'cafe': 0, 'almoco': 0, 'janta': 0}
        por_dep = {}
        for r in registros:
            k = classificar_refeicao(r['data_hora'].time(), t)
            totais[k] += 1
            d = por_dep.setdefault(r['departamento'], {'nome': r['departamento'], 'cafe': 0, 'almoco': 0, 'janta': 0, 'total': 0})
            d[k] += 1
            d['total'] += 1
        total_cafe, total_almoco, total_janta = totais['cafe'], totais['almoco'], totais['janta']
        lista_deps = sorted(por_dep.values(), key=lambda x: (-x['total'], x['nome']))
        todos = departamento == 'TODOS'
        turnos_fmt = {k.replace('turno_', ''): v.strftime('%Hh%M') for k, v in t.items()}

        periodo = f"{data_inicial.strftime('%d/%m/%Y')} até {data_final.strftime('%d/%m/%Y')}"
        agora = datetime.now().strftime('%d/%m/%Y %H:%M')

        if tipo_relatorio == 'excel':
            df = pd.DataFrame(registros)
            output = BytesIO()
            with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                wb = writer.book; ws = wb.add_worksheet("Relatório"); writer.sheets['Relatório'] = ws
                bold = wb.add_format({'bold': True})
                ws.write('A1','Relatório de Emissões por Departamento', bold)
                ws.write('A3','Departamento:', bold); ws.write('B3', "Todos" if departamento=="TODOS" else departamento)
                ws.write('A4','Período:', bold); ws.write('B4', periodo)
                ws.write('A6','Total Café:', bold); ws.write('B6', total_cafe)
                ws.write('A7','Total Almoço:', bold); ws.write('B7', total_almoco)
                ws.write('A8','Total Jantar:', bold); ws.write('B8', total_janta)
                ws.write('A9','Total Geral:', bold); ws.write('B9', total_geral)
                linha = 10
                if todos and lista_deps:
                    ws.write(linha, 0, 'Por departamento', bold); linha += 1
                    for col, titulo in enumerate(['Departamento', 'Café', 'Almoço', 'Jantar', 'Total']):
                        ws.write(linha, col, titulo, bold)
                    for d in lista_deps:
                        linha += 1
                        ws.write_row(linha, 0, [d['nome'], d['cafe'], d['almoco'], d['janta'], d['total']])
                    linha += 2
                if registros:
                    df.to_excel(writer, sheet_name='Relatório', startrow=linha, index=False)
                    for i, col in enumerate(df.columns):
                        ws.set_column(i, i, max(df[col].astype(str).map(len).max(), len(col)) + 2)
            output.seek(0)
            return send_file(output, download_name='relatorio_totalDepartamentos.xlsx', as_attachment=True)
        else:
            html = render_template('relatorio_totalDepartamentos.html', registros=registros,
                                   periodo=periodo, agora=agora, departamento=departamento, todos=todos,
                                   total_cafe=total_cafe, total_almoco=total_almoco,
                                   total_janta=total_janta, total_geral=total_geral,
                                   lista_deps=lista_deps, turnos=turnos_fmt,
                                   nome_instituicao=get_instituicao())
            pdf = gerar_pdf(html)
            return send_file(BytesIO(pdf), download_name='relatorio_totalDepartamentos.pdf', as_attachment=True)

    tmpl = 'menu_admin.html'
    return render_template(tmpl, modulo='relatorio_totalDepartamento', usuario=usuario_logado, departamentos=departamentos)


# ─── EMISSÃO DE SENHAS ────────────────────────────────────────────────────────

@app.route('/senha/colaborador', methods=['GET', 'POST'])
def senha_colaborador():
    modo = request.args.get('modo', '')
    extra = {'modo': 'tablet'} if modo == 'tablet' else {}

    if get_config('tipo_emissao_senha', 'padrao') == 'cardapio':
        return redirect(url_for('senha_colaborador_cardapio', **extra))

    usuario_logado = get_usuario_logado()

    if request.method == 'POST':
        cpf = request.form['cpf']
        if not validar_cpf(cpf):
            flash("CPF inválido.", "error")
            return redirect(url_for('senha_colaborador', **extra))

        cur = mysql.connection.cursor()
        init_escalas()
        cur.execute("SELECT nome, cpf, cargo, departamento, tipo, escala_id FROM colaboradores WHERE cpf = %s", (cpf,))
        colaborador = cur.fetchone()

        if colaborador:
            nome, cpf, cargo, departamento, limite_diario, escala_id = colaborador
            data_hoje = date.today()
            with trava_emissao() as travou:
                if not travou:
                    flash("Sistema ocupado. Tente de novo em alguns segundos.", "error")
                    cur.close()
                    return redirect(url_for('senha_colaborador', **extra))
                recusa = checar_direito_refeicao(cur, cpf, escala_id, limite_diario, refeicao_por_horario())
                if recusa:
                    flash(recusa, "error")
                    cur.close()
                    return redirect(url_for('senha_colaborador', **extra))
                cur.execute("SELECT COALESCE(MAX(numero_senha),0) FROM emissoes_senha WHERE DATE(data_hora)=%s", (data_hoje,))
                novo_numero = cur.fetchone()[0] + 1
                try:
                    cur.execute("INSERT INTO emissoes_senha (nome,cpf,cargo,departamento,data_hora,numero_senha) VALUES (%s,%s,%s,%s,%s,%s)",
                                (nome, cpf, cargo, departamento, datetime.now(), novo_numero))
                    mysql.connection.commit()
                    logger.info(f"{usuario_logado}: Senha Nº {novo_numero:03d} para CPF {cpf}.")
                    flash(f"Senha Nº {novo_numero:03d} emitida com sucesso!", "success")
                except Exception as e:
                    mysql.connection.rollback()
                    flash("Erro ao registrar a senha.", "error")
            cur.close()
        else:
            flash("CPF não encontrado na base de colaboradores.", "error")
            cur.close()
        return redirect(url_for('senha_colaborador', **extra))

    if modo == 'tablet':
        return render_template('emissao_senha_tablet.html', tipo_senha='colaborador')
    return render_template('emissao_senha.html', tipo_senha='colaborador')


@app.route('/senha/visitante', methods=['GET', 'POST'])
def senha_visitante():
    modo = request.args.get('modo', '')
    extra = {'modo': 'tablet'} if modo == 'tablet' else {}
    usuario_logado = get_usuario_logado()
    tipo_emissao = get_config('tipo_emissao_senha', 'padrao')

    cur = mysql.connection.cursor()
    cur.execute("SELECT nome FROM localizacoes ORDER BY nome ASC")
    localizacoes = [r[0] for r in cur.fetchall()]

    cardapios_hoje = cardapios_do_horario(cur) if tipo_emissao == 'cardapio' else []
    cur.close()

    if request.method == 'POST':
        nome       = ' '.join(request.form['nome'].split()).upper()
        cpf        = request.form['cpf'].strip()
        localizacao = request.form['localizacoes'].strip().upper()

        if not nome_completo_valido(nome):
            flash("Informe o nome completo (nome e sobrenome).", "error")
            return redirect(url_for('senha_visitante', **extra))

        if not validar_cpf(cpf):
            flash("CPF inválido.", "error")
            return redirect(url_for('senha_visitante', **extra))

        # Validação do cardápio (somente no modo cardápio)
        cardapio_id = None
        c_tipo = None
        c_descricao = None
        if tipo_emissao == 'cardapio':
            cardapio_id = request.form.get('cardapio_id', '').strip()
            if not cardapio_id:
                flash("Selecione um cardápio.", "error")
                return redirect(url_for('senha_visitante', **extra))
            cur2 = mysql.connection.cursor()
            cur2.execute(
                "SELECT id, tipo_refeicao, descricao FROM cardapios WHERE id=%s AND ativo=1 AND data_cardapio=CURDATE()",
                (cardapio_id,)
            )
            cardapio = cur2.fetchone()
            cur2.close()
            if not cardapio:
                flash("Cardápio inválido ou indisponível.", "error")
                return redirect(url_for('senha_visitante', **extra))
            if refeicao_do_cardapio(cardapio[1]) != refeicao_por_horario():
                flash(msg_cardapio_fora_do_horario(), "error")
                return redirect(url_for('senha_visitante', **extra))
            cardapio_id, c_tipo, c_descricao = cardapio

        cur = mysql.connection.cursor()
        data_hoje = date.today()

        # CPF de colaborador não emite como visitante: a senha sairia com o limite e o custo errados
        cur.execute("SELECT 1 FROM colaboradores WHERE cpf = %s LIMIT 1", (cpf,))
        if cur.fetchone():
            cur.close()
            logger.info(f"{usuario_logado}: CPF {cpf} de colaborador recusado na emissão de visitante.")
            flash("Este CPF está cadastrado como colaborador. Use a opção Colaborador para emitir a senha.", "error")
            return redirect(url_for('senha_visitante', **extra))

        limite_diario = limite_visitante(localizacao)
        with trava_emissao() as travou:
            if not travou:
                flash("Sistema ocupado. Tente de novo em alguns segundos.", "error")
                cur.close()
                return redirect(url_for('senha_visitante', **extra))
            cur.execute("SELECT COUNT(*) FROM emissoes_senha WHERE cpf=%s AND DATE(data_hora)=%s", (cpf, data_hoje))
            if cur.fetchone()[0] >= limite_diario:
                flash(f"Você atingiu o limite diário de {limite_diario} senha(s).", "error")
                cur.close()
                return redirect(url_for('senha_visitante', **extra))

            cur.execute("SELECT COALESCE(MAX(numero_senha),0) FROM emissoes_senha WHERE DATE(data_hora)=%s", (data_hoje,))
            novo_numero = cur.fetchone()[0] + 1
            try:
                cur.execute("""
                    INSERT INTO emissoes_senha
                        (nome, cpf, cargo, departamento, data_hora, numero_senha,
                         cardapio_id, tipo_refeicao, descricao_cardapio)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """, (nome, cpf, 'VISITANTE', localizacao, datetime.now(), novo_numero,
                      cardapio_id, c_tipo, c_descricao))
                mysql.connection.commit()
                logger.info(f"{usuario_logado}: Senha Nº {novo_numero:03d} para visitante CPF {cpf}.")
                flash(f"Senha Nº {novo_numero:03d} emitida com sucesso!", "success")
            except Exception as e:
                mysql.connection.rollback()
                logger.error(f"Erro ao emitir senha visitante: {e}")
                flash("Erro ao registrar a senha.", "error")
        cur.close()
        return redirect(url_for('senha_visitante', **extra))

    if modo == 'tablet':
        return render_template('emissao_senha_tablet.html', tipo_senha='visitante',
                               localizacoes=localizacoes, cardapios_hoje=cardapios_hoje,
                               tipo_emissao=tipo_emissao)
    return render_template('emissao_senha.html', tipo_senha='visitante',
                           localizacoes=localizacoes, cardapios_hoje=cardapios_hoje,
                           tipo_emissao=tipo_emissao)


@app.route('/logout')
def logout():
    if session.get('usuario_id'):
        auditar(forcar=True, resultado='ok')
    session.clear()
    return redirect('/')



# ─── CARDÁPIO ────────────────────────────────────────────────────────────────

import os
from collections import OrderedDict
from werkzeug.utils import secure_filename

CARDAPIO_UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'static', 'uploads', 'cardapio')
CARDAPIO_ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'webp'}
CARDAPIO_MAX_SIZE = 5 * 1024 * 1024  # 5 MB

os.makedirs(CARDAPIO_UPLOAD_FOLDER, exist_ok=True)


def _cardapio_upload_foto(file_obj):
    if not file_obj or file_obj.filename == '':
        return None
    ext = file_obj.filename.rsplit('.', 1)[-1].lower()
    if ext not in CARDAPIO_ALLOWED_EXTENSIONS:
        return None
    file_obj.seek(0, 2)
    size = file_obj.tell()
    file_obj.seek(0)
    if size > CARDAPIO_MAX_SIZE:
        return None
    import time as _time
    filename = f"{int(_time.time())}_{secure_filename(file_obj.filename)}"
    file_obj.save(os.path.join(CARDAPIO_UPLOAD_FOLDER, filename))
    return filename


# Refeições pagas/servidas: café da manhã, almoço e jantar (não há lanche)
TIPOS_REFEICAO = ['Café da Manhã', 'Almoço', 'Jantar']

# (chave, rótulo, ícone, como entra no texto da descrição)
CATEGORIAS_PRATO = [
    ('principal',      'Prato principal',   'fa-drumstick-bite'),
    ('acompanhamento', 'Acompanhamentos',   'fa-bowl-rice'),
    ('padaria',        'Pães e frios',      'fa-bread-slice'),
    ('salada',         'Saladas',           'fa-leaf'),
    ('sobremesa',      'Sobremesa / Fruta', 'fa-apple-whole'),
    ('bebida',         'Bebidas',           'fa-glass-water'),
]
CATEGORIAS_CHAVES = [c[0] for c in CATEGORIAS_PRATO]
_DIAS_SEMANA_PT = ['Segunda', 'Terça', 'Quarta', 'Quinta', 'Sexta', 'Sábado', 'Domingo']
_ORDEM_TIPOS_SQL = "FIELD(tipo_refeicao,'Café da Manhã','Almoço','Jantar')"


def init_cardapio_catalogo():
    """Cria as tabelas do catálogo de pratos (idempotente)."""
    cur = mysql.connection.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS pratos (
            id         INT AUTO_INCREMENT PRIMARY KEY,
            nome       VARCHAR(150) NOT NULL,
            categoria  VARCHAR(30)  NOT NULL,
            foto       VARCHAR(255) DEFAULT NULL,
            ativo      TINYINT(1)   NOT NULL DEFAULT 1,
            criado_em  TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uk_prato_nome_cat (nome, categoria)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS cardapio_itens (
            id          INT AUTO_INCREMENT PRIMARY KEY,
            cardapio_id INT NOT NULL,
            prato_id    INT NOT NULL,
            ordem       INT NOT NULL DEFAULT 0,
            KEY idx_ci_cardapio (cardapio_id),
            KEY idx_ci_prato (prato_id),
            CONSTRAINT fk_ci_cardapio FOREIGN KEY (cardapio_id) REFERENCES cardapios(id) ON DELETE CASCADE,
            CONSTRAINT fk_ci_prato    FOREIGN KEY (prato_id)    REFERENCES pratos(id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    """)
    mysql.connection.commit()
    cur.close()


def _normalizar_nome_prato(nome):
    return ' '.join((nome or '').split()).upper()[:150]


def _gerar_descricao(itens):
    """Monta o texto (formato que o totem e os relatórios já usam) a partir dos itens.
    itens: lista de dicts {nome, categoria} já ordenados."""
    por_cat = {k: [i['nome'] for i in itens if i['categoria'] == k] for k in CATEGORIAS_CHAVES}
    linhas = []
    if por_cat['principal']:
        linhas.append(' OU '.join(por_cat['principal']))
    linhas += por_cat['acompanhamento']
    linhas += por_cat['padaria']
    if por_cat['salada']:
        linhas.append('SALADA: ' + ', '.join(por_cat['salada']))
    if por_cat['sobremesa']:
        linhas.append('SOBREMESA: ' + ' OU '.join(por_cat['sobremesa']))
    if por_cat['bebida']:
        linhas.append('BEBIDA: ' + ' OU '.join(por_cat['bebida']))
    return '\n'.join(linhas)


def _foto_dos_itens(itens):
    """Foto exibida no totem/página pública: 1º prato principal com foto, senão qualquer item com foto."""
    for i in itens:
        if i['categoria'] == 'principal' and i.get('foto'):
            return i['foto']
    for i in itens:
        if i.get('foto'):
            return i['foto']
    return None


def _itens_do_cardapio(cur, cardapio_id):
    cur.execute("""
        SELECT p.id, p.nome, p.categoria, p.foto
        FROM cardapio_itens ci JOIN pratos p ON p.id = ci.prato_id
        WHERE ci.cardapio_id = %s ORDER BY ci.ordem, ci.id
    """, (cardapio_id,))
    return [{'id': r[0], 'nome': r[1], 'categoria': r[2], 'foto': r[3]} for r in cur.fetchall()]


def _gravar_cardapio(cur, data_ref, tipo, prato_ids, ativo=1):
    """Cria ou substitui o cardápio (data, tipo) com os pratos informados. Retorna o id."""
    cur.execute("SELECT id FROM cardapios WHERE data_cardapio=%s AND tipo_refeicao=%s ORDER BY id LIMIT 1",
                (data_ref, tipo))
    row = cur.fetchone()
    if row:
        cardapio_id = row[0]
    else:
        cur.execute("INSERT INTO cardapios (data_cardapio, tipo_refeicao, descricao, ativo, criado_em) "
                    "VALUES (%s, %s, '', %s, NOW())", (data_ref, tipo, ativo))
        cardapio_id = cur.lastrowid
    cur.execute("DELETE FROM cardapio_itens WHERE cardapio_id=%s", (cardapio_id,))
    for ordem, pid in enumerate(prato_ids):
        cur.execute("INSERT INTO cardapio_itens (cardapio_id, prato_id, ordem) VALUES (%s, %s, %s)",
                    (cardapio_id, pid, ordem))
    itens = _itens_do_cardapio(cur, cardapio_id)
    itens.sort(key=lambda i: CATEGORIAS_CHAVES.index(i['categoria']) if i['categoria'] in CATEGORIAS_CHAVES else 99)
    cur.execute("UPDATE cardapios SET descricao=%s, foto=%s, ativo=%s WHERE id=%s",
                (_gerar_descricao(itens), _foto_dos_itens(itens), ativo, cardapio_id))
    return cardapio_id


def _regerar_cardapios_futuros_do_prato(cur, prato_id):
    """Após editar um prato, atualiza texto/foto dos cardápios de hoje em diante que o usam."""
    cur.execute("""
        SELECT DISTINCT c.id, c.data_cardapio, c.tipo_refeicao, c.ativo
        FROM cardapios c JOIN cardapio_itens ci ON ci.cardapio_id = c.id
        WHERE ci.prato_id = %s AND c.data_cardapio >= CURDATE()
    """, (prato_id,))
    for cid, dref, tipo, ativo in cur.fetchall():
        ids = [i['id'] for i in _itens_do_cardapio(cur, cid)]
        _gravar_cardapio(cur, dref, tipo, ids, ativo)


def _parse_data(valor, padrao=None):
    try:
        return datetime.strptime(valor, '%Y-%m-%d').date()
    except (TypeError, ValueError):
        return padrao


def _guard_admin():
    """Só exige login: a permissão da rota é checada em _checar_permissao (perfis)."""
    if 'usuario_id' not in session:
        return redirect('/')
    return None


def _cardapios_do_dia(data_ref, somente_ativos=True):
    """Cardápios de um dia com itens agrupados por categoria (página pública / admin)."""
    cur = mysql.connection.cursor()
    filtro = "AND ativo = 1" if somente_ativos else ""
    cur.execute(f"""
        SELECT id, tipo_refeicao, descricao, foto, ativo FROM cardapios
        WHERE data_cardapio = %s {filtro} ORDER BY {_ORDEM_TIPOS_SQL}
    """, (data_ref,))
    lista = []
    for cid, tipo, desc, foto, ativo in cur.fetchall():
        itens = _itens_do_cardapio(cur, cid)
        grupos = []
        for chave, rotulo, icone in CATEGORIAS_PRATO:
            nomes = [i['nome'] for i in itens if i['categoria'] == chave]
            if nomes:
                grupos.append({'chave': chave, 'rotulo': rotulo, 'icone': icone, 'itens': nomes})
        lista.append({'id': cid, 'tipo_refeicao': tipo, 'descricao': desc or '', 'foto': foto,
                      'ativo': bool(ativo), 'grupos': grupos})
    cur.close()
    return lista


@app.route('/cardapio')
def cardapio_publico():
    from datetime import date as _date, timedelta
    init_cardapio_catalogo()
    hoje = _date.today()
    amanha = hoje + timedelta(days=1)

    _DIAS_PT = {
        'Monday': 'Segunda-feira', 'Tuesday': 'Terça-feira',
        'Wednesday': 'Quarta-feira', 'Thursday': 'Quinta-feira',
        'Friday': 'Sexta-feira', 'Saturday': 'Sábado', 'Sunday': 'Domingo'
    }
    def fmt(d):
        return f"{_DIAS_PT.get(d.strftime('%A'), d.strftime('%A'))}, {d.strftime('%d/%m/%Y')}"

    agora_dt = datetime.now()
    return render_template(
        'cardapio_publico.html',
        cardapios_hoje=_cardapios_do_dia(hoje),
        cardapios_amanha=_cardapios_do_dia(amanha),
        dia_fmt=fmt(hoje),
        amanha_fmt=fmt(amanha),
        agora=agora_dt.strftime('%d/%m/%Y %H:%M'),
        servindo_agora=_refeicao_do_horario(agora_dt.time()),
        nome_instituicao=get_instituicao(),
    )


def _refeicao_do_horario(hora):
    """Refeição em serviço agora, conforme Parâmetros › Horários de turno."""
    t = get_turnos()
    faixas = [('Café da Manhã', 'turno_cafe_ini', 'turno_cafe_fim'),
              ('Almoço', 'turno_almoco_ini', 'turno_almoco_fim'),
              ('Jantar', 'turno_janta_ini', 'turno_janta_fim')]
    for tipo, ini, fim in faixas:
        if t[ini] <= hora <= t[fim]:
            return tipo
    return None


_MINUSCULAS_NOME = {'de', 'da', 'do', 'das', 'dos', 'e', 'ou', 'com', 'a', 'ao', 'à', 'na', 'no', 'em'}

def nome_prato(nome):
    """'COZIDÃO DE CARNE' -> 'Cozidão de carne' (só para exibição)."""
    palavras = (nome or '').lower().split()
    out = []
    for i, p in enumerate(palavras):
        out.append(p if (i > 0 and p in _MINUSCULAS_NOME) else (p[:1].upper() + p[1:]))
    return ' '.join(out)

app.jinja_env.filters['nome_prato'] = nome_prato


# ─── CARDÁPIO: PLANEJAMENTO DA SEMANA ────────────────────────────────────────

@app.route('/admin/cardapio')
def cardapio_admin():
    from datetime import timedelta
    g = _guard_admin()
    if g: return g
    init_cardapio_catalogo()

    ref = _parse_data(request.args.get('semana'), date.today())
    inicio = ref - timedelta(days=ref.weekday())          # segunda-feira
    dias = [inicio + timedelta(days=i) for i in range(7)]

    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT c.id, c.data_cardapio, c.tipo_refeicao, c.descricao, c.ativo, c.foto,
               (SELECT GROUP_CONCAT(p.nome ORDER BY ci.ordem SEPARATOR ' OU ')
                  FROM cardapio_itens ci JOIN pratos p ON p.id = ci.prato_id
                 WHERE ci.cardapio_id = c.id AND p.categoria = 'principal') AS principais,
               (SELECT COUNT(*) FROM cardapio_itens ci WHERE ci.cardapio_id = c.id) AS n_itens
        FROM cardapios c
        WHERE c.data_cardapio BETWEEN %s AND %s
    """, (dias[0], dias[-1]))
    mapa = {}
    for cid, dref, tipo, desc, ativo, foto, principais, n_itens in cur.fetchall():
        resumo = principais or ((desc or '').strip().split('\n')[0] if desc else '')
        mapa[(dref, tipo)] = {'id': cid, 'resumo': resumo, 'ativo': bool(ativo), 'foto': foto,
                              'n_itens': n_itens, 'legado': n_itens == 0}
    cur.close()

    semana = []
    for i, d in enumerate(dias):
        semana.append({
            'data': d, 'iso': d.isoformat(), 'dia_semana': _DIAS_SEMANA_PT[i],
            'rotulo': d.strftime('%d/%m'), 'hoje': d == date.today(),
            'refeicoes': [{'tipo': t, 'c': mapa.get((d, t))} for t in TIPOS_REFEICAO],
        })
    preenchidos = sum(1 for k in mapa if k[1] in TIPOS_REFEICAO)
    return render_template('menu_admin.html', module='cardapio_semana', usuario=get_usuario_logado(),
                           semana=semana, tipos_refeicao=TIPOS_REFEICAO,
                           semana_ini=dias[0], semana_fim=dias[-1],
                           semana_ant=(dias[0] - timedelta(days=7)).isoformat(),
                           semana_prox=(dias[0] + timedelta(days=7)).isoformat(),
                           semana_atual=(date.today() - timedelta(days=date.today().weekday())) == dias[0],
                           preenchidos=preenchidos, total_slots=7 * len(TIPOS_REFEICAO))


@app.route('/admin/cardapio/copiar-semana', methods=['POST'])
def cardapio_copiar_semana():
    """Copia a semana anterior para a semana informada, só nos horários ainda vazios."""
    from datetime import timedelta
    g = _guard_admin()
    if g: return g
    init_cardapio_catalogo()
    ref = _parse_data(request.form.get('semana'), date.today())
    inicio = ref - timedelta(days=ref.weekday())
    copiados = 0
    try:
        cur = mysql.connection.cursor()
        for i in range(7):
            destino = inicio + timedelta(days=i)
            origem = destino - timedelta(days=7)
            for tipo in TIPOS_REFEICAO:
                cur.execute("SELECT id FROM cardapios WHERE data_cardapio=%s AND tipo_refeicao=%s", (destino, tipo))
                if cur.fetchone():
                    continue
                cur.execute("SELECT id, ativo FROM cardapios WHERE data_cardapio=%s AND tipo_refeicao=%s ORDER BY id LIMIT 1",
                            (origem, tipo))
                src = cur.fetchone()
                if not src:
                    continue
                ids = [it['id'] for it in _itens_do_cardapio(cur, src[0])]
                if ids:
                    _gravar_cardapio(cur, destino, tipo, ids, 1)
                    copiados += 1
        mysql.connection.commit()
        cur.close()
        logger.info(f"{get_usuario_logado()} copiou a semana anterior para {inicio} ({copiados} refeições).")
        flash(f"{copiados} refeição(ões) copiada(s) da semana anterior." if copiados
              else "Nada para copiar: a semana anterior não tem refeições montadas ou os horários já estão preenchidos.",
              "success" if copiados else "error")
    except Exception as e:
        mysql.connection.rollback()
        logger.error(f"Erro ao copiar semana: {e}")
        flash("Erro ao copiar a semana anterior.", "error")
    return redirect(url_for('cardapio_admin', semana=inicio.isoformat()))


# ─── CARDÁPIO: MONTAR REFEIÇÃO DO DIA ────────────────────────────────────────

@app.route('/admin/cardapio/montar', methods=['GET', 'POST'])
def cardapio_montar():
    from datetime import timedelta
    g = _guard_admin()
    if g: return g
    init_cardapio_catalogo()

    if request.method == 'POST':
        data_ref = _parse_data(request.form.get('data'))
        tipo = request.form.get('tipo', '')
        ativo = 1 if request.form.get('ativo') else 0
        if not data_ref or tipo not in TIPOS_REFEICAO:
            flash("Data ou refeição inválida.", "error")
            return redirect(url_for('cardapio_admin'))
        try:
            cur = mysql.connection.cursor()
            prato_ids, novos = [], 0
            for cat in CATEGORIAS_CHAVES:
                for nome in request.form.getlist(f'itens_{cat}'):
                    nome = _normalizar_nome_prato(nome)
                    if not nome:
                        continue
                    cur.execute("SELECT id FROM pratos WHERE nome=%s AND categoria=%s", (nome, cat))
                    row = cur.fetchone()
                    if row:
                        pid = row[0]
                    else:
                        cur.execute("INSERT INTO pratos (nome, categoria) VALUES (%s, %s)", (nome, cat))
                        pid = cur.lastrowid
                        novos += 1
                    if pid not in prato_ids:
                        prato_ids.append(pid)
            if not prato_ids:
                cur.close()
                flash("Adicione pelo menos um prato à refeição.", "error")
                return redirect(url_for('cardapio_montar', data=data_ref.isoformat(), tipo=tipo))
            _gravar_cardapio(cur, data_ref, tipo, prato_ids, ativo)
            mysql.connection.commit()
            cur.close()
            logger.info(f"{get_usuario_logado()} montou o cardápio {tipo} de {data_ref} ({len(prato_ids)} itens, {novos} pratos novos).")
            msg = f"{tipo} de {data_ref.strftime('%d/%m')} salvo!"
            if novos:
                msg += f" {novos} prato(s) novo(s) adicionado(s) ao catálogo."
            flash(msg, "success")
        except Exception as e:
            mysql.connection.rollback()
            logger.error(f"Erro ao montar cardápio: {e}")
            flash("Erro ao salvar o cardápio.", "error")
        return redirect(url_for('cardapio_montar', data=data_ref.isoformat(), tipo=tipo))

    data_ref = _parse_data(request.args.get('data'), date.today())
    tipo = request.args.get('tipo')
    if tipo not in TIPOS_REFEICAO:
        tipo = 'Almoço'

    cur = mysql.connection.cursor()
    # status das 4 refeições do dia (abas)
    cur.execute("SELECT tipo_refeicao, ativo FROM cardapios WHERE data_cardapio=%s", (data_ref,))
    status_tipos = {r[0]: bool(r[1]) for r in cur.fetchall()}

    cur.execute("SELECT id, descricao, ativo FROM cardapios WHERE data_cardapio=%s AND tipo_refeicao=%s ORDER BY id LIMIT 1",
                (data_ref, tipo))
    row = cur.fetchone()
    atual = None
    if row:
        itens = _itens_do_cardapio(cur, row[0])
        atual = {'id': row[0], 'descricao': row[1] or '', 'ativo': bool(row[2]), 'itens': itens,
                 'legado': not itens}

    # catálogo + mais usados nesta refeição (sugestões rápidas)
    cur.execute("""
        SELECT p.id, p.nome, p.categoria, p.foto,
               COALESCE(SUM(c.tipo_refeicao = %s), 0) AS usos_tipo, COUNT(ci.id) AS usos
        FROM pratos p
        LEFT JOIN cardapio_itens ci ON ci.prato_id = p.id
        LEFT JOIN cardapios c ON c.id = ci.cardapio_id
        WHERE p.ativo = 1
        GROUP BY p.id ORDER BY usos_tipo DESC, usos DESC, p.nome
    """, (tipo,))
    catalogo = [{'id': r[0], 'nome': r[1], 'categoria': r[2], 'foto': r[3],
                 'usos_tipo': int(r[4]), 'usos': int(r[5])} for r in cur.fetchall()]
    cur.close()

    sugestoes = {}
    for cat in CATEGORIAS_CHAVES:
        sugestoes[cat] = [p for p in catalogo if p['categoria'] == cat and p['usos'] > 0][:8]

    ontem = data_ref - timedelta(days=1)
    semana_passada = data_ref - timedelta(days=7)
    return render_template('menu_admin.html', module='cardapio_montar', usuario=get_usuario_logado(),
                           data_ref=data_ref, data_iso=data_ref.isoformat(),
                           dia_semana=_DIAS_SEMANA_PT[data_ref.weekday()],
                           dia_ant=ontem.isoformat(), dia_prox=(data_ref + timedelta(days=1)).isoformat(),
                           ontem_iso=ontem.isoformat(), semana_passada_iso=semana_passada.isoformat(),
                           tipo=tipo, tipos_refeicao=TIPOS_REFEICAO, status_tipos=status_tipos,
                           atual=atual, catalogo=catalogo, sugestoes=sugestoes,
                           categorias=CATEGORIAS_PRATO, hoje_iso=date.today().isoformat())


@app.route('/admin/cardapio/copiar', methods=['POST'])
def cardapio_copiar():
    """Copia uma refeição (ou o dia inteiro) de uma data para outra, substituindo o destino."""
    g = _guard_admin()
    if g: return g
    init_cardapio_catalogo()
    origem = _parse_data(request.form.get('origem'))
    destino = _parse_data(request.form.get('destino'))
    tipo = request.form.get('tipo', '')
    voltar_tipo = request.form.get('voltar_tipo') or (tipo if tipo in TIPOS_REFEICAO else 'Almoço')
    if not origem or not destino:
        flash("Datas inválidas para copiar.", "error")
        return redirect(url_for('cardapio_admin'))
    tipos = TIPOS_REFEICAO if tipo == 'todas' else ([tipo] if tipo in TIPOS_REFEICAO else [])
    copiados, legados = 0, 0
    try:
        cur = mysql.connection.cursor()
        for t in tipos:
            cur.execute("SELECT id, ativo FROM cardapios WHERE data_cardapio=%s AND tipo_refeicao=%s ORDER BY id LIMIT 1",
                        (origem, t))
            src = cur.fetchone()
            if not src:
                continue
            ids = [it['id'] for it in _itens_do_cardapio(cur, src[0])]
            if not ids:
                legados += 1
                continue
            _gravar_cardapio(cur, destino, t, ids, 1)
            copiados += 1
        mysql.connection.commit()
        cur.close()
        if copiados:
            flash(f"{copiados} refeição(ões) copiada(s) de {origem.strftime('%d/%m')}. Revise e ajuste o que mudou.", "success")
        elif legados:
            flash("A refeição de origem está no formato antigo (texto livre) e não pode ser copiada.", "error")
        else:
            flash(f"Não há cardápio montado em {origem.strftime('%d/%m')} para copiar.", "error")
    except Exception as e:
        mysql.connection.rollback()
        logger.error(f"Erro ao copiar cardápio: {e}")
        flash("Erro ao copiar o cardápio.", "error")
    return redirect(url_for('cardapio_montar', data=destino.isoformat(), tipo=voltar_tipo))


# Rotas antigas: redirecionam para o novo fluxo (links/favoritos continuam funcionando)
@app.route('/admin/cardapio/novo')
def cardapio_novo():
    return redirect(url_for('cardapio_montar', **request.args))


@app.route('/admin/cardapio/editar/<int:cardapio_id>')
def cardapio_editar(cardapio_id):
    g = _guard_admin()
    if g: return g
    cur = mysql.connection.cursor()
    cur.execute("SELECT data_cardapio, tipo_refeicao FROM cardapios WHERE id=%s", (cardapio_id,))
    row = cur.fetchone()
    cur.close()
    if not row:
        flash("Cardápio não encontrado.", "error")
        return redirect(url_for('cardapio_admin'))
    return redirect(url_for('cardapio_montar', data=row[0].isoformat(), tipo=row[1]))


def _voltar_para_montar(cardapio_row):
    if cardapio_row:
        return redirect(url_for('cardapio_montar', data=cardapio_row[0].isoformat(), tipo=cardapio_row[1]))
    return redirect(url_for('cardapio_admin'))


@app.route('/admin/cardapio/toggle/<int:cardapio_id>', methods=['POST'])
def cardapio_toggle(cardapio_id):
    if 'usuario_id' not in session or requer_admin():
        return redirect('/')
    cur = mysql.connection.cursor()
    cur.execute("SELECT data_cardapio, tipo_refeicao FROM cardapios WHERE id=%s", (cardapio_id,))
    row = cur.fetchone()
    try:
        cur.execute("UPDATE cardapios SET ativo = NOT ativo WHERE id = %s", (cardapio_id,))
        mysql.connection.commit()
        flash("Status atualizado.", "success")
    except Exception:
        mysql.connection.rollback()
        flash("Erro ao atualizar status.", "error")
    finally:
        cur.close()
    return _voltar_para_montar(row)


@app.route('/admin/cardapio/excluir/<int:cardapio_id>', methods=['POST'])
def cardapio_excluir(cardapio_id):
    if 'usuario_id' not in session or requer_admin():
        return redirect('/')
    usuario_logado = get_usuario_logado()
    init_cardapio_catalogo()
    cur = mysql.connection.cursor()
    cur.execute("SELECT data_cardapio, tipo_refeicao, foto FROM cardapios WHERE id = %s", (cardapio_id,))
    row = cur.fetchone()
    try:
        cur.execute("DELETE FROM cardapios WHERE id = %s", (cardapio_id,))
        # A foto pode ser do catálogo ou de outros dias: só apaga o arquivo se ninguém mais usa
        if row and row[2]:
            cur.execute("SELECT (SELECT COUNT(*) FROM pratos WHERE foto=%s) + "
                        "(SELECT COUNT(*) FROM cardapios WHERE foto=%s)", (row[2], row[2]))
            if cur.fetchone()[0] == 0:
                foto_path = os.path.join(CARDAPIO_UPLOAD_FOLDER, row[2])
                if os.path.exists(foto_path):
                    os.remove(foto_path)
        mysql.connection.commit()
        logger.info(f"{usuario_logado} excluiu cardápio ID {cardapio_id}.")
        flash("Refeição removida do cardápio.", "success")
    except Exception:
        mysql.connection.rollback()
        flash("Erro ao excluir cardápio.", "error")
    finally:
        cur.close()
    return _voltar_para_montar(row)


# ─── CARDÁPIO: CATÁLOGO DE PRATOS ────────────────────────────────────────────

@app.route('/admin/cardapio/pratos', methods=['GET', 'POST'])
def cardapio_pratos():
    g = _guard_admin()
    if g: return g
    init_cardapio_catalogo()

    if request.method == 'POST':
        nome = _normalizar_nome_prato(request.form.get('nome'))
        categoria = request.form.get('categoria', '')
        if not nome or categoria not in CATEGORIAS_CHAVES:
            flash("Informe o nome e a categoria do prato.", "error")
            return redirect(url_for('cardapio_pratos'))
        foto_nome = None
        foto_file = request.files.get('foto')
        if foto_file and foto_file.filename:
            foto_nome = _cardapio_upload_foto(foto_file)
            if foto_nome is None:
                flash("Foto inválida. Use JPG/PNG/WEBP com no máximo 5 MB.", "error")
                return redirect(url_for('cardapio_pratos'))
        try:
            cur = mysql.connection.cursor()
            cur.execute("SELECT id FROM pratos WHERE nome=%s AND categoria=%s", (nome, categoria))
            if cur.fetchone():
                flash(f"“{nome}” já existe nessa categoria.", "error")
            else:
                cur.execute("INSERT INTO pratos (nome, categoria, foto) VALUES (%s, %s, %s)", (nome, categoria, foto_nome))
                mysql.connection.commit()
                logger.info(f"{get_usuario_logado()} cadastrou o prato {nome} ({categoria}).")
                flash(f"“{nome}” adicionado ao catálogo.", "success")
            cur.close()
        except Exception as e:
            mysql.connection.rollback()
            logger.error(f"Erro ao cadastrar prato: {e}")
            flash("Erro ao cadastrar prato.", "error")
        return redirect(url_for('cardapio_pratos', cat=categoria))

    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT p.id, p.nome, p.categoria, p.foto, p.ativo,
               COUNT(ci.id) AS usos, MAX(c.data_cardapio) AS ultimo
        FROM pratos p
        LEFT JOIN cardapio_itens ci ON ci.prato_id = p.id
        LEFT JOIN cardapios c ON c.id = ci.cardapio_id
        GROUP BY p.id ORDER BY p.ativo DESC, p.nome
    """)
    pratos = [{'id': r[0], 'nome': r[1], 'categoria': r[2], 'foto': r[3], 'ativo': bool(r[4]),
               'usos': int(r[5]), 'ultimo': r[6].strftime('%d/%m/%Y') if r[6] else None}
              for r in cur.fetchall()]
    cur.close()
    contagem = {k: sum(1 for p in pratos if p['categoria'] == k) for k in CATEGORIAS_CHAVES}
    return render_template('menu_admin.html', module='cardapio_pratos', usuario=get_usuario_logado(),
                           pratos=pratos, categorias=CATEGORIAS_PRATO, contagem=contagem,
                           cat_atual=request.args.get('cat', ''))


@app.route('/admin/cardapio/pratos/<int:prato_id>/editar', methods=['POST'])
def cardapio_prato_editar(prato_id):
    g = _guard_admin()
    if g: return g
    nome = _normalizar_nome_prato(request.form.get('nome'))
    categoria = request.form.get('categoria', '')
    ativo = 1 if request.form.get('ativo') else 0
    if not nome or categoria not in CATEGORIAS_CHAVES:
        flash("Informe o nome e a categoria do prato.", "error")
        return redirect(url_for('cardapio_pratos'))
    foto_nome = None
    foto_file = request.files.get('foto')
    if foto_file and foto_file.filename:
        foto_nome = _cardapio_upload_foto(foto_file)
        if foto_nome is None:
            flash("Foto inválida. Use JPG/PNG/WEBP com no máximo 5 MB.", "error")
            return redirect(url_for('cardapio_pratos', cat=categoria))
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT id FROM pratos WHERE nome=%s AND categoria=%s AND id<>%s", (nome, categoria, prato_id))
        if cur.fetchone():
            cur.close()
            flash(f"Já existe outro prato “{nome}” nessa categoria.", "error")
            return redirect(url_for('cardapio_pratos', cat=categoria))
        if foto_nome:
            cur.execute("UPDATE pratos SET nome=%s, categoria=%s, ativo=%s, foto=%s WHERE id=%s",
                        (nome, categoria, ativo, foto_nome, prato_id))
        elif request.form.get('remover_foto'):
            cur.execute("UPDATE pratos SET nome=%s, categoria=%s, ativo=%s, foto=NULL WHERE id=%s",
                        (nome, categoria, ativo, prato_id))
        else:
            cur.execute("UPDATE pratos SET nome=%s, categoria=%s, ativo=%s WHERE id=%s",
                        (nome, categoria, ativo, prato_id))
        _regerar_cardapios_futuros_do_prato(cur, prato_id)
        mysql.connection.commit()
        cur.close()
        logger.info(f"{get_usuario_logado()} editou o prato ID {prato_id} ({nome}).")
        flash(f"“{nome}” atualizado. Cardápios de hoje em diante já refletem a mudança.", "success")
    except Exception as e:
        mysql.connection.rollback()
        logger.error(f"Erro ao editar prato: {e}")
        flash("Erro ao editar prato.", "error")
    return redirect(url_for('cardapio_pratos', cat=categoria))


@app.route('/admin/cardapio/pratos/<int:prato_id>/excluir', methods=['POST'])
def cardapio_prato_excluir(prato_id):
    g = _guard_admin()
    if g: return g
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT COUNT(*) FROM cardapio_itens WHERE prato_id=%s", (prato_id,))
        if cur.fetchone()[0] > 0:
            cur.execute("UPDATE pratos SET ativo=0 WHERE id=%s", (prato_id,))
            flash("Este prato já foi usado em cardápios, então foi desativado (some das sugestões, mas o histórico é mantido).", "success")
        else:
            cur.execute("DELETE FROM pratos WHERE id=%s", (prato_id,))
            flash("Prato excluído do catálogo.", "success")
        mysql.connection.commit()
        cur.close()
    except Exception as e:
        mysql.connection.rollback()
        logger.error(f"Erro ao excluir prato: {e}")
        flash("Erro ao excluir prato.", "error")
    return redirect(url_for('cardapio_pratos'))


# ─── DISPENSA DE REFEIÇÃO PARA PACIENTES ──────────────────────────────────────
# Fase 1: tipos de refeição do paciente, importação do CSV da Salutem (com prévia)
# e tela da cozinha para definir as refeições de cada paciente.

import csv as _csv
import json as _json
import re as _re
import unicodedata as _ud
import uuid as _uuid

DISPENSA_TMP_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads', 'dispensa_tmp')
DISPENSA_CSV_MAX = 5 * 1024 * 1024  # 5 MB
os.makedirs(DISPENSA_TMP_FOLDER, exist_ok=True)

_DISPENSA_TIPOS_PADRAO = ['Desjejum', 'Colação', 'Almoço', 'Lanche', 'Jantar', 'Ceia']

# Colunas aceitas no CSV (nomes normalizados: minúsculas, sem acento, "_" no lugar de espaços)
_DISPENSA_COLUNAS = {
    'nome':             ['nome', 'nome_completo', 'nome_paciente', 'paciente', 'nome_do_paciente'],
    'nome_mae':         ['nome_mae', 'mae', 'nome_da_mae', 'nome_mae_paciente'],
    'data_nascimento':  ['data_nascimento', 'dt_nascimento', 'nascimento', 'data_nasc', 'dt_nasc', 'dn', 'data_de_nascimento'],
    'prontuario':       ['prontuario', 'pront', 'nr_prontuario', 'num_prontuario', 'cd_prontuario'],
    'atendimento':      ['atendimento', 'nr_atendimento', 'num_atendimento', 'cd_atendimento', 'atend'],
    'data_prescricao':  ['data_prescricao', 'dt_prescricao', 'prescricao', 'data', 'data_da_prescricao'],
    'leito':            ['leito', 'leito_atual', 'ds_leito'],
    'dieta':            ['dieta', 'tipo_dieta', 'tipo_de_dieta', 'ds_dieta'],
    'unidade':          ['unidade', 'unidade_internacao', 'unidade_de_internacao', 'setor', 'ala', 'ds_unidade'],
    'observacao':       ['observacao', 'observacoes', 'obs', 'observacao_nutricionista', 'obs_nutricao', 'ds_observacao'],
}
_DISPENSA_OBRIGATORIAS = ['nome', 'atendimento', 'data_prescricao', 'leito']
_DISPENSA_ROTULOS = {
    'nome': 'Nome completo', 'nome_mae': 'Nome da mãe', 'data_nascimento': 'Data de nascimento',
    'prontuario': 'Prontuário', 'atendimento': 'Atendimento', 'data_prescricao': 'Data da prescrição',
    'leito': 'Leito', 'dieta': 'Tipo de dieta', 'unidade': 'Unidade de internação',
    'observacao': 'Observação do nutricionista',
}


def init_dispensa_tables():
    """Cria as tabelas do módulo de dispensa (idempotente) e os tipos padrão."""
    cur = mysql.connection.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS dispensa_tipos (
            id        INT AUTO_INCREMENT PRIMARY KEY,
            nome      VARCHAR(80)  NOT NULL,
            descricao VARCHAR(255) DEFAULT NULL,
            valor     DECIMAL(10,2) NOT NULL DEFAULT 0,
            ordem     INT NOT NULL DEFAULT 0,
            ativo     TINYINT(1) NOT NULL DEFAULT 1,
            criado_em TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uk_dispensa_tipo_nome (nome)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS dispensa_tipos_historico (
            id          INT AUTO_INCREMENT PRIMARY KEY,
            tipo_id     INT NOT NULL,
            valor       DECIMAL(10,2) NOT NULL,
            alterado_em TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
            alterado_por VARCHAR(120) DEFAULT NULL,
            KEY idx_dth_tipo (tipo_id),
            CONSTRAINT fk_dth_tipo FOREIGN KEY (tipo_id) REFERENCES dispensa_tipos(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS dispensa_importacoes (
            id            INT AUTO_INCREMENT PRIMARY KEY,
            arquivo_nome  VARCHAR(255) NOT NULL,
            importado_em  TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
            importado_por VARCHAR(120) DEFAULT NULL,
            total_linhas  INT NOT NULL DEFAULT 0,
            inseridos     INT NOT NULL DEFAULT 0,
            atualizados   INT NOT NULL DEFAULT 0,
            ignorados     INT NOT NULL DEFAULT 0
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS dispensa_pacientes (
            id              INT AUTO_INCREMENT PRIMARY KEY,
            atendimento     VARCHAR(40)  NOT NULL,
            data_prescricao DATE         NOT NULL,
            nome            VARCHAR(200) NOT NULL,
            nome_mae        VARCHAR(200) DEFAULT NULL,
            data_nascimento DATE         DEFAULT NULL,
            prontuario      VARCHAR(40)  DEFAULT NULL,
            leito           VARCHAR(60)  NOT NULL,
            dieta           VARCHAR(200) DEFAULT NULL,
            importacao_id   INT          DEFAULT NULL,
            criado_em       TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
            atualizado_em   TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uk_dispensa_pac (atendimento, data_prescricao),
            KEY idx_dp_data (data_prescricao)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS dispensa_itens (
            id             INT AUTO_INCREMENT PRIMARY KEY,
            paciente_id    INT NOT NULL,
            tipo_id        INT NOT NULL,
            valor_unitario DECIMAL(10,2) NOT NULL DEFAULT 0 COMMENT 'Snapshot do valor no momento da definição',
            status         VARCHAR(20) NOT NULL DEFAULT 'pendente' COMMENT 'pendente | entregue | nao_entregue',
            definido_por   VARCHAR(120) DEFAULT NULL,
            definido_em    TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
            entregue_em    DATETIME DEFAULT NULL,
            entregue_por   VARCHAR(120) DEFAULT NULL,
            motivo         VARCHAR(255) DEFAULT NULL,
            UNIQUE KEY uk_dispensa_item (paciente_id, tipo_id),
            KEY idx_di_tipo (tipo_id),
            CONSTRAINT fk_di_paciente FOREIGN KEY (paciente_id) REFERENCES dispensa_pacientes(id) ON DELETE CASCADE,
            CONSTRAINT fk_di_tipo     FOREIGN KEY (tipo_id)     REFERENCES dispensa_tipos(id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    """)
    _init_dispensa_acomp(cur)
    # "Padrão por dieta" foi retirado do sistema (06/11/2026): remove as tabelas, se existirem
    cur.execute("DROP TABLE IF EXISTS dispensa_padroes_dieta")
    cur.execute("DROP TABLE IF EXISTS dispensa_dietas_sem_refeicao")
    cur.execute("SELECT COUNT(*) FROM dispensa_tipos")
    if cur.fetchone()[0] == 0:
        for i, nome in enumerate(_DISPENSA_TIPOS_PADRAO):
            cur.execute("INSERT INTO dispensa_tipos (nome, valor, ordem) VALUES (%s, 0, %s)", (nome, i))
    mysql.connection.commit()
    cur.close()


# ─── Acompanhante do paciente (pedido da direção, 06/11/2026) ────────────────
# O acompanhante pode receber refeição: padrão até 3 por dia, lactante até 5.
# A nutrição define na importação (ou depois, em Pacientes do dia); a refeição dele é um
# item da dispensa do mesmo paciente com para='acompanhante' (mesmos tipos e valores).
_dispensa_acomp_ok = False


def _init_dispensa_acomp(cur):
    global _dispensa_acomp_ok
    if _dispensa_acomp_ok:
        return
    cur.execute("ALTER TABLE dispensa_pacientes ADD COLUMN IF NOT EXISTS acomp TINYINT(1) NOT NULL DEFAULT 0 "
                "COMMENT 'Acompanhante recebe refeição'")
    cur.execute("ALTER TABLE dispensa_pacientes ADD COLUMN IF NOT EXISTS acomp_lactante TINYINT(1) NOT NULL DEFAULT 0")
    cur.execute("ALTER TABLE dispensa_pacientes ADD COLUMN IF NOT EXISTS acomp_por VARCHAR(120) DEFAULT NULL")
    cur.execute("ALTER TABLE dispensa_pacientes ADD COLUMN IF NOT EXISTS acomp_em DATETIME DEFAULT NULL")
    cur.execute("ALTER TABLE dispensa_pacientes ADD COLUMN IF NOT EXISTS unidade VARCHAR(80) DEFAULT NULL "
                "COMMENT 'Unidade de internação (Salutem ou CSV)' AFTER leito")
    cur.execute("ALTER TABLE dispensa_pacientes ADD COLUMN IF NOT EXISTS observacao TEXT DEFAULT NULL "
                "COMMENT 'Observação do nutricionista na prescrição (Salutem ou CSV)' AFTER dieta")
    cur.execute("ALTER TABLE dispensa_itens ADD COLUMN IF NOT EXISTS para VARCHAR(12) NOT NULL DEFAULT 'paciente' "
                "COMMENT 'paciente | acompanhante' AFTER tipo_id")
    # Prescrição por período (06/11 → 10/11/2026, pedido da direção): a nutrição autoriza; a cozinha só produz
    cur.execute("ALTER TABLE dispensa_tipos ADD COLUMN IF NOT EXISTS periodo VARCHAR(10) DEFAULT NULL "
                "COMMENT 'manha | noite | NULL (fora da prescrição por período)'")
    cur.execute("ALTER TABLE dispensa_tipos ADD COLUMN IF NOT EXISTS dia_seguinte TINYINT(1) NOT NULL DEFAULT 0 "
                "COMMENT '1 = a prescrição vale para a refeição do dia seguinte (ex.: desjejum da prescrição noturna)'")
    cur.execute("ALTER TABLE dispensa_tipos ADD COLUMN IF NOT EXISTS alternativa_de INT DEFAULT NULL "
                "COMMENT 'Tipo do qual este é alternativa (um OU outro, ex.: Jantar (Sopa) de Jantar)'")
    cur.execute("ALTER TABLE dispensa_itens ADD COLUMN IF NOT EXISTS autorizado_por VARCHAR(120) DEFAULT NULL")
    cur.execute("ALTER TABLE dispensa_itens ADD COLUMN IF NOT EXISTS autorizado_em DATETIME DEFAULT NULL")
    cur.execute("ALTER TABLE dispensa_itens ADD COLUMN IF NOT EXISTS origem VARCHAR(30) DEFAULT NULL "
                "COMMENT 'importacao_manha | importacao_noite | ajuste_nutricao | cozinha (antigo)'")
    cur.execute("SELECT COUNT(*) FROM dispensa_tipos WHERE periodo IS NOT NULL")
    if cur.fetchone()[0] == 0:
        # carga inicial conforme a rotina da nutrição (ajustável em Tipos de refeição)
        regras = [('ALMOÇO', 'manha', 0), ('LANCHE DA TARDE', 'manha', 0), ('LANCHE', 'manha', 0),
                  ('JANTAR', 'noite', 0), ('JANTAR (SOPA)', 'noite', 0), ('CEIA', 'noite', 0),
                  ('DESJEJUM', 'noite', 1), ('COLAÇÃO', 'noite', 1)]
        for nome, per, ds in regras:
            cur.execute("UPDATE dispensa_tipos SET periodo=%s, dia_seguinte=%s WHERE UPPER(TRIM(nome))=%s", (per, ds, nome))
        cur.execute("""UPDATE dispensa_tipos s JOIN dispensa_tipos j ON UPPER(TRIM(j.nome))='JANTAR'
                       SET s.alternativa_de = j.id WHERE UPPER(TRIM(s.nome))='JANTAR (SOPA)'""")
    cur.execute("SHOW INDEX FROM dispensa_itens WHERE Key_name = 'uk_dispensa_item'")
    if len(cur.fetchall()) == 2:   # chave antiga (paciente, tipo) -> (paciente, tipo, para)
        cur.execute("ALTER TABLE dispensa_itens ADD UNIQUE KEY uk_dispensa_item_para (paciente_id, tipo_id, para), "
                    "DROP INDEX uk_dispensa_item")
    _dispensa_acomp_ok = True


def acomp_limite(lactante):
    chave, padrao = ('dispensa_acomp_max_lactante', '5') if lactante else ('dispensa_acomp_max', '3')
    try:
        return max(int(get_config(chave, padrao)), 0)
    except (TypeError, ValueError):
        return int(padrao)


def _salvar_acompanhante(cur, pid, tem, lactante, tipos_desejados, tipos, usuario, escopo=None):
    """Grava a decisão da nutrição sobre o acompanhante do paciente `pid`.
    `escopo`: só os tipos que esta decisão pode mudar (na importação por período, os tipos do período);
    None = todos. Refeições já registradas no totem não mudam e contam no limite do dia.
    Retorna (ok, mensagem)."""
    cur.execute("SELECT tipo_id, status FROM dispensa_itens WHERE paciente_id=%s AND para='acompanhante'", (pid,))
    atuais = {r[0]: r[1] for r in cur.fetchall()}
    escopo = set(atuais) | set(tipos) if escopo is None else set(escopo)
    registrados = {tid for tid, st in atuais.items() if st != 'pendente'}
    fora = {tid for tid in atuais if tid not in escopo}                 # outro período: não mexe
    desejados = {t for t in tipos_desejados if t in tipos and t in escopo} if tem else set()
    sem_valor = {t for t in desejados - set(atuais) if tipos[t]['valor'] <= 0}
    desejados -= sem_valor
    final = desejados | registrados | fora
    limite = acomp_limite(lactante)
    if tem and len(final) > limite:
        return False, (f"o acompanhante {'lactante ' if lactante else ''}pode receber até {limite} refeição(ões) "
                       f"por dia ({len(final)} no dia)")
    for tid in desejados - set(atuais):
        cur.execute("""INSERT INTO dispensa_itens (paciente_id, tipo_id, para, valor_unitario, definido_por,
                       autorizado_por, autorizado_em, origem)
                       VALUES (%s, %s, 'acompanhante', %s, %s, %s, NOW(), 'nutricao')""",
                    (pid, tid, tipos[tid]['valor'], usuario, usuario))
    for tid in (set(atuais) & escopo) - desejados - registrados:
        cur.execute("DELETE FROM dispensa_itens WHERE paciente_id=%s AND tipo_id=%s AND para='acompanhante' "
                    "AND status='pendente'", (pid, tid))
    tem_final = bool(final) if tem else bool(registrados or fora)
    cur.execute("""UPDATE dispensa_pacientes SET acomp=%s, acomp_lactante=%s, acomp_por=%s, acomp_em=NOW()
                   WHERE id=%s""", (1 if tem_final else 0, 1 if (tem_final and lactante) else 0, usuario, pid))
    aviso = f" ({len(sem_valor)} tipo(s) sem valor cadastrado ignorado(s))" if sem_valor else ''
    return True, aviso


# ─── Prescrição por período (nutrição autoriza; a cozinha só produz) ─────────
_RE_DIETA_SEM_VO = _re.compile(r'\b(ZERO|JEJUM|NPO|NADA VIA ORAL|DIETA SUSPENSA|SUSPENS[AO])\b', _re.I)


DIETAS_SEM_REFEICAO_PADRAO = 'HIDRATAÇÃO; SUPLEMENTO'


def dietas_sem_refeicao():
    """Termos (sem acento, maiúsculos) das dietas que não recebem refeição. Configurável em Tipos de refeição."""
    txt = get_config('dispensa_dietas_sem_refeicao', DIETAS_SEM_REFEICAO_PADRAO) or ''
    return [_normalizar_txt(t) for t in _re.split(r'[;\n]+', txt) if _normalizar_txt(t)]


def dieta_sem_refeicao(dieta, termos=None):
    """True se TODAS as dietas do paciente são do tipo que não recebe refeição.
    A Salutem junta as dietas da prescrição com ", ": 'DIETA BRANDA, SUPLEMENTO' continua recebendo."""
    termos = dietas_sem_refeicao() if termos is None else termos
    partes = [_normalizar_txt(x) for x in (dieta or '').split(',') if _normalizar_txt(x)]
    return bool(partes and termos) and all(any(t in parte for t in termos) for parte in partes)


_RE_OBS_ACOMP = _re.compile(r'\bPARA\s+(\d+\s+)?((O|A|OS|AS)\s+)?(PACIENTE\s+E\s+)?ACOMPANHANTES?\b')
_RE_OBS_ACOMP_NAO = _re.compile(r'\b(SEM|NAO|NENHUMA|PROIBIDA?|SUSPENSAS?|SUSPENDER)\s+((LIBERAR|ENVIAR|MANDAR|OFERTAR)\s+)?'
                                r'(REI?FEIC\w*\s+)?PARA\s+(\d+\s+)?((O|A|OS|AS)\s+)?ACOMPANHANTES?\b')


def obs_libera_acompanhante(observacao):
    """A observação do nutricionista libera refeição para o acompanhante? ("+ REFEIÇÃO PARA ACOMPANHANTE",
    "REFEIÇÃO PARA 2 ACOMPANHANTE", "PARA PACIENTE E ACOMPANHANTE"...). Negação colada à frase não libera
    ("SEM REFEIÇÃO PARA ACOMPANHANTE"); em "CEIA SEM MINGAU REFEIÇÃO PARA ACOMPANHANTE" o "sem" é do mingau."""
    txt = _normalizar_txt(observacao)
    return bool(_RE_OBS_ACOMP.search(txt)) and not _RE_OBS_ACOMP_NAO.search(txt)


def periodo_sugerido():
    """Manhã antes das 15h; noite a partir das 15h."""
    return 'manha' if datetime.now().hour < 15 else 'noite'


def tipos_do_periodo(periodo, tipos=None):
    return [t for t in (tipos if tipos is not None else _dispensa_tipos(somente_ativos=True))
            if t['ativo'] and t['periodo'] == periodo]


def _autorizar_refeicoes(cur, pid, desejados, escopo, tipos, usuario, origem):
    """Sincroniza as refeições DO PACIENTE autorizadas pela nutrição, só dentro de `escopo`
    (os tipos do período importado). Entregues/não entregues nunca são apagadas. Retorna nº de tipos sem valor ignorados."""
    cur.execute("SELECT tipo_id, status FROM dispensa_itens WHERE paciente_id=%s AND para='paciente'", (pid,))
    atuais = {r[0]: r[1] for r in cur.fetchall()}
    desejados = {t for t in desejados if t in escopo and t in tipos}
    sem_valor = {t for t in desejados - set(atuais) if tipos[t]['valor'] <= 0}
    desejados -= sem_valor
    for tid in desejados - set(atuais):
        cur.execute("""INSERT INTO dispensa_itens (paciente_id, tipo_id, para, valor_unitario, definido_por,
                       autorizado_por, autorizado_em, origem)
                       VALUES (%s, %s, 'paciente', %s, %s, %s, NOW(), %s)""",
                    (pid, tid, tipos[tid]['valor'], usuario, usuario, origem))
    for tid in (set(atuais) & set(escopo)) - desejados:
        if atuais[tid] == 'pendente':
            cur.execute("DELETE FROM dispensa_itens WHERE paciente_id=%s AND tipo_id=%s AND para='paciente' "
                        "AND status='pendente'", (pid, tid))
    return len(sem_valor)


def _uma_alternativa(desejados, tipos):
    """Um OU outro: se a nutrição marcou o tipo e a alternativa dele, fica a alternativa (escolha explícita)."""
    d = set(desejados)
    for tid in list(d):
        alt = (tipos.get(tid) or {}).get('alternativa_de')
        if alt and alt in d:
            d.discard(alt)
    return d


def _paciente_no_dia(cur, r, dia, imp_id):
    """Garante o registro do paciente em `dia` (ex.: dia seguinte, para o desjejum da prescrição noturna)."""
    cur.execute("SELECT id FROM dispensa_pacientes WHERE atendimento=%s AND data_prescricao=%s", (r['atendimento'], dia))
    x = cur.fetchone()
    if x:
        return x[0]
    cur.execute("""INSERT INTO dispensa_pacientes (nome, nome_mae, data_nascimento, prontuario, leito, dieta,
                   importacao_id, unidade, atendimento, data_prescricao) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (r['nome'], r['nome_mae'] or None, r['data_nascimento'], r['prontuario'] or None, r['leito'],
                 r['dieta'] or None, imp_id, r.get('unidade') or None, r['atendimento'], dia))
    return cur.lastrowid


DISPENSA_MOTIVO_AUSENTE = 'Saiu da prescrição (alta/transferência)'


def _dispensa_ausentes(linhas):
    """Pacientes já importados nas datas do arquivo (e no dia seguinte, da prescrição da noite) que NÃO vieram
    nesta importação e ainda têm refeição pendente: provável alta ou transferência."""
    from datetime import timedelta
    vazio = {'lista': [], 'parcial': False, 'n_refeicoes': 0}
    if not linhas:
        return vazio
    no_arquivo = {l['atendimento'] for l in linhas}
    datas_arq = sorted({datetime.strptime(l['data_prescricao'], '%Y-%m-%d').date() for l in linhas})
    datas = [d for d in sorted(set(datas_arq) | {d + timedelta(days=1) for d in datas_arq})
             if not _fechamentos_no_intervalo(d)]
    if not datas:
        return vazio
    cur = mysql.connection.cursor()
    cur.execute(f"""SELECT p.atendimento, p.nome, p.leito, p.unidade, p.data_prescricao, i.id, t.nome, i.para
                    FROM dispensa_pacientes p
                    JOIN dispensa_itens i ON i.paciente_id = p.id AND i.status = 'pendente'
                    JOIN dispensa_tipos t ON t.id = i.tipo_id
                    WHERE p.data_prescricao IN ({','.join(['%s'] * len(datas))})
                    ORDER BY p.data_prescricao, t.ordem""", datas)
    por_at = {}
    for at, nome, leito, unid, dia, item_id, tipo, para in cur.fetchall():
        if at in no_arquivo:
            continue
        a = por_at.setdefault(at, {'atendimento': at, 'nome': nome, 'leito': leito, 'unidade': unid or '',
                                   'item_ids': [], 'refeicoes': []})
        a['item_ids'].append(item_id)
        a['refeicoes'].append(f"{tipo}{' (acomp.)' if para == 'acompanhante' else ''} {dia.strftime('%d/%m')}")
    # arquivo parcial (ex.: CSV de uma unidade só)? então a prévia não marca a remoção sozinha
    cur.execute(f"""SELECT COUNT(DISTINCT atendimento) FROM dispensa_pacientes
                    WHERE data_prescricao IN ({','.join(['%s'] * len(datas_arq))})""", datas_arq)
    base = cur.fetchone()[0] or 0
    cur.close()
    lista = sorted(por_at.values(), key=lambda a: (a['unidade'] or '~', _ordem_leito(a['leito'])))
    return {'lista': lista, 'parcial': len(lista) > 5 and len(lista) > 0.3 * base,
            'n_refeicoes': sum(len(a['item_ids']) for a in lista)}


def _acomp_do_paciente(cur, pids):
    """{paciente_id: {'tem', 'lactante', 'tipos': {tipo_id: status}}} para a lista de pacientes."""
    if not pids:
        return {}
    fmt = ','.join(['%s'] * len(pids))
    cur.execute(f"SELECT id, acomp, acomp_lactante FROM dispensa_pacientes WHERE id IN ({fmt})", list(pids))
    out = {r[0]: {'tem': bool(r[1]), 'lactante': bool(r[2]), 'tipos': {}} for r in cur.fetchall()}
    cur.execute(f"SELECT paciente_id, tipo_id, status FROM dispensa_itens WHERE para='acompanhante' "
                f"AND paciente_id IN ({fmt})", list(pids))
    for pid, tid, st in cur.fetchall():
        out.setdefault(pid, {'tem': True, 'lactante': False, 'tipos': {}})['tipos'][tid] = st
    return out


def _ler_acomp_form(chave, tipos):
    """Lê do formulário os campos acomp_<chave>, acomp_lact_<chave> e acomp_ref_<chave>."""
    tem = request.form.get(f'acomp_{chave}') == '1'
    lact = request.form.get(f'acomp_lact_{chave}') == '1'
    refs = {int(v) for v in request.form.getlist(f'acomp_ref_{chave}') if v.isdigit() and int(v) in tipos}
    return tem, lact, refs


def _dispensa_tipos(somente_ativos=False):
    cur = mysql.connection.cursor()
    filtro = "WHERE ativo = 1" if somente_ativos else ""
    cur.execute(f"""SELECT t.id, t.nome, t.descricao, t.valor, t.ordem, t.ativo,
                           (SELECT COUNT(*) FROM dispensa_itens i WHERE i.tipo_id = t.id) AS usos,
                           t.periodo, t.dia_seguinte, t.alternativa_de
                    FROM dispensa_tipos t {filtro} ORDER BY t.ordem, t.nome""")
    tipos = [{'id': r[0], 'nome': r[1], 'descricao': r[2] or '', 'valor': float(r[3]), 'ordem': r[4],
              'ativo': bool(r[5]), 'usos': int(r[6]), 'periodo': r[7] or '', 'dia_seguinte': bool(r[8]),
              'alternativa_de': r[9]} for r in cur.fetchall()]
    nomes = {t['id']: t['nome'] for t in tipos}
    for t in tipos:
        t['alternativa_de_nome'] = nomes.get(t['alternativa_de'], '')
    cur.close()
    return tipos


def _norm_col(nome):
    nome = _ud.normalize('NFD', (nome or '').strip().lower())
    nome = ''.join(ch for ch in nome if _ud.category(ch) != 'Mn')
    return _re.sub(r'[^a-z0-9]+', '_', nome).strip('_')


def _parse_data_csv(valor):
    valor = (valor or '').strip()
    if not valor:
        return None
    for fmt in ('%d/%m/%Y', '%d/%m/%Y %H:%M', '%d/%m/%Y %H:%M:%S', '%Y-%m-%d', '%Y-%m-%d %H:%M:%S',
                '%Y-%m-%dT%H:%M:%S', '%d-%m-%Y', '%d.%m.%Y', '%d/%m/%y'):
        try:
            return datetime.strptime(valor, fmt).date()
        except ValueError:
            continue
    return 'invalida'


def _ordem_leito(leito):
    """Ordenação natural: 'UTI 2' antes de 'UTI 10'."""
    return [int(p) if p.isdigit() else p.lower() for p in _re.split(r'(\d+)', leito or '')]


def _ler_csv_dispensa(conteudo_bytes):
    """Lê o CSV da Salutem. Retorna (linhas_validas, erros, avisos, colunas_encontradas)."""
    texto = None
    for enc in ('utf-8-sig', 'cp1252', 'latin-1'):
        try:
            texto = conteudo_bytes.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    if texto is None:
        return [], ['Não foi possível ler o arquivo (codificação desconhecida).'], [], {}

    amostra = texto[:4096]
    try:
        dialeto = _csv.Sniffer().sniff(amostra, delimiters=';,\t|')
        sep = dialeto.delimiter
    except _csv.Error:
        sep = max([';', ',', '\t'], key=lambda s: amostra.count(s))

    leitor = _csv.reader(StringIO(texto), delimiter=sep)
    try:
        cabecalho = next(leitor)
    except StopIteration:
        return [], ['O arquivo está vazio.'], [], {}

    normalizado = [_norm_col(c) for c in cabecalho]
    mapa = {}
    for campo, aliases in _DISPENSA_COLUNAS.items():
        for idx, col in enumerate(normalizado):
            if col in aliases:
                mapa[campo] = idx
                break
    faltando = [_DISPENSA_ROTULOS[c] for c in _DISPENSA_OBRIGATORIAS if c not in mapa]
    if faltando:
        return [], [f"Colunas obrigatórias não encontradas: {', '.join(faltando)}. "
                    f"Colunas do arquivo: {', '.join(cabecalho)}"], [], mapa

    avisos = []
    opcionais_faltando = [_DISPENSA_ROTULOS[c] for c in _DISPENSA_COLUNAS if c not in mapa and c not in _DISPENSA_OBRIGATORIAS]
    if opcionais_faltando:
        avisos.append(f"Colunas não encontradas (ficarão em branco): {', '.join(opcionais_faltando)}.")

    linhas, erros, vistos = [], [], {}
    for n, row in enumerate(leitor, start=2):
        if not any((c or '').strip() for c in row):
            continue
        def campo(c):
            i = mapa.get(c)
            return ' '.join((row[i] if i is not None and i < len(row) else '').split())
        reg = {c: campo(c) for c in _DISPENSA_COLUNAS}
        problemas = [f"{_DISPENSA_ROTULOS[c]} vazio" for c in _DISPENSA_OBRIGATORIAS if not reg[c]]
        dp = _parse_data_csv(reg['data_prescricao'])
        dn = _parse_data_csv(reg['data_nascimento'])
        if reg['data_prescricao'] and dp == 'invalida':
            problemas.append(f"data da prescrição inválida ({reg['data_prescricao']})")
        if reg['data_nascimento'] and dn == 'invalida':
            problemas.append(f"data de nascimento inválida ({reg['data_nascimento']})")
        if problemas:
            erros.append(f"Linha {n}: {'; '.join(problemas)}.")
            continue
        reg['nome'] = reg['nome'].upper()[:200]
        reg['nome_mae'] = reg['nome_mae'].upper()[:200]
        reg['leito'] = reg['leito'].upper()[:60]
        reg['dieta'] = reg['dieta'].upper()[:200]
        reg['unidade'] = reg['unidade'].upper()[:80]
        reg['observacao'] = reg['observacao'][:1000]
        reg['tem_obs'] = 'observacao' in mapa   # arquivo sem a coluna não apaga a observação já gravada
        reg['atendimento'] = reg['atendimento'][:40]
        reg['prontuario'] = reg['prontuario'][:40]
        reg['data_prescricao'] = dp.isoformat()
        reg['data_nascimento'] = dn.isoformat() if dn else None
        reg['linha'] = n
        chave = (reg['atendimento'], reg['data_prescricao'])
        if chave in vistos:
            avisos.append(f"Linha {n}: atendimento {reg['atendimento']} repetido no arquivo "
                          f"(linha {vistos[chave]}); vale a última ocorrência.")
            linhas = [l for l in linhas if (l['atendimento'], l['data_prescricao']) != chave]
        vistos[chave] = n
        linhas.append(reg)
    return linhas, erros, avisos, mapa


# ─── Tela da cozinha: pacientes do dia ───────────────────────────────────────

@app.route('/admin/dispensa')
def dispensa_pacientes():
    """Cozinha: SÓ LEITURA. Mostra o que produzir — as refeições autorizadas pela nutrição (importação por período
    ou ajuste com motivo). A cozinha não define nem altera refeições (pedido da direção, 10/11/2026)."""
    from datetime import timedelta
    g = _guard_admin()
    if g: return g
    init_dispensa_tables()

    data_ref = _parse_data(request.args.get('data'), date.today())
    tipos = _dispensa_tipos(somente_ativos=True)
    cur = mysql.connection.cursor()
    cur.execute("""SELECT id, atendimento, nome, nome_mae, data_nascimento, prontuario, leito, dieta, unidade, observacao
                   FROM dispensa_pacientes WHERE data_prescricao=%s""", (data_ref,))
    pacientes = [{'id': r[0], 'atendimento': r[1], 'nome': r[2], 'nome_mae': r[3] or '',
                  'data_nascimento': r[4].strftime('%d/%m/%Y') if r[4] else '', 'prontuario': r[5] or '',
                  'leito': r[6], 'dieta': r[7] or '', 'unidade': (r[8] or '').strip(),
                  'observacao': r[9] or ''} for r in cur.fetchall()]
    # agrupa por unidade de internação (o mesmo "LEITO (01)" existe em várias unidades); sem unidade vai para o fim
    pacientes.sort(key=lambda p: (not p['unidade'], p['unidade'], _ordem_leito(p['leito'])))
    cur.execute("""SELECT i.paciente_id, i.tipo_id, i.status, i.valor_unitario, i.para FROM dispensa_itens i
                   JOIN dispensa_pacientes p ON p.id = i.paciente_id WHERE p.data_prescricao=%s""", (data_ref,))
    itens, valor_dia = {}, 0.0
    for pid, tid, st, vu, para in cur.fetchall():
        if para == 'paciente':
            itens.setdefault(pid, {})[tid] = st
        valor_dia += float(vu or 0)
    acomps = _acomp_do_paciente(cur, [p['id'] for p in pacientes])
    cur.execute("SELECT MAX(importado_em) FROM dispensa_importacoes")
    ultima_imp = cur.fetchone()[0]
    cur.close()
    for p in pacientes:
        p['itens'] = itens.get(p['id'], {})
        p['acomp'] = acomps.get(p['id'], {'tem': False, 'lactante': False, 'tipos': {}})

    etq_pend = 0
    if pacientes and pode('dispensa_etiquetas', 'incluir'):
        init_dispensa_etiquetas()
        c2 = mysql.connection.cursor()
        c2.execute("SELECT id, unidade FROM dispensa_pacientes WHERE data_prescricao=%s", (data_ref,))
        unid_pac = dict(c2.fetchall())
        for p in pacientes:
            c2.execute("SELECT leito, unidade, impresso_em FROM dispensa_etiquetas WHERE atendimento=%s "
                       "ORDER BY impresso_em DESC, id DESC LIMIT 1", (p['atendimento'],))
            ult = c2.fetchone() or (None, None, None)
            if etiqueta_situacao(p['leito'], unid_pac.get(p['id']), *ult) != 'ok':
                etq_pend += 1
        c2.close()
    acomp_por_tipo = {}
    for p in pacientes:
        p['acomp']['travados'] = sorted(t for t, st in p['acomp']['tipos'].items() if st != 'pendente')
        for tid in p['acomp']['tipos']:
            acomp_por_tipo[tid] = acomp_por_tipo.get(tid, 0) + 1
    definidos = sum(1 for p in pacientes if p['itens'])
    ref_por_tipo = {}
    for p in pacientes:
        for tid in p['itens']:
            ref_por_tipo[tid] = ref_por_tipo.get(tid, 0) + 1
    total_acomp = sum(len(p['acomp']['tipos']) for p in pacientes)
    total_ref = sum(len(p['itens']) for p in pacientes) + total_acomp
    dietas, unidades = {}, {}
    for p in pacientes:
        chave = p['dieta'] or '(sem dieta)'
        dietas[chave] = dietas.get(chave, 0) + 1
        u = p['unidade'] or '(sem unidade)'
        unidades[u] = unidades.get(u, 0) + 1
    return render_template('menu_admin.html', module='dispensa_pacientes', usuario=get_usuario_logado(),
                           data_ref=data_ref, data_iso=data_ref.isoformat(),
                           dia_ant=(data_ref - timedelta(days=1)).isoformat(),
                           dia_prox=(data_ref + timedelta(days=1)).isoformat(),
                           dia_semana=_DIAS_SEMANA_PT[data_ref.weekday()], hoje_iso=date.today().isoformat(),
                           pacientes=pacientes, tipos_disp=tipos, definidos=definidos, total_ref=total_ref,
                           total_acomp=total_acomp, acomp_por_tipo=acomp_por_tipo, etq_pend=etq_pend,
                           ref_por_tipo=ref_por_tipo, n_acomp=sum(1 for p in pacientes if p['acomp']['tem']),
                           acomp_max=acomp_limite(False), acomp_max_lact=acomp_limite(True),
                           valor_dia=valor_dia, sem_valor=[t['nome'] for t in tipos if t['valor'] <= 0],
                           dietas=sorted(dietas.items(), key=lambda x: (-x[1], x[0])),
                           unidades=sorted(unidades.items(), key=lambda x: (x[0] == '(sem unidade)', x[0])),
                           ultima_imp=ultima_imp.strftime('%d/%m/%Y %H:%M') if ultima_imp else None,
                           periodo_fechado=(_fechamentos_no_intervalo(data_ref) or [None])[0])


@app.route('/admin/dispensa/refeicoes', methods=['POST'])
def dispensa_refeicoes_ajustar():
    """Nutrição: ajusta as refeições autorizadas de um paciente no dia (motivo obrigatório; fica na auditoria)."""
    g = _guard_admin()
    if g: return g
    init_dispensa_tables()
    pid = request.form.get('paciente_id', type=int)
    motivo = ' '.join((request.form.get('motivo') or '').split())[:240]
    cur = mysql.connection.cursor()
    cur.execute("SELECT data_prescricao, nome, leito FROM dispensa_pacientes WHERE id=%s", (pid,))
    r = cur.fetchone()
    if not r:
        cur.close()
        flash("Paciente não encontrado.", "error")
        return redirect(url_for('dispensa_pacientes'))
    data_ref, nome, leito = r
    voltar = redirect(url_for('dispensa_pacientes', data=data_ref.isoformat()))
    fech = _fechamentos_no_intervalo(data_ref)
    if fech:
        cur.close()
        flash(_msg_fechado(fech[0]), "error")
        return voltar
    if len(motivo) < 10:
        cur.close()
        flash("Informe o motivo do ajuste (mínimo 10 caracteres).", "error")
        return voltar
    tipos = {t['id']: t for t in _dispensa_tipos(somente_ativos=True)}
    desej = _uma_alternativa({int(v) for v in request.form.getlist('ref_m') if v.isdigit()}, tipos)
    cur.execute("SELECT tipo_id FROM dispensa_itens WHERE paciente_id=%s AND para='paciente'", (pid,))
    antes = {x[0] for x in cur.fetchall()}
    usuario = get_usuario_logado()
    sem_valor = _autorizar_refeicoes(cur, pid, desej, set(tipos), tipos, usuario, 'ajuste_nutricao')
    cur.execute("SELECT tipo_id FROM dispensa_itens WHERE paciente_id=%s AND para='paciente'", (pid,))
    depois = {x[0] for x in cur.fetchall()}
    mysql.connection.commit()
    cur.close()
    incl = [tipos[t]['nome'] for t in sorted(depois - antes) if t in tipos]
    retir = [tipos[t]['nome'] for t in sorted(antes - depois) if t in tipos]
    auditar(alvo=f"{leito} · {nome}", detalhes={'incluidas': incl, 'retiradas': retir, 'motivo': motivo})
    logger.info(f"{usuario} ajustou refeições do paciente {pid} ({leito}): +{incl} -{retir}. Motivo: {motivo}")
    if not incl and not retir:
        flash("Nenhuma alteração nas refeições (as já registradas no totem não mudam).", "error" if sem_valor else "success")
    else:
        flash(f"Refeições de {nome} ajustadas" + (f" · incluídas: {', '.join(incl)}" if incl else '')
              + (f" · retiradas: {', '.join(retir)}" if retir else '') + ".", "success")
    if sem_valor:
        flash(f"{sem_valor} tipo(s) sem valor cadastrado não foram autorizados.", "error")
    return voltar


@app.route('/admin/dispensa/acompanhante', methods=['POST'])
def dispensa_acompanhante_salvar():
    """Nutrição: define/ajusta o acompanhante de um paciente (Pacientes do dia)."""
    g = _guard_admin()
    if g: return g
    init_dispensa_tables()
    pid = request.form.get('paciente_id', type=int)
    cur = mysql.connection.cursor()
    cur.execute("SELECT data_prescricao, nome, leito FROM dispensa_pacientes WHERE id=%s", (pid,))
    r = cur.fetchone()
    if not r:
        cur.close()
        flash("Paciente não encontrado.", "error")
        return redirect(url_for('dispensa_pacientes'))
    data_ref, nome, leito = r
    voltar = redirect(url_for('dispensa_pacientes', data=data_ref.isoformat()))
    fech = _fechamentos_no_intervalo(data_ref)
    if fech:
        cur.close()
        flash(_msg_fechado(fech[0]), "error")
        return voltar
    tipos = {t['id']: t for t in _dispensa_tipos(somente_ativos=True)}
    tem, lact, refs = _ler_acomp_form('m', tipos)
    if tem and not refs:
        cur.close()
        flash("Marque ao menos uma refeição para o acompanhante (ou desmarque \"recebe refeição\").", "error")
        return voltar
    ok, msg = _salvar_acompanhante(cur, pid, tem, lact, refs, tipos, get_usuario_logado())
    if not ok:
        mysql.connection.rollback()
        cur.close()
        flash(f"Acompanhante de {nome} não salvo: {msg}.", "error")
        return voltar
    mysql.connection.commit()
    cur.close()
    auditar(alvo=f"{leito} · {nome}", detalhes={'acompanhante': tem, 'lactante': lact,
                                                'refeicoes': [tipos[t]['nome'] for t in sorted(refs)] if tem else []})
    logger.info(f"{get_usuario_logado()} definiu acompanhante do paciente {pid} ({leito}): "
                f"{'sim' if tem else 'não'}{' lactante' if lact else ''} {sorted(refs) if tem else ''}.")
    flash(f"Acompanhante de {nome} salvo{msg}.", "success")
    return voltar


# ─── Importação do CSV (nutricionista) ───────────────────────────────────────

def _limpar_previas(pasta, idade_seg=7200):
    """Apaga prévias temporárias (.json) com mais de 2 h. Elas têm dados de pacientes/colaboradores:
    não podem ficar esquecidas no servidor quando ninguém confirma a importação."""
    try:
        agora_ts = datetime.now().timestamp()
        for f in os.listdir(pasta):
            fp = os.path.join(pasta, f)
            if f.endswith('.json') and agora_ts - os.path.getmtime(fp) > idade_seg:
                os.remove(fp)
    except OSError:
        pass


@app.route('/admin/dispensa/importar', methods=['GET', 'POST'])
def dispensa_importar():
    g = _guard_admin()
    if g: return g
    init_dispensa_tables()
    _limpar_previas(DISPENSA_TMP_FOLDER)
    preview = None

    if request.method == 'POST' and request.form.get('acao') == 'confirmar':
        token = request.form.get('token', '')
        if not _re.fullmatch(r'[0-9a-f]{32}', token):
            flash("Prévia expirada. Envie o arquivo novamente.", "error")
            return redirect(url_for('dispensa_importar'))
        caminho = os.path.join(DISPENSA_TMP_FOLDER, token + '.json')
        if not os.path.exists(caminho):
            flash("Prévia expirada. Envie o arquivo novamente.", "error")
            return redirect(url_for('dispensa_importar'))
        with open(caminho, encoding='utf-8') as f:
            dados = _json.load(f)
        desmarcados = 0
        if request.form.get('selecao') == '1':
            # só os pacientes que ficaram marcados na prévia (desmarcado = não recebe refeição)
            incluir = {int(v) for v in request.form.getlist('incluir') if v.isdigit()}
            desmarcados = sum(1 for r in dados['linhas'] if r['linha'] not in incluir)
            dados['linhas'] = [r for r in dados['linhas'] if r['linha'] in incluir]
            if not dados['linhas']:
                flash("Nenhum paciente marcado para importar.", "error")
                return redirect(url_for('dispensa_importar'))
        from datetime import timedelta
        periodo = dados.get('periodo') if dados.get('periodo') in ('manha', 'noite') else None
        tipos_all = {t['id']: t for t in _dispensa_tipos(somente_ativos=True)}
        per_tipos = {t['id'] for t in tipos_do_periodo(periodo, list(tipos_all.values()))} if periodo else set()
        mesmo_dia = {t for t in per_tipos if not tipos_all[t]['dia_seguinte']}
        dia_seg = per_tipos - mesmo_dia
        _dt_presc = lambda r: datetime.strptime(r['data_prescricao'], '%Y-%m-%d').date()
        datas_checar = {r['data_prescricao'] for r in dados['linhas']}
        if dia_seg:
            datas_checar |= {(_dt_presc(r) + timedelta(days=1)).isoformat() for r in dados['linhas']}
        fechadas = sorted(d for d in datas_checar if _fechamentos_no_intervalo(datetime.strptime(d, '%Y-%m-%d').date()))
        if fechadas:
            flash("Importação bloqueada: o arquivo tem prescrições de período fechado (" +
                  ', '.join(datetime.strptime(d, '%Y-%m-%d').strftime('%d/%m/%Y') for d in fechadas) + ").", "error")
            return redirect(url_for('dispensa_importar'))
        if dados.get('exige_confirmacao_data') and not request.form.get('confirmo_data'):
            flash("O arquivo tem data de prescrição diferente de hoje/amanhã. Marque a confirmação para importar.", "error")
            return redirect(url_for('dispensa_importar'))
        usuario = get_usuario_logado()
        tipos_acomp = tipos_all
        avisos_acomp = []
        sem_valor_total = 0
        origem = f"importacao_{periodo}" if periodo else 'importacao'
        n_autorizadas = 0
        try:
            cur = mysql.connection.cursor()
            cur.execute("""INSERT INTO dispensa_importacoes (arquivo_nome, importado_por, total_linhas)
                           VALUES (%s, %s, %s)""", (dados['arquivo'], usuario, dados['total']))
            imp_id = cur.lastrowid
            ins = upd = 0
            for r in dados['linhas']:
                cur.execute("SELECT id FROM dispensa_pacientes WHERE atendimento=%s AND data_prescricao=%s",
                            (r['atendimento'], r['data_prescricao']))
                existe = cur.fetchone()
                valores = (r['nome'], r['nome_mae'] or None, r['data_nascimento'], r['prontuario'] or None,
                           r['leito'], r['dieta'] or None, imp_id, r.get('unidade') or None)
                if existe:
                    cur.execute("""UPDATE dispensa_pacientes SET nome=%s, nome_mae=%s, data_nascimento=%s,
                                   prontuario=%s, leito=%s, dieta=%s, importacao_id=%s, unidade=%s WHERE id=%s""",
                                valores + (existe[0],))
                    upd += 1
                    pid_imp = existe[0]
                else:
                    cur.execute("""INSERT INTO dispensa_pacientes (nome, nome_mae, data_nascimento, prontuario,
                                   leito, dieta, importacao_id, unidade, atendimento, data_prescricao)
                                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                                valores + (r['atendimento'], r['data_prescricao']))
                    ins += 1
                    pid_imp = cur.lastrowid
                # refeições do PACIENTE autorizadas pela nutrição (período): as do dia e as do dia seguinte
                pid_seg = None
                if periodo:
                    desej = _uma_alternativa({int(v) for v in request.form.getlist(f"ref_{r['linha']}") if v.isdigit()}
                                             & per_tipos, tipos_all)
                    n_autorizadas += len(desej)
                    sem_valor_total += _autorizar_refeicoes(cur, pid_imp, desej, mesmo_dia, tipos_all, usuario, origem)
                    if dia_seg:
                        pid_seg = _paciente_no_dia(cur, r, _dt_presc(r) + timedelta(days=1), imp_id)
                        sem_valor_total += _autorizar_refeicoes(cur, pid_seg, desej, dia_seg, tipos_all, usuario, origem)
                # observação do nutricionista: a da prescrição mais recente vale (também no registro do dia seguinte)
                if r.get('tem_obs'):
                    cur.execute("UPDATE dispensa_pacientes SET observacao=%s WHERE id IN (%s, %s)",
                                (r.get('observacao') or None, pid_imp, pid_seg or pid_imp))
                # acompanhante marcado pela nutrição na prévia (só os tipos do período; dia seguinte idem)
                if request.form.get(f"acomp_set_{r['linha']}") == '1':
                    tem, lact, refs = _ler_acomp_form(r['linha'], tipos_acomp)
                    refs = _uma_alternativa(refs, tipos_all)
                    if tem and not refs:
                        avisos_acomp.append(f"{r['leito']} · {r['nome']}: nenhuma refeição marcada para o acompanhante")
                        tem = False
                    ok_a, msg_a = _salvar_acompanhante(cur, pid_imp, tem, lact, refs, tipos_acomp, usuario,
                                                       escopo=mesmo_dia if periodo else None)
                    if ok_a and pid_seg:
                        ok_a, msg_a = _salvar_acompanhante(cur, pid_seg, tem, lact, refs, tipos_acomp, usuario, escopo=dia_seg)
                    if not ok_a:
                        avisos_acomp.append(f"{r['leito']} · {r['nome']}: {msg_a}")
            # pacientes que não vieram nesta importação: refeições pendentes viram "não entregue" (não apaga:
            # o item pode ter histórico de correção). Só os que a nutrição deixou marcados na prévia.
            remover = set(request.form.getlist('remover_ausente'))
            ids_aus = [i for a in dados.get('ausentes', []) if a['atendimento'] in remover for i in a['itens']]
            n_aus = 0
            if ids_aus:
                cur.execute(f"""UPDATE dispensa_itens i JOIN dispensa_pacientes p ON p.id = i.paciente_id
                                SET i.status='nao_entregue', i.entregue_em=NOW(), i.entregue_por=%s,
                                    i.validacao=NULL, i.motivo=%s
                                WHERE i.id IN ({','.join(['%s'] * len(ids_aus))}) AND i.status='pendente'
                                  AND {_SQL_NAO_FECHADO}""",
                            [usuario, DISPENSA_MOTIVO_AUSENTE] + ids_aus)
                n_aus = cur.rowcount
            cur.execute("UPDATE dispensa_importacoes SET inseridos=%s, atualizados=%s, ignorados=%s WHERE id=%s",
                        (ins, upd, dados['ignorados'] + desmarcados, imp_id))
            mysql.connection.commit()
            cur.close()
            os.remove(caminho)
            logger.info(f"{usuario} importou prescrições de pacientes ({dados['arquivo']}, período {periodo}): "
                        f"{ins} novos, {upd} atualizados, {n_autorizadas} refeição(ões) autorizada(s), "
                        f"{n_aus} pendente(s) encerrada(s) de paciente(s) fora da prescrição.")
            auditar(detalhes={'periodo': periodo, 'pacientes': len(dados['linhas']), 'refeicoes_autorizadas': n_autorizadas,
                              'saiu_da_prescricao': {'pacientes': len(remover & {a['atendimento'] for a in dados.get('ausentes', [])}),
                                                     'refeicoes_encerradas': n_aus}})
            if n_aus:
                flash(f"{n_aus} refeição(ões) pendente(s) de paciente(s) que saíram da prescrição registrada(s) como "
                      f"não entregue ({DISPENSA_MOTIVO_AUSENTE}).", "success")
            if sem_valor_total:
                flash(f"{sem_valor_total} refeição(ões) não autorizada(s): tipo sem valor cadastrado (Tipos de refeição).", "error")
            flash(f"Importação ({'manhã' if periodo == 'manha' else 'noite' if periodo else 'sem período'}) concluída: "
                  f"{n_autorizadas} refeição(ões) autorizada(s), {ins} paciente(s) novo(s), {upd} atualizado(s)"
                  + (f", {dados['ignorados']} linha(s) com erro ignorada(s)" if dados['ignorados'] else "")
                  + (f", {desmarcados} desmarcado(s) na prévia (não importado(s))" if desmarcados else "") + ".", "success")
            if avisos_acomp:
                flash("Acompanhante não gravado para: " + "; ".join(avisos_acomp[:10]) +
                      (f" … e mais {len(avisos_acomp) - 10}" if len(avisos_acomp) > 10 else "") +
                      ". Ajuste em Pacientes do dia.", "error")
            datas = sorted({r['data_prescricao'] for r in dados['linhas']})
            return redirect(url_for('dispensa_pacientes', data=datas[-1] if datas else None))
        except Exception as e:
            mysql.connection.rollback()
            logger.error(f"Erro ao importar prescrições: {e}")
            flash("Erro ao gravar a importação. Nada foi alterado.", "error")
            return redirect(url_for('dispensa_importar'))

    if request.method == 'POST' and request.form.get('acao') == 'salutem':
        # Fonte alternativa ao CSV: busca na API da Salutem e cai na MESMA prévia
        dia = _parse_data(request.form.get('data_salutem'))
        if not dia:
            flash("Informe a data das prescrições.", "error")
            return redirect(url_for('dispensa_importar'))
        try:
            linhas, erros, avisos = salutem_gtr.prescricoes_para_dispensa(salutem_cliente(), dia)
        except salutem_gtr.SalutemErro as e:
            logger.warning(f"{get_usuario_logado()}: busca de prescrições na Salutem falhou: {e}")
            flash(f"Não foi possível buscar na Salutem: {e}", "error")
            return redirect(url_for('dispensa_importar'))
        mapa = {c: True for c in _DISPENSA_COLUNAS}
        nome_fonte = f"Salutem (API) · prescrições de {dia.strftime('%d/%m/%Y')}"
        logger.info(f"{get_usuario_logado()} buscou {len(linhas)} prescrição(ões) na Salutem para {dia}.")
        auditar(forcar=True, detalhes={'fonte': 'Salutem API', 'data': dia.isoformat(), 'pacientes': len(linhas)})
    if request.method == 'POST' and request.form.get('acao') != 'salutem':
        arq = request.files.get('arquivo')
        if not arq or not arq.filename:
            flash("Selecione o arquivo CSV.", "error")
            return redirect(url_for('dispensa_importar'))
        if not arq.filename.lower().endswith(('.csv', '.txt')):
            flash("O arquivo precisa ser .csv.", "error")
            return redirect(url_for('dispensa_importar'))
        conteudo = arq.read(DISPENSA_CSV_MAX + 1)
        if len(conteudo) > DISPENSA_CSV_MAX:
            flash("Arquivo maior que 5 MB.", "error")
            return redirect(url_for('dispensa_importar'))

        linhas, erros, avisos, mapa = _ler_csv_dispensa(conteudo)
        nome_fonte = arq.filename
    if request.method == 'POST':
        # dietas que não recebem refeição (ex.: hidratação, suplemento): ficam fora da importação, com aviso
        termos_sem = dietas_sem_refeicao()
        fora_dieta = [l for l in linhas if dieta_sem_refeicao(l.get('dieta'), termos_sem)]
        if fora_dieta:
            linhas = [l for l in linhas if l not in fora_dieta]
            avisos = list(avisos) + [f"{len(fora_dieta)} paciente(s) com dieta que não recebe refeição ficaram de fora: "
                                     + '; '.join(f"{l['leito']} · {l['nome']} ({l['dieta']})" for l in fora_dieta[:30])
                                     + (' …' if len(fora_dieta) > 30 else '') + '.']
        # já importados (mesmo atendimento + data)
        existentes = set()
        if linhas:
            cur = mysql.connection.cursor()
            datas = sorted({l['data_prescricao'] for l in linhas})
            fmt = ','.join(['%s'] * len(datas))
            cur.execute(f"SELECT atendimento, data_prescricao, id FROM dispensa_pacientes WHERE data_prescricao IN ({fmt})", datas)
            existentes = {(r[0], r[1].isoformat()): r[2] for r in cur.fetchall()}
            acomps_exist = _acomp_do_paciente(cur, list(existentes.values()))
            cur.close()
        from datetime import timedelta
        periodo = request.form.get('periodo') if request.form.get('periodo') in ('manha', 'noite') else periodo_sugerido()
        tipos_per = tipos_do_periodo(periodo)
        ids_mesmo = {t['id'] for t in tipos_per if not t['dia_seguinte']}
        ids_seg = {t['id'] for t in tipos_per if t['dia_seguinte']}
        padrao = {t['id'] for t in tipos_per if not t['alternativa_de']}
        # o que já está autorizado (reimportação do mesmo período): no dia e no dia seguinte
        ja_aut = {}
        if linhas:
            cur = mysql.connection.cursor()
            for l in linhas:
                d0 = datetime.strptime(l['data_prescricao'], '%Y-%m-%d').date()
                cur.execute("""SELECT i.tipo_id, p.data_prescricao, i.status, i.para FROM dispensa_itens i
                               JOIN dispensa_pacientes p ON p.id = i.paciente_id
                               WHERE p.atendimento=%s AND p.data_prescricao IN (%s,%s)""",
                            (l['atendimento'], d0, d0 + timedelta(days=1)))
                tem, trav, ac_seg, ac_seg_trav = set(), set(), set(), set()
                for tid, dref, st, para in cur.fetchall():
                    no_periodo = (dref == d0 and tid in ids_mesmo) or (dref != d0 and tid in ids_seg)
                    if para == 'paciente' and no_periodo:
                        tem.add(tid)
                        if st != 'pendente':
                            trav.add(tid)
                    elif para == 'acompanhante' and dref != d0 and tid in ids_seg:
                        ac_seg.add(tid)          # acompanhante já autorizado para o dia seguinte
                        if st != 'pendente':
                            ac_seg_trav.add(tid)
                ja_aut[(l['atendimento'], l['data_prescricao'])] = (tem, trav, ac_seg, ac_seg_trav)
            cur.close()
        for l in linhas:
            pid_ex = existentes.get((l['atendimento'], l['data_prescricao']))
            tem, trav, ac_seg, ac_seg_trav = ja_aut.get((l['atendimento'], l['data_prescricao']), (set(), set(), set(), set()))
            l['refs'] = sorted(tem) if tem else sorted(padrao)
            l['refs_travadas'] = sorted(trav)
            l['alerta_dieta'] = bool(_RE_DIETA_SEM_VO.search(l.get('dieta') or ''))
            l['ja_existe'] = pid_ex is not None
            a = acomps_exist.get(pid_ex) if pid_ex else None
            l['acomp'] = bool(a and a['tem'])
            l['acomp_lactante'] = bool(a and a['lactante'])
            l['acomp_tipos'] = sorted(set(a['tipos'] if a else []) | ac_seg)
            l['acomp_travados'] = sorted({t for t, st in (a['tipos'].items() if a else []) if st != 'pendente'} | ac_seg_trav)
            if ac_seg and not l['acomp']:
                l['acomp'] = True
            # acompanhante liberado na prescrição — pelo campo da Salutem ou, como a nutrição faz na prática, pela
            # observação ("+ REFEIÇÃO PARA ACOMPANHANTE"): já vem marcado, nas refeições do paciente (a nutrição confere)
            origem_acp = 'salutem' if l.get('acomp_liberado') else 'observacao' if obs_libera_acompanhante(l.get('observacao')) else None
            if origem_acp and not l['acomp']:
                l['acomp'] = True
                l['acomp_tipos'] = sorted(l['refs'])[:acomp_limite(False)]
                l['acomp_sugerido'] = origem_acp
            # observação que só menciona o acompanhante, sem liberar a refeição: alerta para conferir
            l['obs_acomp'] = not l['acomp'] and 'ACOMPANHANTE' in _normalizar_txt(l.get('observacao'))
        ausentes = _dispensa_ausentes(linhas)

        token = None
        if linhas:
            # limpa prévias antigas (> 2 h) e guarda esta temporariamente
            agora_ts = datetime.now().timestamp()
            for f in os.listdir(DISPENSA_TMP_FOLDER):
                fp = os.path.join(DISPENSA_TMP_FOLDER, f)
                if f.endswith('.json') and agora_ts - os.path.getmtime(fp) > 7200:
                    os.remove(fp)
            token = _uuid.uuid4().hex
            with open(os.path.join(DISPENSA_TMP_FOLDER, token + '.json'), 'w', encoding='utf-8') as f:
                _json.dump({'arquivo': (nome_fonte if nome_fonte.startswith('Salutem') else secure_filename(nome_fonte)) or 'arquivo.csv',
                            'periodo': periodo, 'linhas': linhas,
                            'ausentes': [{'atendimento': a['atendimento'], 'itens': a['item_ids']} for a in ausentes['lista']],
                            'total': len(linhas) + len(erros), 'ignorados': len(erros)}, f, ensure_ascii=False)

        datas_fmt = sorted({l['data_prescricao'] for l in linhas})
        from datetime import timedelta
        esperadas = {date.today().isoformat(), (date.today() + timedelta(days=1)).isoformat()}
        datas_fora = [d for d in datas_fmt if d not in esperadas]
        if token and datas_fora:
            caminho_tmp = os.path.join(DISPENSA_TMP_FOLDER, token + '.json')
            with open(caminho_tmp, encoding='utf-8') as f:
                tmp = _json.load(f)
            tmp['exige_confirmacao_data'] = True
            with open(caminho_tmp, 'w', encoding='utf-8') as f:
                _json.dump(tmp, f, ensure_ascii=False)
        preview = {
            'arquivo': nome_fonte, 'token': token,
            'linhas': sorted(linhas, key=lambda l: ((l.get('unidade') or '~'), _ordem_leito(l['leito']))),
            'unidades': sorted({l.get('unidade') or '' for l in linhas} - {''}),
            'erros': erros, 'avisos': avisos,
            'periodo': periodo, 'tipos_periodo': tipos_per,
            'grupos_alt': [{'principal': t, 'opcoes': [t] + [a for a in tipos_per if a['alternativa_de'] == t['id']]}
                           for t in tipos_per if not t['alternativa_de'] and any(a['alternativa_de'] == t['id'] for a in tipos_per)],
            'dia_seguinte_fmt': ((datetime.strptime(sorted({l['data_prescricao'] for l in linhas})[-1], '%Y-%m-%d').date()
                                  + timedelta(days=1)).strftime('%d/%m') if linhas else ''),
            'n_alerta_dieta': sum(1 for l in linhas if l['alerta_dieta']),
            'novos': sum(1 for l in linhas if not l['ja_existe']),
            'atualizar': sum(1 for l in linhas if l['ja_existe']),
            'datas': [datetime.strptime(d, '%Y-%m-%d').strftime('%d/%m/%Y') for d in datas_fmt],
            'colunas': [_DISPENSA_ROTULOS[c] for c in _DISPENSA_COLUNAS if c in mapa],
            'datas_fora': [datetime.strptime(d, '%Y-%m-%d').strftime('%d/%m/%Y') for d in datas_fora],
            'datas_fechadas': [datetime.strptime(d, '%Y-%m-%d').strftime('%d/%m/%Y') for d in datas_fmt
                               if _fechamentos_no_intervalo(datetime.strptime(d, '%Y-%m-%d').date())],
            'hoje': date.today().strftime('%d/%m/%Y'),
            'ausentes': ausentes,
        }
        for l in preview['linhas']:
            l['data_prescricao_fmt'] = datetime.strptime(l['data_prescricao'], '%Y-%m-%d').strftime('%d/%m/%Y')
            l['data_nascimento_fmt'] = (datetime.strptime(l['data_nascimento'], '%Y-%m-%d').strftime('%d/%m/%Y')
                                        if l['data_nascimento'] else '')

    cur = mysql.connection.cursor()
    cur.execute("""SELECT arquivo_nome, importado_em, importado_por, total_linhas, inseridos, atualizados, ignorados
                   FROM dispensa_importacoes ORDER BY id DESC LIMIT 15""")
    historico = cur.fetchall()
    cur.close()
    return render_template('menu_admin.html', module='dispensa_importar', usuario=get_usuario_logado(),
                           preview=preview, historico=historico, colunas_csv=_DISPENSA_ROTULOS,
                           tipos_acomp=(preview['tipos_periodo'] if preview else _dispensa_tipos(somente_ativos=True)),
                           acomp_max=acomp_limite(False), acomp_max_lact=acomp_limite(True),
                           salutem_ok=bool(_salutem_credencial()[0]), hoje_iso=date.today().isoformat(),
                           periodo_sugerido=periodo_sugerido())


@app.route('/admin/dispensa/modelo_csv')
def dispensa_modelo_csv():
    g = _guard_admin()
    if g: return g
    linhas = ["nome;nome_mae;data_nascimento;prontuario;atendimento;data_prescricao;leito;dieta",
              "MARIA DA SILVA EXEMPLO;JOANA DA SILVA;15/03/1958;123456;987654;05/11/2026;ALA A - 101;BRANDA",
              "JOSE DOS SANTOS EXEMPLO;ANA DOS SANTOS;02/09/1971;223344;987655;05/11/2026;UTI - 03;LIQUIDA"]
    return send_file(BytesIO(('\n'.join(linhas) + '\n').encode('utf-8-sig')), mimetype='text/csv',
                     download_name='modelo_prescricoes_pacientes.csv', as_attachment=True)


# ─── Cadastro dos tipos de refeição do paciente ──────────────────────────────

@app.route('/admin/dispensa/tipos', methods=['GET', 'POST'])
def dispensa_tipos():
    g = _guard_admin()
    if g: return g
    init_dispensa_tables()
    if request.method == 'POST':
        nome = ' '.join((request.form.get('nome') or '').split())[:80]
        descricao = (request.form.get('descricao') or '').strip()[:255]
        try:
            valor = round(float((request.form.get('valor') or '0').replace(',', '.')), 2)
        except ValueError:
            valor = -1
        if not nome or valor < 0:
            flash("Informe o nome e um valor válido.", "error")
            return redirect(url_for('dispensa_tipos'))
        try:
            cur = mysql.connection.cursor()
            cur.execute("SELECT id FROM dispensa_tipos WHERE nome=%s", (nome,))
            if cur.fetchone():
                flash(f"Já existe o tipo “{nome}”.", "error")
            else:
                cur.execute("SELECT COALESCE(MAX(ordem), -1) + 1 FROM dispensa_tipos")
                ordem = cur.fetchone()[0]
                cur.execute("INSERT INTO dispensa_tipos (nome, descricao, valor, ordem) VALUES (%s,%s,%s,%s)",
                            (nome, descricao or None, valor, ordem))
                cur.execute("INSERT INTO dispensa_tipos_historico (tipo_id, valor, alterado_por) VALUES (%s,%s,%s)",
                            (cur.lastrowid, valor, get_usuario_logado()))
                mysql.connection.commit()
                flash(f"Tipo “{nome}” cadastrado.", "success")
            cur.close()
        except Exception as e:
            mysql.connection.rollback()
            logger.error(f"Erro ao cadastrar tipo de refeição de paciente: {e}")
            flash("Erro ao cadastrar.", "error")
        return redirect(url_for('dispensa_tipos'))

    init_dispensa_fase2()
    init_dispensa_fechamentos()
    cur = mysql.connection.cursor()
    cur.execute("""SELECT t.nome, h.valor, h.alterado_em, h.alterado_por FROM dispensa_tipos_historico h
                   JOIN dispensa_tipos t ON t.id = h.tipo_id ORDER BY h.id DESC LIMIT 20""")
    historico = cur.fetchall()
    cur.execute("""SELECT i.tipo_id, COUNT(*), MIN(p.data_prescricao), MAX(p.data_prescricao)
                   FROM dispensa_itens i JOIN dispensa_pacientes p ON p.id = i.paciente_id
                   WHERE i.status='entregue' AND i.valor_unitario=0 AND """ + _SQL_NAO_FECHADO + """ GROUP BY i.tipo_id""")
    zerados = {r[0]: {'qtd': int(r[1]), 'ini': r[2].strftime('%d/%m/%Y'), 'fim': r[3].strftime('%d/%m/%Y')}
               for r in cur.fetchall()}
    cur.execute("""SELECT a.feito_em, t.nome, a.qtd_itens, a.valor_antigo, a.valor_novo, a.data_ini, a.data_fim,
                          a.motivo, a.feito_por, a.id
                   FROM dispensa_ajustes_valor a JOIN dispensa_tipos t ON t.id = a.tipo_id
                   ORDER BY a.id DESC LIMIT 20""")
    ajustes = cur.fetchall()
    cur.close()
    return render_template('menu_admin.html', module='dispensa_tipos', usuario=get_usuario_logado(),
                           tipos_disp=_dispensa_tipos(), historico_tipos=historico,
                           dietas_sem_ref=get_config('dispensa_dietas_sem_refeicao', DIETAS_SEM_REFEICAO_PADRAO),
                           zerados=zerados, ajustes=ajustes)


@app.route('/admin/dispensa/tipos/dietas-sem-refeicao', methods=['POST'])
def dispensa_dietas_sem_refeicao():
    """Lista de dietas que não recebem refeição (ficam de fora da importação). Um termo por linha ou separados por ';'."""
    g = _guard_admin()
    if g: return g
    termos = [' '.join(t.split()).upper() for t in _re.split(r'[;\n]+', request.form.get('dietas') or '') if t.strip()]
    set_config('dispensa_dietas_sem_refeicao', '; '.join(dict.fromkeys(termos)))
    flash("Dietas que não recebem refeição salvas: " + (', '.join(termos) if termos else 'nenhuma') + ".", "success")
    return redirect(url_for('dispensa_tipos') + '#dietas-sem-refeicao')


@app.route('/admin/dispensa/tipos/ordem', methods=['POST'])
def dispensa_tipos_ordem():
    """Grava a ordem dos tipos de refeição (cozinha, totem, acompanhante e relatórios seguem esta ordem)."""
    g = _guard_admin()
    if g: return g
    ids = [int(i) for i in request.form.getlist('tipo_id') if i.isdigit()]
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, nome FROM dispensa_tipos")
    nomes = dict(cur.fetchall())
    if not ids or len(set(ids)) != len(ids) or set(ids) != set(nomes):
        cur.close()
        flash("A lista de tipos mudou enquanto você ordenava. Recarregue a página e tente de novo.", "error")
        return redirect(url_for('dispensa_tipos'))
    for pos, tid in enumerate(ids):
        cur.execute("UPDATE dispensa_tipos SET ordem=%s WHERE id=%s", (pos, tid))
    mysql.connection.commit()
    cur.close()
    auditar(detalhes={'ordem': [nomes[i] for i in ids]})
    logger.info(f"{get_usuario_logado()} reordenou os tipos de refeição: {', '.join(nomes[i] for i in ids)}.")
    flash("Ordem dos tipos de refeição salva.", "success")
    return redirect(url_for('dispensa_tipos'))


@app.route('/admin/dispensa/tipos/<int:tipo_id>/editar', methods=['POST'])
def dispensa_tipo_editar(tipo_id):
    g = _guard_admin()
    if g: return g
    init_dispensa_fechamentos()
    nome = ' '.join((request.form.get('nome') or '').split())[:80]
    descricao = (request.form.get('descricao') or '').strip()[:255]
    ativo = 1 if request.form.get('ativo') else 0
    periodo = request.form.get('periodo') if request.form.get('periodo') in ('manha', 'noite') else None
    dia_seguinte = 1 if (periodo and request.form.get('dia_seguinte') == '1') else 0
    alt = request.form.get('alternativa_de', type=int)
    alternativa_de = alt if (alt and alt != tipo_id and periodo) else None
    try:
        valor = round(float((request.form.get('valor') or '0').replace(',', '.')), 2)
    except ValueError:
        valor = -1
    if not nome or valor < 0:
        flash("Informe o nome e um valor válido.", "error")
        return redirect(url_for('dispensa_tipos'))
    try:
        cur = mysql.connection.cursor()
        if alternativa_de:
            cur.execute("SELECT periodo, dia_seguinte, alternativa_de FROM dispensa_tipos WHERE id=%s", (alternativa_de,))
            pr = cur.fetchone()
            if not pr or pr[0] != periodo or int(pr[1]) != dia_seguinte or pr[2]:
                cur.close()
                flash("A alternativa precisa ser de um tipo do MESMO período e do mesmo dia (e que não seja, ele próprio, alternativa).", "error")
                return redirect(url_for('dispensa_tipos'))
        cur.execute("SELECT id FROM dispensa_tipos WHERE nome=%s AND id<>%s", (nome, tipo_id))
        if cur.fetchone():
            cur.close()
            flash(f"Já existe outro tipo “{nome}”.", "error")
            return redirect(url_for('dispensa_tipos'))
        cur.execute("SELECT valor FROM dispensa_tipos WHERE id=%s", (tipo_id,))
        atual = cur.fetchone()
        cur.execute("""UPDATE dispensa_tipos SET nome=%s, descricao=%s, valor=%s, ativo=%s,
                       periodo=%s, dia_seguinte=%s, alternativa_de=%s WHERE id=%s""",
                    (nome, descricao or None, valor, ativo, periodo, dia_seguinte, alternativa_de, tipo_id))
        if not periodo:      # saiu da prescrição por período: quem era alternativa dele deixa de ser
            cur.execute("UPDATE dispensa_tipos SET alternativa_de=NULL WHERE alternativa_de=%s", (tipo_id,))
        pendentes_atualizadas = 0
        if atual and float(atual[0]) != valor:
            cur.execute("INSERT INTO dispensa_tipos_historico (tipo_id, valor, alterado_por) VALUES (%s,%s,%s)",
                        (tipo_id, valor, get_usuario_logado()))
            # refeições ainda não entregues passam a usar o valor novo; entregues ficam com o valor da época
            cur.execute(f"""UPDATE dispensa_itens i JOIN dispensa_pacientes p ON p.id = i.paciente_id
                            SET i.valor_unitario=%s WHERE i.tipo_id=%s AND i.status='pendente' AND {_SQL_NAO_FECHADO}""",
                        (valor, tipo_id))
            pendentes_atualizadas = cur.rowcount
        mysql.connection.commit()
        cur.close()
        msg = f"Tipo “{nome}” atualizado."
        if pendentes_atualizadas:
            msg += f" {pendentes_atualizadas} refeição(ões) ainda não entregue(s) passaram a usar o novo valor."
        flash(msg, "success")
    except Exception as e:
        mysql.connection.rollback()
        logger.error(f"Erro ao editar tipo de refeição de paciente: {e}")
        flash("Erro ao salvar.", "error")
    return redirect(url_for('dispensa_tipos'))


@app.route('/admin/dispensa/tipos/<int:tipo_id>/reajustar', methods=['POST'])
def dispensa_tipo_reajustar(tipo_id):
    """Aplica o valor atual do tipo às entregas que ficaram com R$ 0,00 (com registro de auditoria)."""
    g = _guard_admin()
    if g: return g
    init_dispensa_fase2()
    init_dispensa_fechamentos()
    motivo = ' '.join((request.form.get('motivo') or '').split())[:255]
    if len(motivo) < 5:
        flash("Informe o motivo do reajuste (mínimo 5 caracteres).", "error")
        return redirect(url_for('dispensa_tipos'))
    usuario = get_usuario_logado()
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT nome, valor FROM dispensa_tipos WHERE id=%s", (tipo_id,))
        t = cur.fetchone()
        if not t or float(t[1]) <= 0:
            cur.close()
            flash("Cadastre um valor maior que zero no tipo antes de reajustar.", "error")
            return redirect(url_for('dispensa_tipos'))
        cur.execute("""SELECT i.id, p.data_prescricao FROM dispensa_itens i
                       JOIN dispensa_pacientes p ON p.id = i.paciente_id
                       WHERE i.tipo_id=%s AND i.status='entregue' AND i.valor_unitario=0 AND """ + _SQL_NAO_FECHADO, (tipo_id,))
        alvo = cur.fetchall()
        if not alvo:
            cur.close()
            flash("Não há entregas com valor R$ 0,00 para este tipo.", "error")
            return redirect(url_for('dispensa_tipos'))
        datas = [r[1] for r in alvo]
        cur.execute("""INSERT INTO dispensa_ajustes_valor (tipo_id, valor_antigo, valor_novo, qtd_itens,
                       data_ini, data_fim, motivo, feito_por) VALUES (%s, 0, %s, %s, %s, %s, %s, %s)""",
                    (tipo_id, t[1], len(alvo), min(datas), max(datas), motivo, usuario))
        ajuste_id = cur.lastrowid
        fmt = ','.join(['%s'] * len(alvo))
        cur.execute(f"UPDATE dispensa_itens SET valor_unitario=%s, ajuste_id=%s WHERE id IN ({fmt}) "
                    f"AND status='entregue' AND valor_unitario=0", [t[1], ajuste_id] + [r[0] for r in alvo])
        mysql.connection.commit()
        cur.close()
        logger.info(f"{usuario} reajustou {len(alvo)} entrega(s) de {t[0]} de R$ 0,00 para R$ {moeda_br(float(t[1]))}: {motivo}")
        flash(f"{len(alvo)} entrega(s) de {t[0]} reajustada(s) para R$ {moeda_br(float(t[1]))}. Registro de auditoria nº {ajuste_id}.", "success")
    except Exception as e:
        mysql.connection.rollback()
        logger.error(f"Erro no reajuste de valor da dispensa: {e}")
        flash("Erro ao reajustar. Nada foi alterado.", "error")
    return redirect(url_for('dispensa_tipos'))


@app.route('/admin/dispensa/tipos/<int:tipo_id>/excluir', methods=['POST'])
def dispensa_tipo_excluir(tipo_id):
    g = _guard_admin()
    if g: return g
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT COUNT(*) FROM dispensa_itens WHERE tipo_id=%s", (tipo_id,))
        if cur.fetchone()[0]:
            cur.execute("UPDATE dispensa_tipos SET ativo=0 WHERE id=%s", (tipo_id,))
            flash("Este tipo já foi usado, então foi desativado (o histórico é mantido).", "success")
        else:
            cur.execute("DELETE FROM dispensa_tipos WHERE id=%s", (tipo_id,))
            flash("Tipo excluído.", "success")
        mysql.connection.commit()
        cur.close()
    except Exception as e:
        mysql.connection.rollback()
        logger.error(f"Erro ao excluir tipo de refeição de paciente: {e}")
        flash("Erro ao excluir.", "error")
    return redirect(url_for('dispensa_tipos'))


# ─── DISPENSA: FASE 2 — TOTEM DE ENTREGA NO LEITO (TABLET) ───────────────────

_DISPENSA_MOTIVOS = ['Paciente em jejum', 'Em exame ou procedimento', 'Alta hospitalar', 'Recusou a refeição',
                     'Ausente do leito', 'Óbito', 'Dieta suspensa', 'Outro']
_DISPENSA_MOTIVOS_SEM_QR = ['Pulseira ilegível ou danificada', 'Paciente sem pulseira', 'Câmera não funciona', 'Outro']


def init_dispensa_fase2():
    """Colunas de validação da entrega + perfil 'dispensa' no cadastro de usuários (idempotente)."""
    init_dispensa_tables()
    cur = mysql.connection.cursor()
    cur.execute("ALTER TABLE dispensa_itens ADD COLUMN IF NOT EXISTS validacao VARCHAR(20) DEFAULT NULL "
                "COMMENT 'qr | manual' AFTER motivo")
    cur.execute("ALTER TABLE dispensa_itens ADD COLUMN IF NOT EXISTS ajuste_id INT DEFAULT NULL "
                "COMMENT 'Reajuste de valor aplicado depois da entrega' AFTER validacao")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS dispensa_ajustes_valor (
            id           INT AUTO_INCREMENT PRIMARY KEY,
            tipo_id      INT NOT NULL,
            valor_antigo DECIMAL(10,2) NOT NULL,
            valor_novo   DECIMAL(10,2) NOT NULL,
            qtd_itens    INT NOT NULL,
            data_ini     DATE DEFAULT NULL,
            data_fim     DATE DEFAULT NULL,
            motivo       VARCHAR(255) NOT NULL,
            feito_por    VARCHAR(120) DEFAULT NULL,
            feito_em     TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
            KEY idx_dav_tipo (tipo_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    """)
    # Avaria: a refeição foi entregue mas caiu/estragou → reposição, entregue e cobrada à parte (sem limite)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS dispensa_reposicoes (
            id             INT AUTO_INCREMENT PRIMARY KEY,
            item_id        INT NOT NULL COMMENT 'Refeição original (dispensa_itens) que sofreu a avaria',
            seq            INT NOT NULL COMMENT '1ª, 2ª... reposição da mesma refeição',
            avaria_motivo  VARCHAR(255) NOT NULL,
            avaria_por     VARCHAR(120) DEFAULT NULL,
            avaria_em      TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
            status         VARCHAR(20) NOT NULL DEFAULT 'pendente' COMMENT 'pendente | entregue | nao_entregue',
            valor_unitario DECIMAL(10,2) NOT NULL DEFAULT 0.00 COMMENT 'Valor da refeição original (cobrado de novo)',
            entregue_em    DATETIME DEFAULT NULL,
            entregue_por   VARCHAR(120) DEFAULT NULL,
            validacao      VARCHAR(20) DEFAULT NULL COMMENT 'qr | manual',
            motivo         VARCHAR(255) DEFAULT NULL,
            UNIQUE KEY uk_repo_item_seq (item_id, seq),
            CONSTRAINT fk_repo_item FOREIGN KEY (item_id) REFERENCES dispensa_itens (id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    """)
    cur.execute("SHOW COLUMNS FROM usuarios LIKE 'perfil'")
    tipo_col = (cur.fetchone() or [None, ''])[1] or ''
    if tipo_col.startswith('enum(') and "'dispensa'" not in tipo_col:
        valores = tipo_col[5:-1] + ",'dispensa'"
        cur.execute(f"ALTER TABLE usuarios MODIFY perfil ENUM({valores}) NOT NULL")
    mysql.connection.commit()
    cur.close()


DISPENSA_INATIVIDADE_SEG = 10 * 60   # logout automático do totem (dados sensíveis de pacientes)


def _guard_dispensa():
    if 'usuario_id' not in session:
        return redirect('/')
    if (perfil_atual() or {}).get('inicio') == 'dispensa':
        agora = datetime.now().timestamp()
        ult = session.get('disp_ult')
        if ult and agora - ult > DISPENSA_INATIVIDADE_SEG:
            logger.info(f"{get_usuario_logado()}: sessão do totem encerrada por inatividade.")
            session.clear()
            flash("Sessão encerrada por inatividade (10 minutos). Entre novamente.")
            return redirect('/')
        # a atualização automática da lista não conta como uso
        if request.endpoint != 'dispensa_totem_status':
            session['disp_ult'] = agora
    return None


def _normalizar_txt(s):
    s = _ud.normalize('NFD', (s or '').upper())
    s = ''.join(ch for ch in s if _ud.category(ch) != 'Mn')
    return ' '.join(_re.sub(r'[^A-Z0-9]+', ' ', s).split())


def _datas_possiveis(d):
    if not d:
        return []
    return [d.strftime(f) for f in ('%d/%m/%Y', '%Y-%m-%d', '%d%m%Y', '%Y%m%d', '%d-%m-%Y', '%d.%m.%Y')]


def _conferir_qr(qr_texto, paciente):
    """Confere o texto lido do QR (etiqueta do GTR ou pulseira) com o paciente esperado.
    Etiqueta do GTR: o código tem de ser o do atendimento do paciente.
    Pulseira: sem depender do formato (separadores/ordem/JSON), exige atendimento, nome completo e
    data de nascimento (se houver)."""
    cod = _etiqueta_lida(qr_texto)
    if cod:
        return [] if _hmac.compare_digest(cod, etiqueta_codigo(paciente['atendimento'])) else ['etiqueta de outro paciente']
    bruto = qr_texto or ''
    texto = ' ' + _normalizar_txt(bruto) + ' '
    tokens = set(texto.split())
    problemas = []
    atend = _normalizar_txt(paciente['atendimento'])
    if not atend or (atend not in tokens and (' ' + atend + ' ') not in texto):
        problemas.append('atendimento')
    nome = _normalizar_txt(paciente['nome'])
    if nome and (' ' + nome + ' ') not in texto:
        problemas.append('nome')
    if paciente.get('data_nascimento_obj'):
        digitos_qr = _re.sub(r'\D', '', bruto)
        ok_dn = any(f in bruto for f in _datas_possiveis(paciente['data_nascimento_obj'])) or \
                paciente['data_nascimento_obj'].strftime('%d%m%Y') in digitos_qr
        if not ok_dn:
            problemas.append('data de nascimento')
    return problemas


def _mesmo_identificador(digitado, esperado):
    """Compara prontuário/atendimento digitado com o cadastrado (ignora pontuação, espaços e zeros à esquerda)."""
    a = _normalizar_txt(digitado).replace(' ', '')
    b = _normalizar_txt(esperado).replace(' ', '')
    if not a or not b:
        return False
    return a == b or (a.isdigit() and b.isdigit() and a.lstrip('0') == b.lstrip('0'))


DISPENSA_MOTIVOS_AVARIA = ['Caiu no chão', 'Derramou', 'Contaminada', 'Embalagem danificada',
                           'Temperatura inadequada', 'Outro']


def _dispensa_repo(cur, repo_id):
    cur.execute("""SELECT id, item_id, seq, status, valor_unitario, avaria_motivo FROM dispensa_reposicoes
                   WHERE id=%s""", (repo_id,))
    r = cur.fetchone()
    return {'id': r[0], 'item_id': r[1], 'seq': r[2], 'status': r[3], 'valor': float(r[4] or 0),
            'avaria_motivo': r[5]} if r else None


def _ref_dispensa(raw):
    """'123' = refeição (dispensa_itens); 'r45' = reposição por avaria. Devolve (item_id, repo_id)."""
    raw = (raw or '').strip()
    try:
        return (None, int(raw[1:])) if raw[:1] == 'r' else (int(raw), None)
    except ValueError:
        return (0, None)


def _repos_resumo(cur, item_ids):
    """item_id → {'n': reposições registradas, 'pend': há reposição pendente}."""
    if not item_ids:
        return {}
    cur.execute(f"""SELECT item_id, COUNT(*), SUM(status='pendente') FROM dispensa_reposicoes
                    WHERE item_id IN ({','.join(['%s'] * len(item_ids))}) GROUP BY item_id""", list(item_ids))
    return {r[0]: {'n': int(r[1]), 'pend': bool(r[2])} for r in cur.fetchall()}


def _resposta_ja_registrado(cur, item_id, repo_id=None):
    """Resposta padrão quando outro tablet (ou o mesmo) já registrou o item (ou a reposição)."""
    if repo_id:
        cur.execute("SELECT status, entregue_por, entregue_em FROM dispensa_reposicoes WHERE id=%s", (repo_id,))
    else:
        cur.execute("SELECT status, entregue_por, entregue_em FROM dispensa_itens WHERE id=%s", (item_id,))
    r = cur.fetchone() or ('?', None, None)
    quando = r[2].strftime('%H:%M') if r[2] else ''
    acao = 'entregue' if r[0] == 'entregue' else 'registrada como não entregue'
    return {'ok': False, 'tipo': 'ja_registrado', 'status': r[0], 'por': r[1] or '—', 'hora': quando,
            'erro': f"Esta refeição já foi {acao} por {r[1] or '—'} às {quando}."}, 409


DISPENSA_VIRADA_HORA = 3   # até 03:00 o totem ainda mostra e aceita a ceia/jantar do dia anterior


def dispensa_data_totem(periodo, dia_seguinte, agora=None):
    """Dia de prescrição que o totem atende para um tipo de refeição. As refeições da noite do próprio dia
    (Jantar, Jantar (Sopa), Ceia) continuam valendo até as 03:00 do dia seguinte; as demais são sempre de hoje."""
    from datetime import timedelta
    agora = agora or datetime.now()
    if agora.hour < DISPENSA_VIRADA_HORA and periodo == 'noite' and not dia_seguinte:
        return agora.date() - timedelta(days=1)
    return agora.date()


def _dispensa_tipo_totem(cur, tipo_id):
    """(nome, dia de prescrição atendido pelo totem) do tipo, ou None."""
    cur.execute("SELECT nome, periodo, dia_seguinte FROM dispensa_tipos WHERE id=%s", (tipo_id,))
    t = cur.fetchone()
    return (t[0], dispensa_data_totem(t[1], t[2])) if t else None


def _dispensa_item(cur, item_id):
    cur.execute("""SELECT i.id, i.status, i.tipo_id, t.nome, p.id, p.atendimento, p.nome, p.nome_mae,
                          p.data_nascimento, p.leito, p.data_prescricao, i.entregue_por, i.entregue_em,
                          p.prontuario, i.valor_unitario, i.para, p.acomp_lactante, t.periodo, t.dia_seguinte
                   FROM dispensa_itens i
                   JOIN dispensa_pacientes p ON p.id = i.paciente_id
                   JOIN dispensa_tipos t ON t.id = i.tipo_id
                   WHERE i.id = %s""", (item_id,))
    r = cur.fetchone()
    if not r:
        return None
    return {'id': r[0], 'status': r[1], 'tipo_id': r[2], 'tipo': r[3], 'paciente_id': r[4], 'atendimento': r[5],
            'nome': r[6], 'nome_mae': r[7], 'data_nascimento_obj': r[8], 'leito': r[9], 'data_prescricao': r[10],
            'entregue_por': r[11], 'entregue_em': r[12], 'prontuario': r[13] or '', 'valor': float(r[14] or 0),
            'para': r[15] or 'paciente', 'lactante': bool(r[16]),
            'data_totem': dispensa_data_totem(r[17], r[18])}


@app.route('/dispensa')
def dispensa_totem():
    g = _guard_dispensa()
    if g: return g
    init_dispensa_fase2()
    hoje = date.today()
    # cada tipo é atendido em um único dia (ceia/jantar de ontem até as 03:00, ver dispensa_data_totem)
    por_dia = {}
    for t in _dispensa_tipos():
        por_dia.setdefault(dispensa_data_totem(t['periodo'], t['dia_seguinte']), []).append(t['id'])
    filtro = ' OR '.join(f"(p.data_prescricao = %s AND i.tipo_id IN ({','.join(['%s'] * len(ids))}))"
                         for ids in por_dia.values()) or 'FALSE'
    params = [v for d, ids in por_dia.items() for v in [d] + ids]
    cur = mysql.connection.cursor()
    cur.execute(f"""SELECT t.id, t.nome, COUNT(i.id),
                          SUM(i.status='entregue'), SUM(i.status='nao_entregue'), p.data_prescricao
                   FROM dispensa_itens i
                   JOIN dispensa_pacientes p ON p.id = i.paciente_id
                   JOIN dispensa_tipos t ON t.id = i.tipo_id
                   WHERE {filtro}
                   GROUP BY t.id, t.nome, t.ordem, p.data_prescricao ORDER BY t.ordem, t.nome""", params)
    refeicoes = [{'id': r[0], 'nome': r[1], 'total': int(r[2]), 'entregues': int(r[3] or 0),
                  'nao_entregues': int(r[4] or 0), 'de_ontem': r[5] < hoje,
                  'data_fmt': r[5].strftime('%d/%m')} for r in cur.fetchall()]
    # reposições por avaria contam como mais uma entrega a fazer na refeição
    cur.execute(f"""SELECT i.tipo_id, COUNT(*), SUM(r.status='entregue'), SUM(r.status='nao_entregue')
                    FROM dispensa_reposicoes r JOIN dispensa_itens i ON i.id = r.item_id
                    JOIN dispensa_pacientes p ON p.id = i.paciente_id
                    WHERE {filtro} GROUP BY i.tipo_id""", params)
    por_tipo = {r['id']: r for r in refeicoes}
    for tid, n, ent, nao in cur.fetchall():
        if tid in por_tipo:
            por_tipo[tid]['total'] += int(n)
            por_tipo[tid]['entregues'] += int(ent or 0)
            por_tipo[tid]['nao_entregues'] += int(nao or 0)
    cur.close()
    for r in refeicoes:
        r['pendentes'] = r['total'] - r['entregues'] - r['nao_entregues']
        r['pct'] = round((r['entregues'] + r['nao_entregues']) * 100 / r['total']) if r['total'] else 0
    return render_template('dispensa_totem.html', tela='inicio', refeicoes=refeicoes,
                           hoje_fmt=f"{_DIAS_SEMANA_PT[hoje.weekday()]}, {hoje.strftime('%d/%m/%Y')}",
                           usuario=get_usuario_logado(), perfil=session.get('usuario_perfil'))


@app.route('/dispensa/<int:tipo_id>')
def dispensa_totem_lista(tipo_id):
    g = _guard_dispensa()
    if g: return g
    init_dispensa_fase2()
    cur = mysql.connection.cursor()
    t = _dispensa_tipo_totem(cur, tipo_id)
    if not t:
        cur.close()
        return redirect(url_for('dispensa_totem'))
    hoje = t[1]   # dia de prescrição atendido (ontem, para a ceia/jantar antes das 03:00)
    cur.execute("""SELECT i.id, i.status, i.motivo, i.validacao, i.entregue_em, i.entregue_por,
                          p.leito, p.nome, p.nome_mae, p.data_nascimento, p.atendimento, p.prontuario, p.dieta,
                          i.para, p.id, p.acomp_lactante, p.unidade, p.observacao
                   FROM dispensa_itens i JOIN dispensa_pacientes p ON p.id = i.paciente_id
                   WHERE p.data_prescricao = %s AND i.tipo_id = %s""", (hoje, tipo_id))
    rows = cur.fetchall()
    repos = _repos_resumo(cur, [r[0] for r in rows])
    por_pac, pac_do_item = {}, {}
    for r in rows:
        rp = repos.get(r[0], {'n': 0, 'pend': False})
        reg = {'id': r[0], 'status': r[1], 'motivo': r[2] or '', 'validacao': r[3] or '',
               'hora': r[4].strftime('%H:%M') if r[4] else '', 'entregue_por': r[5] or '',
               'n_repo': rp['n'], 'repo_pend': rp['pend']}
        pac_do_item[r[0]] = (r[14], r[13])
        base = por_pac.setdefault(r[14], {
            'leito': r[6], 'nome': r[7], 'nome_mae': r[8] or '',
            'unidade': (r[16] or '').strip() or 'Unidade não informada',
            'data_nascimento': r[9].strftime('%d/%m/%Y') if r[9] else '',
            # atendimento/prontuário NÃO vão para a tela: são a segunda checagem da entrega sem QR
            'prontuario': bool(r[11]), 'dieta': r[12] or '', 'observacao': r[17] or '', 'pac': None, 'acomp': None})
        if r[13] == 'acompanhante':
            base['acomp'] = dict(reg, lactante=bool(r[15]))
        else:
            base['pac'] = reg
    itens = []
    for base in por_pac.values():
        # o card segue a refeição do paciente; se só o acompanhante tem refeição, segue a dele
        principal = base['pac'] or base['acomp']
        it = dict(base, **principal, so_acomp=base['pac'] is None)
        # o leito só sai de "Pendentes" quando paciente E acompanhante estiverem resolvidos
        it['falta_acomp'] = bool(base['pac'] and base['acomp'] and base['pac']['status'] != 'pendente'
                                 and base['acomp']['status'] == 'pendente')
        it['card_status'] = 'pendente' if it['falta_acomp'] else it['status']
        itens.append(it)
    # reposições por avaria: um card próprio por reposição (id "r<id>"), entregue com nova conferência no leito
    if repos:
        cur.execute(f"""SELECT id, item_id, seq, avaria_motivo, status, motivo, validacao, entregue_em, entregue_por
                        FROM dispensa_reposicoes WHERE item_id IN ({','.join(['%s'] * len(repos))})
                        ORDER BY item_id, seq""", list(repos))
        for rid, item_id, seq, av_mot, st, mot, val, em, por in cur.fetchall():
            pid, para = pac_do_item[item_id]
            base = {k: v for k, v in por_pac[pid].items() if k not in ('pac', 'acomp')}
            itens.append(dict(base, id=f"r{rid}", status=st, motivo=mot or '', validacao=val or '',
                              hora=em.strftime('%H:%M') if em else '', entregue_por=por or '',
                              acomp=None, so_acomp=False, falta_acomp=False, card_status=st,
                              n_repo=0, repo_pend=repos[item_id]['pend'],
                              repo={'seq': seq, 'avaria': av_mot, 'acompanhante': para == 'acompanhante'}))
    cur.close()
    itens.sort(key=lambda x: (x['card_status'] != 'pendente', x['unidade'] == 'Unidade não informada',
                              x['unidade'], _ordem_leito(x['leito'])))
    # setores (unidades de internação) para o entregador escolher antes de ver os leitos
    unid = {}
    for it in itens:
        u = unid.setdefault(it['unidade'], {'nome': it['unidade'], 'total': 0, 'pendentes': 0})
        u['total'] += 1
        u['pendentes'] += it['card_status'] == 'pendente'
    unidades = sorted(unid.values(), key=lambda u: (u['nome'] == 'Unidade não informada', u['nome']))
    resumo = {'total': len(itens), 'entregues': sum(1 for i in itens if i['card_status'] == 'entregue'),
              'nao': sum(1 for i in itens if i['card_status'] == 'nao_entregue'),
              'acomp': sum(1 for i in itens if i['acomp']),
              'acomp_pend': sum(1 for i in itens if i['acomp'] and i['acomp']['status'] == 'pendente')}
    resumo['pendentes'] = resumo['total'] - resumo['entregues'] - resumo['nao']
    return render_template('dispensa_totem.html', tela='lista', tipo_id=tipo_id, tipo_nome=t[0], itens=itens,
                           unidades=unidades,
                           resumo=resumo, motivos=_DISPENSA_MOTIVOS, motivos_sem_qr=_DISPENSA_MOTIVOS_SEM_QR,
                           motivos_avaria=DISPENSA_MOTIVOS_AVARIA,
                           data_iso=hoje.isoformat(), de_ontem=hoje < date.today(), virada_hora=DISPENSA_VIRADA_HORA,
                           hoje_fmt=f"{_DIAS_SEMANA_PT[hoje.weekday()]}, {hoje.strftime('%d/%m/%Y')}",
                           usuario=get_usuario_logado(), perfil=session.get('usuario_perfil'))


@app.route('/dispensa/ping', methods=['POST'])
def dispensa_ping():
    """'Continuar' no aviso de inatividade: renova o tempo de uso do totem."""
    g = _guard_dispensa()
    if g:
        return {'ok': False}, 401
    return {'ok': True}


@app.route('/dispensa/<int:tipo_id>/status')
def dispensa_totem_status(tipo_id):
    """Situação atual dos itens da refeição (para os tablets se atualizarem sozinhos)."""
    g = _guard_dispensa()
    if g:
        return {'ok': False, 'erro': 'Sessão expirada.'}, 401
    cur = mysql.connection.cursor()
    t = _dispensa_tipo_totem(cur, tipo_id)
    if not t or request.args.get('data', t[1].isoformat()) != t[1].isoformat():
        # passou das 03:00 com a ceia de ontem aberta: o tablet volta para a tela inicial
        cur.close()
        return {'ok': False, 'tipo': 'virou_dia'}
    cur.execute("""SELECT i.id, i.status, i.entregue_em, i.entregue_por, i.validacao, i.motivo, i.para
                   FROM dispensa_itens i JOIN dispensa_pacientes p ON p.id = i.paciente_id
                   WHERE p.data_prescricao = %s AND i.tipo_id = %s""", (t[1], tipo_id))
    itens = {str(r[0]): {'status': r[1], 'hora': r[2].strftime('%H:%M') if r[2] else '', 'por': r[3] or '',
                         'validacao': r[4] or '', 'motivo': r[5] or '', 'para': r[6]} for r in cur.fetchall()}
    # reposições por avaria (chave "r<id>"): uma nova aparece aqui e o tablet recarrega a lista
    cur.execute("""SELECT r.id, r.status, r.entregue_em, r.entregue_por, r.validacao, r.motivo, i.para
                   FROM dispensa_reposicoes r JOIN dispensa_itens i ON i.id = r.item_id
                   JOIN dispensa_pacientes p ON p.id = i.paciente_id
                   WHERE p.data_prescricao = %s AND i.tipo_id = %s""", (t[1], tipo_id))
    itens.update({f"r{r[0]}": {'status': r[1], 'hora': r[2].strftime('%H:%M') if r[2] else '', 'por': r[3] or '',
                               'validacao': r[4] or '', 'motivo': r[5] or '', 'para': r[6]} for r in cur.fetchall()})
    cur.close()
    return {'ok': True, 'itens': itens}


@app.route('/dispensa/registrar', methods=['POST'])
def dispensa_registrar():
    """Registra a entrega (QR ou manual) ou a não entrega de um item ou de uma reposição por avaria
    (item_id "r<id>"). Responde JSON para o totem."""
    g = _guard_dispensa()
    if g:
        return {'ok': False, 'erro': 'Sessão expirada. Entre novamente.'}, 401
    init_dispensa_fase2()
    item_id, repo_id = _ref_dispensa(request.form.get('item_id'))
    acao = request.form.get('acao', '')
    usuario = get_usuario_logado()
    cur = mysql.connection.cursor()
    repo = _dispensa_repo(cur, repo_id) if repo_id else None
    if repo:
        item_id = repo['item_id']   # a conferência (QR, identificação, prazo) é a da refeição original
    item = _dispensa_item(cur, item_id) if (repo or not repo_id) else None
    if not item:
        cur.close()
        return {'ok': False, 'erro': 'Item não encontrado para hoje.'}, 404
    if item['data_prescricao'] != item['data_totem']:
        cur.close()
        if item['data_prescricao'] < item['data_totem']:
            return {'ok': False, 'tipo': 'virou_dia',
                    'erro': f"Prazo encerrado: {item['tipo']} de {item['data_prescricao'].strftime('%d/%m')} "
                            f"só pode ser registrado(a) até as {DISPENSA_VIRADA_HORA:02d}:00."}, 409
        return {'ok': False, 'erro': 'Item não encontrado para hoje.'}, 404
    if _fechamentos_no_intervalo(item['data_prescricao']):
        cur.close()
        return {'ok': False, 'tipo': 'periodo_fechado', 'erro': 'Este dia pertence a um período fechado. Nada pode ser alterado.'}, 409
    if acao in ('qr', 'manual', 'nao_entregue') and not pode('dispensa_totem', 'incluir'):
        cur.close()
        return {'ok': False, 'erro': 'Seu perfil não tem permissão para registrar entregas.'}, 403
    alvo = repo or item   # o que será gravado: a refeição ou a reposição
    if alvo['status'] != 'pendente':
        resp = _resposta_ja_registrado(cur, item_id, repo_id)
        cur.close()
        return resp
    if acao in ('qr', 'manual') and alvo['valor'] <= 0:
        cur.close()
        return {'ok': False, 'tipo': 'sem_valor',
                'erro': f"O tipo {item['tipo']} está sem valor cadastrado. Avise a nutrição antes de entregar."}, 409
    tabela, alvo_id = ('dispensa_reposicoes', repo['id']) if repo else ('dispensa_itens', item_id)

    try:
        if acao == 'qr':
            problemas = _conferir_qr(request.form.get('qr', ''), item)
            if problemas:
                # a pulseira é de outro paciente do dia?
                outro = None
                cur.execute("SELECT atendimento, nome, leito FROM dispensa_pacientes WHERE data_prescricao=%s AND id<>%s",
                            (item['data_prescricao'], item['paciente_id']))
                texto = ' ' + _normalizar_txt(request.form.get('qr', '')) + ' '
                cod = _etiqueta_lida(request.form.get('qr', ''))
                for at, nm, lt in cur.fetchall():
                    if (cod and _hmac.compare_digest(cod, etiqueta_codigo(at))) or \
                            (not cod and (' ' + _normalizar_txt(at) + ' ') in texto):
                        outro = {'nome': nm, 'leito': lt}
                        break
                logger.warning(f"{usuario}: QR não confere para item {item_id} (leito {item['leito']}): {problemas}.")
                cur.close()
                if outro:
                    return {'ok': False, 'tipo': 'outro_paciente',
                            'erro': f"{'Etiqueta' if cod else 'Pulseira'} de OUTRO paciente ({outro['nome']}, leito {outro['leito']}). Não entregue."}
                return {'ok': False, 'tipo': 'nao_confere',
                        'erro': ('A etiqueta' if cod else 'A pulseira') + ' não confere com este paciente ('
                                + ', '.join(problemas) + '). Não entregue.'}
            cur.execute(f"""UPDATE {tabela} SET status='entregue', entregue_em=NOW(), entregue_por=%s,
                            validacao='qr', motivo=NULL WHERE id=%s AND status='pendente'""", (usuario, alvo_id))
            _fonte = 'pela etiqueta do leito' if _etiqueta_lida(request.form.get('qr', '')) else 'pela pulseira'
            msg = (f'Entrega ao acompanhante confirmada {_fonte}.' if item['para'] == 'acompanhante'
                   else f'Entrega confirmada {_fonte}.')
        elif acao == 'manual':
            motivo = (request.form.get('motivo') or '').strip()[:255]
            if motivo not in _DISPENSA_MOTIVOS_SEM_QR or (motivo == 'Outro' and not (request.form.get('obs') or '').strip()):
                cur.close()
                return {'ok': False, 'erro': 'Informe o motivo da entrega sem leitura da pulseira.'}, 400
            # Segunda checagem de identificação: prontuário e atendimento digitados devem conferir
            dig_pront = request.form.get('prontuario', '')
            dig_atend = request.form.get('atendimento', '')
            divergentes = []
            if not _mesmo_identificador(dig_atend, item['atendimento']):
                divergentes.append('atendimento')
            if item['prontuario'] and not _mesmo_identificador(dig_pront, item['prontuario']):
                divergentes.append('prontuário')
            if divergentes:
                logger.warning(f"{usuario}: entrega sem QR recusada no item {item_id} (leito {item['leito']}): "
                               f"{', '.join(divergentes)} não confere.")
                cur.close()
                return {'ok': False, 'tipo': 'ident_nao_confere',
                        'erro': 'Identificação não confere (' + ' e '.join(divergentes) + '). '
                                'Confira na pulseira ou no prontuário. Não entregue.'}, 400
            if motivo == 'Outro':
                motivo = 'Outro: ' + request.form.get('obs', '').strip()[:240]
            cur.execute(f"""UPDATE {tabela} SET status='entregue', entregue_em=NOW(), entregue_por=%s,
                            validacao='manual', motivo=%s WHERE id=%s AND status='pendente'""",
                        (usuario, motivo, alvo_id))
            msg = ('Entrega ao acompanhante registrada sem leitura da pulseira.' if item['para'] == 'acompanhante'
                   else 'Entrega registrada sem leitura da pulseira.')
        elif acao == 'nao_entregue':
            motivo = (request.form.get('motivo') or '').strip()[:255]
            if motivo not in _DISPENSA_MOTIVOS or (motivo == 'Outro' and not (request.form.get('obs') or '').strip()):
                cur.close()
                return {'ok': False, 'erro': 'Informe o motivo da não entrega.'}, 400
            if motivo == 'Outro':
                motivo = 'Outro: ' + request.form.get('obs', '').strip()[:240]
            cur.execute(f"""UPDATE {tabela} SET status='nao_entregue', entregue_em=NOW(), entregue_por=%s,
                            validacao=NULL, motivo=%s WHERE id=%s AND status='pendente'""", (usuario, motivo, alvo_id))
            msg = 'Registrado como não entregue.'
        else:
            cur.close()
            return {'ok': False, 'erro': 'Ação inválida.'}, 400
        if cur.rowcount == 0:
            # outro tablet registrou este item entre a leitura e a gravação
            mysql.connection.rollback()
            resp = _resposta_ja_registrado(cur, item_id, repo_id)
            cur.close()
            return resp
        if repo:
            msg = f"Reposição nº {repo['seq']}: " + msg[0].lower() + msg[1:]
        acomp_junto = None
        if not repo and item['para'] == 'paciente' and acao in ('qr', 'manual') and request.form.get('acomp_junto') == '1':
            # mesma leitura da pulseira vale para a refeição do acompanhante (mesmo leito, mesma refeição)
            cur.execute("""UPDATE dispensa_itens SET status='entregue', entregue_em=NOW(), entregue_por=%s,
                           validacao=%s, motivo=%s
                           WHERE paciente_id=%s AND tipo_id=%s AND para='acompanhante' AND status='pendente'
                             AND valor_unitario > 0""",
                        (usuario, acao, (motivo if acao == 'manual' else None), item['paciente_id'], item['tipo_id']))
            acomp_junto = cur.rowcount > 0
            if acomp_junto:
                msg += ' Acompanhante também recebeu.'
        mysql.connection.commit()
        logger.info(f"{usuario}: dispensa item {item_id}" + (f" reposição nº {repo['seq']}" if repo else "")
                    + f" ({item['para']}, leito {item['leito']}, {item['tipo']}) -> {acao}"
                    + (" + acompanhante" if acomp_junto else "") + ".")
        cur.close()
        return {'ok': True, 'msg': msg, 'acomp_junto': bool(acomp_junto)}
    except Exception as e:
        mysql.connection.rollback()
        cur.close()
        logger.error(f"Erro ao registrar dispensa: {e}")
        return {'ok': False, 'erro': 'Erro ao registrar. Tente novamente.'}, 500


@app.route('/dispensa/<int:tipo_id>/identificar', methods=['POST'])
def dispensa_identificar(tipo_id):
    """Leitor de QR sem fio (funciona como teclado): a dispenseira lê o QR com a lista aberta e o totem abre o leito.
    Devolve os cards do paciente lido nesta refeição (reposição pendente primeiro). Não registra nada: a entrega
    continua passando pela conferência de /dispensa/registrar. Por POST para o conteúdo da pulseira não ir para a URL."""
    g = _guard_dispensa()
    if g:
        return {'ok': False, 'erro': 'Sessão expirada. Entre novamente.'}, 401
    lido = (request.form.get('codigo') or '')[:2000]
    cod = _etiqueta_lida(lido)
    texto = ' ' + _normalizar_txt(lido) + ' '
    cur = mysql.connection.cursor()
    t = _dispensa_tipo_totem(cur, tipo_id)
    if not t or len(texto.strip()) < 4:
        cur.close()
        return {'ok': False, 'erro': 'Código não reconhecido. Leia o QR da etiqueta do leito ou da pulseira.'}, 404
    cur.execute("""SELECT p.id, p.atendimento, p.nome, p.leito, i.id, i.para, i.status
                   FROM dispensa_itens i JOIN dispensa_pacientes p ON p.id = i.paciente_id
                   WHERE p.data_prescricao = %s AND i.tipo_id = %s""", (t[1], tipo_id))
    rows = cur.fetchall()
    candidatos = {}
    for pid, at, nome, leito, *_ in rows:
        if (cod and _hmac.compare_digest(cod, etiqueta_codigo(at))) or \
                (not cod and _normalizar_txt(at) and (' ' + _normalizar_txt(at) + ' ') in texto):
            candidatos[pid] = (pid, nome, leito)
    # pulseira: o prontuário de um paciente pode coincidir com o atendimento de outro → vence quem tem o nome no texto
    pac = next((p for p in candidatos.values() if (' ' + _normalizar_txt(p[1]) + ' ') in texto),
               next(iter(candidatos.values()), None))
    if not pac:
        cur.close()
        return {'ok': False, 'erro': f"{'Etiqueta' if cod else 'Pulseira'} sem {t[0].lower()} nesta lista: o paciente "
                                     "não tem esta refeição liberada, é de outro dia ou o código não é do GTR."}, 404
    itens = [r for r in rows if r[0] == pac[0]]
    principal = next((r for r in itens if r[5] == 'paciente'), itens[0])
    cards = [f"r{rid}" for rid in _repos_pendentes(cur, [r[4] for r in itens])] + [str(principal[4])]
    cur.close()
    return {'ok': True, 'cards': cards, 'nome': pac[1], 'leito': pac[2]}


def _repos_pendentes(cur, item_ids):
    if not item_ids:
        return []
    cur.execute(f"""SELECT id FROM dispensa_reposicoes WHERE status='pendente'
                    AND item_id IN ({','.join(['%s'] * len(item_ids))}) ORDER BY id""", list(item_ids))
    return [r[0] for r in cur.fetchall()]


@app.route('/dispensa/avaria', methods=['POST'])
def dispensa_avaria():
    """A refeição foi entregue mas caiu/estragou: registra a avaria e libera uma REPOSIÇÃO pendente, que é
    entregue no totem com nova conferência e cobrada à parte. Vale também para uma reposição que sofreu avaria."""
    g = _guard_dispensa()
    if g:
        return {'ok': False, 'erro': 'Sessão expirada. Entre novamente.'}, 401
    init_dispensa_fase2()
    if not pode('dispensa_totem', 'incluir'):
        return {'ok': False, 'erro': 'Seu perfil não tem permissão para registrar avaria.'}, 403
    motivo = (request.form.get('motivo') or '').strip()[:255]
    obs = ' '.join((request.form.get('obs') or '').split())[:240]
    if motivo not in DISPENSA_MOTIVOS_AVARIA or (motivo == 'Outro' and not obs):
        return {'ok': False, 'erro': 'Informe o que aconteceu com a refeição.'}, 400
    if motivo == 'Outro':
        motivo = 'Outro: ' + obs
    item_id, repo_id = _ref_dispensa(request.form.get('item_id'))
    usuario = get_usuario_logado()
    cur = mysql.connection.cursor()
    repo = _dispensa_repo(cur, repo_id) if repo_id else None
    if repo:
        item_id = repo['item_id']
    item = _dispensa_item(cur, item_id) if (repo or not repo_id) else None
    erro = None
    if not item:
        erro = ('Refeição não encontrada.', 404)
    elif item['data_prescricao'] != item['data_totem']:
        erro = (f"Prazo encerrado: {item['tipo']} de {item['data_prescricao'].strftime('%d/%m')} não aceita mais registros.", 409)
    elif _fechamentos_no_intervalo(item['data_prescricao']):
        erro = ('Este dia pertence a um período fechado. Nada pode ser alterado.', 409)
    elif (repo or item)['status'] != 'entregue':
        erro = ('Só é possível registrar avaria de uma refeição já entregue.', 409)
    else:
        cur.execute("SELECT COUNT(*) FROM dispensa_reposicoes WHERE item_id=%s AND status='pendente'", (item_id,))
        if cur.fetchone()[0]:
            erro = ('Já existe uma reposição pendente desta refeição. Entregue-a antes de registrar outra avaria.', 409)
    if erro:
        cur.close()
        return {'ok': False, 'erro': erro[0]}, erro[1]
    try:
        cur.execute("SELECT COALESCE(MAX(seq), 0) + 1 FROM dispensa_reposicoes WHERE item_id=%s", (item_id,))
        seq = cur.fetchone()[0]
        # cobra de novo o valor da refeição original (o congelado na entrega)
        cur.execute("""INSERT INTO dispensa_reposicoes (item_id, seq, avaria_motivo, avaria_por, valor_unitario)
                       VALUES (%s, %s, %s, %s, %s)""", (item_id, seq, motivo, usuario, item['valor']))
        novo_id = cur.lastrowid
        mysql.connection.commit()
    except MySQLdb.IntegrityError:
        # outro tablet registrou a avaria desta refeição no mesmo instante
        mysql.connection.rollback()
        cur.close()
        return {'ok': False, 'erro': 'Outro tablet acabou de registrar uma avaria desta refeição. A lista será atualizada.'}, 409
    except Exception as e:
        mysql.connection.rollback()
        cur.close()
        logger.error(f"Erro ao registrar avaria na dispensa: {e}")
        return {'ok': False, 'erro': 'Erro ao registrar. Tente novamente.'}, 500
    cur.close()
    quem = ' do acompanhante' if item['para'] == 'acompanhante' else ''
    logger.info(f"{usuario}: avaria na dispensa item {item_id} ({item['para']}, leito {item['leito']}, {item['tipo']}): "
                f"{motivo} -> reposição nº {seq}.")
    auditar(alvo=f"{item['leito']} · {item['tipo']}{quem}",
            detalhes={'motivo': motivo, 'reposicao': seq, 'valor': item['valor']})
    return {'ok': True, 'repo_id': f"r{novo_id}",
            'msg': f"Avaria registrada. Reposição nº {seq}{quem} liberada.",
            'sub': 'Leve a nova refeição ao leito e confirme a entrega com a leitura do QR.'}


# ─── RELATÓRIO DE FATURAMENTO (consolidado: refeitório + dispensa) ───────────

_FAT_GRUPOS = [('colab', 'Colaboradores', 'Refeitório'), ('visit', 'Visitantes', 'Refeitório'),
               ('pac', 'Pacientes', 'Dispensa no leito'), ('acp', 'Acompanhantes', 'Dispensa no leito')]


def _faturamento_dados(data_ini, data_fim):
    """Consolida tudo o que é faturável no período:
    refeitório (colaboradores e visitantes) = senhas emitidas × custo unitário vigente NO DIA da emissão;
    dispensa (pacientes e acompanhantes) = refeições entregues × valor unitário vigente na entrega."""
    from collections import OrderedDict
    t = get_turnos()
    cur = mysql.connection.cursor()
    cur.execute(f"""SELECT DATE(data_hora), {sql_refeicao(t)}, cargo = 'VISITANTE', COUNT(*)
                    FROM emissoes_senha WHERE DATE(data_hora) BETWEEN %s AND %s
                    GROUP BY 1, 2, 3""", (data_ini, data_fim))
    emis = cur.fetchall()
    cur.close()

    custos_dia, linhas, por_dia, sem_custo = {}, {}, OrderedDict(), set()
    ordem_ref = {'cafe': 0, 'almoco': 1, 'janta': 2}
    for dia, ref, visit, n in emis:
        if dia not in custos_dia:
            custos_dia[dia] = get_custos_na_data(dia)
        unit = float(custos_dia[dia].get(ref, {}).get('custo_unitario', 0) or 0)
        if unit <= 0:
            sem_custo.add(REFEICAO_NOME[ref])
        grp_k = 'visit' if visit else 'colab'
        k = (grp_k, ordem_ref[ref], REFEICAO_NOME[ref], unit)
        linhas[k] = linhas.get(k, 0) + int(n)
        d = por_dia.setdefault(dia, {g2: 0.0 for g2, _, _ in _FAT_GRUPOS} | {f'q_{g2}': 0 for g2, _, _ in _FAT_GRUPOS})
        d[grp_k] += n * unit; d[f'q_{grp_k}'] += int(n)

    disp = _dispensa_dados_relatorio(data_ini, data_fim)
    for grp in disp['faturamento']:
        grp_k = 'acp' if grp['para'] == 'Acompanhante' else 'pac'
        for l in grp['linhas']:
            k = (grp_k, 0, l['refeicao'], l['unit'])
            linhas[k] = linhas.get(k, 0) + l['qtd']
    # todos os tipos aparecem no demonstrativo, com 0 quando não houve entrega (valor atual como referência)
    for grp_k in ('pac', 'acp'):
        for tp in disp['tipos']:
            if not any(k[0] == grp_k and k[2] == tp['nome'] for k in linhas):
                linhas[(grp_k, 0, tp['nome'], float(tp.get('valor_atual') or 0))] = 0
    custos_hoje = get_custos_na_data(data_fim)
    for grp_k in ('colab', 'visit'):
        for ref, ordem in ordem_ref.items():
            if not any(k[0] == grp_k and k[2] == REFEICAO_NOME[ref] for k in linhas):
                linhas[(grp_k, ordem, REFEICAO_NOME[ref], float(custos_hoje.get(ref, {}).get('custo_unitario', 0) or 0))] = 0
    # ordem dos tipos da dispensa (a definida em Tipos de refeição) para as linhas de paciente/acompanhante
    ordem_disp = {tp['nome']: i for i, tp in enumerate(disp['tipos'])}
    for dd in disp['dias']:
        d = por_dia.setdefault(dd['data'], {g2: 0.0 for g2, _, _ in _FAT_GRUPOS} | {f'q_{g2}': 0 for g2, _, _ in _FAT_GRUPOS})
        d['acp'] += dd['valor_acomp']; d['pac'] += dd['valor'] - dd['valor_acomp']
        d['q_acp'] += dd['acomp']; d['q_pac'] += dd['qtd'] - dd['acomp']

    grupos = []
    for grp_k, nome, origem in _FAT_GRUPOS:
        ls = sorted(((k, n) for k, n in linhas.items() if k[0] == grp_k),
                    key=lambda x: (x[0][1] if grp_k in ('colab', 'visit') else ordem_disp.get(x[0][2], 99), x[0][2], x[0][3]))
        itens = [{'refeicao': k[2], 'qtd': n, 'unit': k[3], 'subtotal': n * k[3]} for k, n in ls]
        grupos.append({'chave': grp_k, 'nome': nome, 'origem': origem, 'itens': itens,
                       'qtd': sum(i['qtd'] for i in itens), 'valor': sum(i['subtotal'] for i in itens)})
    total = sum(gr['valor'] for gr in grupos)
    for gr in grupos:
        gr['pct'] = gr['valor'] * 100 / total if total else 0
    dias = []
    for dia in sorted(por_dia):
        d = por_dia[dia]
        d['data'] = dia
        d['total'] = sum(d[grp_k] for grp_k, _, _ in _FAT_GRUPOS)
        d['qtd'] = sum(d[f'q_{grp_k}'] for grp_k, _, _ in _FAT_GRUPOS)
        dias.append(d)
    refeitorio = sum(gr['valor'] for gr in grupos if gr['chave'] in ('colab', 'visit'))
    dt = disp['tot']
    avisos = []
    if sem_custo:
        avisos.append(f"Refeitório: senha(s) de {', '.join(sorted(sem_custo))} sem custo unitário cadastrado no período "
                      "(Parâmetros › Custos de refeição) — entraram com R$ 0,00.")
    if dt['zerados']:
        avisos.append(f"Dispensa: {dt['zerados']} refeição(ões) entregue(s) com valor R$ 0,00 (tipo sem valor na entrega).")
    if dt['pendentes']:
        avisos.append(f"Dispensa: {dt['pendentes']} refeição(ões) liberada(s) ficaram sem registro no totem e não foram faturadas.")
    if dt['corrigidos']:
        avisos.append(f"Dispensa: {dt['corrigidos']} registro(s) do totem foram corrigidos manualmente, com motivo registrado.")
    if dt['repos']:
        avisos.append(f"Dispensa: {dt['repos']} reposição(ões) por avaria entregue(s) e cobrada(s) "
                      f"(R$ {moeda_br(dt['valor_repos'])}), além da refeição original.")
    if dt['manual']:
        avisos.append(f"Dispensa: {dt['manual']} de {dt['entregues']} entrega(s) ({str(dt['pct_manual']).replace('.', ',')}%) "
                      "confirmadas sem leitura da pulseira.")
    n_dias = (data_fim - data_ini).days + 1
    return {'grupos': grupos, 'total': total, 'qtd': sum(gr['qtd'] for gr in grupos), 'dias': dias,
            'refeitorio': refeitorio, 'dispensa': total - refeitorio, 'n_dias': n_dias,
            'media_dia': total / n_dias if n_dias else 0, 'avisos': avisos,
            'fechamentos': _fechamentos_no_intervalo(data_ini, data_fim),
            'nao_entregues': dt['nao'], 'pacientes': dt['pacientes'], 'acompanhantes': dt['acompanhantes']}


@app.route('/admin/relatorio/faturamento', methods=['GET', 'POST'])
def relatorio_faturamento():
    if 'usuario_id' not in session:
        return redirect('/')
    init_dispensa_fase2()
    if request.method == 'POST':
        data_ini = _parse_data(request.form.get('data_inicial'))
        data_fim = _parse_data(request.form.get('data_final'))
        if not data_ini or not data_fim:
            flash("Datas inválidas.", "error")
            return redirect(url_for('relatorio_faturamento'))
        if data_fim < data_ini:
            flash("A data final não pode ser anterior à inicial.", "error")
            return redirect(url_for('relatorio_faturamento'))
        formato = request.form.get('tipo_relatorio', 'pdf')
        f = _faturamento_dados(data_ini, data_fim)
        periodo = f"{data_ini.strftime('%d/%m/%Y')} a {data_fim.strftime('%d/%m/%Y')}"
        agora = datetime.now().strftime('%d/%m/%Y %H:%M')
        usuario = get_usuario_logado()
        logger.info(f"{usuario} emitiu o relatório de faturamento ({periodo}, {formato}): R$ {moeda_br(f['total'])}.")
        auditar(detalhes={'periodo': periodo, 'formato': formato, 'total': round(f['total'], 2)})
        nome_arq = f"faturamento_{data_ini.strftime('%Y%m%d')}_{data_fim.strftime('%Y%m%d')}"

        if formato == 'excel':
            import xlsxwriter
            out = BytesIO()
            wb = xlsxwriter.Workbook(out, {'in_memory': True})
            F = lambda **k: wb.add_format({'font_name': 'Arial', 'font_size': 10, **k})
            f_tit, f_sub, f_b = F(bold=True, font_size=14), F(font_color='#666666', font_size=9), F(bold=True)
            f_th = F(bold=True, bg_color='#13233a', font_color='#ffffff', border=1, align='center', valign='vcenter')
            f_td, f_num = F(border=1), F(border=1, align='center')
            f_val = F(border=1, num_format='R$ #,##0.00')
            f_pct = F(border=1, num_format='0.0%', align='center')
            f_sec = F(bold=True, bg_color='#e8eef6', border=1)
            f_secv = F(bold=True, bg_color='#e8eef6', border=1, num_format='R$ #,##0.00')
            f_secn = F(bold=True, bg_color='#e8eef6', border=1, align='center')
            f_tot = F(bold=True, bg_color='#13233a', font_color='#ffffff', border=1)
            f_totv = F(bold=True, bg_color='#13233a', font_color='#ffffff', border=1, num_format='R$ #,##0.00')
            f_totn = F(bold=True, bg_color='#13233a', font_color='#ffffff', border=1, align='center')
            f_data = F(border=1, num_format='dd/mm/yyyy', align='center')

            ws = wb.add_worksheet('Resumo')
            ws.write('A1', 'Demonstrativo de Faturamento de Refeições', f_tit)
            ws.write('A2', get_instituicao(), f_sub)
            ws.write('A4', 'Período:', f_b); ws.write('B4', f"{periodo} ({f['n_dias']} dia(s))")
            ws.write('A5', 'Emitido em:', f_b); ws.write('B5', f"{agora} por {usuario}")
            r = 7
            ws.write_row(r, 0, ['Grupo', 'Origem', 'Refeições', 'Valor', '% do total'], f_th)
            for gr in f['grupos']:
                r += 1
                ws.write(r, 0, gr['nome'], f_td); ws.write(r, 1, gr['origem'], f_td); ws.write(r, 2, gr['qtd'], f_num)
                ws.write(r, 3, gr['valor'], f_val); ws.write(r, 4, gr['pct'] / 100, f_pct)
            r += 1
            ws.write(r, 0, 'TOTAL A FATURAR', f_tot); ws.write(r, 1, '', f_tot); ws.write(r, 2, f['qtd'], f_totn)
            ws.write(r, 3, f['total'], f_totv); ws.write(r, 4, 1 if f['total'] else 0, F(bold=True, bg_color='#13233a', font_color='#ffffff', border=1, num_format='0.0%', align='center'))
            r += 2
            for a in f['avisos']:
                ws.write(r, 0, '• ' + a, f_sub); r += 1
            ws.set_column(0, 0, 26); ws.set_column(1, 1, 20); ws.set_column(2, 4, 16)

            wd = wb.add_worksheet('Detalhamento')
            wd.write_row(0, 0, ['Grupo', 'Refeição', 'Quantidade', 'Valor unitário', 'Subtotal'], f_th)
            r = 0
            for gr in f['grupos']:
                for it in gr['itens']:
                    r += 1
                    wd.write(r, 0, gr['nome'], f_td); wd.write(r, 1, it['refeicao'], f_td); wd.write(r, 2, it['qtd'], f_num)
                    wd.write(r, 3, it['unit'], f_val); wd.write(r, 4, it['subtotal'], f_val)
                r += 1
                wd.write(r, 0, f"Subtotal {gr['nome'].lower()}", f_sec); wd.write(r, 1, '', f_sec)
                wd.write(r, 2, gr['qtd'], f_secn); wd.write(r, 3, '', f_sec); wd.write(r, 4, gr['valor'], f_secv)
            r += 1
            wd.write(r, 0, 'TOTAL A FATURAR', f_tot); wd.write(r, 1, '', f_tot); wd.write(r, 2, f['qtd'], f_totn)
            wd.write(r, 3, '', f_tot); wd.write(r, 4, f['total'], f_totv)
            wd.set_column(0, 1, 22); wd.set_column(2, 4, 16)

            wp = wb.add_worksheet('Por dia')
            cab = ['Data'] + [n for _, n, _ in _FAT_GRUPOS] + ['Refeições', 'Total do dia']
            wp.write_row(0, 0, cab, f_th)
            for i, d in enumerate(f['dias'], start=1):
                wp.write_datetime(i, 0, datetime.combine(d['data'], time(0, 0)), f_data)
                for c, (chave_grp, _, _) in enumerate(_FAT_GRUPOS, start=1):
                    wp.write(i, c, d[chave_grp], f_val)
                wp.write(i, 5, d['qtd'], f_num); wp.write(i, 6, d['total'], f_val)
            i = len(f['dias']) + 1
            wp.write(i, 0, 'TOTAL', f_tot)
            for c, gr in enumerate(f['grupos'], start=1):
                wp.write(i, c, gr['valor'], f_totv)
            wp.write(i, 5, f['qtd'], f_totn); wp.write(i, 6, f['total'], f_totv)
            wp.set_column(0, 0, 12); wp.set_column(1, 6, 16)
            wp.freeze_panes(1, 1)
            wb.close()
            out.seek(0)
            return send_file(out, download_name=nome_arq + '.xlsx', as_attachment=True)

        html = render_template('relatorio_faturamento.html', f=f, periodo=periodo, agora=agora, usuario=usuario,
                               nome_instituicao=get_instituicao(), data_ini=data_ini, data_fim=data_fim)
        pdf = gerar_pdf(html)
        return send_file(BytesIO(pdf), download_name=nome_arq + '.pdf', as_attachment=True)

    hoje = date.today()
    ini_mes = hoje.replace(day=1)
    return render_template('menu_admin.html', modulo='relatorio_faturamento', module='relatorio_faturamento',
                           usuario=get_usuario_logado(), ini_padrao=ini_mes.isoformat(), fim_padrao=hoje.isoformat())


# ─── DISPENSA: FASE 3 — RELATÓRIO FINANCEIRO ─────────────────────────────────

def _dispensa_dados_relatorio(data_ini, data_fim, tipo_id=None):
    """Consolida os itens de dispensa do período (pela data da prescrição)."""
    from collections import OrderedDict
    sql = """SELECT p.data_prescricao, t.id, t.nome, t.ordem, i.status, i.valor_unitario, i.validacao, i.motivo,
                    i.entregue_em, i.entregue_por, p.leito, p.nome, p.atendimento, p.prontuario, i.ajuste_id, i.para,
                    COALESCE(i.autorizado_por, i.definido_por), i.origem, 0, NULL
             FROM dispensa_itens i
             JOIN dispensa_pacientes p ON p.id = i.paciente_id
             JOIN dispensa_tipos t ON t.id = i.tipo_id
             WHERE p.data_prescricao BETWEEN %s AND %s"""
    # reposições por avaria: entram como mais uma refeição a cobrar (valor da original), em linha própria
    sql_repo = """SELECT p.data_prescricao, t.id, t.nome, t.ordem, r.status, r.valor_unitario, r.validacao, r.motivo,
                         r.entregue_em, r.entregue_por, p.leito, p.nome, p.atendimento, p.prontuario, NULL, i.para,
                         r.avaria_por, 'avaria', r.seq, r.avaria_motivo
                  FROM dispensa_reposicoes r
                  JOIN dispensa_itens i ON i.id = r.item_id
                  JOIN dispensa_pacientes p ON p.id = i.paciente_id
                  JOIN dispensa_tipos t ON t.id = i.tipo_id
                  WHERE p.data_prescricao BETWEEN %s AND %s"""
    params = [data_ini, data_fim]
    if tipo_id:
        sql += " AND t.id = %s"
        sql_repo += " AND t.id = %s"
        params.append(tipo_id)
    cur = mysql.connection.cursor()
    cur.execute(sql, params)
    rows = list(cur.fetchall())
    cur.execute(sql_repo, params)
    rows += list(cur.fetchall())
    cur.close()

    tipos = OrderedDict()
    novo_tipo = lambda tid, nome: {'id': tid, 'nome': nome, 'entregues': 0, 'valor': 0.0, 'qr': 0, 'manual': 0,
                                   'nao': 0, 'pendentes': 0, 'unitarios': set(), 'acomp': 0, 'valor_acomp': 0.0,
                                   'repos': 0, 'valor_repos': 0.0}
    # todos os tipos ATIVOS aparecem (na ordem definida em Tipos de refeição), mesmo sem refeição no período;
    # tipos inativos só se tiveram refeição no período
    ordem_tipos = {}
    for tp in _dispensa_tipos():
        ordem_tipos[tp['id']] = (tp['ordem'], tp['nome'])
        if tp['ativo'] and (not tipo_id or tp['id'] == tipo_id):
            tipos[tp['id']] = novo_tipo(tp['id'], tp['nome'])
            tipos[tp['id']]['valor_atual'] = tp['valor']
    for r in sorted(rows, key=lambda r: (r[3], r[2])):
        tipos.setdefault(r[1], novo_tipo(r[1], r[2]))
    tipos = OrderedDict(sorted(tipos.items(), key=lambda kv: ordem_tipos.get(kv[0], (999, kv[1]['nome']))))
    dias = OrderedDict()
    motivos_nao, motivos_manual, detalhe, nao_lista = {}, {}, [], []
    zerados = ajustados = 0
    fat = {}
    _ORIGEM_TXT = {'importacao_manha': 'prescrição da manhã', 'importacao_noite': 'prescrição da noite',
                   'ajuste_nutricao': 'ajuste da nutrição', 'nutricao': 'nutrição', None: 'cozinha (antes da regra)',
                   'avaria': 'avaria registrada no totem'}
    for (dref, tid, tnome, _o, st, vu, val, mot, ent_em, ent_por, leito, nome, atend, pront, aj, para, aut_por, origem_it,
         repo_seq, av_mot) in sorted(rows, key=lambda r: (r[0], r[3], r[10] or '', r[15] or '', r[18])):
        autorizado = f"{aut_por or '—'} ({_ORIGEM_TXT.get(origem_it, origem_it)})"
        t = tipos[tid]
        vu = float(vu or 0)
        eh_acomp = para == 'acompanhante'
        nome_exib = f"{nome} (acompanhante)" if eh_acomp else nome
        if repo_seq:
            tnome = f"{tnome} · reposição nº {repo_seq} (avaria: {av_mot})"
        d = dias.setdefault(dref, {'data': dref, 'por_tipo': {}, 'qtd': 0, 'valor': 0.0, 'acomp': 0, 'valor_acomp': 0.0})
        if st == 'entregue':
            t['entregues'] += 1; t['valor'] += vu; t['unitarios'].add(vu)
            if repo_seq:
                t['repos'] += 1; t['valor_repos'] += vu
            if eh_acomp:
                t['acomp'] += 1; t['valor_acomp'] += vu; d['acomp'] += 1; d['valor_acomp'] += vu
            # faturamento: refeição × beneficiário × valor unitário (reposição por avaria em linha própria)
            chave_f = (f"{t['nome']} — reposição por avaria" if repo_seq else t['nome'], _o + (0.5 if repo_seq else 0),
                       'Acompanhante' if eh_acomp else 'Paciente', vu)
            fat[chave_f] = fat.get(chave_f, 0) + 1
            t['qr' if val == 'qr' else 'manual'] += 1
            d['por_tipo'][tid] = d['por_tipo'].get(tid, 0) + 1
            d['qtd'] += 1; d['valor'] += vu
            if vu <= 0:
                zerados += 1
            if aj:
                ajustados += 1
            if val == 'manual' and mot:
                motivos_manual[mot] = motivos_manual.get(mot, 0) + 1
            detalhe.append({'data': dref, 'hora': ent_em.strftime('%H:%M') if ent_em else '', 'leito': leito,
                            'nome': nome_exib, 'para': 'Acompanhante' if eh_acomp else 'Paciente', 'atendimento': atend, 'prontuario': pront or '', 'tipo': tnome,
                            'valor': vu, 'validacao': 'QR' if val == 'qr' else 'Sem QR', 'por': ent_por or '', 'autorizado': autorizado,
                            'motivo': mot or ''})
        elif st == 'nao_entregue':
            t['nao'] += 1
            chave = (mot or 'Sem motivo').split(':')[0]
            motivos_nao[chave] = motivos_nao.get(chave, 0) + 1
            nao_lista.append({'data': dref, 'hora': ent_em.strftime('%H:%M') if ent_em else '', 'leito': leito,
                              'nome': nome_exib, 'atendimento': atend, 'tipo': tnome, 'motivo': mot or '', 'por': ent_por or ''})
        else:
            t['pendentes'] += 1

    for t in tipos.values():
        t['pac'] = t['entregues'] - t['acomp']
        t['valor_pac'] = t['valor'] - t['valor_acomp']
        us = sorted(t.pop('unitarios'))
        t['unit_txt'] = ('R$ ' + moeda_br(us[0])) if len(us) == 1 else \
                        (f"R$ {moeda_br(us[0])} a {moeda_br(us[-1])}" if us else
                         (f"R$ {moeda_br(t['valor_atual'])}" if t.get('valor_atual') else '—'))
    tot = {
        'entregues': sum(t['entregues'] for t in tipos.values()),
        'valor': sum(t['valor'] for t in tipos.values()),
        'qr': sum(t['qr'] for t in tipos.values()),
        'manual': sum(t['manual'] for t in tipos.values()),
        'nao': sum(t['nao'] for t in tipos.values()),
        'pendentes': sum(t['pendentes'] for t in tipos.values()),
        'zerados': zerados,
        'ajustados': ajustados,
        'pacientes': len({(r[0], r[12]) for r in rows}),
        'acomp': sum(t['acomp'] for t in tipos.values()),
        'valor_acomp': sum(t['valor_acomp'] for t in tipos.values()),
        'acompanhantes': len({(r[0], r[12]) for r in rows if r[15] == 'acompanhante'}),
        'dias': len(dias),
        'repos': sum(t['repos'] for t in tipos.values()),
        'valor_repos': sum(t['valor_repos'] for t in tipos.values()),
    }
    tot['previstas'] = tot['entregues'] + tot['nao'] + tot['pendentes']
    tot['entregues_pac'] = tot['entregues'] - tot['acomp']
    init_dispensa_correcoes()
    cur = mysql.connection.cursor()
    cur.execute("""SELECT COUNT(DISTINCT c.item_id) FROM dispensa_correcoes c JOIN dispensa_itens i ON i.id = c.item_id
                   JOIN dispensa_pacientes p ON p.id = i.paciente_id
                   WHERE p.data_prescricao BETWEEN %s AND %s""" + (" AND i.tipo_id = %s" if tipo_id else ""),
                [data_ini, data_fim] + ([tipo_id] if tipo_id else []))
    tot['corrigidos'] = int(cur.fetchone()[0] or 0)
    cur.close()
    tot['valor_pac'] = tot['valor'] - tot['valor_acomp']
    tot['pct_manual'] = round(tot['manual'] * 100 / tot['entregues'], 1) if tot['entregues'] else 0
    tot['media_dia'] = tot['valor'] / tot['dias'] if tot['dias'] else 0
    # Refeições para faturamento: uma linha por refeição × beneficiário × valor; subtotal por beneficiário
    linhas_fat = [{'refeicao': k[0], 'para': k[2], 'qtd': n, 'unit': k[3], 'subtotal': n * k[3]}
                  for k, n in sorted(fat.items(), key=lambda x: (x[0][2] != 'Paciente', x[0][1], x[0][0], x[0][3]))]
    faturamento = []
    for para in ('Paciente', 'Acompanhante'):
        ls = [l for l in linhas_fat if l['para'] == para]
        if ls:
            faturamento.append({'para': para, 'linhas': ls, 'qtd': sum(l['qtd'] for l in ls),
                                'valor': sum(l['subtotal'] for l in ls)})
    return {'tipos': list(tipos.values()), 'dias': list(dias.values()), 'tot': tot, 'faturamento': faturamento,
            'motivos_nao': sorted(motivos_nao.items(), key=lambda x: -x[1]),
            'motivos_manual': sorted(motivos_manual.items(), key=lambda x: -x[1]),
            'detalhe': detalhe, 'nao_lista': nao_lista}


@app.route('/admin/dispensa/relatorio', methods=['GET', 'POST'])
def dispensa_relatorio():
    g = _guard_admin()
    if g: return g
    init_dispensa_fase2()
    tipos_disp = _dispensa_tipos()

    if request.method == 'POST':
        data_ini = _parse_data(request.form.get('data_inicial'))
        data_fim = _parse_data(request.form.get('data_final'))
        if not data_ini or not data_fim:
            flash("Datas inválidas.", "error")
            return redirect(url_for('dispensa_relatorio'))
        if data_fim < data_ini:
            flash("A data final não pode ser anterior à inicial.", "error")
            return redirect(url_for('dispensa_relatorio'))
        tipo_id = request.form.get('tipo_id', '')
        tipo_id = int(tipo_id) if tipo_id.isdigit() else None
        tipo_nome = next((t['nome'] for t in tipos_disp if t['id'] == tipo_id), 'Todos')
        detalhado = bool(request.form.get('detalhado'))
        formato = request.form.get('tipo_relatorio', 'pdf')

        dados = _dispensa_dados_relatorio(data_ini, data_fim, tipo_id)
        periodo = f"{data_ini.strftime('%d/%m/%Y')} até {data_fim.strftime('%d/%m/%Y')}"
        agora = datetime.now().strftime('%d/%m/%Y %H:%M')
        usuario = get_usuario_logado()
        logger.info(f"{usuario} emitiu relatório financeiro de dispensa ({periodo}, {tipo_nome}, {formato}).")

        if formato == 'excel':
            import xlsxwriter
            out = BytesIO()
            wb = xlsxwriter.Workbook(out, {'in_memory': True})
            f_tit = wb.add_format({'bold': True, 'font_size': 13, 'font_color': '#0f1115'})
            f_sub = wb.add_format({'font_size': 9, 'font_color': '#777777'})
            f_b = wb.add_format({'bold': True})
            f_th = wb.add_format({'bold': True, 'bg_color': '#1e2d3a', 'font_color': '#ffffff', 'border': 1, 'align': 'center'})
            f_td = wb.add_format({'border': 1})
            f_num = wb.add_format({'border': 1, 'align': 'center'})
            f_val = wb.add_format({'border': 1, 'num_format': 'R$ #,##0.00'})
            f_tot = wb.add_format({'bold': True, 'bg_color': '#1e2d3a', 'font_color': '#ffffff', 'border': 1})
            f_totv = wb.add_format({'bold': True, 'bg_color': '#1e2d3a', 'font_color': '#ffffff', 'border': 1, 'num_format': 'R$ #,##0.00'})
            f_data = wb.add_format({'border': 1, 'num_format': 'dd/mm/yyyy', 'align': 'center'})

            ws = wb.add_worksheet('Resumo')
            ws.write('A1', 'GTR – Relatório Financeiro de Dispensa (pacientes)', f_tit)
            ws.write('A2', get_instituicao(), f_sub)
            ws.write('A4', 'Período:', f_b); ws.write('B4', periodo)
            ws.write('A5', 'Tipo de refeição:', f_b); ws.write('B5', tipo_nome)
            ws.write('A6', 'Gerado em:', f_b); ws.write('B6', agora)
            ws.write('A7', 'Critério:', f_b); ws.write('B7', 'Somente refeições entregues; valor unitário vigente no momento da entrega.')
            r = 9
            ws.write_row(r, 0, ['Tipo de refeição', 'Entregues', 'Valor unitário', 'Custo total', 'Com QR', 'Sem QR', 'Não entregues', 'Pendentes', 'Dos entregues: acompanhante', 'Custo acompanhante'], f_th)
            for t in dados['tipos']:
                r += 1
                ws.write(r, 0, t['nome'], f_td); ws.write(r, 1, t['entregues'], f_num); ws.write(r, 2, t['unit_txt'], f_td)
                ws.write(r, 3, t['valor'], f_val); ws.write(r, 4, t['qr'], f_num); ws.write(r, 5, t['manual'], f_num)
                ws.write(r, 6, t['nao'], f_num); ws.write(r, 7, t['pendentes'], f_num)
                ws.write(r, 8, t['acomp'], f_num); ws.write(r, 9, t['valor_acomp'], f_val)
            r += 1
            tt = dados['tot']
            ws.write(r, 0, 'TOTAL', f_tot); ws.write(r, 1, tt['entregues'], f_tot); ws.write(r, 2, '', f_tot)
            ws.write(r, 3, tt['valor'], f_totv); ws.write(r, 4, tt['qr'], f_tot); ws.write(r, 5, tt['manual'], f_tot)
            ws.write(r, 6, tt['nao'], f_tot); ws.write(r, 7, tt['pendentes'], f_tot)
            ws.write(r, 8, tt['acomp'], f_tot); ws.write(r, 9, tt['valor_acomp'], f_totv)
            if tt['repos']:
                r += 1
                ws.write(r, 0, f"Dos entregues, {tt['repos']} são reposições por avaria (cobradas de novo): "
                               f"R$ {moeda_br(tt['valor_repos'])}.", f_sub)
            r += 3
            ws.write(r, 0, 'Custo por dia', f_b); r += 1
            cab = ['Data'] + [t['nome'] for t in dados['tipos']] + ['Total entregues', 'Dos quais acompanhante', 'Custo acompanhante', 'Custo do dia']
            ws.write_row(r, 0, cab, f_th)
            nt = len(dados['tipos'])
            for d in dados['dias']:
                r += 1
                ws.write_datetime(r, 0, datetime.combine(d['data'], time(0, 0)), f_data)
                for c, t in enumerate(dados['tipos'], start=1):
                    ws.write(r, c, d['por_tipo'].get(t['id'], 0), f_num)
                ws.write(r, nt + 1, d['qtd'], f_num)
                ws.write(r, nt + 2, d['acomp'], f_num)
                ws.write(r, nt + 3, d['valor_acomp'], f_val)
                ws.write(r, nt + 4, d['valor'], f_val)
            ws.set_column(0, 0, 22); ws.set_column(1, 12, 15)

            wsf = wb.add_worksheet('Faturamento')
            wsf.write('A1', 'Refeições para faturamento — dispensa (pacientes e acompanhantes)', f_tit)
            wsf.write('A2', f"Período: {periodo} · Refeição: {tipo_nome} · Gerado em: {agora}", f_sub)
            wsf.write('A3', 'Somente refeições entregues e confirmadas no totem, pelo valor unitário vigente na entrega.', f_sub)
            rf = 4
            wsf.write_row(rf, 0, ['Beneficiário', 'Refeição', 'Quantidade', 'Valor unitário', 'Subtotal'], f_th)
            for grp in dados['faturamento']:
                for l in grp['linhas']:
                    rf += 1
                    wsf.write(rf, 0, l['para'], f_td); wsf.write(rf, 1, l['refeicao'], f_td)
                    wsf.write(rf, 2, l['qtd'], f_num); wsf.write(rf, 3, l['unit'], f_val); wsf.write(rf, 4, l['subtotal'], f_val)
                rf += 1
                wsf.write(rf, 0, f"Subtotal {grp['para'].lower()}s", f_b); wsf.write(rf, 1, '', f_b)
                wsf.write(rf, 2, grp['qtd'], f_num); wsf.write(rf, 3, '', f_b); wsf.write(rf, 4, grp['valor'], f_val)
            rf += 1
            wsf.write(rf, 0, 'TOTAL A FATURAR', f_tot); wsf.write(rf, 1, '', f_tot)
            wsf.write(rf, 2, dados['tot']['entregues'], f_tot); wsf.write(rf, 3, '', f_tot); wsf.write(rf, 4, dados['tot']['valor'], f_totv)
            wsf.set_column(0, 1, 24); wsf.set_column(2, 4, 16)

            ws2 = wb.add_worksheet('Entregas')
            ws2.write_row(0, 0, ['Data', 'Hora', 'Leito', 'Paciente', 'Atendimento', 'Prontuário', 'Refeição', 'Valor', 'Validação', 'Motivo (sem QR)', 'Entregue por', 'Para', 'Autorizado por'], f_th)
            for n, e in enumerate(dados['detalhe'], start=1):
                ws2.write_datetime(n, 0, datetime.combine(e['data'], time(0, 0)), f_data)
                ws2.write(n, 1, e['hora'], f_num); ws2.write(n, 2, e['leito'], f_td); ws2.write(n, 3, e['nome'], f_td)
                ws2.write(n, 4, e['atendimento'], f_td); ws2.write(n, 5, e['prontuario'], f_td); ws2.write(n, 6, e['tipo'], f_td)
                ws2.write(n, 7, e['valor'], f_val); ws2.write(n, 8, e['validacao'], f_num); ws2.write(n, 9, e['motivo'], f_td)
                ws2.write(n, 10, e['por'], f_td); ws2.write(n, 11, e['para'], f_td); ws2.write(n, 12, e['autorizado'], f_td)
            ws2.set_column(0, 0, 12); ws2.set_column(1, 1, 8); ws2.set_column(2, 2, 14); ws2.set_column(3, 3, 40)
            ws2.set_column(4, 8, 13); ws2.set_column(9, 10, 28)
            ws2.set_column(12, 12, 34)
            ws2.autofilter(0, 0, max(len(dados['detalhe']), 1), 12)

            ws3 = wb.add_worksheet('Não entregues')
            ws3.write_row(0, 0, ['Data', 'Hora', 'Leito', 'Paciente', 'Atendimento', 'Refeição', 'Motivo', 'Registrado por'], f_th)
            for n, e in enumerate(dados['nao_lista'], start=1):
                ws3.write_datetime(n, 0, datetime.combine(e['data'], time(0, 0)), f_data)
                ws3.write_row(n, 1, [e['hora'], e['leito'], e['nome'], e['atendimento'], e['tipo'], e['motivo'], e['por']], f_td)
            ws3.set_column(0, 2, 12); ws3.set_column(3, 3, 40); ws3.set_column(4, 7, 22)
            wb.close()
            out.seek(0)
            nome_arq = f"relatorio_dispensa_{data_ini.strftime('%Y%m%d')}_{data_fim.strftime('%Y%m%d')}.xlsx"
            return send_file(out, download_name=nome_arq, as_attachment=True)

        html = render_template('relatorio_dispensa.html', dados=dados, periodo=periodo, agora=agora,
                               tipo_nome=tipo_nome, detalhado=detalhado, nome_instituicao=get_instituicao(),
                               fechamentos=_fechamentos_no_intervalo(data_ini, data_fim),
                               periodo_ini=data_ini, periodo_fim=data_fim)
        pdf = gerar_pdf(html)
        nome_arq = f"relatorio_dispensa_{data_ini.strftime('%Y%m%d')}_{data_fim.strftime('%Y%m%d')}.pdf"
        return send_file(BytesIO(pdf), download_name=nome_arq, as_attachment=True)

    hoje = date.today()
    return render_template('menu_admin.html', modulo='dispensa_relatorio', module='dispensa_relatorio',
                           usuario=get_usuario_logado(), tipos_disp=tipos_disp,
                           ini_padrao=hoje.replace(day=1).isoformat(), fim_padrao=hoje.isoformat())


# ─── DISPENSA: RELATÓRIO DE AVARIAS (refeição entregue que caiu/estragou → reposição cobrada) ─────

_AVARIA_SITUACAO = {'entregue': 'Reposição entregue', 'nao_entregue': 'Reposição não entregue', 'pendente': 'Reposição pendente'}


def _avarias_dados(data_ini, data_fim, tipo_id=None):
    """Avarias do período (pela data da prescrição): custo das reposições, motivos, responsáveis e lista detalhada.
    Só a reposição ENTREGUE é cobrada (pelo valor da refeição original)."""
    from collections import OrderedDict
    init_dispensa_fase2()
    sql = """SELECT p.data_prescricao, r.avaria_em, r.seq, r.avaria_motivo, r.avaria_por, r.status, r.valor_unitario,
                    r.entregue_em, r.entregue_por, r.validacao, r.motivo, i.para, t.id, t.nome, t.ordem,
                    p.leito, p.nome, p.atendimento, p.unidade, i.entregue_em, i.entregue_por
             FROM dispensa_reposicoes r
             JOIN dispensa_itens i ON i.id = r.item_id
             JOIN dispensa_pacientes p ON p.id = i.paciente_id
             JOIN dispensa_tipos t ON t.id = i.tipo_id
             WHERE p.data_prescricao BETWEEN %s AND %s"""
    params = [data_ini, data_fim]
    if tipo_id:
        sql += " AND t.id = %s"
        params.append(tipo_id)
    cur = mysql.connection.cursor()
    cur.execute(sql + " ORDER BY p.data_prescricao, r.avaria_em", params)
    rows = cur.fetchall()
    cur.close()

    def soma(d, chave, rotulo, st, vu):
        x = d.setdefault(chave, {'nome': rotulo, 'qtd': 0, 'entregues': 0, 'nao': 0, 'pendentes': 0, 'valor': 0.0})
        x['qtd'] += 1
        x['entregues' if st == 'entregue' else 'nao' if st == 'nao_entregue' else 'pendentes'] += 1
        if st == 'entregue':
            x['valor'] += vu

    motivos, tipos, pessoas, unidades, dias = {}, {}, {}, {}, OrderedDict()
    detalhe = []
    for (dref, av_em, seq, av_mot, av_por, st, vu, ent_em, ent_por, val, mot, para, tid, tnome, tordem,
         leito, nome, atend, unid, orig_em, orig_por) in rows:
        vu = float(vu or 0)
        soma(motivos, (av_mot or 'Sem motivo').split(':')[0], (av_mot or 'Sem motivo').split(':')[0], st, vu)
        soma(tipos, (tordem, tnome), tnome, st, vu)
        soma(pessoas, av_por or '—', av_por or '—', st, vu)
        soma(unidades, (unid or '').strip() or 'Unidade não informada', (unid or '').strip() or 'Unidade não informada', st, vu)
        soma(dias, dref, dref, st, vu)
        if st == 'entregue':
            situacao = (f"Entregue às {ent_em.strftime('%H:%M') if ent_em else '—'} por {ent_por or '—'} "
                        f"({'QR' if val == 'qr' else 'sem QR'})")
        elif st == 'nao_entregue':
            situacao = f"Não entregue — {mot or 'sem motivo'}"
        else:
            situacao = 'Pendente (sem registro no totem)'
        detalhe.append({'data': dref, 'hora': av_em.strftime('%H:%M') if av_em else '', 'leito': leito,
                        'unidade': (unid or '').strip(), 'nome': nome, 'atendimento': atend,
                        'para': 'Acompanhante' if para == 'acompanhante' else 'Paciente', 'refeicao': tnome,
                        'seq': seq, 'motivo': av_mot or '', 'registrada_por': av_por or '',
                        'original': f"{orig_em.strftime('%H:%M') if orig_em else '—'} por {orig_por or '—'}",
                        'status': st, 'situacao': situacao, 'valor': vu if st == 'entregue' else 0.0,
                        'valor_ref': vu})
    ordena = lambda d: sorted(d.values(), key=lambda x: (-x['qtd'], str(x['nome'])))
    n = len(rows)
    tot = {'avarias': n,
           'entregues': sum(1 for d in detalhe if d['status'] == 'entregue'),
           'nao': sum(1 for d in detalhe if d['status'] == 'nao_entregue'),
           'pendentes': sum(1 for d in detalhe if d['status'] == 'pendente'),
           'valor': sum(d['valor'] for d in detalhe),
           'valor_pendente': sum(d['valor_ref'] for d in detalhe if d['status'] == 'pendente'),
           'pacientes': len({(d['data'], d['atendimento']) for d in detalhe}),
           'acomp': sum(1 for d in detalhe if d['para'] == 'Acompanhante'),
           'dias': len(dias)}
    # peso das avarias na dispensa do período (mesmo filtro de refeição)
    disp = _dispensa_dados_relatorio(data_ini, data_fim, tipo_id)['tot']
    originais = disp['entregues'] - disp['repos']
    tot['entregas_originais'] = originais
    tot['valor_dispensa'] = disp['valor']
    tot['pct_avaria'] = round(n * 100 / originais, 2) if originais else 0
    tot['pct_custo'] = round(tot['valor'] * 100 / disp['valor'], 2) if disp['valor'] else 0
    tot['media_dia'] = tot['valor'] / ((data_fim - data_ini).days + 1)
    for grupo in (motivos, tipos, pessoas, unidades):
        for x in grupo.values():
            x['pct'] = round(x['qtd'] * 100 / n, 1) if n else 0
    return {'tot': tot, 'motivos': ordena(motivos), 'tipos': sorted(tipos.values(), key=lambda x: x['nome']),
            'pessoas': ordena(pessoas), 'unidades': ordena(unidades), 'dias': list(dias.values()), 'detalhe': detalhe}


@app.route('/admin/dispensa/avarias', methods=['GET', 'POST'])
def dispensa_avarias_relatorio():
    g = _guard_admin()
    if g: return g
    init_dispensa_fase2()
    tipos_disp = _dispensa_tipos()
    if request.method == 'POST':
        data_ini = _parse_data(request.form.get('data_inicial'))
        data_fim = _parse_data(request.form.get('data_final'))
        if not data_ini or not data_fim:
            flash("Datas inválidas.", "error")
            return redirect(url_for('dispensa_avarias_relatorio'))
        if data_fim < data_ini:
            flash("A data final não pode ser anterior à inicial.", "error")
            return redirect(url_for('dispensa_avarias_relatorio'))
        tipo_id = request.form.get('tipo_id', '')
        tipo_id = int(tipo_id) if tipo_id.isdigit() else None
        tipo_nome = next((t['nome'] for t in tipos_disp if t['id'] == tipo_id), 'Todas')
        formato = request.form.get('tipo_relatorio', 'pdf')
        dados = _avarias_dados(data_ini, data_fim, tipo_id)
        periodo = f"{data_ini.strftime('%d/%m/%Y')} até {data_fim.strftime('%d/%m/%Y')}"
        agora = datetime.now().strftime('%d/%m/%Y %H:%M')
        usuario = get_usuario_logado()
        tt = dados['tot']
        logger.info(f"{usuario} emitiu o relatório de avarias ({periodo}, {tipo_nome}, {formato}): "
                    f"{tt['avarias']} avaria(s), R$ {moeda_br(tt['valor'])}.")
        auditar(detalhes={'periodo': periodo, 'refeicao': tipo_nome, 'formato': formato,
                          'avarias': tt['avarias'], 'valor': round(tt['valor'], 2)})
        nome_arq = f"relatorio_avarias_{data_ini.strftime('%Y%m%d')}_{data_fim.strftime('%Y%m%d')}"

        if formato == 'excel':
            import xlsxwriter
            out = BytesIO()
            wb = xlsxwriter.Workbook(out, {'in_memory': True})
            F = lambda **k: wb.add_format({'font_name': 'Arial', 'font_size': 10, **k})
            f_tit, f_sub, f_b = F(bold=True, font_size=13), F(font_color='#777777', font_size=9), F(bold=True)
            f_th = F(bold=True, bg_color='#1e2d3a', font_color='#ffffff', border=1, align='center', text_wrap=True)
            f_td, f_num = F(border=1), F(border=1, align='center')
            f_val = F(border=1, num_format='R$ #,##0.00')
            f_pct = F(border=1, num_format='0.0"%"', align='center')
            f_tot = F(bold=True, bg_color='#1e2d3a', font_color='#ffffff', border=1)
            f_totv = F(bold=True, bg_color='#1e2d3a', font_color='#ffffff', border=1, num_format='R$ #,##0.00')
            f_data = F(border=1, num_format='dd/mm/yyyy', align='center')

            ws = wb.add_worksheet('Resumo')
            ws.write('A1', 'GTR – Relatório de Avarias da Dispensa', f_tit)
            ws.write('A2', get_instituicao(), f_sub)
            ws.write('A4', 'Período:', f_b); ws.write('B4', periodo)
            ws.write('A5', 'Refeição:', f_b); ws.write('B5', tipo_nome)
            ws.write('A6', 'Gerado em:', f_b); ws.write('B6', f"{agora} por {usuario}")
            ws.write('A7', 'Critério:', f_b)
            ws.write('B7', 'Refeição entregue que caiu/estragou gera uma reposição; só a reposição ENTREGUE é cobrada, '
                           'pelo valor da refeição original.')
            resumo = [('Avarias registradas', tt['avarias'], f_num), ('Reposições entregues (cobradas)', tt['entregues'], f_num),
                      ('Reposições não entregues', tt['nao'], f_num), ('Reposições pendentes', tt['pendentes'], f_num),
                      ('Custo das reposições cobradas', tt['valor'], f_val),
                      ('Custo potencial das pendentes', tt['valor_pendente'], f_val),
                      ('Média de custo por dia', tt['media_dia'], f_val),
                      ('Pacientes afetados', tt['pacientes'], f_num), ('Das avarias: acompanhante', tt['acomp'], f_num),
                      ('Avarias por 100 entregas', tt['pct_avaria'], F(border=1, num_format='0.00', align='center')),
                      ('Peso no custo da dispensa', tt['pct_custo'], F(border=1, num_format='0.00"%"', align='center'))]
            for i, (rot, v, fm) in enumerate(resumo, start=9):
                ws.write(i, 0, rot, f_td); ws.write(i, 1, v, fm)
            ws.set_column(0, 0, 34); ws.set_column(1, 1, 22)

            def aba(nome, titulo, linhas):
                w = wb.add_worksheet(nome)
                w.write_row(0, 0, [titulo, 'Avarias', '% das avarias', 'Entregues', 'Não entregues', 'Pendentes', 'Custo cobrado'], f_th)
                for i, x in enumerate(linhas, start=1):
                    w.write(i, 0, str(x['nome']), f_td); w.write(i, 1, x['qtd'], f_num); w.write(i, 2, x['pct'], f_pct)
                    w.write(i, 3, x['entregues'], f_num); w.write(i, 4, x['nao'], f_num); w.write(i, 5, x['pendentes'], f_num)
                    w.write(i, 6, x['valor'], f_val)
                i = len(linhas) + 1
                w.write(i, 0, 'TOTAL', f_tot); w.write(i, 1, tt['avarias'], f_tot); w.write(i, 2, '', f_tot)
                w.write(i, 3, tt['entregues'], f_tot); w.write(i, 4, tt['nao'], f_tot); w.write(i, 5, tt['pendentes'], f_tot)
                w.write(i, 6, tt['valor'], f_totv)
                w.set_column(0, 0, 32); w.set_column(1, 6, 14)
            aba('Por motivo', 'Motivo', dados['motivos'])
            aba('Por refeição', 'Refeição', dados['tipos'])
            aba('Por quem registrou', 'Registrada por', dados['pessoas'])
            aba('Por unidade', 'Unidade de internação', dados['unidades'])

            wd = wb.add_worksheet('Por dia')
            wd.write_row(0, 0, ['Data', 'Avarias', 'Entregues', 'Não entregues', 'Pendentes', 'Custo cobrado'], f_th)
            for i, x in enumerate(dados['dias'], start=1):
                wd.write_datetime(i, 0, datetime.combine(x['nome'], time(0, 0)), f_data)
                wd.write(i, 1, x['qtd'], f_num); wd.write(i, 2, x['entregues'], f_num); wd.write(i, 3, x['nao'], f_num)
                wd.write(i, 4, x['pendentes'], f_num); wd.write(i, 5, x['valor'], f_val)
            wd.set_column(0, 5, 14)

            wl = wb.add_worksheet('Avarias')
            cab = ['Data', 'Hora da avaria', 'Unidade', 'Leito', 'Paciente', 'Atendimento', 'Para', 'Refeição', 'Reposição nº',
                   'Motivo / descrição', 'Registrada por', 'Entrega original', 'Situação da reposição', 'Valor cobrado']
            wl.write_row(0, 0, cab, f_th)
            for i, d in enumerate(dados['detalhe'], start=1):
                wl.write_datetime(i, 0, datetime.combine(d['data'], time(0, 0)), f_data)
                wl.write_row(i, 1, [d['hora'], d['unidade'], d['leito'], d['nome'], d['atendimento'], d['para'], d['refeicao']], f_td)
                wl.write(i, 8, d['seq'], f_num)
                wl.write_row(i, 9, [d['motivo'], d['registrada_por'], d['original'], d['situacao']], f_td)
                wl.write(i, 13, d['valor'], f_val)
            wl.set_column(0, 1, 12); wl.set_column(2, 3, 18); wl.set_column(4, 4, 34); wl.set_column(5, 8, 13)
            wl.set_column(9, 9, 40); wl.set_column(10, 12, 26); wl.set_column(13, 13, 14)
            wl.autofilter(0, 0, max(len(dados['detalhe']), 1), len(cab) - 1)
            wl.freeze_panes(1, 0)
            wb.close()
            out.seek(0)
            return send_file(out, download_name=nome_arq + '.xlsx', as_attachment=True)

        html = render_template('relatorio_avarias.html', dados=dados, periodo=periodo, agora=agora, tipo_nome=tipo_nome,
                               nome_instituicao=get_instituicao())
        return send_file(BytesIO(gerar_pdf(html)), download_name=nome_arq + '.pdf', as_attachment=True)

    hoje = date.today()
    return render_template('menu_admin.html', modulo='dispensa_avarias_relatorio', module='dispensa_avarias_relatorio',
                           usuario=get_usuario_logado(), tipos_disp=tipos_disp,
                           ini_padrao=hoje.replace(day=1).isoformat(), fim_padrao=hoje.isoformat())


# ─── DISPENSA: ACOMPANHAMENTO DA ENTREGA (COZINHA, AO VIVO) ─────────────────

def _dispensa_acompanhamento_dados(data_ref):
    cur = mysql.connection.cursor()
    cur.execute("""SELECT i.id, t.id, t.nome, t.ordem, i.status, i.entregue_em, i.entregue_por, i.validacao, i.motivo,
                          p.leito, p.nome, p.dieta, p.atendimento, i.para, 0, NULL
                   FROM dispensa_itens i
                   JOIN dispensa_pacientes p ON p.id = i.paciente_id
                   JOIN dispensa_tipos t ON t.id = i.tipo_id
                   WHERE p.data_prescricao = %s""", (data_ref,))
    rows = list(cur.fetchall())
    # reposições por avaria: a cozinha precisa produzir a refeição de novo
    cur.execute("""SELECT CONCAT('r', r.id), t.id, t.nome, t.ordem, r.status, r.entregue_em, r.entregue_por, r.validacao,
                          r.motivo, p.leito, p.nome, p.dieta, p.atendimento, i.para, r.seq, r.avaria_motivo
                   FROM dispensa_reposicoes r
                   JOIN dispensa_itens i ON i.id = r.item_id
                   JOIN dispensa_pacientes p ON p.id = i.paciente_id
                   JOIN dispensa_tipos t ON t.id = i.tipo_id
                   WHERE p.data_prescricao = %s""", (data_ref,))
    rows += list(cur.fetchall())
    cur.close()
    refeicoes = {}
    itens = []
    for (iid, tid, tnome, tordem, st, em, por, val, mot, leito, nome, dieta, atend, para, repo_seq, av_mot) in rows:
        if para == 'acompanhante':
            nome, dieta = f"{nome} — acompanhante", 'Acompanhante'
        if repo_seq:
            dieta = f"Reposição nº {repo_seq} · avaria: {av_mot}" + (' (acompanhante)' if para == 'acompanhante' else '')
        r = refeicoes.setdefault(tid, {'id': tid, 'nome': tnome, 'ordem': tordem, 'total': 0,
                                       'entregues': 0, 'nao': 0, 'pendentes': 0, 'sem_qr': 0})
        r['total'] += 1
        if st == 'entregue':
            r['entregues'] += 1
            r['sem_qr'] += 1 if val == 'manual' else 0
        elif st == 'nao_entregue':
            r['nao'] += 1
        else:
            r['pendentes'] += 1
        itens.append({'id': iid, 'tipo_id': tid, 'tipo': f"{tnome} (reposição)" if repo_seq else tnome,
                      'status': st, 'leito': leito, 'nome': nome,
                      'dieta': dieta or '', 'por': por or '', 'validacao': val or '',
                      'motivo': mot or '', 'hora': em.strftime('%H:%M') if em else '',
                      'ts': em.strftime('%Y-%m-%d %H:%M:%S') if em else '', 'repo': bool(repo_seq)})
    corrigidos = {c['item_id'] for c in _dispensa_correcoes_do_dia(data_ref)}
    for x in itens:
        x['corrigido'] = x['id'] in corrigidos
    itens.sort(key=lambda x: _ordem_leito(x['leito']))
    feed = sorted([x for x in itens if x['status'] != 'pendente' and x['ts']], key=lambda x: x['ts'], reverse=True)[:20]
    lista = sorted(refeicoes.values(), key=lambda r: (r['ordem'], r['nome']))
    tot = {k: sum(r[k] for r in lista) for k in ('total', 'entregues', 'nao', 'pendentes', 'sem_qr')}
    return {'refeicoes': lista, 'itens': itens, 'feed': feed, 'tot': tot,
            'atualizado': datetime.now().strftime('%H:%M:%S')}


@app.route('/admin/dispensa/acompanhamento')
def dispensa_acompanhamento():
    from datetime import timedelta
    init_dispensa_fase2()
    data_ref = _parse_data(request.args.get('data'), date.today())
    dados = _dispensa_acompanhamento_dados(data_ref)
    return render_template('menu_admin.html', module='dispensa_acompanhamento', usuario=get_usuario_logado(),
                           data_ref=data_ref, data_iso=data_ref.isoformat(), hoje_iso=date.today().isoformat(),
                           dia_semana=_DIAS_SEMANA_PT[data_ref.weekday()],
                           dia_ant=(data_ref - timedelta(days=1)).isoformat(),
                           dia_prox=(data_ref + timedelta(days=1)).isoformat(), acomp=dados,
                           correcoes=_dispensa_correcoes_do_dia(data_ref) if pode('dispensa_correcao') else [],
                           periodo_fechado=(_fechamentos_no_intervalo(data_ref) or [None])[0])


@app.route('/admin/dispensa/acompanhamento/dados')
def dispensa_acompanhamento_dados():
    data_ref = _parse_data(request.args.get('data'), date.today())
    return {'ok': True, **_dispensa_acompanhamento_dados(data_ref)}


# ─── DISPENSA: ETIQUETAS QR DO LEITO (alternativa à pulseira da Salutem) ────
# O QR traz um código opaco por ATENDIMENTO (HMAC com chave da unidade): não expõe dados do paciente e não
# pode ser forjado. A chave fica no banco (vai junto no backup: restaurar não invalida as etiquetas).
ETIQUETA_PREFIXO = 'GTRD1-'
_etq_ok = False


def init_dispensa_etiquetas():
    global _etq_ok
    if _etq_ok:
        return
    cur = mysql.connection.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS dispensa_etiquetas (
            id           INT AUTO_INCREMENT PRIMARY KEY,
            atendimento  VARCHAR(40) NOT NULL,
            leito        VARCHAR(60) NOT NULL,
            impresso_em  DATETIME NOT NULL,
            impresso_por VARCHAR(120) DEFAULT NULL,
            KEY idx_de_atend (atendimento, impresso_em)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci""")
    cur.execute("ALTER TABLE dispensa_etiquetas ADD COLUMN IF NOT EXISTS unidade VARCHAR(80) DEFAULT NULL AFTER leito")
    mysql.connection.commit()
    cur.close()
    if not get_config('dispensa_etiqueta_chave', None):
        set_config('dispensa_etiqueta_chave', _secrets.token_hex(32))
    _etq_ok = True


def etiqueta_codigo(atendimento):
    import base64
    chave = (get_config('dispensa_etiqueta_chave', '') or '').encode()
    dig = _hmac.new(chave, b'GTR-ETQ1|' + str(atendimento).strip().encode(), 'sha256').digest()[:15]
    return ETIQUETA_PREFIXO + base64.b32encode(dig).decode()


def _local_txt(v):
    return ' '.join(str(v or '').split()).upper()


def etiqueta_situacao(leito, unidade, leito_imp, unidade_imp, impresso_em):
    """'nunca' | 'mudou' (outro leito/unidade, ou impressa antes de a etiqueta ter a unidade) | 'ok'."""
    if not impresso_em:
        return 'nunca'
    if _local_txt(leito_imp) != _local_txt(leito):
        return 'mudou'
    if _local_txt(unidade) and _local_txt(unidade_imp) != _local_txt(unidade):
        return 'mudou'
    return 'ok'


def _etiqueta_lida(texto):
    """Código de etiqueta do GTR contido no texto lido (ou None)."""
    m = _re.search(r'GTRD1-[A-Z2-7]{24}', (texto or '').upper())
    return m.group(0) if m else None


def _qr_png_datauri(texto):
    import base64, qrcode
    q = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=10, border=1)
    q.add_data(texto)
    q.make(fit=True)
    buf = BytesIO()
    q.make_image(fill_color='black', back_color='white').save(buf, format='PNG')
    return 'data:image/png;base64,' + base64.b64encode(buf.getvalue()).decode()


@app.route('/admin/dispensa/etiquetas')
def dispensa_etiquetas():
    from datetime import timedelta
    init_dispensa_tables()
    init_dispensa_etiquetas()
    data_ref = _parse_data(request.args.get('data'), date.today())
    cur = mysql.connection.cursor()
    cur.execute("""SELECT p.id, p.atendimento, p.nome, p.leito, p.data_nascimento, p.dieta, e.leito, e.impresso_em,
                          e.impresso_por, p.unidade, e.unidade
                   FROM dispensa_pacientes p
                   LEFT JOIN dispensa_etiquetas e ON e.id = (SELECT e2.id FROM dispensa_etiquetas e2
                        WHERE e2.atendimento = p.atendimento ORDER BY e2.impresso_em DESC, e2.id DESC LIMIT 1)
                   WHERE p.data_prescricao = %s""", (data_ref,))
    pacs = []
    for r in cur.fetchall():
        sit = etiqueta_situacao(r[3], r[9], r[6], r[10], r[7])
        pacs.append({'id': r[0], 'nome': r[2], 'leito': r[3], 'nasc': r[4].strftime('%d/%m/%Y') if r[4] else '',
                     'dieta': r[5] or '', 'leito_impresso': r[6] or '', 'impresso_em': r[7], 'impresso_por': r[8] or '',
                     'unidade': r[9] or '', 'unidade_impressa': r[10] or '', 'situacao': sit,
                     'sem_unidade_na_etiqueta': bool(r[7] and r[9] and not r[10] and _local_txt(r[6]) == _local_txt(r[3]))})
    cur.close()
    pacs.sort(key=lambda p: (p['unidade'] or '~', _ordem_leito(p['leito'])))
    cont = {k: sum(1 for p in pacs if p['situacao'] == k) for k in ('nunca', 'mudou', 'ok')}
    return render_template('menu_admin.html', module='dispensa_etiquetas', usuario=get_usuario_logado(),
                           pacientes=pacs, cont=cont, data_ref=data_ref, data_iso=data_ref.isoformat(),
                           hoje_iso=date.today().isoformat(), dia_semana=_DIAS_SEMANA_PT[data_ref.weekday()],
                           dia_ant=(data_ref - timedelta(days=1)).isoformat(), dia_prox=(data_ref + timedelta(days=1)).isoformat())


@app.route('/admin/dispensa/etiquetas/imprimir', methods=['POST'])
def dispensa_etiquetas_imprimir():
    """PDF de etiquetas 100 × 40 mm (uma por página, para impressora térmica)."""
    import weasyprint
    init_dispensa_etiquetas()
    ids = sorted({int(i) for i in request.form.getlist('paciente_id') if i.isdigit()})
    data_iso = request.form.get('data') or date.today().isoformat()
    if not ids:
        flash("Marque ao menos um paciente para imprimir a etiqueta.", "error")
        return redirect(url_for('dispensa_etiquetas', data=data_iso))
    fmt = ','.join(['%s'] * len(ids))
    cur = mysql.connection.cursor()
    cur.execute(f"SELECT atendimento, nome, leito, data_nascimento, nome_mae, unidade FROM dispensa_pacientes WHERE id IN ({fmt})", ids)
    pacs = sorted(cur.fetchall(), key=lambda r: ((r[5] or '~'), _ordem_leito(r[2])))
    agora = datetime.now()
    usuario = get_usuario_logado()
    # identificação do paciente: os 3 marcadores obrigatórios (nome, data de nascimento e nome da mãe)
    etiquetas = [{'qr': _qr_png_datauri(etiqueta_codigo(at)), 'nome': nome, 'leito': leito, 'unidade': unid or '',
                  'nasc': dn.strftime('%d/%m/%Y') if dn else '', 'mae': mae or ''} for at, nome, leito, dn, mae, unid in pacs]
    for at, _n, leito, _d, _m, unid in pacs:
        cur.execute("INSERT INTO dispensa_etiquetas (atendimento, leito, unidade, impresso_em, impresso_por) VALUES (%s,%s,%s,%s,%s)",
                    (at, leito, unid, agora, usuario))
    mysql.connection.commit()
    cur.close()
    html = render_template('etiqueta_dispensa.html', etiquetas=etiquetas, agora=agora.strftime('%d/%m/%Y %H:%M'))
    pdf = weasyprint.HTML(string=html, base_url=app.root_path).write_pdf()
    auditar(detalhes={'etiquetas': len(etiquetas), 'leitos': [e['leito'] for e in etiquetas][:100]})
    logger.info(f"{usuario} imprimiu {len(etiquetas)} etiqueta(s) QR da dispensa.")
    return send_file(BytesIO(pdf), mimetype='application/pdf', as_attachment=False,
                     download_name=f"etiquetas_dispensa_{agora:%Y%m%d_%H%M}.pdf")


# ─── DISPENSA: CORREÇÃO DE REGISTRO DO TOTEM (permissão própria) ─────────────
# O totem não tem desfazer. Quem tem a permissão "Correção de registro (totem) › Editar"
# corrige pelo Acompanhamento da entrega, com motivo obrigatório; tudo fica no histórico.
_DISP_STATUS_ROT = {'pendente': 'Falta entregar', 'entregue': 'Entregue', 'nao_entregue': 'Não entregue'}
_disp_correcao_ok = False


def init_dispensa_correcoes():
    global _disp_correcao_ok
    if _disp_correcao_ok:
        return
    cur = mysql.connection.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS dispensa_correcoes (
            id              INT AUTO_INCREMENT PRIMARY KEY,
            item_id         INT NOT NULL,
            status_antes    VARCHAR(20) NOT NULL,
            validacao_antes VARCHAR(20) DEFAULT NULL,
            motivo_antes    VARCHAR(255) DEFAULT NULL,
            por_antes       VARCHAR(120) DEFAULT NULL,
            em_antes        DATETIME DEFAULT NULL,
            status_depois   VARCHAR(20) NOT NULL,
            motivo          VARCHAR(255) NOT NULL,
            feito_por       VARCHAR(120) DEFAULT NULL,
            feito_em        TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
            KEY idx_dc_item (item_id),
            CONSTRAINT fk_dc_item FOREIGN KEY (item_id) REFERENCES dispensa_itens(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    """)
    mysql.connection.commit()
    cur.close()
    _disp_correcao_ok = True


@app.route('/admin/dispensa/corrigir', methods=['POST'])
def dispensa_corrigir():
    init_dispensa_fase2()
    init_dispensa_correcoes()
    item_id = request.form.get('item_id', type=int)
    novo = request.form.get('novo_status', '')
    motivo = ' '.join((request.form.get('motivo') or '').split())[:240]
    usuario = get_usuario_logado()
    cur = mysql.connection.cursor()
    item = _dispensa_item(cur, item_id) if item_id else None
    if not item:
        cur.close()
        flash("Registro não encontrado.", "error")
        return redirect(url_for('dispensa_acompanhamento'))
    cur.execute("SELECT validacao, motivo FROM dispensa_itens WHERE id=%s", (item_id,))
    val_antes, mot_antes = cur.fetchone()
    voltar = redirect(url_for('dispensa_acompanhamento', data=item['data_prescricao'].isoformat()))
    quem = f"{item['leito']} · {item['nome']}{' (acompanhante)' if item['para'] == 'acompanhante' else ''} · {item['tipo']}"
    erro = None
    if novo not in _DISP_STATUS_ROT:
        erro = "Escolha a situação correta."
    elif novo == item['status']:
        erro = "A situação escolhida é a mesma registrada."
    elif len(motivo) < 10:
        erro = "Informe o motivo da correção (mínimo 10 caracteres)."
    elif novo == 'entregue' and item['valor'] <= 0:
        erro = f"O tipo {item['tipo']} está sem valor cadastrado. Cadastre o valor antes de marcar como entregue."
    elif item['status'] == 'entregue' and _repos_resumo(cur, [item_id]).get(item_id):
        erro = ("Esta refeição teve avaria registrada no totem, com reposição: a entrega original não pode ser desfeita "
                "(a reposição pressupõe que ela foi entregue).")
    else:
        fech = _fechamentos_no_intervalo(item['data_prescricao'])
        if fech:
            erro = _msg_fechado(fech[0])
    if erro:
        cur.close()
        flash(erro, "error")
        return voltar
    try:
        if novo == 'pendente':
            cur.execute("""UPDATE dispensa_itens SET status='pendente', entregue_em=NULL, entregue_por=NULL,
                           validacao=NULL, motivo=NULL WHERE id=%s""", (item_id,))
        elif novo == 'entregue':
            cur.execute("""UPDATE dispensa_itens SET status='entregue', entregue_em=NOW(), entregue_por=%s,
                           validacao='manual', motivo=%s WHERE id=%s""", (usuario, 'Correção: ' + motivo, item_id))
        else:
            cur.execute("""UPDATE dispensa_itens SET status='nao_entregue', entregue_em=NOW(), entregue_por=%s,
                           validacao=NULL, motivo=%s WHERE id=%s""", (usuario, 'Correção: ' + motivo, item_id))
        cur.execute("""INSERT INTO dispensa_correcoes (item_id, status_antes, validacao_antes, motivo_antes, por_antes,
                       em_antes, status_depois, motivo, feito_por) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (item_id, item['status'], val_antes, mot_antes, item['entregue_por'], item['entregue_em'],
                     novo, motivo, usuario))
        mysql.connection.commit()
    except Exception as e:
        mysql.connection.rollback()
        cur.close()
        logger.error(f"Erro ao corrigir registro da dispensa {item_id}: {e}")
        flash("Erro ao corrigir o registro. Nada foi alterado.", "error")
        return voltar
    cur.close()
    auditar(alvo=quem, detalhes={'de': _DISP_STATUS_ROT[item['status']], 'para': _DISP_STATUS_ROT[novo],
                                 'registrado_antes_por': item['entregue_por'] or '-', 'motivo': motivo})
    logger.warning(f"{usuario} CORRIGIU o registro da dispensa {item_id} ({quem}): "
                   f"{item['status']} -> {novo}. Motivo: {motivo}")
    flash(f"Registro corrigido: {quem} — {_DISP_STATUS_ROT[item['status']]} → {_DISP_STATUS_ROT[novo]}.", "success")
    return voltar


def _dispensa_correcoes_do_dia(data_ref):
    init_dispensa_correcoes()
    cur = mysql.connection.cursor()
    cur.execute("""SELECT c.feito_em, c.feito_por, c.status_antes, c.status_depois, c.motivo, c.por_antes,
                          p.leito, p.nome, t.nome, i.para, c.item_id
                   FROM dispensa_correcoes c JOIN dispensa_itens i ON i.id = c.item_id
                   JOIN dispensa_pacientes p ON p.id = i.paciente_id JOIN dispensa_tipos t ON t.id = i.tipo_id
                   WHERE p.data_prescricao = %s ORDER BY c.feito_em DESC, c.id DESC""", (data_ref,))
    out = [{'hora': r[0].strftime('%H:%M') if r[0] else '', 'por': r[1] or '', 'de': _DISP_STATUS_ROT.get(r[2], r[2]),
            'para_st': _DISP_STATUS_ROT.get(r[3], r[3]), 'motivo': r[4], 'por_antes': r[5] or '—', 'leito': r[6],
            'nome': r[7] + (' (acompanhante)' if r[9] == 'acompanhante' else ''), 'tipo': r[8], 'item_id': r[10]}
           for r in cur.fetchall()]
    cur.close()
    return out


# ─── DISPENSA: FECHAMENTO DE PERÍODO ─────────────────────────────────────────
# Depois de conferido (e usado para pagar a terceirizada), o período é fechado:
# nada dentro dele pode mudar (cozinha, importação, totem, reajustes). Reabrir exige motivo.

_SQL_NAO_FECHADO = ("NOT EXISTS (SELECT 1 FROM dispensa_fechamentos f WHERE f.status='fechado' "
                    "AND p.data_prescricao BETWEEN f.data_ini AND f.data_fim)")


def init_dispensa_fechamentos():
    cur = mysql.connection.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS dispensa_fechamentos (
            id            INT AUTO_INCREMENT PRIMARY KEY,
            data_ini      DATE NOT NULL,
            data_fim      DATE NOT NULL,
            status        VARCHAR(20) NOT NULL DEFAULT 'fechado' COMMENT 'fechado | reaberto',
            qtd_previstas INT NOT NULL DEFAULT 0,
            qtd_entregues INT NOT NULL DEFAULT 0,
            qtd_sem_qr    INT NOT NULL DEFAULT 0,
            qtd_nao       INT NOT NULL DEFAULT 0,
            qtd_pendentes INT NOT NULL DEFAULT 0,
            valor_total   DECIMAL(12,2) NOT NULL DEFAULT 0,
            observacao    VARCHAR(255) DEFAULT NULL,
            fechado_por   VARCHAR(120) DEFAULT NULL,
            fechado_em    TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
            reaberto_por  VARCHAR(120) DEFAULT NULL,
            reaberto_em   DATETIME DEFAULT NULL,
            motivo_reabertura VARCHAR(255) DEFAULT NULL,
            KEY idx_df_periodo (data_ini, data_fim)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    """)
    mysql.connection.commit()
    cur.close()


def _fechamentos_no_intervalo(data_ini, data_fim=None):
    """Fechamentos ativos que cobrem alguma data do intervalo."""
    data_fim = data_fim or data_ini
    init_dispensa_fechamentos()
    cur = mysql.connection.cursor()
    cur.execute("""SELECT id, data_ini, data_fim, valor_total, qtd_entregues, fechado_por, fechado_em
                   FROM dispensa_fechamentos WHERE status='fechado' AND data_ini <= %s AND data_fim >= %s
                   ORDER BY data_ini""", (data_fim, data_ini))
    r = [{'id': x[0], 'ini': x[1], 'fim': x[2], 'valor': float(x[3]), 'entregues': int(x[4]), 'por': x[5] or '',
          'em': x[6], 'txt': f"{x[1].strftime('%d/%m/%Y')} a {x[2].strftime('%d/%m/%Y')}"} for x in cur.fetchall()]
    cur.close()
    return r


def _msg_fechado(f):
    return (f"O período {f['txt']} está fechado (por {f['por']} em {f['em'].strftime('%d/%m/%Y %H:%M') if f['em'] else '—'}). "
            "Nada nele pode ser alterado. Para corrigir, reabra o período em Dispensa Refeição › Fechamento de período.")


@app.route('/admin/dispensa/fechamento', methods=['GET', 'POST'])
def dispensa_fechamento():
    from datetime import timedelta
    init_dispensa_fase2()
    init_dispensa_fechamentos()
    usuario = get_usuario_logado()

    if request.method == 'POST':
        data_ini = _parse_data(request.form.get('data_inicial'))
        data_fim = _parse_data(request.form.get('data_final'))
        obs = ' '.join((request.form.get('observacao') or '').split())[:255]
        voltar = redirect(url_for('dispensa_fechamento', ini=request.form.get('data_inicial'), fim=request.form.get('data_final')))
        if not data_ini or not data_fim or data_fim < data_ini:
            flash("Período inválido.", "error")
            return redirect(url_for('dispensa_fechamento'))
        if data_fim >= date.today():
            flash("Só é possível fechar dias que já terminaram (a data final deve ser anterior a hoje).", "error")
            return voltar
        if _fechamentos_no_intervalo(data_ini, data_fim):
            flash("Parte deste período já está fechada. Os períodos fechados não podem se sobrepor.", "error")
            return voltar
        dados = _dispensa_dados_relatorio(data_ini, data_fim)
        t = dados['tot']
        if t['previstas'] == 0:
            flash("Não há refeições no período para fechar.", "error")
            return voltar
        if (t['pendentes'] or t['zerados']) and not request.form.get('ciente'):
            flash("Há pendências no período. Marque que está ciente para fechar mesmo assim.", "error")
            return voltar
        try:
            cur = mysql.connection.cursor()
            cur.execute("""INSERT INTO dispensa_fechamentos (data_ini, data_fim, qtd_previstas, qtd_entregues, qtd_sem_qr,
                           qtd_nao, qtd_pendentes, valor_total, observacao, fechado_por)
                           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                        (data_ini, data_fim, t['previstas'], t['entregues'], t['manual'], t['nao'], t['pendentes'],
                         round(t['valor'], 2), obs or None, usuario))
            fid = cur.lastrowid
            mysql.connection.commit()
            cur.close()
            logger.info(f"{usuario} fechou o período de dispensa {data_ini}–{data_fim} (nº {fid}): "
                        f"{t['entregues']} entregues, R$ {moeda_br(t['valor'])}.")
            flash(f"Período {data_ini.strftime('%d/%m/%Y')} a {data_fim.strftime('%d/%m/%Y')} fechado "
                  f"(nº {fid}) — {t['entregues']} refeições, R$ {moeda_br(t['valor'])}.", "success")
        except Exception as e:
            mysql.connection.rollback()
            logger.error(f"Erro ao fechar período: {e}")
            flash("Erro ao fechar o período. Nada foi alterado.", "error")
        return redirect(url_for('dispensa_fechamento'))

    # Conferência (prévia) do período escolhido
    conferencia = None
    ini = _parse_data(request.args.get('ini'))
    fim = _parse_data(request.args.get('fim'))
    if ini and fim and fim >= ini:
        dados = _dispensa_dados_relatorio(ini, fim)
        conferencia = {'ini': ini, 'fim': fim, 'tot': dados['tot'], 'tipos': dados['tipos'],
                       'sobrepoe': _fechamentos_no_intervalo(ini, fim), 'futuro': fim >= date.today()}
    cur = mysql.connection.cursor()
    cur.execute("""SELECT id, data_ini, data_fim, status, qtd_entregues, qtd_sem_qr, qtd_nao, qtd_pendentes, valor_total,
                          fechado_por, fechado_em, reaberto_por, reaberto_em, motivo_reabertura, observacao
                   FROM dispensa_fechamentos ORDER BY data_ini DESC, id DESC LIMIT 50""")
    lista = [{'id': r[0], 'ini': r[1], 'fim': r[2], 'status': r[3], 'entregues': r[4], 'sem_qr': r[5], 'nao': r[6],
              'pendentes': r[7], 'valor': float(r[8]), 'fechado_por': r[9] or '', 'fechado_em': r[10],
              'reaberto_por': r[11] or '', 'reaberto_em': r[12], 'motivo': r[13] or '', 'obs': r[14] or ''}
             for r in cur.fetchall()]
    cur.close()
    hoje = date.today()
    sugestao_fim = hoje - timedelta(days=1)
    return render_template('menu_admin.html', module='dispensa_fechamento', usuario=usuario,
                           conferencia=conferencia, fechamentos=lista,
                           ini_padrao=(ini or sugestao_fim.replace(day=1)).isoformat(),
                           fim_padrao=(fim or sugestao_fim).isoformat())


@app.route('/admin/dispensa/fechamento/<int:fid>/reabrir', methods=['POST'])
def dispensa_fechamento_reabrir(fid):
    init_dispensa_fechamentos()
    motivo = ' '.join((request.form.get('motivo') or '').split())[:255]
    if len(motivo) < 10:
        flash("Informe o motivo da reabertura (mínimo 10 caracteres).", "error")
        return redirect(url_for('dispensa_fechamento'))
    usuario = get_usuario_logado()
    try:
        cur = mysql.connection.cursor()
        cur.execute("""UPDATE dispensa_fechamentos SET status='reaberto', reaberto_por=%s, reaberto_em=NOW(),
                       motivo_reabertura=%s WHERE id=%s AND status='fechado'""", (usuario, motivo, fid))
        n = cur.rowcount
        mysql.connection.commit()
        cur.close()
        if n:
            logger.warning(f"{usuario} REABRIU o fechamento de dispensa nº {fid}: {motivo}")
            flash(f"Período nº {fid} reaberto. Depois de corrigir, feche o período novamente.", "success")
        else:
            flash("Este período não está fechado.", "error")
    except Exception as e:
        mysql.connection.rollback()
        logger.error(f"Erro ao reabrir fechamento: {e}")
        flash("Erro ao reabrir o período.", "error")
    return redirect(url_for('dispensa_fechamento'))


# ─── PERFIS E PERMISSÕES ─────────────────────────────────────────────────────
# Perfis configuráveis pela tela (Cadastro › Perfis). Cada perfil tem um tipo de
# acesso (para onde vai ao entrar) e, por módulo, as permissões Ver/Incluir/Editar/Excluir.
# A checagem é central (before_request), pela rota acessada.

from flask import g, has_request_context

ACOES = ('ver', 'incluir', 'editar', 'excluir')
ACOES_ROTULO = {'ver': 'Ver', 'incluir': 'Incluir', 'editar': 'Editar', 'excluir': 'Excluir'}

# (chave, nome, área, ações aplicáveis, descrição curta)
MODULOS = [
    ('dashboard',          'Dashboard',                  'Painel',        ('ver',),                                 'Indicadores da tela inicial'),
    ('colaboradores',      'Colaboradores',              'Cadastro',      ACOES,                                    'Cadastro e importação de colaboradores'),
    ('usuarios',           'Usuários',                   'Cadastro',      ACOES,                                    'Usuários do sistema'),
    ('perfis',             'Perfis e permissões',        'Cadastro',      ACOES,                                    'Esta tela'),
    ('departamentos',      'Departamentos',              'Cadastro',      ACOES,                                    ''),
    ('grupos',             'Grupos SND',                 'Cadastro',      ACOES,                                    ''),
    ('escalas',            'Escalas de trabalho',        'Cadastro',      ACOES,                                    'Direito a refeição por escala; aplicar em lote exige editar Colaboradores'),
    ('cardapio',           'Cardápio (semana e montagem)', 'Cardápio',    ACOES,                                    'Incluir/editar = montar e copiar cardápios'),
    ('cardapio_pratos',    'Catálogo de pratos',         'Cardápio',      ACOES,                                    ''),
    ('dispensa_pacientes', 'Pacientes do dia (cozinha)', 'Dispensa Refeição', ('ver',),                         'Ver = o que produzir (só leitura: quem autoriza as refeições é a nutrição, em Importar prescrições)'),
    ('dispensa_acompanhamento', 'Acompanhamento da entrega', 'Dispensa Refeição', ('ver',),                  'Ver, ao vivo, o que a dispenseira registra no totem'),
    ('dispensa_importar',  'Importar prescrições',       'Dispensa Refeição', ('ver', 'incluir'),              'Incluir = importar e AUTORIZAR as refeições (CSV/Salutem), ajustar refeições e acompanhante (nutrição)'),
    ('dispensa_tipos',     'Tipos de refeição',          'Dispensa Refeição', ACOES,                           'Editar inclui reajuste de valores'),
    ('dispensa_fechamento', 'Fechamento de período',     'Dispensa Refeição', ('ver', 'incluir', 'editar'),    'Incluir = fechar um período · Editar = reabrir (com motivo)'),
    ('dispensa_etiquetas', 'Etiquetas QR do leito',      'Dispensa Refeição', ('ver', 'incluir'),           'Ver = consultar quais leitos estão sem etiqueta · Incluir = imprimir as etiquetas (e ver o aviso em Pacientes do dia)'),
    ('dispensa_correcao',  'Correção de registro (totem)', 'Dispensa Refeição', ('ver', 'editar'),           'Ver = histórico de correções · Editar = corrigir um registro do totem (motivo obrigatório)'),
    ('dispensa_totem',     'Totem de dispensa',          'Dispensa Refeição', ACOES,                           'Incluir = registrar entrega (o registro é definitivo: não há desfazer no totem)'),
    ('rel_total_senhas',   'Total de senhas',            'Relatórios',    ('ver',),                                 'Ver = gerar o relatório'),
    ('rel_lista_senhas',   'Lista de senhas emitidas',   'Relatórios',    ('ver',),                                 ''),
    ('rel_visitantes',     'Total de visitantes',        'Relatórios',    ('ver',),                                 ''),
    ('rel_departamento',   'Por departamento',           'Relatórios',    ('ver',),                                 ''),
    ('rel_cardapio',       'Emissões com cardápio',      'Relatórios',    ('ver',),                                 ''),
    ('rel_snd',            'Financeiro SND',             'Relatórios',    ('ver',),                                 ''),
    ('rel_dispensa',       'Financeiro Dispensa',        'Relatórios',    ('ver',),                                 ''),
    ('rel_avarias',        'Avarias da dispensa',        'Relatórios',    ('ver',),                                 'Refeições que caíram/estragaram: reposições, custos e motivos'),
    ('rel_faturamento',    'Faturamento (consolidado)',  'Relatórios',    ('ver',),                                 'Colaboradores, visitantes, pacientes e acompanhantes'),
    ('cfg_localizacoes',   'Localizações',               'Parâmetros',    ACOES,                                    ''),
    ('cfg_emissao',        'Emissão de senha',           'Parâmetros',    ('ver', 'editar'),                        ''),
    ('cfg_custos',         'Custos de refeição',         'Parâmetros',    ('ver', 'editar'),                        ''),
    ('cfg_turnos',         'Horários de turno',          'Parâmetros',    ('ver', 'editar'),                        ''),
    ('cfg_limite_visit',   'Limite de senhas (visitante)', 'Parâmetros',  ('ver', 'editar'),                        ''),
]
MODULOS_CHAVES = [m[0] for m in MODULOS]
MODULO_ACOES = {m[0]: m[3] for m in MODULOS}
MODULO_NOME = {m[0]: m[1] for m in MODULOS}

TIPOS_ACESSO = [
    ('painel',        'Painel administrativo', 'Usa o painel; vê só os módulos permitidos'),
    ('totem_desktop', 'Totem de senhas (desktop)', 'Vai direto para a emissão de senhas'),
    ('totem_tablet',  'Totem de senhas (tablet)',  'Vai direto para a emissão de senhas no tablet'),
    ('dispensa',      'Totem de dispensa (pacientes)', 'Vai direto para o totem de entrega no leito'),
]
TIPOS_ACESSO_CHAVES = [t[0] for t in TIPOS_ACESSO]

# Rotas públicas (sem login) ou que fazem a própria checagem
ROTAS_PUBLICAS = {'login', 'logout', 'static', 'favicon', 'cardapio_publico',
                  'emissao_senha', 'emissao_senha_tablet', 'senha_colaborador', 'senha_visitante',
                  'senha_colaborador_cardapio', 'usuario', 'inicio_perfil'}
# Menu Configurações: uso exclusivo do Administrador. Ficam fora de ROTAS_PERMISSAO de propósito
# (rota sem regra = só o perfil protegido) e não aparecem no editor de perfis.
ROTAS_SO_ADMIN = {'config_identidade', 'config_seguranca', 'config_seguranca_desbloquear', 'config_seguranca_senha',
                  'config_auditoria', 'config_auditoria_exportar',
                  'config_backup', 'config_backup_status', 'config_backup_baixar', 'config_backup_excluir',
                  'config_backup_restaurar', 'config_salutem'}
# qualquer usuário logado, de qualquer perfil (ex.: trocar a própria senha)
ROTAS_LOGADO = {'minha_senha'}
ROTAS_JSON = {'dispensa_registrar', 'dispensa_avaria', 'dispensa_identificar', 'dispensa_totem_status', 'dispensa_ping', 'dispensa_acompanhamento_dados',
              'config_backup_status'}

_V = lambda m: {'GET': (m, 'ver'), 'POST': (m, 'ver')}            # relatórios: ver = gerar
ROTAS_PERMISSAO = {
    'admin':                  {'GET': ('dashboard', 'ver')},
    # Cadastro
    'cadastro':               {'GET': ('colaboradores', 'ver'), 'POST': ('colaboradores', 'incluir')},
    'importar_colaboradores': {'POST': ('colaboradores', 'incluir')},
    'modelo_colaboradores_csv': {'GET': ('colaboradores', 'ver')},
    'editar_colaborador':     {'POST': ('colaboradores', 'editar')},
    'excluir_colaborador':    {'POST': ('colaboradores', 'excluir')},
    'escalas':                {'GET': ('escalas', 'ver'), 'POST': ('escalas', 'incluir')},
    'escala_editar':          {'POST': ('escalas', 'editar')},
    'escala_excluir':         {'POST': ('escalas', 'excluir')},
    'escalas_lote':           {'POST': ('colaboradores', 'editar')},
    'escalas_modelo_csv':     {'GET': ('colaboradores', 'editar')},
    'escalas_importar':       {'POST': ('colaboradores', 'editar')},
    'escalas_importar_confirmar': {'POST': ('colaboradores', 'editar')},
    'cadastro_usuario':       {'GET': ('usuarios', 'ver'), 'POST': ('usuarios', 'incluir')},
    'editar_usuario':         {'POST': ('usuarios', 'editar')},
    'excluir_usuario':        {'POST': ('usuarios', 'excluir')},
    'perfis_lista':           {'GET': ('perfis', 'ver')},
    'perfil_novo':            {'GET': ('perfis', 'incluir'), 'POST': ('perfis', 'incluir')},
    'perfil_editar':          {'GET': ('perfis', 'ver'), 'POST': ('perfis', 'editar')},
    'perfil_excluir':         {'POST': ('perfis', 'excluir')},
    'departamentos':          {'GET': ('departamentos', 'ver'), 'POST': ('departamentos', 'incluir')},
    'editar_departamento':    {'POST': ('departamentos', 'editar')},
    'excluir_departamento':   {'POST': ('departamentos', 'excluir')},
    'admin_grupos':           {'GET': ('grupos', 'ver'), 'POST': ('grupos', 'incluir')},
    'editar_grupo':           {'POST': ('grupos', 'editar')},
    'excluir_grupo':          {'POST': ('grupos', 'excluir')},
    # Cardápio
    'cardapio_admin':         {'GET': ('cardapio', 'ver')},
    'cardapio_montar':        {'GET': ('cardapio', 'ver'), 'POST': ('cardapio', ('incluir', 'editar'))},
    'cardapio_copiar':        {'POST': ('cardapio', 'incluir')},
    'cardapio_copiar_semana': {'POST': ('cardapio', 'incluir')},
    'cardapio_novo':          {'GET': ('cardapio', 'incluir')},
    'cardapio_editar':        {'GET': ('cardapio', 'ver')},
    'cardapio_toggle':        {'POST': ('cardapio', 'editar')},
    'cardapio_excluir':       {'POST': ('cardapio', 'excluir')},
    'cardapio_pratos':        {'GET': ('cardapio_pratos', 'ver'), 'POST': ('cardapio_pratos', 'incluir')},
    'cardapio_prato_editar':  {'POST': ('cardapio_pratos', 'editar')},
    'cardapio_prato_excluir': {'POST': ('cardapio_pratos', 'excluir')},
    # Dispensa
    'dispensa_pacientes':     {'GET': ('dispensa_pacientes', 'ver')},
    'dispensa_refeicoes_ajustar': {'POST': ('dispensa_importar', 'incluir')},   # nutrição ajusta refeições autorizadas
    'dispensa_importar':      {'GET': ('dispensa_importar', 'ver'), 'POST': ('dispensa_importar', 'incluir')},
    'dispensa_acompanhante_salvar': {'POST': ('dispensa_importar', 'incluir')},   # nutrição define o acompanhante
    'dispensa_modelo_csv':    {'GET': ('dispensa_importar', 'ver')},
    'dispensa_tipos':         {'GET': ('dispensa_tipos', 'ver'), 'POST': ('dispensa_tipos', 'incluir')},
    'dispensa_tipo_editar':   {'POST': ('dispensa_tipos', 'editar')},
    'dispensa_tipos_ordem':   {'POST': ('dispensa_tipos', 'editar')},
    'dispensa_dietas_sem_refeicao': {'POST': ('dispensa_tipos', 'editar')},
    'dispensa_tipo_reajustar': {'POST': ('dispensa_tipos', 'editar')},
    'dispensa_tipo_excluir':  {'POST': ('dispensa_tipos', 'excluir')},
    'dispensa_acompanhamento': {'GET': ('dispensa_acompanhamento', 'ver')},
    'dispensa_acompanhamento_dados': {'GET': ('dispensa_acompanhamento', 'ver')},
    'dispensa_corrigir':      {'POST': ('dispensa_correcao', 'editar')},
    'dispensa_etiquetas':     {'GET': ('dispensa_etiquetas', 'ver')},
    'dispensa_etiquetas_imprimir': {'POST': ('dispensa_etiquetas', 'incluir')},
    'dispensa_fechamento':    {'GET': ('dispensa_fechamento', 'ver'), 'POST': ('dispensa_fechamento', 'incluir')},
    'dispensa_fechamento_reabrir': {'POST': ('dispensa_fechamento', 'editar')},
    'dispensa_totem':         {'GET': ('dispensa_totem', 'ver')},
    'dispensa_totem_lista':   {'GET': ('dispensa_totem', 'ver')},
    'dispensa_totem_status':  {'GET': ('dispensa_totem', 'ver')},
    'dispensa_ping':          {'POST': ('dispensa_totem', 'ver')},
    'dispensa_registrar':     {'POST': ('dispensa_totem', ('incluir', 'editar', 'excluir'))},
    'dispensa_avaria':        {'POST': ('dispensa_totem', ('incluir', 'editar', 'excluir'))},
    'dispensa_identificar':   {'POST': ('dispensa_totem', 'ver')},
    'dispensa_relatorio':     _V('rel_dispensa'),
    'dispensa_avarias_relatorio': _V('rel_avarias'),
    'relatorio_faturamento':  _V('rel_faturamento'),
    # Relatórios
    'relatorio_totalEmissao':      _V('rel_total_senhas'),
    'relatorio_emissaoDiaria':     _V('rel_lista_senhas'),
    'relatorio_totalVisitantes':   _V('rel_visitantes'),
    'relatorio_totalDepartamento': _V('rel_departamento'),
    'relatorio_cardapio':          _V('rel_cardapio'),
    'relatorio_snd':               _V('rel_snd'),
    # Parâmetros
    'config_localizacoes':    {'GET': ('cfg_localizacoes', 'ver'), 'POST': ('cfg_localizacoes', 'incluir')},
    'editar_localizacao':     {'POST': ('cfg_localizacoes', 'editar')},
    'excluir_localizacao':    {'POST': ('cfg_localizacoes', 'excluir')},
    'config_emissao_senha':   {'GET': ('cfg_emissao', 'ver'), 'POST': ('cfg_emissao', 'editar')},
    'config_custos_refeicao': {'GET': ('cfg_custos', 'ver'), 'POST': ('cfg_custos', 'editar')},
    'config_turnos':          {'GET': ('cfg_turnos', 'ver'), 'POST': ('cfg_turnos', 'editar')},
    'config_limite_visitantes': {'GET': ('cfg_limite_visit', 'ver'), 'POST': ('cfg_limite_visit', 'editar')},
}

# Ordem das telas para escolher a "página inicial" de quem não tem o dashboard
_PAGINA_DO_MODULO = [
    ('dashboard', 'admin'), ('dispensa_importar', 'dispensa_importar'), ('dispensa_pacientes', 'dispensa_pacientes'), ('dispensa_acompanhamento', 'dispensa_acompanhamento'),
    ('cardapio', 'cardapio_admin'), ('colaboradores', 'cadastro'), ('usuarios', 'cadastro_usuario'),
    ('perfis', 'perfis_lista'), ('departamentos', 'departamentos'), ('grupos', 'admin_grupos'), ('escalas', 'escalas'),
    ('cardapio_pratos', 'cardapio_pratos'), ('dispensa_tipos', 'dispensa_tipos'), ('dispensa_fechamento', 'dispensa_fechamento'),
    ('rel_total_senhas', 'relatorio_totalEmissao'), ('rel_lista_senhas', 'relatorio_emissaoDiaria'),
    ('rel_visitantes', 'relatorio_totalVisitantes'), ('rel_departamento', 'relatorio_totalDepartamento'),
    ('rel_cardapio', 'relatorio_cardapio'), ('rel_snd', 'relatorio_snd'), ('rel_dispensa', 'dispensa_relatorio'), ('rel_avarias', 'dispensa_avarias_relatorio'), ('rel_faturamento', 'relatorio_faturamento'),
    ('cfg_localizacoes', 'config_localizacoes'), ('cfg_emissao', 'config_emissao_senha'), ('cfg_custos', 'config_custos_refeicao'),
    ('cfg_turnos', 'config_turnos'), ('cfg_limite_visit', 'config_limite_visitantes'), ('dispensa_totem', 'dispensa_totem'),
]

# Perfis que já existiam (mantêm exatamente o acesso de antes)
_PERFIS_BASE = [
    ('admin', 'Administrador', 'Acesso total ao sistema (perfil protegido)', 'painel', {m: MODULO_ACOES[m] for m in MODULOS_CHAVES}),
    ('usuario', 'Usuário', 'Dashboard, consulta de colaboradores/departamentos e relatórios',
     'painel', {'dashboard': ('ver',), 'colaboradores': ('ver',), 'departamentos': ('ver',),
                'rel_total_senhas': ('ver',), 'rel_lista_senhas': ('ver',), 'rel_visitantes': ('ver',),
                'rel_departamento': ('ver',), 'rel_cardapio': ('ver',), 'rel_snd': ('ver',)}),
    ('totem_desktop', 'Totem Desktop', 'Totem de emissão de senhas (computador)', 'totem_desktop', {}),
    ('totem_tablet', 'Totem Tablet', 'Totem de emissão de senhas (tablet)', 'totem_tablet', {}),
    ('dispensa', 'Dispensa (totem de pacientes)', 'Dispenseira: entrega de refeições no leito', 'dispensa',
     {'dispensa_totem': ('ver', 'incluir', 'editar')}),
]


def init_perfis():
    """Cria as tabelas de perfis, migra os perfis fixos antigos e vincula os usuários (idempotente)."""
    cur = mysql.connection.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS perfis (
            id        INT AUTO_INCREMENT PRIMARY KEY,
            chave     VARCHAR(40) DEFAULT NULL COMMENT 'Perfis de sistema (admin, usuario, ...)',
            nome      VARCHAR(80) NOT NULL,
            descricao VARCHAR(255) DEFAULT NULL,
            inicio    VARCHAR(20) NOT NULL DEFAULT 'painel' COMMENT 'painel | totem_desktop | totem_tablet | dispensa',
            protegido TINYINT(1) NOT NULL DEFAULT 0 COMMENT 'Administrador: acesso total, não pode ser alterado/excluído',
            ativo     TINYINT(1) NOT NULL DEFAULT 1,
            criado_em TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
            atualizado_em TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uk_perfil_nome (nome),
            UNIQUE KEY uk_perfil_chave (chave)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS perfil_permissoes (
            perfil_id INT NOT NULL,
            modulo    VARCHAR(40) NOT NULL,
            ver       TINYINT(1) NOT NULL DEFAULT 0,
            incluir   TINYINT(1) NOT NULL DEFAULT 0,
            editar    TINYINT(1) NOT NULL DEFAULT 0,
            excluir   TINYINT(1) NOT NULL DEFAULT 0,
            PRIMARY KEY (perfil_id, modulo),
            CONSTRAINT fk_pp_perfil FOREIGN KEY (perfil_id) REFERENCES perfis(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    """)
    cur.execute("SELECT COUNT(*) FROM perfis")
    if cur.fetchone()[0] == 0:
        for chave, nome, desc, inicio, perms in _PERFIS_BASE:
            cur.execute("INSERT INTO perfis (chave, nome, descricao, inicio, protegido) VALUES (%s,%s,%s,%s,%s)",
                        (chave, nome, desc, inicio, 1 if chave == 'admin' else 0))
            pid = cur.lastrowid
            for mod, acoes in perms.items():
                cur.execute("""INSERT INTO perfil_permissoes (perfil_id, modulo, ver, incluir, editar, excluir)
                               VALUES (%s,%s,%s,%s,%s,%s)""", (pid, mod, *[1 if a in acoes else 0 for a in ACOES]))
    # usuários: coluna perfil passa a texto livre + vínculo ao perfil configurável
    cur.execute("SHOW COLUMNS FROM usuarios LIKE 'perfil'")
    col = cur.fetchone()
    if col and str(col[1]).startswith('enum('):
        cur.execute("ALTER TABLE usuarios MODIFY perfil VARCHAR(40) NOT NULL DEFAULT 'usuario'")
    cur.execute("ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS perfil_id INT DEFAULT NULL AFTER perfil")
    cur.execute("""UPDATE usuarios u JOIN perfis p ON p.chave = u.perfil
                   SET u.perfil_id = p.id WHERE u.perfil_id IS NULL""")
    mysql.connection.commit()
    cur.close()


def _carregar_perfil(perfil_id):
    """Retorna {id, nome, chave, inicio, protegido, ativo, perms: {modulo: set(acoes)}}."""
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, nome, chave, inicio, protegido, ativo FROM perfis WHERE id=%s", (perfil_id,))
    r = cur.fetchone()
    if not r:
        cur.close()
        return None
    perfil = {'id': r[0], 'nome': r[1], 'chave': r[2], 'inicio': r[3], 'protegido': bool(r[4]), 'ativo': bool(r[5])}
    if perfil['protegido']:
        perfil['perms'] = {m: set(MODULO_ACOES[m]) for m in MODULOS_CHAVES}
    else:
        cur.execute("SELECT modulo, ver, incluir, editar, excluir FROM perfil_permissoes WHERE perfil_id=%s", (perfil_id,))
        perfil['perms'] = {}
        for mod, *vals in cur.fetchall():
            acoes = {a for a, v in zip(ACOES, vals) if v and a in MODULO_ACOES.get(mod, ())}
            if acoes:
                perfil['perms'][mod] = acoes
    cur.close()
    return perfil


def perfil_atual():
    if 'perfil' not in g:
        g.perfil = None
        if session.get('perfil_id'):
            try:
                g.perfil = _carregar_perfil(session['perfil_id'])
            except Exception as e:
                logger.error(f"Erro ao carregar perfil: {e}")
    return g.perfil


def pode(modulo, acao='ver'):
    p = perfil_atual()
    if not p or not p['ativo']:
        return False
    acoes = acao if isinstance(acao, (tuple, list, set)) else (acao,)
    return bool(p['perms'].get(modulo, set()) & set(acoes))


def pagina_inicial():
    """Para onde o usuário vai ao entrar (ou quando não tem permissão para a página pedida)."""
    p = perfil_atual()
    if not p:
        return '/'
    destinos = {'totem_desktop': 'emissao_senha', 'totem_tablet': 'emissao_senha_tablet', 'dispensa': 'dispensa_totem'}
    if p['inicio'] in destinos:
        return url_for(destinos[p['inicio']])
    for mod, endpoint in _PAGINA_DO_MODULO:
        if pode(mod, 'ver'):
            return url_for(endpoint)
    return None


@app.context_processor
def _injetar_permissoes():
    p = perfil_atual() if session.get('usuario_id') else None
    return {'pode': pode, 'perfil_nome': p['nome'] if p else '', 'perfil_inicio': p['inicio'] if p else '',
            'eh_admin': bool(p and p['ativo'] and p['protegido'])}


@app.before_request
def _checar_permissao():
    ep = request.endpoint
    if ep is None or ep in ROTAS_PUBLICAS:
        return None
    eh_json = ep in ROTAS_JSON
    if 'usuario_id' not in session:
        return ({'ok': False, 'erro': 'Sessão expirada. Entre novamente.'}, 401) if eh_json else redirect('/')
    if not session.get('perfil_id'):
        # sessão antiga (antes dos perfis configuráveis): pede novo login
        session.clear()
        flash("Entre novamente para carregar o seu perfil de acesso.")
        return redirect('/')
    p = perfil_atual()
    if not p or not p['ativo']:
        session.clear()
        flash("Seu perfil de acesso está inativo. Procure o administrador.")
        return redirect('/')
    if p['inicio'] not in ('totem_desktop', 'totem_tablet', 'dispensa') and SESSAO_INATIVIDADE_MIN > 0:
        agora = time_mod.time()
        ult = session.get('ult')
        if ult and agora - ult > SESSAO_INATIVIDADE_MIN * 60:
            auditar(forcar=True, modulo='Acesso', acao='Sessão encerrada por inatividade', resultado='ok',
                    detalhes={'minutos_sem_uso': int((agora - ult) // 60)})
            logger.info(f"{get_usuario_logado()}: sessão encerrada por inatividade.")
            session.clear()
            if eh_json:
                return {'ok': False, 'erro': 'Sessão expirada por inatividade. Entre novamente.'}, 401
            flash(f"Sessão encerrada após {SESSAO_INATIVIDADE_MIN} minutos sem uso. Entre novamente.")
            return redirect('/')
        if not ult or agora - ult > 30:   # regrava no máximo a cada 30 s
            session['ult'] = agora
    if session.get('trocar_senha') and ep not in ROTAS_LOGADO:
        # troca de senha pendente: nada mais abre até trocar
        if eh_json:
            return {'ok': False, 'erro': 'Troque a sua senha para continuar.'}, 403
        return redirect(url_for('minha_senha'))
    if ep in ROTAS_LOGADO:
        return None
    regra = ROTAS_PERMISSAO.get(ep, {}).get(request.method)
    permitido = pode(*regra) if regra else bool(p['protegido'])   # rota não mapeada: só Administrador
    if permitido:
        return None
    auditar(forcar=True, resultado='negado', motivo='perfil sem permissão',
            acao=AUDIT_ROTULOS.get(ep, ('', ''))[1] or f"Acessar {request.path}")
    logger.warning(f"{get_usuario_logado()} ({p['nome']}) sem permissão para {ep} [{request.method}].")
    if eh_json:
        return {'ok': False, 'erro': 'Seu perfil não tem permissão para esta ação.'}, 403
    flash("Seu perfil não tem permissão para esta ação.", "error")
    destino = request.referrer if request.method == 'POST' and request.referrer else pagina_inicial()
    if not destino or destino == request.url:
        return redirect(url_for('inicio_perfil'))
    return redirect(destino)


@app.route('/inicio')
def inicio_perfil():
    """Página de quem não tem nenhuma tela liberada."""
    if 'usuario_id' not in session:
        return redirect('/')
    destino = pagina_inicial()
    if destino and destino != url_for('inicio_perfil'):
        return redirect(destino)
    return render_template('sem_acesso.html', usuario=get_usuario_logado(), perfil_nome=(perfil_atual() or {}).get('nome', ''))


# ─── Telas de perfis (Cadastro › Perfis) ─────────────────────────────────────

def _modulos_por_area():
    areas = []
    for chave, nome, area, acoes, desc in MODULOS:
        if not areas or areas[-1]['area'] != area:
            areas.append({'area': area, 'modulos': []})
        areas[-1]['modulos'].append({'chave': chave, 'nome': nome, 'acoes': acoes, 'desc': desc})
    return areas


@app.route('/admin/perfis')
def perfis_lista():
    init_perfis()
    cur = mysql.connection.cursor()
    cur.execute("""SELECT p.id, p.nome, p.descricao, p.inicio, p.protegido, p.ativo,
                          (SELECT COUNT(*) FROM usuarios u WHERE u.perfil_id = p.id) AS usuarios,
                          (SELECT COUNT(*) FROM perfil_permissoes pp WHERE pp.perfil_id = p.id
                             AND (pp.ver OR pp.incluir OR pp.editar OR pp.excluir)) AS modulos
                   FROM perfis p ORDER BY p.protegido DESC, p.nome""")
    perfis = [{'id': r[0], 'nome': r[1], 'descricao': r[2] or '', 'inicio': r[3], 'protegido': bool(r[4]),
               'ativo': bool(r[5]), 'usuarios': int(r[6]), 'modulos': len(MODULOS) if r[4] else int(r[7])}
              for r in cur.fetchall()]
    cur.close()
    return render_template('menu_admin.html', module='perfis', usuario=get_usuario_logado(), perfis=perfis,
                           tipos_acesso=dict((t[0], t[1]) for t in TIPOS_ACESSO))


def _salvar_perfil(perfil_id=None):
    nome = ' '.join((request.form.get('nome') or '').split())[:80]
    descricao = (request.form.get('descricao') or '').strip()[:255]
    inicio = request.form.get('inicio', 'painel')
    ativo = 1 if request.form.get('ativo') else 0
    if not nome or inicio not in TIPOS_ACESSO_CHAVES:
        flash("Informe o nome e o tipo de acesso do perfil.", "error")
        return None
    cur = mysql.connection.cursor()
    cur.execute("SELECT id FROM perfis WHERE nome=%s AND id<>%s", (nome, perfil_id or 0))
    if cur.fetchone():
        cur.close()
        flash(f"Já existe um perfil chamado “{nome}”.", "error")
        return None
    if perfil_id:
        cur.execute("SELECT protegido FROM perfis WHERE id=%s", (perfil_id,))
        r = cur.fetchone()
        if not r:
            cur.close()
            flash("Perfil não encontrado.", "error")
            return None
        if r[0]:
            # Administrador: só nome/descrição podem mudar; permissões e tipo de acesso são fixos
            cur.execute("UPDATE perfis SET nome=%s, descricao=%s WHERE id=%s", (nome, descricao or None, perfil_id))
            mysql.connection.commit()
            cur.close()
            return perfil_id
        if not ativo and perfil_id == session.get('perfil_id'):
            cur.close()
            flash("Você não pode desativar o seu próprio perfil.", "error")
            return None
        cur.execute("UPDATE perfis SET nome=%s, descricao=%s, inicio=%s, ativo=%s WHERE id=%s",
                    (nome, descricao or None, inicio, ativo, perfil_id))
    else:
        cur.execute("INSERT INTO perfis (nome, descricao, inicio, ativo) VALUES (%s,%s,%s,%s)",
                    (nome, descricao or None, inicio, ativo))
        perfil_id = cur.lastrowid
    cur.execute("DELETE FROM perfil_permissoes WHERE perfil_id=%s", (perfil_id,))
    for mod in MODULOS_CHAVES:
        marcadas = {a for a in MODULO_ACOES[mod] if request.form.get(f'perm_{mod}_{a}')}
        if marcadas - {'ver'}:
            marcadas.add('ver')    # quem inclui/edita/exclui precisa ver a tela
        if marcadas:
            cur.execute("""INSERT INTO perfil_permissoes (perfil_id, modulo, ver, incluir, editar, excluir)
                           VALUES (%s,%s,%s,%s,%s,%s)""", (perfil_id, mod, *[1 if a in marcadas else 0 for a in ACOES]))
    mysql.connection.commit()
    cur.close()
    return perfil_id


@app.route('/admin/perfis/novo', methods=['GET', 'POST'])
def perfil_novo():
    init_perfis()
    if request.method == 'POST':
        try:
            pid = _salvar_perfil()
            if pid:
                logger.info(f"{get_usuario_logado()} criou o perfil ID {pid} ({request.form.get('nome')}).")
                flash("Perfil criado.", "success")
                return redirect(url_for('perfil_editar', perfil_id=pid))
        except Exception as e:
            mysql.connection.rollback()
            logger.error(f"Erro ao criar perfil: {e}")
            flash("Erro ao criar o perfil.", "error")
        return redirect(url_for('perfil_novo'))
    base = None
    copiar = request.args.get('copiar', '')
    if copiar.isdigit():
        base = _carregar_perfil(int(copiar))
        if base:
            base = dict(base, id=None, nome=f"{base['nome']} (cópia)", protegido=False)
    return render_template('menu_admin.html', module='perfil_form', usuario=get_usuario_logado(),
                           perfil_edit=base, areas=_modulos_por_area(), tipos_acesso=TIPOS_ACESSO,
                           acoes=ACOES, acoes_rotulo=ACOES_ROTULO)


@app.route('/admin/perfis/<int:perfil_id>', methods=['GET', 'POST'])
def perfil_editar(perfil_id):
    init_perfis()
    if request.method == 'POST':
        try:
            if _salvar_perfil(perfil_id):
                logger.info(f"{get_usuario_logado()} alterou o perfil ID {perfil_id}.")
                flash("Perfil atualizado. As permissões valem a partir da próxima ação dos usuários.", "success")
        except Exception as e:
            mysql.connection.rollback()
            logger.error(f"Erro ao salvar perfil: {e}")
            flash("Erro ao salvar o perfil.", "error")
        return redirect(url_for('perfil_editar', perfil_id=perfil_id))
    p = _carregar_perfil(perfil_id)
    if not p:
        flash("Perfil não encontrado.", "error")
        return redirect(url_for('perfis_lista'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT descricao FROM perfis WHERE id=%s", (perfil_id,))
    p['descricao'] = (cur.fetchone() or [''])[0] or ''
    cur.execute("SELECT nome, usuario FROM usuarios WHERE perfil_id=%s ORDER BY nome", (perfil_id,))
    usuarios_perfil = cur.fetchall()
    cur.close()
    return render_template('menu_admin.html', module='perfil_form', usuario=get_usuario_logado(),
                           perfil_edit=p, areas=_modulos_por_area(), tipos_acesso=TIPOS_ACESSO,
                           acoes=ACOES, acoes_rotulo=ACOES_ROTULO, usuarios_perfil=usuarios_perfil)


@app.route('/admin/perfis/<int:perfil_id>/excluir', methods=['POST'])
def perfil_excluir(perfil_id):
    init_perfis()
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT nome, protegido, (SELECT COUNT(*) FROM usuarios WHERE perfil_id=%s) FROM perfis WHERE id=%s",
                    (perfil_id, perfil_id))
        r = cur.fetchone()
        if not r:
            flash("Perfil não encontrado.", "error")
        elif r[1]:
            flash("O perfil Administrador não pode ser excluído.", "error")
        elif r[2]:
            flash(f"O perfil “{r[0]}” tem {r[2]} usuário(s). Mude o perfil deles antes de excluir, ou desative o perfil.", "error")
        else:
            cur.execute("DELETE FROM perfis WHERE id=%s", (perfil_id,))
            mysql.connection.commit()
            logger.info(f"{get_usuario_logado()} excluiu o perfil “{r[0]}”.")
            flash(f"Perfil “{r[0]}” excluído.", "success")
        cur.close()
    except Exception as e:
        mysql.connection.rollback()
        logger.error(f"Erro ao excluir perfil: {e}")
        flash("Erro ao excluir o perfil.", "error")
    return redirect(url_for('perfis_lista'))


def _perfis_para_select():
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, nome, inicio, ativo FROM perfis ORDER BY protegido DESC, nome")
    r = [{'id': x[0], 'nome': x[1], 'inicio': x[2], 'ativo': bool(x[3])} for x in cur.fetchall()]
    cur.close()
    return r


# ─── RELATÓRIO: EMISSÕES COM CARDÁPIO ────────────────────────────────────────

# ─── RELATÓRIO SND – CUSTO DE REFEIÇÕES POR DEPARTAMENTO ─────────────────────

@app.route('/admin/relatorio/snd', methods=['GET', 'POST'])
def relatorio_snd():
    if 'usuario_id' not in session:
        return redirect('/')
    usuario_logado = get_usuario_logado()
    perfil = session.get('usuario_perfil', 'desconhecido')

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT nome FROM departamentos ORDER BY nome ASC")
    departamentos = [r[0] for r in cursor.fetchall()]
    cursor.close()

    if request.method == 'POST':
        try:
            data_inicial = datetime.strptime(request.form.get('data_inicial'), "%Y-%m-%d")
            data_final   = datetime.strptime(request.form.get('data_final'),   "%Y-%m-%d")
        except ValueError:
            flash("Datas inválidas.", "error")
            return redirect(url_for('relatorio_snd'))
        if data_final < data_inicial:
            flash("Data final não pode ser anterior à data inicial.", "error")
            return redirect(url_for('relatorio_snd'))

        tipo_relatorio = request.form.get('tipo_relatorio')
        dt_inicio = datetime.combine(data_inicial, time(0, 0))
        dt_fim    = datetime.combine(data_final,   time(23, 59, 59))

        # ── busca emissões ──────────────────────────────────────────────────
        cursor = mysql.connection.cursor()
        cursor.execute("""
            SELECT e.departamento, e.data_hora,
                   d.grupo
            FROM   emissoes_senha e
            LEFT JOIN departamentos d ON d.nome = e.departamento
            WHERE  e.data_hora BETWEEN %s AND %s
            ORDER  BY d.grupo, e.departamento, e.data_hora
        """, (dt_inicio, dt_fim))
        rows = cursor.fetchall()
        cursor.close()

        # ── custos vigentes na data inicial do período (preserva histórico) ─
        custos = get_custos_na_data(dt_inicio)
        cu_cafe   = float(custos.get('cafe',   {}).get('custo_unitario', 0))
        cu_almoco = float(custos.get('almoco', {}).get('custo_unitario', 0))
        cu_janta  = float(custos.get('janta',  {}).get('custo_unitario', 0))

        # ── agrupa por (grupo, departamento) ───────────────────────────────
        from collections import defaultdict
        dados = defaultdict(lambda: defaultdict(lambda: {'qtd_cafe':0,'qtd_almoco':0,'qtd_janta':0,'grupo':''}))
        t = get_turnos()

        for dept, dh, grupo in rows:

            dept = (dept or '').strip()

            if dept.upper().startswith('VISITANTE'):
                g = 'VISITANTES'
                dept = 'VISITANTES'
            else:
                g = grupo or 'SEM GRUPO'

            h = dh.time()

            dados[g][dept]['grupo'] = g

            dados[g][dept]['qtd_' + classificar_refeicao(h, t)] += 1

        # ── monta estrutura para template / export ──────────────────────────
        ordem_grupos_db = [g[1] for g in get_grupos()] if True else _GRUPOS_PADRAO
        total_qtd_cafe = total_qtd_almoco = total_qtd_janta = 0
        total_custo_cafe = total_custo_almoco = total_custo_janta = 0.0

        # contagem geral para % (base = custo total geral)
        for gn in dados:
            for dn in dados[gn]:
                d = dados[gn][dn]
                total_qtd_cafe   += d['qtd_cafe']
                total_qtd_almoco += d['qtd_almoco']
                total_qtd_janta  += d['qtd_janta']

        total_custo_cafe   = total_qtd_cafe   * cu_cafe
        total_custo_almoco = total_qtd_almoco * cu_almoco
        total_custo_janta  = total_qtd_janta  * cu_janta
        total_custo_geral  = total_custo_cafe + total_custo_almoco + total_custo_janta
        total_senhas       = total_qtd_cafe + total_qtd_almoco + total_qtd_janta

        grupos_list = []
        grupos_presentes = sorted(dados.keys(), key=lambda x: ordem_grupos_db.index(x) if x in ordem_grupos_db else 99)
        for gn in grupos_presentes:
            depts = []
            sub_qtd_cafe = sub_qtd_almoco = sub_qtd_janta = 0
            for dn in sorted(dados[gn].keys()):
                d  = dados[gn][dn]
                qc = d['qtd_cafe'];   qa = d['qtd_almoco'];   qj = d['qtd_janta']
                cc = qc * cu_cafe;    ca = qa * cu_almoco;    cj = qj * cu_janta
                ct = cc + ca + cj
                pct = (ct / total_custo_geral * 100) if total_custo_geral else 0
                depts.append({'nome': dn, 'qtd_cafe': qc, 'custo_cafe': cc,
                              'qtd_almoco': qa, 'custo_almoco': ca,
                              'qtd_janta': qj, 'custo_janta': cj,
                              'qtd_total': qc+qa+qj, 'custo_total': ct,
                              'percentual': pct})
                sub_qtd_cafe   += qc; sub_qtd_almoco += qa; sub_qtd_janta += qj
            sc_cafe   = sub_qtd_cafe   * cu_cafe
            sc_almoco = sub_qtd_almoco * cu_almoco
            sc_janta  = sub_qtd_janta  * cu_janta
            sc_total  = sc_cafe + sc_almoco + sc_janta
            sc_pct    = (sc_total / total_custo_geral * 100) if total_custo_geral else 0
            grupos_list.append({
                'nome': gn, 'departamentos': depts,
                'sub_qtd_cafe': sub_qtd_cafe,   'sub_custo_cafe': sc_cafe,
                'sub_qtd_almoco': sub_qtd_almoco,'sub_custo_almoco': sc_almoco,
                'sub_qtd_janta': sub_qtd_janta,  'sub_custo_janta': sc_janta,
                'sub_qtd_total': sub_qtd_cafe+sub_qtd_almoco+sub_qtd_janta,
                'sub_custo_total': sc_total, 'sub_percentual': sc_pct
            })

        periodo = f"{data_inicial.strftime('%d/%m/%Y')} até {data_final.strftime('%d/%m/%Y')}"
        agora   = datetime.now().strftime('%d/%m/%Y %H:%M')

        custo_ref_data = data_inicial.strftime('%d/%m/%Y')
        ctx = dict(
            grupos=grupos_list, periodo=periodo, agora=agora,
            custo_cafe=cu_cafe, custo_almoco=cu_almoco, custo_janta=cu_janta,
            custo_ref_data=custo_ref_data,
            total_qtd_cafe=total_qtd_cafe, total_qtd_almoco=total_qtd_almoco,
            total_qtd_janta=total_qtd_janta, total_senhas=total_senhas,
            total_custo_cafe=total_custo_cafe, total_custo_almoco=total_custo_almoco,
            total_custo_janta=total_custo_janta, total_custo_geral=total_custo_geral,
            nome_instituicao=get_instituicao(),
        )

        # ── PDF ─────────────────────────────────────────────────────────────
        if tipo_relatorio == 'pdf':
            html_str = render_template('relatorio_snd.html', **ctx)
            pdf = gerar_pdf(html_str)
            fname = f"relatorio_snd_{data_inicial.strftime('%Y%m%d')}_{data_final.strftime('%Y%m%d')}.pdf"
            return send_file(BytesIO(pdf), download_name=fname, as_attachment=True)

        # ── EXCEL ────────────────────────────────────────────────────────────
        output = BytesIO()
        import xlsxwriter
        wb = xlsxwriter.Workbook(output)
        ws = wb.add_worksheet("SND")

        # formatos
        fmt_title  = wb.add_format({'bold':True,'font_size':13,'font_color':'#1e2d3a'})
        fmt_sub    = wb.add_format({'font_size':9,'font_color':'#777777'})
        fmt_info   = wb.add_format({'font_size':10,'bold':True})
        fmt_info_v = wb.add_format({'font_size':10})
        fmt_th     = wb.add_format({'bold':True,'bg_color':'#1e2d3a','font_color':'#ffffff',
                                    'align':'center','valign':'vcenter','border':1,'font_size':9})
        fmt_th_l   = wb.add_format({'bold':True,'bg_color':'#1e2d3a','font_color':'#ffffff',
                                    'align':'left','valign':'vcenter','border':1,'font_size':9})
        fmt_grupo  = wb.add_format({'bold':True,'bg_color':'#e8f0f5','font_color':'#1e2d3a',
                                    'font_size':10,'border':1})
        fmt_sub_t  = wb.add_format({'bold':True,'bg_color':'#dce8f0','font_color':'#1e2d3a',
                                    'font_size':10,'border':1,'num_format':'#,##0.00'})
        fmt_sub_ti = wb.add_format({'bold':True,'bg_color':'#dce8f0','font_color':'#1e2d3a',
                                    'font_size':10,'border':1})
        fmt_total  = wb.add_format({'bold':True,'bg_color':'#1e2d3a','font_color':'#ffffff',
                                    'font_size':11,'border':1,'num_format':'#,##0.00'})
        fmt_total_i= wb.add_format({'bold':True,'bg_color':'#1e2d3a','font_color':'#ffffff',
                                    'font_size':11,'border':1})
        fmt_dept   = wb.add_format({'font_size':10,'border':1})
        fmt_num    = wb.add_format({'font_size':10,'border':1,'align':'center'})
        fmt_val    = wb.add_format({'font_size':10,'border':1,'num_format':'R$ #,##0.00'})
        fmt_pct    = wb.add_format({'font_size':10,'border':1,'align':'center','num_format':'0.0"%"'})
        fmt_zero   = wb.add_format({'font_size':10,'border':1,'align':'center','font_color':'#bbbbbb'})

        # larguras
        ws.set_column('A:A', 38)
        ws.set_column('B:B', 9); ws.set_column('C:C', 13)
        ws.set_column('D:D', 10); ws.set_column('E:E', 13)
        ws.set_column('F:F', 9); ws.set_column('G:G', 13)
        ws.set_column('H:H', 10); ws.set_column('I:I', 15); ws.set_column('J:J', 9)

        # ── cabeçalho ──
        ws.write('A1', 'GTR – Relatório Financeiro SND', fmt_title)
        ws.write('A2', 'Serviço de Nutrição e Dietética – Custo de Refeições por Departamento', fmt_sub)
        ws.write('A4', 'Período:', fmt_info);     ws.write('B4', periodo, fmt_info_v)
        ws.write('A5', 'Gerado em:', fmt_info);   ws.write('B5', agora, fmt_info_v)
        ws.write('A6', 'Total de senhas:', fmt_info); ws.write('B6', total_senhas, fmt_info_v)
        ws.write('D4', 'Custo Café R$:', fmt_info);   ws.write('E4', cu_cafe,   wb.add_format({'num_format':'R$ #,##0.00','font_size':10}))
        ws.write('D5', 'Custo Almoço R$:', fmt_info); ws.write('E5', cu_almoco, wb.add_format({'num_format':'R$ #,##0.00','font_size':10}))
        ws.write('D6', 'Custo Jantar R$:', fmt_info);  ws.write('E6', cu_janta,  wb.add_format({'num_format':'R$ #,##0.00','font_size':10}))
        ws.write('D7', 'Custos vigentes em:', fmt_info); ws.write('E7', custo_ref_data, fmt_info_v)

        # ── cabeçalho da tabela ──
        r = 8
        cabecalhos = ['Centro de Custo','Café Qtd','Café R$','Almoço Qtd','Almoço R$',
                      'Jantar Qtd','Jantar R$','Total Qtd','Custo Total','%']
        fmts_h = [fmt_th_l]+[fmt_th]*9
        for c, (h, f) in enumerate(zip(cabecalhos, fmts_h)):
            ws.write(r, c, h, f)
        r += 1

        for grupo in grupos_list:
            # grupo header
            ws.merge_range(r, 0, r, 9, grupo['nome'], fmt_grupo)
            r += 1
            for d in grupo['departamentos']:
                ws.write(r, 0, d['nome'],       fmt_dept)
                ws.write(r, 1, d['qtd_cafe'],   fmt_zero if d['qtd_cafe']==0   else fmt_num)
                ws.write(r, 2, d['custo_cafe'],  fmt_zero if d['custo_cafe']==0  else fmt_val)
                ws.write(r, 3, d['qtd_almoco'], fmt_zero if d['qtd_almoco']==0 else fmt_num)
                ws.write(r, 4, d['custo_almoco'],fmt_zero if d['custo_almoco']==0 else fmt_val)
                ws.write(r, 5, d['qtd_janta'],  fmt_zero if d['qtd_janta']==0  else fmt_num)
                ws.write(r, 6, d['custo_janta'], fmt_zero if d['custo_janta']==0  else fmt_val)
                ws.write(r, 7, d['qtd_total'],  fmt_num)
                ws.write(r, 8, d['custo_total'], fmt_val)
                ws.write(r, 9, round(d['percentual'],1), fmt_pct)
                r += 1
            # subtotal
            ws.write(r, 0, f"Subtotal – {grupo['nome']}", fmt_sub_ti)
            ws.write(r, 1, grupo['sub_qtd_cafe'],    fmt_sub_ti)
            ws.write(r, 2, grupo['sub_custo_cafe'],  fmt_sub_t)
            ws.write(r, 3, grupo['sub_qtd_almoco'],  fmt_sub_ti)
            ws.write(r, 4, grupo['sub_custo_almoco'],fmt_sub_t)
            ws.write(r, 5, grupo['sub_qtd_janta'],   fmt_sub_ti)
            ws.write(r, 6, grupo['sub_custo_janta'], fmt_sub_t)
            ws.write(r, 7, grupo['sub_qtd_total'],   fmt_sub_ti)
            ws.write(r, 8, grupo['sub_custo_total'], fmt_sub_t)
            ws.write(r, 9, round(grupo['sub_percentual'],1), fmt_sub_ti)
            r += 1

        # total geral
        ws.write(r, 0, 'TOTAL GERAL',           fmt_total_i)
        ws.write(r, 1, total_qtd_cafe,           fmt_total_i)
        ws.write(r, 2, total_custo_cafe,         fmt_total)
        ws.write(r, 3, total_qtd_almoco,         fmt_total_i)
        ws.write(r, 4, total_custo_almoco,       fmt_total)
        ws.write(r, 5, total_qtd_janta,          fmt_total_i)
        ws.write(r, 6, total_custo_janta,        fmt_total)
        ws.write(r, 7, total_senhas,             fmt_total_i)
        ws.write(r, 8, total_custo_geral,        fmt_total)
        ws.write(r, 9, '100%',                   fmt_total_i)

        wb.close()
        output.seek(0)
        fname = f"relatorio_snd_{data_inicial.strftime('%Y%m%d')}_{data_final.strftime('%Y%m%d')}.xlsx"
        return send_file(output, download_name=fname, as_attachment=True)

    tmpl = 'menu_admin.html'
    return render_template(tmpl, modulo='relatorio_snd', usuario=usuario_logado,
                           departamentos=departamentos)


@app.route('/relatorio/cardapio', methods=['GET', 'POST'])
def relatorio_cardapio():
    if 'usuario_id' not in session:
        return redirect('/')
    usuario_logado = get_usuario_logado()
    perfil = session.get('usuario_perfil', 'desconhecido')

    # Listas para os filtros
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT nome FROM departamentos ORDER BY nome ASC")
    departamentos = [r[0] for r in cursor.fetchall()]
    cursor.execute("""
        SELECT DISTINCT tipo_refeicao FROM emissoes_senha
        WHERE tipo_refeicao IS NOT NULL ORDER BY tipo_refeicao
    """)
    tipos_refeicao = [r[0] for r in cursor.fetchall()]
    cursor.close()

    if request.method == 'POST':
        try:
            data_inicial = datetime.strptime(request.form.get('data_inicial'), "%Y-%m-%d")
            data_final   = datetime.strptime(request.form.get('data_final'),   "%Y-%m-%d")
        except ValueError:
            flash("Datas inválidas.", "error")
            return redirect(url_for('relatorio_cardapio'))
        if data_final < data_inicial:
            flash("Data final não pode ser anterior à data inicial.", "error")
            return redirect(url_for('relatorio_cardapio'))

        departamento  = request.form.get('departamento', 'TODOS')
        tipo_refeicao = request.form.get('tipo_refeicao', 'TODOS')
        tipo_pessoa   = request.form.get('tipo_pessoa', 'TODOS')   # TODOS | colaborador | visitante
        tipo_relatorio = request.form.get('tipo_relatorio', 'pdf')

        dt_inicio = datetime.combine(data_inicial, time(0, 0))
        dt_fim    = datetime.combine(data_final,   time(23, 59, 59))

        # Monta WHERE dinâmico
        where  = ["data_hora BETWEEN %s AND %s", "tipo_refeicao IS NOT NULL"]
        params = [dt_inicio, dt_fim]

        if departamento != 'TODOS':
            where.append("departamento = %s")
            params.append(departamento)

        if tipo_refeicao != 'TODOS':
            where.append("tipo_refeicao = %s")
            params.append(tipo_refeicao)

        if tipo_pessoa == 'colaborador':
            where.append("cargo != 'VISITANTE'")
        elif tipo_pessoa == 'visitante':
            where.append("cargo = 'VISITANTE'")

        sql = f"""
            SELECT numero_senha, cpf, nome, cargo, departamento,
                   tipo_refeicao, descricao_cardapio, data_hora
            FROM emissoes_senha
            WHERE {' AND '.join(where)}
            ORDER BY data_hora ASC
        """
        cursor = mysql.connection.cursor()
        cursor.execute(sql, params)
        colunas  = [d[0] for d in cursor.description]
        registros = [dict(zip(colunas, r)) for r in cursor.fetchall()]
        cursor.close()

        # Totais por tipo de refeição e por cardápio (descrição)
        from collections import Counter, defaultdict
        contagem_refeicao = Counter(r['tipo_refeicao'] for r in registros)
        total_geral = len(registros)
        total_colaboradores = sum(1 for r in registros if r['cargo'] != 'VISITANTE')
        total_visitantes    = sum(1 for r in registros if r['cargo'] == 'VISITANTE')

        # Agrupa por descrição do cardápio: { tipo_refeicao: [ {descricao, colab, visit, total} ] }
        _por_cardapio = defaultdict(lambda: defaultdict(lambda: {'colab': 0, 'visit': 0}))
        for r in registros:
            tr  = r['tipo_refeicao'] or 'Sem Refeição'
            desc = (r['descricao_cardapio'] or '').strip() or 'Sem descrição'
            if r['cargo'] == 'VISITANTE':
                _por_cardapio[tr][desc]['visit'] += 1
            else:
                _por_cardapio[tr][desc]['colab'] += 1

        # Converte para lista ordenada: { tipo_refeicao: [ {descricao, colab, visit, total} ] }
        contagem_cardapio = {}
        for tr in sorted(_por_cardapio.keys()):
            itens = []
            for desc in sorted(_por_cardapio[tr].keys()):
                c = _por_cardapio[tr][desc]['colab']
                v = _por_cardapio[tr][desc]['visit']
                itens.append({'descricao': desc, 'colab': c, 'visit': v, 'total': c + v})
            contagem_cardapio[tr] = itens

        periodo = f"{data_inicial.strftime('%d/%m/%Y')} até {data_final.strftime('%d/%m/%Y')}"
        agora   = datetime.now().strftime('%d/%m/%Y %H:%M')

        logger.info(f"{usuario_logado} emitiu relatório de cardápio ({tipo_relatorio}) — {total_geral} registros.")

        if tipo_relatorio == 'excel':
            df = pd.DataFrame(registros)
            if not df.empty:
                df['data_hora'] = df['data_hora'].apply(
                    lambda x: x.strftime('%d/%m/%Y %H:%M') if hasattr(x, 'strftime') else str(x)
                )
            output = BytesIO()
            with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                wb = writer.book
                ws = wb.add_worksheet("Cardápio")
                writer.sheets['Cardápio'] = ws
                bold    = wb.add_format({'bold': True})
                header  = wb.add_format({'bold': True, 'bg_color': '#D9E1F2', 'border': 1})
                wrap    = wb.add_format({'text_wrap': True, 'valign': 'top'})

                ws.write('A1', 'GTR — Relatório de Emissões com Cardápio', bold)
                ws.write('A3', 'Período:',           bold); ws.write('B3', periodo)
                ws.write('A4', 'Departamento:',      bold); ws.write('B4', 'Todos' if departamento == 'TODOS' else departamento)
                ws.write('A5', 'Tipo de Refeição:',  bold); ws.write('B5', 'Todos' if tipo_refeicao == 'TODOS' else tipo_refeicao)
                ws.write('A6', 'Tipo de Pessoa:',    bold); ws.write('B6', {'TODOS': 'Todos', 'colaborador': 'Colaborador', 'visitante': 'Visitante'}.get(tipo_pessoa, tipo_pessoa))
                ws.write('A7', 'Gerado em:',         bold); ws.write('B7', agora)

                ws.write('A9', 'Resumo por Refeição', bold)
                row_res = 10
                ws.write(row_res, 0, 'Refeição',    header)
                ws.write(row_res, 1, 'Colaborador', header)
                ws.write(row_res, 2, 'Visitante',   header)
                ws.write(row_res, 3, 'Total',        header)
                row_res += 1
                todos_tipos = sorted(contagem_refeicao.keys())
                for tr in todos_tipos:
                    colab = sum(1 for r in registros if r['tipo_refeicao'] == tr and r['cargo'] != 'VISITANTE')
                    visit = sum(1 for r in registros if r['tipo_refeicao'] == tr and r['cargo'] == 'VISITANTE')
                    ws.write(row_res, 0, tr);    ws.write(row_res, 1, colab)
                    ws.write(row_res, 2, visit); ws.write(row_res, 3, colab + visit)
                    row_res += 1
                ws.write(row_res, 0, 'TOTAL', bold)
                ws.write(row_res, 1, total_colaboradores, bold)
                ws.write(row_res, 2, total_visitantes, bold)
                ws.write(row_res, 3, total_geral, bold)

                start_detail = row_res + 2
                headers_det  = ['Senha', 'CPF', 'Nome', 'Cargo', 'Departamento', 'Refeição', 'Cardápio', 'Data/Hora']
                keys_det     = ['numero_senha', 'cpf', 'nome', 'cargo', 'departamento', 'tipo_refeicao', 'descricao_cardapio', 'data_hora']
                for col_idx, h in enumerate(headers_det):
                    ws.write(start_detail, col_idx, h, header)
                for row_idx, rec in enumerate(registros, start=start_detail + 1):
                    for col_idx, key in enumerate(keys_det):
                        val = rec.get(key, '') or ''
                        ws.write(row_idx, col_idx, str(val), wrap)

                ws.set_column(0, 0, 8)   # Senha
                ws.set_column(1, 1, 15)  # CPF
                ws.set_column(2, 2, 30)  # Nome
                ws.set_column(3, 3, 18)  # Cargo
                ws.set_column(4, 4, 22)  # Departamento
                ws.set_column(5, 5, 16)  # Refeição
                ws.set_column(6, 6, 40)  # Cardápio
                ws.set_column(7, 7, 18)  # Data/Hora

                # ── Aba 2: Total por Cardápio ──────────────────────────────
                ws2 = wb.add_worksheet("Total por Cardápio")
                writer.sheets['Total por Cardápio'] = ws2
                header2 = wb.add_format({'bold': True, 'bg_color': '#D9E1F2', 'border': 1})
                subtitulo = wb.add_format({'bold': True, 'bg_color': '#E8F0FE', 'border': 1})

                ws2.write('A1', 'GTR — Total por Cardápio', bold)
                ws2.write('A3', 'Período:', bold); ws2.write('B3', periodo)
                ws2.write('A4', 'Gerado em:', bold); ws2.write('B4', agora)

                row2 = 6
                for tr_key, itens in contagem_cardapio.items():
                    ws2.merge_range(row2, 0, row2, 3, tr_key, subtitulo)
                    row2 += 1
                    ws2.write(row2, 0, 'Cardápio',     header2)
                    ws2.write(row2, 1, 'Colaborador',  header2)
                    ws2.write(row2, 2, 'Visitante',    header2)
                    ws2.write(row2, 3, 'Total',        header2)
                    row2 += 1
                    for item in itens:
                        ws2.write(row2, 0, item['descricao'])
                        ws2.write(row2, 1, item['colab'])
                        ws2.write(row2, 2, item['visit'])
                        ws2.write(row2, 3, item['total'])
                        row2 += 1
                    # Subtotal da refeição
                    sub_colab = sum(i['colab'] for i in itens)
                    sub_visit = sum(i['visit'] for i in itens)
                    sub_fmt = wb.add_format({'bold': True, 'top': 1})
                    ws2.write(row2, 0, f'Subtotal {tr_key}', sub_fmt)
                    ws2.write(row2, 1, sub_colab, sub_fmt)
                    ws2.write(row2, 2, sub_visit, sub_fmt)
                    ws2.write(row2, 3, sub_colab + sub_visit, sub_fmt)
                    row2 += 2  # linha em branco entre grupos

                ws2.set_column(0, 0, 45)  # Cardápio
                ws2.set_column(1, 3, 14)  # Colaborador / Visitante / Total

            output.seek(0)
            return send_file(output, download_name='relatorio_cardapio.xlsx', as_attachment=True)

        else:  # PDF
            html = render_template(
                'relatorio_cardapio.html',
                registros=registros,
                periodo=periodo,
                agora=agora,
                departamento=departamento,
                tipo_refeicao=tipo_refeicao,
                tipo_pessoa=tipo_pessoa,
                contagem_refeicao=contagem_refeicao,
                contagem_cardapio=contagem_cardapio,
                total_geral=total_geral,
                total_colaboradores=total_colaboradores,
                total_visitantes=total_visitantes,
                nome_instituicao=get_instituicao(),
            )
            pdf = gerar_pdf(html)
            return send_file(BytesIO(pdf), download_name='relatorio_cardapio.pdf', as_attachment=True)

    tmpl = 'menu_admin.html'
    return render_template(tmpl, modulo='relatorio_cardapio', usuario=usuario_logado,
                           departamentos=departamentos, tipos_refeicao=tipos_refeicao)


# ─── HELPER: configurações do sistema ────────────────────────────────────────

def get_config(chave, default='padrao'):
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT valor FROM configuracoes_sistema WHERE chave = %s", (chave,))
        row = cur.fetchone()
        cur.close()
        return row[0] if row else default
    except Exception:
        return default

def set_config(chave, valor):
    antes = get_config(chave, None)
    _audit_registrar_mudanca_config(chave, antes, valor)
    cur = mysql.connection.cursor()
    cur.execute("""
        INSERT INTO configuracoes_sistema (chave, valor)
        VALUES (%s, %s)
        ON DUPLICATE KEY UPDATE valor = VALUES(valor), atualizado_em = NOW()
    """, (chave, valor))
    mysql.connection.commit()
    cur.close()


def get_instituicao():
    return get_config('nome_instituicao', 'Serviço de Nutrição e Dietética')


_TURNO_DEFAULTS = {
    'turno_cafe_ini':   '02:00',
    'turno_cafe_fim':   '10:59',
    'turno_almoco_ini': '11:00',
    'turno_almoco_fim': '17:59',
    'turno_janta_ini':  '18:00',
    'turno_janta_fim':  '23:59',
}

def get_turnos():
    """Retorna os horários de turno como objetos time(), lendo do BD."""
    result = {}
    for chave, default in _TURNO_DEFAULTS.items():
        val = get_config(chave, default)
        try:
            h, m = map(int, val.split(':'))
            result[chave] = time(h, m)
        except Exception:
            h, m = map(int, default.split(':'))
            result[chave] = time(h, m)
    return result




# ─── CUSTOS DE REFEIÇÃO ───────────────────────────────────────────────────────

def get_custos_refeicao():
    """Retorna dict {tipo: {descricao, custo_unitario, ativo}} para uso em qualquer rota."""
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT tipo_refeicao, descricao, custo_unitario, ativo FROM custos_refeicao ORDER BY id")
        rows = cur.fetchall()
        cur.close()
        return {r[0]: {"descricao": r[1], "custo_unitario": float(r[2]), "ativo": bool(r[3])} for r in rows}
    except Exception:
        return {}


@app.route("/admin/configuracoes/custos-refeicao", methods=["GET", "POST"])
def config_custos_refeicao():
    if "usuario_id" not in session:
        return redirect("/")
    if requer_admin():
        flash("Acesso restrito a administradores.", "error")
        return redirect("/usuario")

    init_custos_historico_table()

    if request.method == "POST":
        from decimal import Decimal, InvalidOperation
        tipos  = ["cafe", "almoco", "janta"]
        erros  = []
        usuario_logado = get_usuario_logado()

        for tipo in tipos:
            custo_raw = request.form.get(f"custo_{tipo}", "0").replace(",", ".")
            descricao = request.form.get(f"desc_{tipo}", "").strip() or tipo.capitalize()
            ativo     = 1 if request.form.get(f"ativo_{tipo}") else 0

            try:
                custo = Decimal(custo_raw)
                if custo < 0:
                    raise ValueError("negativo")
            except (InvalidOperation, ValueError):
                erros.append(f"Custo inválido para '{tipo}': '{custo_raw}'")
                continue

            try:
                cur = mysql.connection.cursor()

                cur.execute("SELECT custo_unitario FROM custos_refeicao WHERE tipo_refeicao = %s", (tipo,))
                old_row = cur.fetchone()
                custo_anterior = float(old_row[0]) if old_row else None

                cur.execute("""
                    UPDATE custos_refeicao
                       SET custo_unitario = %s, descricao = %s, ativo = %s
                     WHERE tipo_refeicao  = %s
                """, (str(custo), descricao, ativo, tipo))

                if custo_anterior is None or abs(float(custo) - custo_anterior) > 0.001:
                    cur.execute("""
                        INSERT INTO custos_historico
                            (tipo_refeicao, descricao, custo_unitario, vigente_desde, alterado_por)
                        VALUES (%s, %s, %s, NOW(), %s)
                    """, (tipo, descricao, str(custo), usuario_logado))

                mysql.connection.commit()
                cur.close()
            except Exception as e:
                erros.append(f"Erro ao salvar '{tipo}': {e}")

        if erros:
            for msg in erros:
                flash(msg, "error")
        else:
            logger.info(f"{get_usuario_logado()} atualizou custos de refeicao")
            flash("Custos de refeição atualizados com sucesso!", "success")

        return redirect(url_for("config_custos_refeicao"))

    custos = get_custos_refeicao()
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT tipo_refeicao, descricao, custo_unitario, vigente_desde, alterado_por
        FROM custos_historico
        ORDER BY vigente_desde DESC
        LIMIT 60
    """)
    historico_custos = cur.fetchall()
    cur.close()

    return render_template(
        "menu_admin.html",
        module="config_custos_refeicao",
        usuario=get_usuario_logado(),
        dashboard_data=get_dashboard_data(),
        custos=custos,
        historico_custos=historico_custos,
    )

# ─── CONFIGURAÇÕES: EMISSÃO DE SENHA ─────────────────────────────────────────

@app.route('/admin/configuracoes/emissao-senha', methods=['GET', 'POST'])
def config_emissao_senha():
    if 'usuario_id' not in session:
        return redirect('/')
    if requer_admin():
        flash("Acesso restrito a administradores.", "error")
        return redirect('/usuario')

    if request.method == 'POST':
        tipo = request.form.get('tipo_emissao', 'padrao')
        if tipo in ('padrao', 'cardapio'):
            set_config('tipo_emissao_senha', tipo)
            label = 'Padrão' if tipo == 'padrao' else 'Com Cardápio'
            flash(f"Tipo de emissão atualizado para: {label}.", "success")
            logger.info(f"{get_usuario_logado()} alterou tipo_emissao_senha → {tipo}")
        return redirect(url_for('config_emissao_senha'))

    tipo_atual = get_config('tipo_emissao_senha', 'padrao')
    return render_template('menu_admin.html',
                           module='config_emissao_senha',
                           usuario=get_usuario_logado(),
                           dashboard_data=get_dashboard_data(),
                           tipo_atual=tipo_atual)


# ─── EMISSÃO COM CARDÁPIO ─────────────────────────────────────────────────────

@app.route('/senha/colaborador/cardapio', methods=['GET', 'POST'])
def senha_colaborador_cardapio():
    modo = request.args.get('modo', '')
    extra = {'modo': 'tablet'} if modo == 'tablet' else {}
    usuario_logado = get_usuario_logado()

    cur = mysql.connection.cursor()
    cardapios_hoje = cardapios_do_horario(cur)
    cur.close()

    if request.method == 'POST':
        cpf         = request.form.get('cpf', '').strip()
        cardapio_id = request.form.get('cardapio_id', '').strip()

        if not validar_cpf(cpf):
            flash("CPF inválido.", "error")
            return redirect(url_for('senha_colaborador_cardapio', **extra))

        if not cardapio_id:
            flash("Selecione um cardápio.", "error")
            return redirect(url_for('senha_colaborador_cardapio', **extra))

        cur = mysql.connection.cursor()

        init_escalas()
        cur.execute("SELECT nome, cpf, cargo, departamento, tipo, escala_id FROM colaboradores WHERE cpf = %s", (cpf,))
        colaborador = cur.fetchone()
        if not colaborador:
            flash("CPF não encontrado na base de colaboradores.", "error")
            cur.close()
            return redirect(url_for('senha_colaborador_cardapio', **extra))

        nome, cpf_db, cargo, departamento, limite_diario, escala_id = colaborador
        data_hoje = date.today()

        cur.execute(
            "SELECT id, tipo_refeicao, descricao FROM cardapios WHERE id=%s AND ativo=1 AND data_cardapio=CURDATE()",
            (cardapio_id,)
        )
        cardapio = cur.fetchone()
        if not cardapio:
            flash("Cardápio inválido ou indisponível.", "error")
            cur.close()
            return redirect(url_for('senha_colaborador_cardapio', **extra))
        if refeicao_do_cardapio(cardapio[1]) != refeicao_por_horario():
            flash(msg_cardapio_fora_do_horario(), "error")
            cur.close()
            return redirect(url_for('senha_colaborador_cardapio', **extra))

        c_id, c_tipo, c_descricao = cardapio

        with trava_emissao() as travou:
            if not travou:
                flash("Sistema ocupado. Tente de novo em alguns segundos.", "error")
                cur.close()
                return redirect(url_for('senha_colaborador_cardapio', **extra))
            recusa = checar_direito_refeicao(cur, cpf_db, escala_id, limite_diario, refeicao_por_horario())
            if recusa:
                flash(recusa, "error")
                cur.close()
                return redirect(url_for('senha_colaborador_cardapio', **extra))

            cur.execute("SELECT COALESCE(MAX(numero_senha),0) FROM emissoes_senha WHERE DATE(data_hora)=%s", (data_hoje,))
            novo_numero = cur.fetchone()[0] + 1

            try:
                cur.execute("""
                    INSERT INTO emissoes_senha
                        (nome, cpf, cargo, departamento, data_hora, numero_senha,
                         cardapio_id, tipo_refeicao, descricao_cardapio)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """, (nome, cpf_db, cargo, departamento, datetime.now(), novo_numero,
                      c_id, c_tipo, c_descricao))
                mysql.connection.commit()
                logger.info(f"{usuario_logado}: Senha Nº {novo_numero:03d} para CPF {cpf_db} — cardápio: {c_tipo}.")
                flash(f"Senha Nº {novo_numero:03d} emitida! Refeição: {c_tipo}.", "success")
            except Exception as e:
                mysql.connection.rollback()
                logger.error(f"Erro ao emitir senha com cardápio: {e}")
                flash("Erro ao registrar a senha.", "error")
        cur.close()

        return redirect(url_for('senha_colaborador_cardapio', **extra))

    if modo == 'tablet':
        return render_template('emissao_senha_tablet.html',
                               tipo_senha='colaborador_cardapio',
                               cardapios_hoje=cardapios_hoje)
    return render_template('emissao_senha.html',
                           tipo_senha='colaborador_cardapio',
                           cardapios_hoje=cardapios_hoje)


# ─── CONFIGURAÇÕES: HORÁRIOS DE TURNO ────────────────────────────────────────

@app.route('/admin/configuracoes/turnos', methods=['GET', 'POST'])
def config_turnos():
    if 'usuario_id' not in session:
        return redirect('/')
    if requer_admin():
        flash("Acesso restrito a administradores.", "error")
        return redirect('/usuario')
    usuario_logado = get_usuario_logado()

    if request.method == 'POST':
        campos = [
            'turno_cafe_ini', 'turno_cafe_fim',
            'turno_almoco_ini', 'turno_almoco_fim',
            'turno_janta_ini', 'turno_janta_fim',
        ]
        erros = []
        valores = {}
        for c in campos:
            val = request.form.get(c, '').strip()
            try:
                h, m = map(int, val.split(':'))
                if not (0 <= h <= 23 and 0 <= m <= 59):
                    raise ValueError
                valores[c] = f"{h:02d}:{m:02d}"
            except Exception:
                erros.append(c)

        if erros:
            flash("Horários inválidos. Use o formato HH:MM.", "error")
        else:
            for chave, valor in valores.items():
                set_config(chave, valor)
            logger.info(f"{usuario_logado} atualizou os horários de turno.")
            flash("Horários de turno salvos com sucesso!", "success")
        return redirect(url_for('config_turnos'))

    turnos_atuais = {k: get_config(k, v) for k, v in _TURNO_DEFAULTS.items()}
    return render_template('menu_admin.html', module='config_turnos',
                           turnos_atuais=turnos_atuais, usuario=usuario_logado)


# ─── PARÂMETROS: LIMITE DE SENHAS DE VISITANTE ───────────────────────────────

VISITANTE_LIMITE_MAX = 10
_visit_limite_ok = False


def init_visitante_limites():
    """Coluna de limite por localização. Na 1ª vez, mantém a regra que estava no código
    (ACOMPANHANTE = 3; demais = 1)."""
    global _visit_limite_ok
    if _visit_limite_ok:
        return
    cur = mysql.connection.cursor()
    cur.execute("ALTER TABLE localizacoes ADD COLUMN IF NOT EXISTS limite_diario TINYINT UNSIGNED DEFAULT NULL "
                "COMMENT 'Senhas por dia do visitante desta localização; NULL = limite padrão'")
    if get_config('visitante_limite_padrao', None) is None:
        cur.execute("UPDATE localizacoes SET limite_diario = 3 WHERE UPPER(TRIM(nome)) = 'ACOMPANHANTE' "
                    "AND limite_diario IS NULL")
        cur.execute("""INSERT IGNORE INTO configuracoes_sistema (chave, valor, descricao)
                       VALUES ('visitante_limite_padrao', '1', 'Senhas por dia do visitante (padrão)')""")
    mysql.connection.commit()
    cur.close()
    _visit_limite_ok = True


def limite_visitante(localizacao):
    """Quantas senhas por dia o visitante desta localização pode emitir."""
    init_visitante_limites()
    try:
        padrao = int(get_config('visitante_limite_padrao', '1'))
    except (TypeError, ValueError):
        padrao = 1
    cur = mysql.connection.cursor()
    cur.execute("SELECT limite_diario FROM localizacoes WHERE UPPER(TRIM(nome)) = %s AND limite_diario IS NOT NULL",
                ((localizacao or '').strip().upper(),))
    r = cur.fetchone()
    cur.close()
    return int(r[0]) if r else max(padrao, 1)


@app.route('/admin/parametros/limite_visitantes', methods=['GET', 'POST'])
def config_limite_visitantes():
    if 'usuario_id' not in session:
        return redirect('/')
    usuario_logado = get_usuario_logado()
    init_visitante_limites()
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, nome, limite_diario FROM localizacoes ORDER BY nome")
    locs = [{'id': r[0], 'nome': r[1], 'limite': r[2]} for r in cur.fetchall()]

    if request.method == 'POST':
        def ler(campo, vazio_ok):
            v = (request.form.get(campo) or '').strip()
            if v == '' and vazio_ok:
                return None
            n = int(v)                          # ValueError tratado abaixo
            if not 1 <= n <= VISITANTE_LIMITE_MAX:
                raise ValueError
            return n
        try:
            padrao = ler('limite_padrao', False)
            novos = {l['id']: ler(f"loc_{l['id']}", True) for l in locs}
        except ValueError:
            cur.close()
            flash(f"Informe limites entre 1 e {VISITANTE_LIMITE_MAX}. Deixe a localização em branco para usar o padrão.",
                  "error")
            return redirect(url_for('config_limite_visitantes'))
        set_config('visitante_limite_padrao', str(padrao))
        mudancas = {}
        for l in locs:
            if novos[l['id']] != l['limite']:
                cur.execute("UPDATE localizacoes SET limite_diario = %s WHERE id = %s", (novos[l['id']], l['id']))
                mudancas[f"limite: {l['nome']}"] = [l['limite'] if l['limite'] is not None else 'padrão',
                                                     novos[l['id']] if novos[l['id']] is not None else 'padrão']
        mysql.connection.commit()
        cur.close()
        if mudancas:   # junta com a mudança do padrão, já anotada por set_config
            g.setdefault('audit', {}).setdefault('detalhes', {}).setdefault('mudancas', {}).update(mudancas)
        logger.info(f"{usuario_logado} atualizou o limite de senhas de visitante (padrão {padrao}).")
        flash("Limites de senhas de visitante salvos.", "success")
        return redirect(url_for('config_limite_visitantes'))

    cur.close()
    return render_template('menu_admin.html', module='config_limite_visitantes', usuario=usuario_logado,
                           limite_padrao=get_config('visitante_limite_padrao', '1'), locs=locs,
                           limite_max=VISITANTE_LIMITE_MAX)


# ─── CONFIGURAÇÕES: BACKUP (somente Administrador) ───────────────────────────
# Backup feito pelo próprio GTR (backup_gtr.py): funciona igual em instalação nativa ou Docker.
# Execução em segundo plano (não esbarra no timeout do gunicorn); o automático é disparado pelo próprio
# sistema no horário configurado (não depende de cron) e uma trava no banco garante um backup por vez.
import threading as _threading
import shutil as _shutil
import backup_gtr

BACKUP_DIR = os.path.abspath(os.getenv('GTR_BACKUP_DIR') or os.path.join(os.path.dirname(__file__), 'backups'))
BACKUP_PASTAS = {'cardapio': CARDAPIO_UPLOAD_FOLDER}          # arquivos enviados ao sistema que entram no backup
_BACKUP_PADROES = {'backup_auto_ativo': '1', 'backup_auto_hora': '02:00', 'backup_retencao': '14'}
_BACKUP_TIPOS = {'manual': 'Manual', 'automatico': 'Automático', 'seguranca': 'Segurança (antes de restaurar)',
                 'restauracao': 'Restauração'}
_backup_ok = False
_backup_ultima_checagem = 0.0


def _backup_cfg_banco():
    return {'host': app.config['MYSQL_HOST'], 'user': app.config['MYSQL_USER'], 'password': app.config['MYSQL_PASSWORD'],
            'db': app.config['MYSQL_DB'], 'port': int(os.getenv('MYSQL_PORT') or 3306)}


def _backup_sql(sql, params=(), um=False, todos=False):
    """Consulta com conexão própria (usável fora da requisição, nas threads)."""
    conn = backup_gtr._conectar(_backup_cfg_banco())
    try:
        cur = conn.cursor()
        cur.execute(sql, params)
        r = cur.fetchone() if um else (cur.fetchall() if todos else cur.lastrowid)
        conn.commit()
        return r
    finally:
        conn.close()


def init_backups():
    global _backup_ok
    if _backup_ok:
        return
    os.makedirs(BACKUP_DIR, exist_ok=True)
    _backup_sql("""
        CREATE TABLE IF NOT EXISTS gtr_backups (
            id           INT AUTO_INCREMENT PRIMARY KEY,
            tipo         VARCHAR(20) NOT NULL COMMENT 'manual | automatico | seguranca | restauracao',
            status       VARCHAR(20) NOT NULL DEFAULT 'executando' COMMENT 'executando | ok | erro',
            arquivo      VARCHAR(200) DEFAULT NULL,
            tamanho      BIGINT DEFAULT NULL,
            tabelas      INT DEFAULT NULL,
            linhas       BIGINT DEFAULT NULL,
            arquivos     INT DEFAULT NULL,
            etapa        VARCHAR(200) DEFAULT NULL,
            mensagem     TEXT DEFAULT NULL,
            origem_id    INT DEFAULT NULL COMMENT 'restauração: backup usado',
            por          VARCHAR(120) DEFAULT NULL,
            iniciado_em  DATETIME NOT NULL,
            concluido_em DATETIME DEFAULT NULL,
            excluido     TINYINT(1) NOT NULL DEFAULT 0,
            KEY idx_gb_tipo (tipo, iniciado_em)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci""")
    _backup_sql("ALTER TABLE gtr_backups ADD COLUMN IF NOT EXISTS pid INT DEFAULT NULL COMMENT 'Processo executor'")
    _backup_ok = True


def _backup_conf():
    return {k: get_config(k, v) for k, v in _BACKUP_PADROES.items()}


def _processo_vivo(pid):
    """Processo existe e não é "zumbi" (terminou mas ainda não foi recolhido)."""
    if not pid:
        return False
    try:
        os.kill(int(pid), 0)
    except (OSError, ValueError):
        return False
    try:
        with open(f'/proc/{int(pid)}/stat') as fh:
            return fh.read().rsplit(')', 1)[1].split()[0] not in ('Z', 'X')
    except OSError:
        return True      # sem /proc (outro sistema): vale o os.kill


def _backup_conferir_processos():
    """Marca como interrompido o que ficou 'executando' sem processo vivo (servidor/container reiniciado)."""
    for bid, pid, tipo, ini in _backup_sql("SELECT id, pid, tipo, iniciado_em FROM gtr_backups WHERE status='executando'", todos=True):
        if (pid and not _processo_vivo(pid)) or (not pid and (datetime.now() - ini).total_seconds() > 120):
            msg = ('Interrompida: o processo parou no meio (servidor reiniciado?). Confira os dados e, se necessário, '
                   'restaure o backup de segurança mais recente.' if tipo == 'restauracao'
                   else 'Interrompido: o processo parou no meio (servidor reiniciado?). Faça um novo backup.')
            _backup_sql("UPDATE gtr_backups SET status='erro', mensagem=%s, concluido_em=NOW() WHERE id=%s", (msg, bid))


def _manutencao_info():
    """Restauração em andamento (arquivo-sinal do executor). Remove o sinal se o processo já não existe."""
    arq = os.path.join(BACKUP_DIR, backup_gtr.ARQ_MANUTENCAO)
    if not os.path.exists(arq):
        return None
    try:
        with open(arq) as fh:
            info = _json.load(fh)
    except Exception:
        info = {}
    if not _processo_vivo(info.get('pid')):
        try:
            os.remove(arq)
        except OSError:
            pass
        logger.error(f"Restauração interrompida sem terminar (sinal de manutenção órfão): {info}")
        return None
    return info


def _backup_iniciar(tipo, por, restaurar_id=None):
    """Registra o pedido e inicia o executor em processo separado (python backup_gtr.py ...).
    Retorna (True, id) ou (False, mensagem)."""
    import subprocess, sys
    init_backups()
    _backup_conferir_processos()
    if _backup_sql("SELECT COUNT(*) FROM gtr_backups WHERE status='executando'", um=True)[0]:
        return False, "Já existe um backup ou restauração em andamento. Aguarde terminar."
    bid = _backup_sql("INSERT INTO gtr_backups (tipo, por, iniciado_em, etapa, origem_id) VALUES (%s,%s,NOW(),'Iniciando',%s)",
                      ('restauracao' if restaurar_id else tipo, por, restaurar_id))
    c = _backup_cfg_banco()
    env = dict(os.environ, GTR_DB_HOST=c['host'], GTR_DB_USER=c['user'], GTR_DB_PASSWORD=c['password'],
               GTR_DB_NAME=c['db'], GTR_DB_PORT=str(c['port']), GTR_BACKUP_DIR=BACKUP_DIR,
               GTR_BACKUP_PASTAS=_json.dumps(BACKUP_PASTAS))
    try:
        proc = subprocess.Popen([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backup_gtr.py'),
                                 'restaurar' if restaurar_id else 'backup', str(bid)],
                                cwd=os.path.dirname(os.path.abspath(__file__)), env=env, start_new_session=True,
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
        # recolhe o processo quando terminar (não deixa "zumbi"); se este worker reiniciar, o sistema o adota
        _threading.Thread(target=proc.wait, name=f"gtr-backup-wait-{bid}", daemon=True).start()
    except Exception as e:
        _backup_sql("UPDATE gtr_backups SET status='erro', mensagem=%s, concluido_em=NOW() WHERE id=%s",
                    (f"Não foi possível iniciar o processo: {e}"[:2000], bid))
        return False, f"Não foi possível iniciar: {e}"
    return True, bid


_ROTAS_DURANTE_RESTAURACAO = {'config_backup', 'config_backup_status', 'static', 'logout'}


@app.before_request
def _modo_manutencao():
    """Durante a restauração, o sistema fica indisponível (exceto a tela de backup do Administrador)."""
    if request.endpoint in _ROTAS_DURANTE_RESTAURACAO:
        return None
    info = _manutencao_info()
    if not info:
        return None
    if request.endpoint in ROTAS_JSON or 'application/json' in (request.headers.get('Accept') or ''):
        return {'ok': False, 'erro': 'Sistema em manutenção (restauração de backup). Tente em alguns minutos.'}, 503
    return ("""<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="20"><title>GTR em manutenção</title></head>
<body style="font-family:Arial,sans-serif;background:#eceef2;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;">
<div style="background:#fff;border-radius:22px;padding:36px 40px;max-width:460px;text-align:center;box-shadow:0 10px 28px rgba(16,24,40,.08);">
<div style="font-size:42px;">🛠️</div><h1 style="font-size:22px;color:#0f1115;">Sistema em manutenção</h1>
<p style="color:#5b6170;line-height:1.6;">O administrador está restaurando um backup do GTR. Em alguns minutos o sistema volta a funcionar.
Esta página se atualiza sozinha.</p></div></body></html>""", 503)


@app.before_request
def _backup_agendado():
    """Backup automático: no máximo uma checagem por minuto por processo; dispara se passou do horário
    configurado e ainda não há backup automático (concluído ou em andamento) hoje."""
    global _backup_ultima_checagem
    agora_ts = time_mod.time()
    if agora_ts - _backup_ultima_checagem < 60:
        return None
    _backup_ultima_checagem = agora_ts
    try:
        init_backups()
        conf = _backup_conf()
        if conf['backup_auto_ativo'] != '1':
            return None
        h, m = map(int, conf['backup_auto_hora'].split(':'))
        agora = datetime.now()
        if agora.time() < time(h, m):
            return None
        feito = _backup_sql("""SELECT COUNT(*) FROM gtr_backups WHERE tipo='automatico' AND DATE(iniciado_em)=CURDATE()
                               AND status IN ('ok','executando')""", um=True)[0]
        if not feito and not _manutencao_info():
            _backup_iniciar('automatico', 'Sistema (automático)')
    except Exception as e:
        logger.error(f"Checagem do backup automático falhou: {e}")
    return None


def _backup_lista():
    rows = _backup_sql("""SELECT id, tipo, status, arquivo, tamanho, tabelas, linhas, arquivos, etapa, mensagem, por,
                                 iniciado_em, concluido_em, excluido, origem_id
                          FROM gtr_backups ORDER BY iniciado_em DESC, id DESC LIMIT 60""", todos=True)
    out = []
    for r in rows:
        existe = bool(r[3]) and r[1] != 'restauracao' and not r[13] and os.path.exists(os.path.join(BACKUP_DIR, r[3]))
        out.append({'id': r[0], 'tipo': r[1], 'tipo_txt': _BACKUP_TIPOS.get(r[1], r[1]), 'status': r[2], 'arquivo': r[3],
                    'tamanho': r[4], 'tabelas': r[5], 'linhas': r[6], 'arquivos': r[7], 'etapa': r[8] or '',
                    'mensagem': r[9] or '', 'por': r[10] or '', 'iniciado_em': r[11], 'concluido_em': r[12],
                    'excluido': bool(r[13]), 'existe': existe,
                    'duracao': int((r[12] - r[11]).total_seconds()) if r[12] and r[11] else None})
    return out


def _tamanho_txt(n):
    if n is None:
        return '—'
    for u in ('B', 'KB', 'MB', 'GB'):
        if n < 1024 or u == 'GB':
            return (f"{n:.0f} {u}" if u == 'B' else f"{n:.1f} {u}").replace('.', ',')
        n /= 1024

app.jinja_env.filters['tamanho'] = _tamanho_txt


@app.route('/admin/configuracoes/backup', methods=['GET', 'POST'])
def config_backup():
    if 'usuario_id' not in session:
        return redirect('/')
    init_backups()
    if request.method == 'POST':
        acao = request.form.get('acao')
        if acao == 'config':
            ativo = '1' if request.form.get('backup_auto_ativo') == '1' else '0'
            hora = (request.form.get('backup_auto_hora') or '').strip()
            try:
                hh, mm = map(int, hora.split(':'))
                assert 0 <= hh <= 23 and 0 <= mm <= 59
                ret = int(request.form.get('backup_retencao') or 0)
                assert 1 <= ret <= 365
            except (ValueError, AssertionError):
                flash("Configuração inválida: informe o horário (HH:MM) e a retenção entre 1 e 365.", "error")
                return redirect(url_for('config_backup'))
            set_config('backup_auto_ativo', ativo)
            set_config('backup_auto_hora', f"{hh:02d}:{mm:02d}")
            set_config('backup_retencao', str(ret))
            flash("Configuração do backup salva.", "success")
            return redirect(url_for('config_backup'))
        if acao == 'agora':
            ok, r = _backup_iniciar('manual', get_usuario_logado())
            flash("Backup iniciado. Acompanhe o andamento abaixo." if ok else r, "success" if ok else "error")
            return redirect(url_for('config_backup'))
        flash("Ação inválida.", "error")
        return redirect(url_for('config_backup'))

    _backup_conferir_processos()
    lista = _backup_lista()
    validos = [b for b in lista if b['status'] == 'ok' and b['existe']]
    ult_ok = next((b for b in lista if b['status'] == 'ok' and b['tipo'] != 'restauracao'), None)
    ult_auto = next((b for b in lista if b['tipo'] == 'automatico'), None)
    disco = _shutil.disk_usage(BACKUP_DIR)
    em_docker = os.path.exists('/.dockerenv')
    alertas = []
    if em_docker and not os.getenv('GTR_BACKUP_DIR') and not os.path.ismount(BACKUP_DIR):
        alertas.append("O GTR está rodando em Docker e a pasta de backups não parece ser um volume: os backups seriam perdidos "
                       "ao recriar o container. Mapeie um volume para " + BACKUP_DIR + " (ex.: ./backups:/app/backups).")
    if ult_auto and ult_auto['status'] == 'erro':
        alertas.append(f"O último backup automático ({ult_auto['iniciado_em']:%d/%m/%Y %H:%M}) falhou: {ult_auto['mensagem']}")
    if not ult_ok:
        alertas.append("Ainda não há nenhum backup concluído. Faça o primeiro agora.")
    elif (datetime.now() - ult_ok['iniciado_em']).total_seconds() > 2 * 86400:
        alertas.append(f"O último backup concluído tem mais de 2 dias ({ult_ok['iniciado_em']:%d/%m/%Y %H:%M}).")
    ult_rest = next((b for b in lista if b['tipo'] == 'restauracao'), None)
    if ult_rest and ult_rest['status'] == 'erro' and 'MANUALMENTE' in ult_rest['mensagem']:
        alertas.insert(0, "ATENÇÃO: " + ult_rest['mensagem'])
    elif ult_rest and ult_rest['status'] == 'erro' and ult_rest['mensagem'].startswith('Interrompida'):
        alertas.insert(0, f"A restauração de {ult_rest['iniciado_em']:%d/%m/%Y %H:%M} foi interrompida. " + ult_rest['mensagem'])
    if disco.free < 1024 ** 3:
        alertas.append(f"Pouco espaço livre no disco dos backups: {_tamanho_txt(disco.free)}.")
    return render_template('menu_admin.html', module='config_backup', usuario=get_usuario_logado(),
                           backups=lista, validos=validos, ult_ok=ult_ok, conf=_backup_conf(), alertas=alertas,
                           backup_dir=BACKUP_DIR, disco_livre=disco.free, disco_total=disco.total,
                           em_andamento=any(b['status'] == 'executando' for b in lista),
                           infra='Docker' if em_docker else 'Instalação nativa')


@app.route('/admin/configuracoes/backup/status')
def config_backup_status():
    init_backups()
    _backup_conferir_processos()
    lista = _backup_lista()[:10]
    return {'ok': True, 'em_andamento': any(b['status'] == 'executando' for b in lista),
            'itens': [{'id': b['id'], 'status': b['status'], 'etapa': b['etapa']} for b in lista]}


def _backup_por_id(bid):
    r = _backup_sql("SELECT arquivo, tipo, excluido FROM gtr_backups WHERE id=%s AND status='ok'", (bid,), um=True)
    if not r or not r[0] or r[1] == 'restauracao' or r[2]:
        return None
    caminho = os.path.join(BACKUP_DIR, r[0])
    return caminho if os.path.isfile(caminho) else None


@app.route('/admin/configuracoes/backup/<int:bid>/baixar')
def config_backup_baixar(bid):
    init_backups()
    caminho = _backup_por_id(bid)
    if not caminho:
        flash("Arquivo de backup não encontrado.", "error")
        return redirect(url_for('config_backup'))
    auditar(forcar=True, alvo=os.path.basename(caminho))
    logger.info(f"{get_usuario_logado()} baixou o backup {os.path.basename(caminho)}.")
    return send_file(caminho, as_attachment=True, download_name=os.path.basename(caminho), mimetype='application/zip')


@app.route('/admin/configuracoes/backup/<int:bid>/excluir', methods=['POST'])
def config_backup_excluir(bid):
    init_backups()
    caminho = _backup_por_id(bid)
    if caminho:
        os.remove(caminho)
    _backup_sql("UPDATE gtr_backups SET excluido=1, etapa='Excluído pelo administrador' WHERE id=%s", (bid,))
    auditar(alvo=os.path.basename(caminho) if caminho else f"backup {bid}")
    flash("Backup excluído.", "success")
    return redirect(url_for('config_backup'))


@app.route('/admin/configuracoes/backup/restaurar', methods=['POST'])
def config_backup_restaurar():
    """Restaura um backup da lista ou enviado pelo administrador. Exige digitar RESTAURAR.
    Antes de restaurar, o sistema faz automaticamente um backup de segurança do estado atual."""
    init_backups()
    if (request.form.get('confirmacao') or '').strip().upper() != 'RESTAURAR':
        flash("Para restaurar, digite RESTAURAR no campo de confirmação.", "error")
        return redirect(url_for('config_backup') + '#restaurar')
    usuario = get_usuario_logado()
    bid = request.form.get('backup_id', type=int)
    arq = request.files.get('arquivo')
    if arq and arq.filename:
        nome = f"gtr_enviado_{datetime.now():%Y%m%d_%H%M%S}.zip"
        destino = os.path.join(BACKUP_DIR, nome)
        arq.save(destino)
        ok, m, msg = backup_gtr.verificar_backup(destino)
        if not ok:
            os.remove(destino)
            flash(f"Arquivo recusado: {msg}", "error")
            return redirect(url_for('config_backup') + '#restaurar')
        bid = _backup_sql("""INSERT INTO gtr_backups (tipo, status, arquivo, tamanho, tabelas, linhas, arquivos, etapa, mensagem,
                             por, iniciado_em, concluido_em) VALUES ('manual','ok',%s,%s,%s,%s,%s,'Enviado pelo administrador',%s,%s,NOW(),NOW())""",
                          (nome, os.path.getsize(destino), len(m['tabelas']), m['linhas'], sum(m.get('arquivos', {}).values()),
                           f"Arquivo enviado (gerado em {m.get('gerado_em', '?')}, banco {m.get('banco', '?')})", usuario))
    if not bid or not _backup_por_id(bid):
        flash("Escolha um backup da lista ou envie um arquivo de backup do GTR.", "error")
        return redirect(url_for('config_backup') + '#restaurar')
    ok, m, msg = backup_gtr.verificar_backup(_backup_por_id(bid))
    if not ok:
        flash(f"Backup recusado: {msg}", "error")
        return redirect(url_for('config_backup') + '#restaurar')
    ok, r = _backup_iniciar('restauracao', usuario, restaurar_id=bid)
    auditar(alvo=os.path.basename(_backup_por_id(bid)), resultado='ok' if ok else 'erro',
            detalhes={'gerado_em': m.get('gerado_em'), 'linhas': m.get('linhas')})
    flash("Restauração iniciada: primeiro o sistema faz um backup de segurança do estado atual e depois restaura. "
          "Acompanhe abaixo e não desligue o servidor." if ok else r, "success" if ok else "error")
    return redirect(url_for('config_backup'))


# ─── CONFIGURAÇÕES: INTEGRAÇÃO SALUTEM (somente Administrador) ──────────────
# URL/certificado/empresa ficam em configuracoes_sistema; usuário e senha do usuário de serviço ficam
# em instance/salutem.json (permissão 600): fora do banco e fora dos backups, como a secret_key.
import salutem_gtr

SALUTEM_CRED = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'salutem.json')
# padrões de instalação nova (vêm do .env); depois de salvos na tela, valem os do banco
_SALUTEM_PADROES = {'salutem_url': os.getenv('SALUTEM_URL', ''),
                    'salutem_nome_certificado': os.getenv('SALUTEM_NOME_CERTIFICADO', ''),
                    'salutem_empresa_id': os.getenv('SALUTEM_EMPRESA_ID', '1')}


def _salutem_credencial():
    try:
        with open(SALUTEM_CRED) as fh:
            d = _json.load(fh)
        return d.get('usuario', ''), d.get('senha', '')
    except (OSError, ValueError):
        return '', ''


def salutem_cliente():
    conf = {k: get_config(k, v) for k, v in _SALUTEM_PADROES.items()}
    usuario, senha = _salutem_credencial()
    return salutem_gtr.SalutemCliente(conf['salutem_url'], usuario, senha, int(conf['salutem_empresa_id'] or 1),
                                      conf['salutem_nome_certificado'])


@app.route('/admin/configuracoes/salutem', methods=['GET', 'POST'])
def config_salutem():
    if 'usuario_id' not in session:
        return redirect('/')
    if request.method == 'POST':
        acao = request.form.get('acao')
        if acao == 'salvar':
            url = (request.form.get('salutem_url') or '').strip().rstrip('/')
            nome = (request.form.get('salutem_nome_certificado') or '').strip()
            emp = (request.form.get('salutem_empresa_id') or '1').strip()
            if not url.lower().startswith('https://') or not emp.isdigit():
                flash("A URL precisa começar com https:// e a empresa deve ser um número.", "error")
                return redirect(url_for('config_salutem'))
            set_config('salutem_url', url)
            set_config('salutem_nome_certificado', nome)
            set_config('salutem_empresa_id', emp)
            usuario = (request.form.get('salutem_usuario') or '').strip()
            senha = request.form.get('salutem_senha') or ''
            u_atual, s_atual = _salutem_credencial()
            if usuario != u_atual or senha:
                os.makedirs(os.path.dirname(SALUTEM_CRED), exist_ok=True)
                fd = os.open(SALUTEM_CRED, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, 'w') as fh:
                    _json.dump({'usuario': usuario, 'senha': senha or s_atual}, fh)
                os.chmod(SALUTEM_CRED, 0o600)
            auditar(detalhes={'url': url, 'usuario': usuario, 'senha_alterada': bool(senha)})
            flash("Integração com a Salutem salva. Use \"Testar conexão\" para conferir.", "success")
            return redirect(url_for('config_salutem'))
        if acao == 'testar':
            try:
                msg = salutem_cliente().testar()
                flash(msg, "success")
                logger.info(f"{get_usuario_logado()} testou a integração Salutem: OK.")
            except salutem_gtr.SalutemErro as e:
                flash(f"Falhou: {e}", "error")
                logger.warning(f"{get_usuario_logado()} testou a integração Salutem: {e}")
            return redirect(url_for('config_salutem'))
    conf = {k: get_config(k, v) for k, v in _SALUTEM_PADROES.items()}
    usuario, senha = _salutem_credencial()
    return render_template('menu_admin.html', module='config_salutem', usuario=get_usuario_logado(),
                           conf=conf, sal_usuario=usuario, sal_tem_senha=bool(senha), sal_cred_arquivo=SALUTEM_CRED)


# ─── CONFIGURAÇÕES: IDENTIDADE ────────────────────────────────────────────────

@app.route('/admin/configuracoes/identidade', methods=['GET', 'POST'])
def config_identidade():
    if 'usuario_id' not in session:
        return redirect('/')
    if requer_admin():
        flash("Acesso restrito a administradores.", "error")
        return redirect('/usuario')
    usuario_logado = get_usuario_logado()

    if request.method == 'POST':
        nome = request.form.get('nome_instituicao', '').strip()
        if nome:
            set_config('nome_instituicao', nome)
            flash("Nome da instituição atualizado!", "success")
        else:
            flash("O nome não pode estar vazio.", "error")
        return redirect(url_for('config_identidade'))

    return render_template('menu_admin.html', module='config_identidade',
                           nome_instituicao_atual=get_instituicao(),
                           usuario=usuario_logado)


# ─── CONFIGURAÇÕES › SEGURANÇA: PROTEÇÃO DO LOGIN ───────────────────────────

SEG_PADROES = {                       # chave em configuracoes_sistema: (padrão, mínimo, máximo, rótulo)
    'seg_login_max_usuario':  (5,  3, 20,   'Tentativas erradas por usuário'),
    'seg_login_max_ip':       (20, 5, 200,  'Tentativas erradas por IP'),
    'seg_login_janela_min':   (15, 1, 240,  'Janela de contagem (minutos)'),
    'seg_login_bloqueio_min': (15, 1, 1440, 'Tempo de bloqueio (minutos)'),
}
SEG_RETENCAO_DIAS = 180
# hash de uma senha qualquer: conferido quando o usuário não existe, para o tempo de resposta não denunciar isso
_HASH_FANTASMA = generate_password_hash('gtr-usuario-inexistente')
_seg_tabelas_ok = False


def init_seguranca():
    global _seg_tabelas_ok
    if _seg_tabelas_ok:
        return
    cur = mysql.connection.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS login_tentativas (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            usuario VARCHAR(100) NOT NULL,
            ip VARCHAR(45) NOT NULL,
            sucesso TINYINT(1) NOT NULL DEFAULT 0,
            resultado VARCHAR(20) NOT NULL,
            criado_em DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
            KEY idx_lt_usuario (usuario, criado_em),
            KEY idx_lt_ip (ip, criado_em),
            KEY idx_lt_data (criado_em)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS login_bloqueios (
            id INT AUTO_INCREMENT PRIMARY KEY,
            tipo ENUM('usuario','ip') NOT NULL,
            valor VARCHAR(100) NOT NULL,
            inicio DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
            ate DATETIME NOT NULL,
            tentativas INT NOT NULL DEFAULT 0,
            desbloqueado_em DATETIME(6) DEFAULT NULL,
            desbloqueado_por VARCHAR(100) DEFAULT NULL,
            KEY idx_lb_valor (tipo, valor, ate)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    """)
    # precisão de microssegundos: tentativas no mesmo segundo de um bloqueio/desbloqueio precisam ser ordenáveis
    for tabela, coluna, extra in (('login_tentativas', 'criado_em', 'NOT NULL DEFAULT CURRENT_TIMESTAMP(6)'),
                                  ('login_bloqueios', 'inicio', 'NOT NULL DEFAULT CURRENT_TIMESTAMP(6)'),
                                  ('login_bloqueios', 'desbloqueado_em', 'DEFAULT NULL')):
        cur.execute(f"SHOW COLUMNS FROM {tabela} LIKE %s", (coluna,))
        if cur.fetchone()[1].lower() != 'datetime(6)':
            cur.execute(f"ALTER TABLE {tabela} MODIFY {coluna} DATETIME(6) {extra}")
    mysql.connection.commit()
    cur.close()
    init_politica_senha()
    _seg_tabelas_ok = True


def seg_params():
    out = {}
    for chave, (padrao, mini, maxi, _) in SEG_PADROES.items():
        try:
            v = int(get_config(chave, padrao))
        except (TypeError, ValueError):
            v = padrao
        out[chave] = min(max(v, mini), maxi)
    return out


def _ip_cliente():
    # sem proxy reverso na frente: o endereço da conexão é o do cliente (X-Forwarded-For seria forjável)
    return (request.remote_addr or '?')[:45]


def _login_normalizado(usuario):
    return (usuario or '').strip().lower()[:100]


def _bloqueio_ativo(usuario, ip):
    """Bloqueio vigente para o usuário ou o IP: (tipo, minutos restantes) ou None."""
    cur = mysql.connection.cursor()
    cur.execute("""SELECT tipo, CEIL(TIMESTAMPDIFF(SECOND, NOW(), ate) / 60) FROM login_bloqueios
                   WHERE desbloqueado_em IS NULL AND ate > NOW()
                     AND ((tipo='usuario' AND valor=%s) OR (tipo='ip' AND valor=%s))
                   ORDER BY ate DESC LIMIT 1""", (usuario, ip))
    r = cur.fetchone()
    cur.close()
    return (r[0], max(int(r[1] or 1), 1)) if r else None


def _registrar_tentativa(usuario, ip, sucesso, resultado):
    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO login_tentativas (usuario, ip, sucesso, resultado) VALUES (%s,%s,%s,%s)",
                (usuario, ip, 1 if sucesso else 0, resultado))
    mysql.connection.commit()
    cur.close()


def _falhas_recentes(tipo, valor, janela_min):
    """Erros desde o mais recente entre: início da janela, último login certo (só p/ usuário) e último bloqueio/desbloqueio."""
    col = 'usuario' if tipo == 'usuario' else 'ip'
    cur = mysql.connection.cursor()
    cur.execute(f"""
        SELECT COUNT(*) FROM login_tentativas t
        WHERE t.{col} = %s AND t.sucesso = 0 AND t.resultado = 'senha'
          AND t.criado_em > NOW() - INTERVAL %s MINUTE
          AND t.criado_em > COALESCE((SELECT MAX(GREATEST(b.inicio, COALESCE(b.desbloqueado_em, b.inicio)))
                                      FROM login_bloqueios b WHERE b.tipo=%s AND b.valor=%s), '1970-01-01')
          {"AND t.id > COALESCE((SELECT MAX(o.id) FROM login_tentativas o WHERE o.usuario=t.usuario AND o.sucesso=1), 0)" if tipo == 'usuario' else ''}
    """, (valor, janela_min, tipo, valor))
    n = cur.fetchone()[0]
    cur.close()
    return n


def _registrar_falha(usuario, ip):
    """Grava o erro e bloqueia ao atingir o limite. Retorna (bloqueado_agora, tentativas_restantes_do_usuario)."""
    prm = seg_params()
    _registrar_tentativa(usuario, ip, False, 'senha')
    n_usu = _falhas_recentes('usuario', usuario, prm['seg_login_janela_min'])
    n_ip = _falhas_recentes('ip', ip, prm['seg_login_janela_min'])
    bloqueou = False
    cur = mysql.connection.cursor()
    for tipo, valor, n, limite in (('usuario', usuario, n_usu, prm['seg_login_max_usuario']),
                                   ('ip', ip, n_ip, prm['seg_login_max_ip'])):
        if n >= limite:
            cur.execute("""INSERT INTO login_bloqueios (tipo, valor, ate, tentativas)
                           VALUES (%s, %s, NOW() + INTERVAL %s MINUTE, %s)""", (tipo, valor, prm['seg_login_bloqueio_min'], n))
            logger.warning(f"Login: {tipo} '{valor}' bloqueado por {prm['seg_login_bloqueio_min']} min após {n} tentativas erradas.")
            bloqueou = True
    cur.execute("DELETE FROM login_tentativas WHERE criado_em < NOW() - INTERVAL %s DAY", (SEG_RETENCAO_DIAS,))
    mysql.connection.commit()
    cur.close()
    return bloqueou, max(prm['seg_login_max_usuario'] - n_usu, 0)


def _msg_bloqueio(minutos):
    return (f"Acesso bloqueado temporariamente por excesso de tentativas sem sucesso. "
            f"Tente novamente em {minutos} minuto{'s' if minutos != 1 else ''} ou procure o administrador do sistema.")


@app.route('/admin/configuracoes/seguranca', methods=['GET', 'POST'])
def config_seguranca():
    init_seguranca()
    if request.method == 'POST':
        erros = []
        for chave, (padrao, mini, maxi, rotulo) in SEG_PADROES.items():
            try:
                v = int(request.form.get(chave, ''))
            except ValueError:
                erros.append(f"{rotulo}: informe um número.")
                continue
            if not mini <= v <= maxi:
                erros.append(f"{rotulo}: use um valor entre {mini} e {maxi}.")
                continue
            set_config(chave, str(v))
        if erros:
            for e in erros:
                flash(e, "error")
        else:
            logger.info(f"{get_usuario_logado()} alterou os parâmetros de proteção do login: "
                        + ', '.join(f"{k}={request.form.get(k)}" for k in SEG_PADROES))
            flash("Parâmetros de proteção do login salvos.", "success")
        return redirect(url_for('config_seguranca'))
    cur = mysql.connection.cursor()
    cur.execute("""SELECT id, tipo, valor, inicio, ate, tentativas FROM login_bloqueios
                   WHERE desbloqueado_em IS NULL AND ate > NOW() ORDER BY ate DESC""")
    bloqueios = [{'id': r[0], 'tipo': r[1], 'valor': r[2], 'inicio': r[3], 'ate': r[4], 'tentativas': r[5]} for r in cur.fetchall()]
    cur.execute("""SELECT SUM(sucesso=0 AND resultado='senha'), SUM(resultado='bloqueado'), SUM(sucesso=1),
                          COUNT(DISTINCT CASE WHEN sucesso=0 THEN ip END)
                   FROM login_tentativas WHERE criado_em > NOW() - INTERVAL 24 HOUR""")
    k = cur.fetchone()
    cur.execute("SELECT COUNT(*) FROM login_bloqueios WHERE inicio > NOW() - INTERVAL 24 HOUR")
    resumo = {'falhas': int(k[0] or 0), 'barradas': int(k[1] or 0), 'sucessos': int(k[2] or 0),
              'ips': int(k[3] or 0), 'bloqueios': cur.fetchone()[0]}
    cur.execute("""SELECT criado_em, usuario, ip, resultado FROM login_tentativas
                   WHERE sucesso = 0 ORDER BY id DESC LIMIT 40""")
    tentativas = [{'em': r[0], 'usuario': r[1], 'ip': r[2], 'resultado': r[3]} for r in cur.fetchall()]
    cur.close()
    return render_template('menu_admin.html', module='config_seguranca', usuario=get_usuario_logado(),
                           seg=seg_params(), seg_campos=SEG_PADROES, bloqueios=bloqueios, resumo=resumo,
                           tentativas=tentativas, ip_atual=_ip_cliente(), retencao=SEG_RETENCAO_DIAS,
                           pol=politica_senha(), pol_campos=SENHA_PADROES, pendentes_troca=_pendentes_troca())


def _pendentes_troca():
    cur = mysql.connection.cursor()
    cur.execute("SELECT nome, usuario FROM usuarios WHERE trocar_senha=1 AND status=1 ORDER BY nome")
    r = [{'nome': a, 'usuario': b} for a, b in cur.fetchall()]
    cur.close()
    return r


@app.route('/admin/configuracoes/seguranca/desbloquear/<int:bloqueio_id>', methods=['POST'])
def config_seguranca_desbloquear(bloqueio_id):
    init_seguranca()
    cur = mysql.connection.cursor()
    cur.execute("""UPDATE login_bloqueios SET desbloqueado_em = NOW(6), desbloqueado_por = %s
                   WHERE id = %s AND desbloqueado_em IS NULL""", (get_usuario_logado(), bloqueio_id))
    mudou = cur.rowcount
    cur.execute("SELECT tipo, valor FROM login_bloqueios WHERE id = %s", (bloqueio_id,))
    r = cur.fetchone()
    mysql.connection.commit()
    cur.close()
    if mudou and r:
        logger.info(f"{get_usuario_logado()} desbloqueou o {r[0]} '{r[1]}'.")
        flash(f"{'Usuário' if r[0] == 'usuario' else 'IP'} {r[1]} desbloqueado.", "success")
    else:
        flash("Esse bloqueio já não estava ativo.", "error")
    return redirect(url_for('config_seguranca'))


# ─── CONFIGURAÇÕES › SEGURANÇA: POLÍTICA DE SENHA ───────────────────────────

SENHA_PADROES = {     # chave: (padrão, mínimo, máximo, rótulo) — 0/1 nos itens marcáveis
    'seg_senha_min':             (8, 6, 64,  'Tamanho mínimo'),
    'seg_senha_maiusc_minusc':   (1, 0, 1,   'Letras maiúsculas e minúsculas'),
    'seg_senha_numero':          (1, 0, 1,   'Pelo menos um número'),
    'seg_senha_especial':        (0, 0, 1,   'Pelo menos um caractere especial (!@#…)'),
    'seg_senha_validade_dias':   (0, 0, 365, 'Validade da senha (dias, 0 = não vence)'),
    'seg_senha_exigir_fora':     (1, 0, 1,   'Pedir troca no login de quem tem senha fora da política'),
}
_SENHAS_OBVIAS = {'123456', '1234567', '12345678', '123456789', '1234567890', '654321', '111111', '000000',
                  '123123', 'abc123', 'abcd1234', 'qwerty', 'qwerty123', 'senha', 'senha1', 'senha12', 'senha123',
                  'senha1234', 'password', 'password1', 'admin', 'admin123', 'admin1234', 'gtr', 'gtr123', 'gtr12345',
                  'mudar123', 'mudar@123', 'trocar123', 'hospital', 'hospital123', 'nutricao', 'nutricao123',
                  'refeicao', 'refeicao123', 'cozinha', 'cozinha123', 'totem', 'totem123', 'usuario', 'usuario123'}


def politica_senha():
    out = {}
    for chave, (padrao, mini, maxi, _) in SENHA_PADROES.items():
        try:
            v = int(get_config(chave, padrao))
        except (TypeError, ValueError):
            v = padrao
        out[chave] = min(max(v, mini), maxi)
    return out


def regras_senha(pol=None):
    """Lista (id, texto) das regras em vigor — a mesma lista vai para a tela (checagem ao vivo)."""
    pol = pol or politica_senha()
    r = [('min', f"Pelo menos {pol['seg_senha_min']} caracteres")]
    if pol['seg_senha_maiusc_minusc']:
        r.append(('caixa', 'Letras maiúsculas e minúsculas'))
    if pol['seg_senha_numero']:
        r.append(('numero', 'Pelo menos um número'))
    if pol['seg_senha_especial']:
        r.append(('especial', 'Pelo menos um caractere especial (!@#$%…)'))
    r.append(('login', 'Não conter o nome de usuário'))
    r.append(('obvia', 'Não ser uma senha óbvia (123456, senha123…)'))
    return r


def validar_senha(senha, login='', pol=None):
    """Devolve a lista de problemas da senha (vazia = senha aceita)."""
    pol = pol or politica_senha()
    senha = senha or ''
    erros = []
    if len(senha) < pol['seg_senha_min']:
        erros.append(f"ter pelo menos {pol['seg_senha_min']} caracteres")
    if pol['seg_senha_maiusc_minusc'] and not (any(c.isupper() for c in senha) and any(c.islower() for c in senha)):
        erros.append('ter letras maiúsculas e minúsculas')
    if pol['seg_senha_numero'] and not any(c.isdigit() for c in senha):
        erros.append('ter pelo menos um número')
    if pol['seg_senha_especial'] and all(c.isalnum() for c in senha):
        erros.append('ter pelo menos um caractere especial')
    lg = (login or '').strip().lower()
    if len(lg) >= 3 and lg in senha.lower():
        erros.append('não conter o usuário')
    if senha.lower() in _SENHAS_OBVIAS:
        erros.append('não ser uma senha óbvia')
    return erros


def msg_senha_invalida(erros):
    return "A senha precisa " + (', '.join(erros[:-1]) + ' e ' + erros[-1] if len(erros) > 1 else erros[0]) + "."


def _eh_hash(valor):
    return (valor or '').startswith(('pbkdf2:', 'scrypt:'))


def init_politica_senha():
    """Colunas novas + conversão (uma vez) das senhas legadas em texto puro para hash — a senha de ninguém muda."""
    cur = mysql.connection.cursor()
    cur.execute("ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS trocar_senha TINYINT(1) NOT NULL DEFAULT 0")
    cur.execute("ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS senha_alterada_em DATETIME DEFAULT NULL")
    cur.execute("SELECT id, senha FROM usuarios WHERE senha NOT LIKE 'pbkdf2:%%' AND senha NOT LIKE 'scrypt:%%'")
    legadas = cur.fetchall()
    for uid, txt in legadas:
        cur.execute("UPDATE usuarios SET senha=%s WHERE id=%s AND senha=%s", (generate_password_hash(txt), uid, txt))
    mysql.connection.commit()
    cur.close()
    if legadas:
        logger.warning(f"{len(legadas)} senha(s) legada(s) em texto puro convertida(s) para hash.")


def _motivo_troca(trocar_flag, senha_digitada, login, alterada_em):
    """Por que o usuário precisa trocar a senha agora (None = não precisa)."""
    pol = politica_senha()
    if trocar_flag:
        return 'reset'
    if pol['seg_senha_validade_dias'] and alterada_em and \
            (datetime.now() - alterada_em).days >= pol['seg_senha_validade_dias']:
        return 'vencida'
    if pol['seg_senha_exigir_fora'] and validar_senha(senha_digitada, login, pol):
        return 'fora'
    return None


_MOTIVOS_TROCA = {
    'reset':   'Sua senha foi definida pelo administrador. Crie uma senha pessoal para continuar.',
    'vencida': 'Sua senha venceu. Crie uma nova senha para continuar.',
    'fora':    'Sua senha atual não atende à política de segurança do sistema. Crie uma nova senha para continuar.',
}


@app.route('/minha-senha', methods=['GET', 'POST'])
def minha_senha():
    if 'usuario_id' not in session:
        return redirect('/')
    init_seguranca()
    motivo = session.get('trocar_senha')
    cur = mysql.connection.cursor()
    cur.execute("SELECT usuario, senha FROM usuarios WHERE id=%s AND status=1", (session['usuario_id'],))
    r = cur.fetchone()
    cur.close()
    if not r:
        session.clear()
        return redirect('/')
    login, hash_atual = r
    pol = politica_senha()
    if request.method == 'POST':
        atual = request.form.get('senha_atual', '')
        nova = request.form.get('senha_nova', '')
        conf = request.form.get('senha_confirma', '')
        login_norm, ip = _login_normalizado(login), _ip_cliente()
        if not check_password_hash(hash_atual, atual):
            # erro na senha atual conta como tentativa de login (evita chute por uma sessão aberta)
            bloqueou, _ = _registrar_falha(login_norm, ip)
            logger.info(f"{login}: senha atual errada na troca de senha.")
            if bloqueou:
                session.clear()
                flash(_msg_bloqueio(seg_params()['seg_login_bloqueio_min']))
                return redirect('/')
            flash("A senha atual não confere.", "error")
            return redirect(url_for('minha_senha'))
        erros = validar_senha(nova, login, pol)
        if nova != conf:
            flash("A confirmação não é igual à nova senha.", "error")
        elif erros:
            flash(msg_senha_invalida(erros), "error")
        elif check_password_hash(hash_atual, nova):
            flash("A nova senha precisa ser diferente da atual.", "error")
        else:
            cur = mysql.connection.cursor()
            cur.execute("UPDATE usuarios SET senha=%s, trocar_senha=0, senha_alterada_em=NOW() WHERE id=%s",
                        (generate_password_hash(nova), session['usuario_id']))
            mysql.connection.commit()
            cur.close()
            session.pop('trocar_senha', None)
            logger.info(f"{login} trocou a própria senha" + (f" (motivo: {motivo})." if motivo else "."))
            flash("Senha alterada com sucesso.", "success")
            return redirect(pagina_inicial() or url_for('inicio_perfil'))
        return redirect(url_for('minha_senha'))
    return render_template('minha_senha.html', motivo=_MOTIVOS_TROCA.get(motivo), obrigatoria=bool(motivo),
                           regras=regras_senha(pol), pol=pol, login=login, usuario=get_usuario_logado(), obvias=sorted(_SENHAS_OBVIAS),
                           voltar=pagina_inicial() or url_for('inicio_perfil'), nome_instituicao=get_instituicao())


@app.route('/admin/configuracoes/seguranca/senha', methods=['POST'])
def config_seguranca_senha():
    init_seguranca()
    erros = []
    for chave, (padrao, mini, maxi, rotulo) in SENHA_PADROES.items():
        bruto = request.form.get(chave, '0' if maxi == 1 else '')
        try:
            v = int(bruto)
        except ValueError:
            erros.append(f"{rotulo}: informe um número.")
            continue
        if not mini <= v <= maxi:
            erros.append(f"{rotulo}: use um valor entre {mini} e {maxi}.")
            continue
        set_config(chave, str(v))
    if erros:
        for e in erros:
            flash(e, "error")
    else:
        logger.info(f"{get_usuario_logado()} alterou a política de senha: "
                    + ', '.join(f"{k}={request.form.get(k, '0')}" for k in SENHA_PADROES))
        flash("Política de senha salva. Vale para as próximas senhas criadas ou trocadas.", "success")
    return redirect(url_for('config_seguranca') + '#politica')


# ─── CONFIGURAÇÕES › AUDITORIA ───────────────────────────────────────────────
# Toda ação que altera dados (POST) vira uma linha em `auditoria`: quem, quando, de onde, o quê, o resultado,
# os campos enviados (sem senhas) e, em edições/exclusões, o "antes → depois" da linha alterada.
# Também entram: login (certo, errado, bloqueado), saída, sessão vencida, acessos negados e CSRF recusado.
# A tabela só recebe INSERT pelo sistema — não há tela para editar ou apagar; a limpeza é só por retenção.

from datetime import timedelta
import hashlib
AUDIT_RETENCAO_DIAS = 730
AUDIT_POR_PAGINA = 50
# alto volume e já registrados nas próprias tabelas (emissoes_senha) — não entram na auditoria
AUDIT_IGNORAR = {'senha_colaborador', 'senha_visitante', 'senha_colaborador_cardapio', 'dispensa_ping', 'dispensa_identificar',
                 'emissao_senha', 'emissao_senha_tablet', 'static'}
AUDIT_ROTULOS = {
    'login': ('Acesso', 'Entrar no sistema'),
    'logout': ('Acesso', 'Sair do sistema'),
    'minha_senha': ('Acesso', 'Trocar a própria senha'),
    'cadastro_usuario': ('Usuários', 'Cadastrar usuário'),
    'editar_usuario': ('Usuários', 'Editar usuário'),
    'excluir_usuario': ('Usuários', 'Excluir usuário'),
    'cadastro': ('Colaboradores', 'Cadastrar colaborador'),
    'editar_colaborador': ('Colaboradores', 'Editar colaborador'),
    'excluir_colaborador': ('Colaboradores', 'Excluir colaborador'),
    'escalas': ('Escalas', 'Cadastrar escala'),
    'escala_editar': ('Escalas', 'Editar escala'),
    'escala_excluir': ('Escalas', 'Excluir escala'),
    'escalas_lote': ('Escalas', 'Aplicar escala em lote'),
    'escalas_modelo_csv': ('Escalas', 'Baixar modelo de escalas (CSV)'),
    'escalas_importar': ('Escalas', 'Enviar CSV de escalas (prévia)'),
    'escalas_importar_confirmar': ('Escalas', 'Importar escalas por CSV'),
    'importar_colaboradores': ('Colaboradores', 'Importar colaboradores (planilha)'),
    'departamentos': ('Departamentos', 'Cadastrar departamento'),
    'editar_departamento': ('Departamentos', 'Editar departamento'),
    'excluir_departamento': ('Departamentos', 'Excluir departamento'),
    'admin_grupos': ('Grupos SND', 'Cadastrar grupo'),
    'editar_grupo': ('Grupos SND', 'Editar grupo'),
    'excluir_grupo': ('Grupos SND', 'Excluir grupo'),
    'perfil_novo': ('Perfis e permissões', 'Criar perfil'),
    'perfil_editar': ('Perfis e permissões', 'Editar perfil e permissões'),
    'perfil_excluir': ('Perfis e permissões', 'Excluir perfil'),
    'cardapio_montar': ('Cardápio', 'Montar / alterar cardápio'),
    'cardapio_copiar': ('Cardápio', 'Copiar cardápio'),
    'cardapio_copiar_semana': ('Cardápio', 'Copiar cardápio da semana'),
    'cardapio_toggle': ('Cardápio', 'Ativar / desativar cardápio'),
    'cardapio_excluir': ('Cardápio', 'Excluir cardápio'),
    'cardapio_pratos': ('Catálogo de pratos', 'Cadastrar prato'),
    'cardapio_prato_editar': ('Catálogo de pratos', 'Editar prato'),
    'cardapio_prato_excluir': ('Catálogo de pratos', 'Excluir prato'),
    'dispensa_importar': ('Dispensa Refeição', 'Importar prescrições (CSV)'),
    'dispensa_acompanhante_salvar': ('Dispensa Refeição', 'Definir acompanhante do paciente'),
    'dispensa_corrigir': ('Dispensa Refeição', 'Corrigir registro do totem'),
    'dispensa_etiquetas_imprimir': ('Dispensa Refeição', 'Imprimir etiquetas QR'),
    'dispensa_pacientes': ('Dispensa Refeição', 'Ver pacientes do dia'),
    'dispensa_refeicoes_ajustar': ('Dispensa Refeição', 'Ajustar refeições autorizadas (nutrição)'),
    'dispensa_registrar': ('Dispensa Refeição', 'Registro no totem de dispensa'),
    'dispensa_avaria': ('Dispensa Refeição', 'Avaria no totem (reposição liberada)'),
    'dispensa_tipos': ('Dispensa Refeição', 'Cadastrar tipo de refeição'),
    'dispensa_tipo_editar': ('Dispensa Refeição', 'Editar tipo de refeição'),
    'dispensa_tipos_ordem': ('Dispensa Refeição', 'Reordenar tipos de refeição'),
    'dispensa_dietas_sem_refeicao': ('Dispensa Refeição', 'Alterar dietas que não recebem refeição'),
    'dispensa_tipo_reajustar': ('Dispensa Refeição', 'Reajustar valor de entregas'),
    'dispensa_tipo_excluir': ('Dispensa Refeição', 'Excluir tipo de refeição'),
    'dispensa_fechamento': ('Dispensa Refeição', 'Fechar período'),
    'dispensa_fechamento_reabrir': ('Dispensa Refeição', 'Reabrir período fechado'),
    'dispensa_relatorio': ('Relatórios', 'Gerar relatório financeiro da dispensa'),
    'dispensa_avarias_relatorio': ('Relatórios', 'Gerar relatório de avarias da dispensa'),
    'relatorio_faturamento': ('Relatórios', 'Gerar relatório de faturamento'),
    'relatorio_totalEmissao': ('Relatórios', 'Gerar relatório: total de senhas'),
    'relatorio_emissaoDiaria': ('Relatórios', 'Gerar relatório: lista de senhas emitidas'),
    'relatorio_totalVisitantes': ('Relatórios', 'Gerar relatório: total de visitantes'),
    'relatorio_totalDepartamento': ('Relatórios', 'Gerar relatório: por departamento'),
    'relatorio_cardapio': ('Relatórios', 'Gerar relatório: emissões com cardápio'),
    'relatorio_snd': ('Relatórios', 'Gerar relatório: financeiro SND'),
    'config_localizacoes': ('Parâmetros', 'Cadastrar localização'),
    'editar_localizacao': ('Parâmetros', 'Editar localização'),
    'excluir_localizacao': ('Parâmetros', 'Excluir localização'),
    'config_emissao_senha': ('Parâmetros', 'Alterar emissão de senha'),
    'config_custos_refeicao': ('Parâmetros', 'Alterar custos de refeição'),
    'config_turnos': ('Parâmetros', 'Alterar horários de turno'),
    'config_limite_visitantes': ('Parâmetros', 'Alterar limite de senhas de visitante'),
    'config_identidade': ('Configurações', 'Alterar identidade da instituição'),
    'config_seguranca': ('Configurações', 'Alterar proteção do login'),
    'config_seguranca_senha': ('Configurações', 'Alterar política de senha'),
    'config_seguranca_desbloquear': ('Configurações', 'Desbloquear usuário / IP'),
    'config_auditoria_exportar': ('Configurações', 'Exportar auditoria'),
    'config_backup': ('Configurações', 'Backup: configurar / fazer backup'),
    'config_backup_baixar': ('Configurações', 'Baixar backup'),
    'config_backup_excluir': ('Configurações', 'Excluir backup'),
    'config_backup_restaurar': ('Configurações', 'RESTAURAR backup'),
    'config_salutem': ('Configurações', 'Integração Salutem (salvar / testar)'),
}
# endpoint → (tabela, de onde vem o id: 'view:<arg>' | 'form:<campo>' | None = tabela inteira)
# usado para guardar a linha ANTES da ação e comparar com a de DEPOIS
AUDIT_ENTIDADES = {
    'editar_usuario': ('usuarios', 'view:usuario_id'), 'excluir_usuario': ('usuarios', 'view:usuario_id'),
    'editar_colaborador': ('colaboradores', 'view:colaborador_id'), 'excluir_colaborador': ('colaboradores', 'view:colaborador_id'),
    'escala_editar': ('escalas', 'view:escala_id'), 'escala_excluir': ('escalas', 'view:escala_id'),
    'editar_departamento': ('departamentos', 'view:dep_id'), 'excluir_departamento': ('departamentos', 'view:dep_id'),
    'editar_grupo': ('grupos', 'view:grupo_id'), 'excluir_grupo': ('grupos', 'view:grupo_id'),
    'editar_localizacao': ('localizacoes', 'view:loc_id'), 'excluir_localizacao': ('localizacoes', 'view:loc_id'),
    'cardapio_toggle': ('cardapios', 'view:cardapio_id'), 'cardapio_excluir': ('cardapios', 'view:cardapio_id'),
    'cardapio_prato_editar': ('pratos', 'view:prato_id'), 'cardapio_prato_excluir': ('pratos', 'view:prato_id'),
    'dispensa_tipo_editar': ('dispensa_tipos', 'view:tipo_id'), 'dispensa_tipo_excluir': ('dispensa_tipos', 'view:tipo_id'),
    'dispensa_tipo_reajustar': ('dispensa_tipos', 'view:tipo_id'),
    'dispensa_fechamento_reabrir': ('dispensa_fechamentos', 'view:fid'),
    'dispensa_registrar': ('dispensa_itens', 'form:item_id'),
    'dispensa_corrigir': ('dispensa_itens', 'form:item_id'),
    'perfil_editar': ('perfis', 'view:perfil_id'), 'perfil_excluir': ('perfis', 'view:perfil_id'),
    'config_custos_refeicao': ('custos_refeicao', None),
}
_AUDIT_COLUNAS_FORA = {'foto', 'atualizado_em', 'criado_em'}
# campos que contêm a senha em si (formulários e coluna do banco) — nunca são guardados
_AUDIT_CAMPOS_SENHA = {'senha', 'nova_senha', 'senha_atual', 'senha_nova', 'senha_confirma'}
_AUDIT_TABELAS = {t for t, _ in AUDIT_ENTIDADES.values()}
_audit_ok = False
_audit_ultima_limpeza = None


def init_auditoria():
    global _audit_ok
    if _audit_ok:
        return
    cur = mysql.connection.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS auditoria (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            criado_em DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
            usuario_id INT DEFAULT NULL,
            usuario VARCHAR(100) NOT NULL DEFAULT '',
            perfil VARCHAR(100) NOT NULL DEFAULT '',
            ip VARCHAR(45) NOT NULL DEFAULT '',
            modulo VARCHAR(60) NOT NULL DEFAULT '',
            acao VARCHAR(120) NOT NULL DEFAULT '',
            endpoint VARCHAR(80) NOT NULL DEFAULT '',
            metodo VARCHAR(8) NOT NULL DEFAULT '',
            alvo VARCHAR(255) NOT NULL DEFAULT '',
            resultado VARCHAR(10) NOT NULL DEFAULT 'ok',
            detalhes LONGTEXT,
            KEY idx_aud_data (criado_em),
            KEY idx_aud_usuario (usuario, criado_em),
            KEY idx_aud_modulo (modulo, criado_em),
            KEY idx_aud_resultado (resultado, criado_em)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    """)
    mysql.connection.commit()
    cur.close()
    _audit_ok = True


def _audit_mascarar(chave, valor):
    """Nunca guarda senha/QR; identificadores de pessoa ficam parciais."""
    k = (chave or '').lower()
    if k in _AUDIT_CAMPOS_SENHA or 'password' in k or 'csrf' in k or k.endswith('token'):
        return None
    if k in ('qr', 'conteudo_qr'):
        return '[conteúdo do QR omitido]'
    v = '' if valor is None else str(valor)
    if any(x in k for x in ('cpf', 'prontuario', 'atendimento', 'nome_mae', 'data_nascimento')) and v:
        so = ''.join(ch for ch in v if ch.isalnum())
        return '•' * max(len(so) - 3, 3) + so[-3:] if len(so) > 3 else '•••'
    return v[:300]


def _audit_sessao():
    p = None
    try:
        p = perfil_atual() if session.get('usuario_id') else None
    except Exception:
        p = None
    return {'usuario_id': session.get('usuario_id'), 'usuario': session.get('usuario_nome', ''),
            'perfil': (p or {}).get('nome', '')}


def auditar(**kw):
    """Acrescenta informação ao registro de auditoria desta requisição.
    Campos: acao, modulo, alvo, resultado ('ok'|'erro'|'negado'), motivo, detalhes (dict), forcar (registra mesmo em GET)."""
    a = g.setdefault('audit', {})
    if 'quem' not in a:
        a['quem'] = _audit_sessao()       # foto de quem fez, antes de um eventual session.clear()
    det = kw.pop('detalhes', None)
    if det:
        a.setdefault('detalhes', {}).update(det)
    a.update({k: v for k, v in kw.items() if v is not None})


def _audit_registrar_mudanca_config(chave, antes, depois):
    if not has_request_context() or str(antes) == str(depois):
        return
    m = g.setdefault('audit', {}).setdefault('detalhes', {}).setdefault('mudancas', {})
    m[f'config: {chave}'] = [antes, depois]


def _audit_id_alvo(origem):
    if not origem:
        return None
    tipo, nome = origem.split(':', 1)
    v = (request.view_args or {}).get(nome) if tipo == 'view' else request.form.get(nome)
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _audit_foto(tabela, alvo_id):
    """Linha(s) atuais da entidade, como dict de texto (sem colunas sensíveis)."""
    if tabela not in _AUDIT_TABELAS:
        return None
    cur = mysql.connection.cursor()
    try:
        if alvo_id is None:
            cur.execute(f"SELECT * FROM `{tabela}`")
        else:
            cur.execute(f"SELECT * FROM `{tabela}` WHERE id = %s", (alvo_id,))
        cols = [d[0] for d in cur.description]
        linhas = cur.fetchall()
        out = {}
        for ln in linhas:
            reg = {c: v for c, v in zip(cols, ln)}
            pre = '' if alvo_id is not None else f"#{reg.get('id')} "
            for c, v in reg.items():
                if c in _AUDIT_COLUNAS_FORA or (alvo_id is None and c == 'id'):
                    continue
                if c == 'senha':   # impressão digital interna, só para saber se mudou (descartada antes de gravar)
                    out[pre + '__senha'] = hashlib.sha256(str(v).encode()).hexdigest()
                    continue
                mv = _audit_mascarar(c, v)
                if mv is not None:
                    out[pre + c] = mv
        if tabela == 'perfis' and alvo_id is not None and linhas:
            cur.execute("SELECT modulo, ver, incluir, editar, excluir FROM perfil_permissoes WHERE perfil_id=%s", (alvo_id,))
            for mod, *vals in cur.fetchall():
                ac = [a for a, v in zip(ACOES, vals) if v]
                if ac:
                    out[f'permissão {mod}'] = ', '.join(ac)
        return out if linhas else {}
    finally:
        cur.close()


def _audit_rotulo_alvo(tabela, alvo_id, foto):
    if foto is None:
        return ''
    if tabela == 'dispensa_itens' and alvo_id:
        cur = mysql.connection.cursor()
        cur.execute("""SELECT p.leito, p.nome, t.nome FROM dispensa_itens i JOIN dispensa_pacientes p ON p.id=i.paciente_id
                       JOIN dispensa_tipos t ON t.id=i.tipo_id WHERE i.id=%s""", (alvo_id,))
        r = cur.fetchone()
        cur.close()
        return f"Leito {r[0]} · {r[1]} · {r[2]}" if r else f"Item #{alvo_id}"
    if alvo_id is None:
        return f"Tabela {tabela}"
    nome = foto.get('nome') or foto.get('usuario') or foto.get('descricao') or ''
    return (f"{nome} (#{alvo_id})" if nome else f"#{alvo_id}")[:255]


@app.before_request
def _audit_antes():
    if request.method in ('GET', 'HEAD', 'OPTIONS') or request.endpoint in AUDIT_IGNORAR:
        return None
    g.audit_flash_n = len(session.get('_flashes', []) or [])
    spec = AUDIT_ENTIDADES.get(request.endpoint)
    if spec:
        try:
            alvo_id = _audit_id_alvo(spec[1])
            if spec[1] is None or alvo_id is not None:
                g.audit_antes = (spec[0], alvo_id, _audit_foto(spec[0], alvo_id))
        except Exception as e:
            logger.error(f"Auditoria: falha ao fotografar {request.endpoint}: {e}")
    return None


def _audit_campos_form():
    campos, extra = {}, 0
    for k in request.form.keys():
        vals = request.form.getlist(k)
        mv = [_audit_mascarar(k, v) for v in vals]
        if mv and mv[0] is None:
            continue
        if len(campos) >= 60:
            extra += 1
            continue
        campos[k] = mv[0] if len(mv) == 1 else mv[:20]
    if extra:
        campos['…'] = f"+{extra} campo(s)"
    arquivos = [f.filename for f in request.files.values() if f and f.filename]
    return campos, arquivos


@app.after_request
def _audit_depois(response):
    try:
        a = g.get('audit') or {}
        ep = request.endpoint or ''
        mutante = request.method not in ('GET', 'HEAD', 'OPTIONS')
        if not a.get('forcar') and (not mutante or ep in AUDIT_IGNORAR):
            return response
        init_auditoria()
        quem = a.get('quem') or _audit_sessao()
        mod_padrao, acao_padrao = AUDIT_ROTULOS.get(ep, ('', ''))
        if not mod_padrao:
            regra = ROTAS_PERMISSAO.get(ep, {}).get(request.method)
            mod_padrao = MODULO_NOME.get(regra[0], regra[0]) if regra else ('Configurações' if ep in ROTAS_SO_ADMIN else 'Sistema')
            acao_padrao = ep or request.path
        det = dict(a.get('detalhes') or {})
        if mutante:
            campos, arquivos = _audit_campos_form()
            if campos:
                det['campos'] = campos
            if arquivos:
                det['arquivos'] = arquivos
        # mensagens mostradas ao usuário nesta ação
        flashes = (session.get('_flashes', []) or [])[g.get('audit_flash_n', 0):]
        if flashes:
            det['mensagens'] = [f"{c}: {m}" for c, m in flashes][:5]
        # antes → depois
        alvo = a.get('alvo', '')
        antes = g.get('audit_antes')
        if antes and antes[2] is not None:
            tabela, alvo_id, foto_antes = antes
            foto_depois = _audit_foto(tabela, alvo_id) or {}
            if not alvo:
                alvo = _audit_rotulo_alvo(tabela, alvo_id, foto_antes or foto_depois)
            senha_mudou = foto_antes.pop('__senha', None) != foto_depois.pop('__senha', None)
            if foto_antes and not foto_depois and alvo_id is not None:
                det['removido'] = foto_antes
            else:
                if senha_mudou and foto_depois:
                    det.setdefault('mudancas', {})['senha'] = ['••••••', 'alterada']
                mud = {k: [foto_antes.get(k), foto_depois.get(k)] for k in sorted(set(foto_antes) | set(foto_depois))
                       if str(foto_antes.get(k)) != str(foto_depois.get(k))}
                if mud:
                    det.setdefault('mudancas', {}).update(mud)
        # resultado
        resultado = a.get('resultado')
        if not resultado:
            if response.status_code >= 400:
                resultado = 'negado' if response.status_code in (401, 403) else 'erro'
            elif response.is_json:
                resultado = 'ok' if (response.get_json(silent=True) or {}).get('ok') else 'erro'
            elif any(c == 'error' for c, _ in flashes):
                resultado = 'erro'
            else:
                resultado = 'ok'
        if a.get('motivo'):
            det['motivo'] = a['motivo']
        cur = mysql.connection.cursor()
        cur.execute("""INSERT INTO auditoria (usuario_id, usuario, perfil, ip, modulo, acao, endpoint, metodo, alvo, resultado, detalhes)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (quem.get('usuario_id') or None, (a.get('usuario') or quem.get('usuario') or '')[:100],
                     (quem.get('perfil') or '')[:100], (request.remote_addr or '')[:45],
                     (a.get('modulo') or mod_padrao)[:60], (a.get('acao') or acao_padrao)[:120], ep[:80], request.method[:8],
                     str(alvo or '')[:255], resultado, _json.dumps(det, ensure_ascii=False, default=str) if det else None))
        global _audit_ultima_limpeza
        if _audit_ultima_limpeza != date.today():
            cur.execute("DELETE FROM auditoria WHERE criado_em < NOW() - INTERVAL %s DAY", (AUDIT_RETENCAO_DIAS,))
            _audit_ultima_limpeza = date.today()
        mysql.connection.commit()
        cur.close()
    except Exception as e:   # a auditoria nunca pode derrubar a ação do usuário
        logger.error(f"Auditoria: falha ao registrar {request.endpoint}: {e}")
    return response


def _audit_filtros():
    hoje = date.today()
    f = {'de': _parse_data(request.args.get('de'), hoje - timedelta(days=6)),
         'ate': _parse_data(request.args.get('ate'), hoje),
         'usuario': (request.args.get('usuario') or '').strip(),
         'modulo': (request.args.get('modulo') or '').strip(),
         'resultado': (request.args.get('resultado') or '').strip(),
         'busca': (request.args.get('busca') or '').strip()[:100]}
    if f['ate'] < f['de']:
        f['de'], f['ate'] = f['ate'], f['de']
    where = ["criado_em >= %s", "criado_em < %s + INTERVAL 1 DAY"]
    par = [f['de'], f['ate']]
    if f['usuario']:
        where.append("usuario = %s"); par.append(f['usuario'])
    if f['modulo']:
        where.append("modulo = %s"); par.append(f['modulo'])
    if f['resultado'] in ('ok', 'erro', 'negado'):
        where.append("resultado = %s"); par.append(f['resultado'])
    if f['busca']:
        like = '%' + f['busca'].replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%'
        where.append("(acao LIKE %s OR alvo LIKE %s OR detalhes LIKE %s OR ip LIKE %s)"); par += [like] * 4
    return f, ' AND '.join(where), par


def _audit_linhas(where, par, limite=None, offset=0):
    cur = mysql.connection.cursor()
    sql = f"""SELECT id, criado_em, usuario, perfil, ip, modulo, acao, alvo, resultado, detalhes, metodo
              FROM auditoria WHERE {where} ORDER BY id DESC"""
    if limite:
        sql += f" LIMIT {int(limite)} OFFSET {int(offset)}"
    cur.execute(sql, par)
    out = []
    for r in cur.fetchall():
        try:
            det = _json.loads(r[9]) if r[9] else {}
        except ValueError:
            det = {'texto': r[9]}
        out.append({'id': r[0], 'em': r[1], 'usuario': r[2], 'perfil': r[3], 'ip': r[4], 'modulo': r[5], 'acao': r[6],
                    'alvo': r[7], 'resultado': r[8], 'det': det, 'metodo': r[10]})
    cur.close()
    return out


@app.route('/admin/configuracoes/auditoria')
def config_auditoria():
    init_auditoria()
    f, where, par = _audit_filtros()
    try:
        pagina = max(int(request.args.get('pagina', 1)), 1)
    except ValueError:
        pagina = 1
    cur = mysql.connection.cursor()
    cur.execute(f"""SELECT COUNT(*), SUM(resultado='negado'), SUM(resultado='erro'), COUNT(DISTINCT NULLIF(usuario, ''))
                    FROM auditoria WHERE {where}""", par)
    k = cur.fetchone()
    resumo = {'total': int(k[0] or 0), 'negadas': int(k[1] or 0), 'erros': int(k[2] or 0), 'usuarios': int(k[3] or 0)}
    cur.execute("SELECT DISTINCT usuario FROM auditoria WHERE usuario <> '' AND criado_em > NOW() - INTERVAL 1 YEAR ORDER BY usuario")
    usuarios = [r[0] for r in cur.fetchall()]
    cur.execute("SELECT DISTINCT modulo FROM auditoria WHERE modulo <> '' ORDER BY modulo")
    modulos = [r[0] for r in cur.fetchall()]
    cur.close()
    paginas = max((resumo['total'] + AUDIT_POR_PAGINA - 1) // AUDIT_POR_PAGINA, 1)
    pagina = min(pagina, paginas)
    linhas = _audit_linhas(where, par, AUDIT_POR_PAGINA, (pagina - 1) * AUDIT_POR_PAGINA)
    args_base = {k: v for k, v in request.args.items() if k != 'pagina'}
    return render_template('menu_admin.html', module='config_auditoria', usuario=get_usuario_logado(),
                           filtros=f, resumo=resumo, linhas=linhas, usuarios_aud=usuarios, modulos_aud=modulos,
                           au_pagina=pagina, au_paginas=paginas, args_base=args_base, retencao=AUDIT_RETENCAO_DIAS)


@app.route('/admin/configuracoes/auditoria/exportar')
def config_auditoria_exportar():
    import xlsxwriter
    init_auditoria()
    f, where, par = _audit_filtros()
    linhas = _audit_linhas(where, par, 20000)
    auditar(forcar=True, alvo=f"{f['de'].strftime('%d/%m/%Y')} a {f['ate'].strftime('%d/%m/%Y')}",
            detalhes={'filtros': {k: str(v) for k, v in f.items() if v}, 'linhas': len(linhas)})
    buf = BytesIO()
    wb = xlsxwriter.Workbook(buf, {'in_memory': True})
    ws = wb.add_worksheet('Auditoria')
    cab = wb.add_format({'bold': True, 'bg_color': '#0f1115', 'font_color': '#ffffff'})
    dt = wb.add_format({'num_format': 'dd/mm/yyyy hh:mm:ss'})
    quebra = wb.add_format({'text_wrap': True, 'valign': 'top'})
    titulos = ['Data/hora', 'Usuário', 'Perfil', 'IP', 'Módulo', 'Ação', 'Alvo', 'Resultado', 'Mudanças (antes → depois)', 'Detalhes']
    larg = [19, 22, 20, 15, 22, 34, 34, 10, 60, 60]
    for i, (t, w) in enumerate(zip(titulos, larg)):
        ws.write(0, i, t, cab); ws.set_column(i, i, w)
    for n, l in enumerate(linhas, start=1):
        mud = l['det'].get('mudancas') or {}
        txt_mud = '\n'.join(f"{k}: {v[0]} → {v[1]}" for k, v in mud.items())
        resto = {k: v for k, v in l['det'].items() if k != 'mudancas'}
        ws.write_datetime(n, 0, l['em'], dt)
        for i, v in enumerate([l['usuario'], l['perfil'], l['ip'], l['modulo'], l['acao'], l['alvo'], l['resultado']], start=1):
            ws.write_string(n, i, str(v or ''))
        ws.write_string(n, 8, txt_mud, quebra)
        ws.write_string(n, 9, _json.dumps(resto, ensure_ascii=False, default=str) if resto else '', quebra)
    ws.freeze_panes(1, 0)
    ws.autofilter(0, 0, max(len(linhas), 1), len(titulos) - 1)
    wb.close()
    buf.seek(0)
    nome = f"auditoria_{f['de'].strftime('%Y%m%d')}_{f['ate'].strftime('%Y%m%d')}.xlsx"
    return send_file(buf, as_attachment=True, download_name=nome,
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')


# ─── CONFIGURAÇÕES: LOCALIZAÇÕES ──────────────────────────────────────────────

@app.route('/admin/configuracoes/localizacoes', methods=['GET', 'POST'])
def config_localizacoes():
    if 'usuario_id' not in session:
        return redirect('/')
    if requer_admin():
        flash("Acesso restrito a administradores.", "error")
        return redirect('/usuario')
    usuario_logado = get_usuario_logado()
    dashboard_data = get_dashboard_data()

    cur = mysql.connection.cursor()

    if request.method == 'POST':
        nome = request.form.get('nome', '').strip().upper()
        if nome:
            try:
                cur.execute("INSERT INTO localizacoes (nome) VALUES (%s)", (nome,))
                mysql.connection.commit()
                flash(f"Localização '{nome}' adicionada com sucesso.", "success")
            except Exception as e:
                mysql.connection.rollback()
                flash("Erro ao adicionar localização (pode já existir).", "error")
        cur.close()
        return redirect(url_for('config_localizacoes'))

    search = request.args.get('search', '').strip()
    if search:
        cur.execute("SELECT id, nome FROM localizacoes WHERE nome LIKE %s ORDER BY nome ASC", (f'%{search}%',))
    else:
        cur.execute("SELECT id, nome FROM localizacoes ORDER BY nome ASC")
    lista_localizacoes = cur.fetchall()
    cur.close()

    return render_template('menu_admin.html',
                           module='config_localizacoes',
                           usuario=usuario_logado,
                           dashboard_data=dashboard_data,
                           lista_localizacoes=lista_localizacoes,
                           search=search)


@app.route('/admin/configuracoes/localizacoes/editar/<int:loc_id>', methods=['POST'])
def editar_localizacao(loc_id):
    if 'usuario_id' not in session or requer_admin():
        return redirect('/')
    novo_nome = request.form.get('nome', '').strip().upper()
    if novo_nome:
        cur = mysql.connection.cursor()
        try:
            cur.execute("UPDATE localizacoes SET nome = %s WHERE id = %s", (novo_nome, loc_id))
            mysql.connection.commit()
            flash("Localização atualizada com sucesso.", "success")
        except Exception:
            mysql.connection.rollback()
            flash("Erro ao atualizar localização.", "error")
        cur.close()
    return redirect(url_for('config_localizacoes'))


@app.route('/admin/configuracoes/localizacoes/excluir/<int:loc_id>', methods=['POST'])
def excluir_localizacao(loc_id):
    if 'usuario_id' not in session or requer_admin():
        return redirect('/')
    cur = mysql.connection.cursor()
    try:
        cur.execute("DELETE FROM localizacoes WHERE id = %s", (loc_id,))
        mysql.connection.commit()
        flash("Localização excluída com sucesso.", "success")
    except Exception:
        mysql.connection.rollback()
        flash("Erro ao excluir localização.", "error")
    cur.close()
    return redirect(url_for('config_localizacoes'))


@app.route('/modelo_colaboradores_csv')
def modelo_colaboradores_csv():
    if 'usuario_id' not in session or requer_admin():
        return redirect('/')
    modelo = (
        "nome,cpf,cargo,departamento,escala\n"
        "JOAO DA SILVA,123.456.789-09,ANALISTA,TECNOLOGIA,8h (Seg a Sex)\n"
        "MARIA SOUZA,987.654.321-00,ENFERMEIRA,UTI,12h noturno (12x36 / 12x60)\n"
    )
    return send_file(
        BytesIO(modelo.encode('utf-8-sig')),
        mimetype='text/csv',
        as_attachment=True,
        download_name='modelo_colaboradores.csv'
    )


@app.route('/importar_colaboradores', methods=['POST'])
def importar_colaboradores():
    if 'usuario_id' not in session or requer_admin():
        return redirect('/')

    usuario_logado = get_usuario_logado()
    arquivo = request.files.get('arquivo_csv')

    if not arquivo or not arquivo.filename.lower().endswith('.csv'):
        flash("Envie um arquivo no formato CSV.", "error")
        return redirect(url_for('cadastro'))

    try:
        conteudo = arquivo.read().decode('utf-8-sig')
        df = pd.read_csv(StringIO(conteudo), dtype=str)
    except Exception as e:
        flash(f"Erro ao ler o arquivo CSV: {str(e)}", "error")
        return redirect(url_for('cadastro'))

    df.columns = [c.strip().lower() for c in df.columns]
    faltando = {'nome', 'cpf', 'cargo', 'departamento', 'escala'} - set(df.columns)
    if faltando:
        flash(f"Colunas ausentes no CSV: {', '.join(sorted(faltando))}", "error")
        return redirect(url_for('cadastro'))

    init_escalas()
    cur = mysql.connection.cursor()
    cur.execute("SELECT cpf FROM colaboradores")
    cpfs_banco = {row[0] for row in cur.fetchall()}
    cur.execute("SELECT id, nome FROM escalas")
    escalas_banco = {' '.join(n.split()).upper(): i for i, n in cur.fetchall()}
    cur.execute("SELECT nome FROM departamentos")
    deps_banco = {row[0].upper() for row in cur.fetchall()}

    resultados = []
    inseridos = 0
    cpfs_no_csv = set()

    for idx, row in df.iterrows():
        linha = idx + 2

        nome        = str(row.get('nome', '')        or '').strip().upper()
        cpf_raw     = str(row.get('cpf', '')         or '').strip()
        cargo       = str(row.get('cargo', '')       or '').strip().upper()
        departamento = str(row.get('departamento', '') or '').strip().upper()
        escala_txt  = ' '.join(str(row.get('escala', '') or '').split()).upper()

        campos = [nome, cpf_raw, cargo, departamento, escala_txt]
        if not all(campos) or any(v in ('NAN', 'NONE') for v in campos):
            resultados.append({'linha': linha, 'nome': nome or '—', 'status': 'erro', 'motivo': 'Campo obrigatório vazio'})
            continue

        escala_id = escalas_banco.get(escala_txt)
        if not escala_id:
            resultados.append({'linha': linha, 'nome': nome, 'status': 'erro',
                               'motivo': f'Escala "{escala_txt}" não cadastrada — use o nome exato de Cadastro › Escalas'})
            continue

        if not validar_cpf(cpf_raw):
            resultados.append({'linha': linha, 'nome': nome, 'status': 'erro', 'motivo': f'CPF "{cpf_raw}" inválido'})
            continue

        if cpf_raw in cpfs_no_csv:
            resultados.append({'linha': linha, 'nome': nome, 'status': 'erro', 'motivo': 'CPF duplicado dentro do arquivo'})
            continue
        cpfs_no_csv.add(cpf_raw)

        if cpf_raw in cpfs_banco:
            resultados.append({'linha': linha, 'nome': nome, 'status': 'erro', 'motivo': 'CPF já cadastrado no sistema'})
            continue

        if departamento not in deps_banco:
            try:
                cur.execute("INSERT INTO departamentos (nome) VALUES (%s)", (departamento,))
                mysql.connection.commit()
                deps_banco.add(departamento)
            except Exception:
                mysql.connection.rollback()

        try:
            cur.execute(
                "INSERT INTO colaboradores (nome, cpf, cargo, departamento, tipo, escala_id) VALUES (%s,%s,%s,%s,1,%s)",
                (nome, cpf_raw, cargo, departamento, escala_id)
            )
            mysql.connection.commit()
            cpfs_banco.add(cpf_raw)
            inseridos += 1
            resultados.append({'linha': linha, 'nome': nome, 'status': 'sucesso', 'motivo': 'Importado com sucesso'})
        except Exception as e:
            mysql.connection.rollback()
            resultados.append({'linha': linha, 'nome': nome, 'status': 'erro', 'motivo': f'Erro: {str(e)}'})

    cur.close()
    logger.info(f"{usuario_logado} importou CSV: {inseridos}/{len(df)} colaboradores inseridos.")

    per_page = 20
    cur = mysql.connection.cursor()
    cur.execute("SELECT COUNT(*) FROM colaboradores")
    total_colaboradores = cur.fetchone()[0]
    total_pages = max((total_colaboradores + per_page - 1) // per_page, 1)
    cur.execute("""SELECT c.id, c.nome, c.cpf, c.cargo, c.departamento, c.tipo, c.escala_id, e.nome
                   FROM colaboradores c LEFT JOIN escalas e ON e.id = c.escala_id
                   ORDER BY c.nome LIMIT %s OFFSET %s""", (per_page, 0))
    colaboradores = cur.fetchall()
    cur.execute("SELECT COUNT(*) FROM colaboradores WHERE escala_id IS NULL")
    sem_escala = cur.fetchone()[0]
    cur.execute("SELECT nome FROM departamentos ORDER BY nome")
    departamentos_list = [row[0] for row in cur.fetchall()]
    cur.close()

    return render_template(
        'menu_admin.html',
        colaboradores=colaboradores,
        departamentos=departamentos_list,
        page=1,
        total_pages=total_pages,
        search='',
        escalas=listar_escalas(), filtro_escala='', sem_escala=sem_escala,
        module='cadastro',
        usuario=usuario_logado,
        import_result={'inseridos': inseridos, 'total': len(df), 'linhas': resultados}
    )


if __name__ == '__main__':
    app.run(debug=os.environ.get('FLASK_DEBUG') == '1', host='0.0.0.0')