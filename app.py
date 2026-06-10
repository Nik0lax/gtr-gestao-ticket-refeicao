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

##################################CONFIGS##################################
logger = get_logger()

app = Flask(__name__)
app.secret_key = 'gtr'
logger.info("🚀 Aplicação iniciada.")

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

def get_usuario_logado():
    return session.get('usuario_nome', 'Usuário não autenticado')

def requer_admin():
    """Retorna True se o usuário NÃO for admin."""
    return session.get('usuario_perfil') != 'admin'

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

config_pdf = pdfkit.configuration(wkhtmltopdf='/usr/bin/wkhtmltopdf')

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
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER') or 'gtruser'
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD') or 'Psm@cqua'
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB') or 'gtr'
mysql = MySQL(app)

##################################APP##################################

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usuario = request.form['usuario']
        senha = request.form['senha']
        cur = mysql.connection.cursor()
        cur.execute("SELECT id, nome, senha, perfil FROM usuarios WHERE usuario = %s AND status = TRUE", (usuario,))
        logger.info(f"Consultando se o {usuario} existe no banco de dados...")
        usuario_db = cur.fetchone()
        cur.close()
        if usuario_db:
            id, nome, senha_armazenada, perfil = usuario_db
            # Suporta hashes werkzeug e plain text legado (migração automática)
            if senha_armazenada.startswith(('pbkdf2:', 'scrypt:')):
                senha_ok = check_password_hash(senha_armazenada, senha)
            else:
                senha_ok = (senha == senha_armazenada)
                if senha_ok:
                    cur2 = mysql.connection.cursor()
                    cur2.execute("UPDATE usuarios SET senha=%s WHERE id=%s",
                                 (generate_password_hash(senha), id))
                    mysql.connection.commit()
                    cur2.close()
                    logger.info(f"Senha de '{usuario}' migrada para hash.")
        else:
            senha_ok = False
        if senha_ok:
            session.update({'usuario_id': id, 'usuario_nome': nome, 'usuario_perfil': perfil})
            logger.info(f"{usuario} logou com sucesso!")
            destinos = {
                'admin': '/admin', 'usuario': '/usuario',
                'totem_desktop': '/emissao_senha', 'totem_tablet': '/emissao_senha_tablet'
            }
            return redirect(destinos.get(perfil, '/'))
        else:
            logger.info("Usuário não encontrado ou senha incorreta.")
            flash("Usuário não encontrado ou senha incorreta.")
    return render_template('login.html')


@app.route('/admin')
def admin():
    if 'usuario_id' not in session:
        return redirect('/')
    if requer_admin():
        flash("Acesso restrito a administradores.", "error")
        return redirect('/usuario')
    usuario_logado = get_usuario_logado()
    dashboard_data = get_dashboard_data()
    return render_template('menu_admin.html', module=None, usuario=usuario_logado, dashboard_data=dashboard_data)


@app.route('/usuario')
def usuario():
    if 'usuario_id' not in session:
        return redirect('/')
    usuario_logado = get_usuario_logado()
    dashboard_data = get_dashboard_data()
    return render_template('menu_usuario.html', modulo=None, usuario=usuario_logado, dashboard_data=dashboard_data)


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
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page

    cur = mysql.connection.cursor()

    if search:
        logger.info(f"{usuario_logado} pesquisou colaborador: '{search}'")
        cur.execute("SELECT COUNT(*) FROM colaboradores WHERE nome LIKE %s OR cpf LIKE %s",
                    (f"%{search}%", f"%{search}%"))
    else:
        cur.execute("SELECT COUNT(*) FROM colaboradores")

    total_colaboradores = cur.fetchone()[0]
    total_pages = max((total_colaboradores + per_page - 1) // per_page, 1)

    if search:
        cur.execute("SELECT * FROM colaboradores WHERE nome LIKE %s OR cpf LIKE %s ORDER BY nome LIMIT %s OFFSET %s",
                    (f"%{search}%", f"%{search}%", per_page, offset))
    else:
        cur.execute("SELECT * FROM colaboradores ORDER BY nome LIMIT %s OFFSET %s", (per_page, offset))

    colaboradores = cur.fetchall()
    cur.execute("SELECT nome FROM departamentos ORDER BY nome")
    departamentos = [row[0] for row in cur.fetchall()]
    cur.close()

    if request.method == 'POST':
        nome = request.form['nome'].strip().upper()
        cpf = request.form['cpf'].strip()
        cargo = request.form['cargo'].strip().upper()
        departamento = request.form['departamento'].strip()
        tipo = request.form['tipo'].strip()

        if not all([nome, cpf, cargo, departamento, tipo]):
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
            cur.execute("INSERT INTO colaboradores (nome, cpf, cargo, departamento, tipo) VALUES (%s,%s,%s,%s,%s)",
                        (nome, cpf, cargo, departamento, tipo))
            mysql.connection.commit()
            logger.info(f"{usuario_logado} cadastrou colaborador {nome}.")
            flash("Colaborador cadastrado com sucesso!", "success")
        except Exception as e:
            mysql.connection.rollback()
            flash(f"Erro ao cadastrar colaborador: {str(e)}", "error")
        finally:
            cur.close()
        return redirect(url_for('cadastro'))

    tmpl = 'menu_admin.html' if perfil == 'admin' else 'menu_usuario.html'
    return render_template(tmpl, colaboradores=colaboradores, departamentos=departamentos,
                           page=page, total_pages=total_pages, search=search,
                           module='cadastro', usuario=usuario_logado)


@app.route('/editar_colaborador/<int:colaborador_id>', methods=['POST'])
def editar_colaborador(colaborador_id):
    if 'usuario_id' not in session or requer_admin():
        return redirect('/')
    usuario_logado = get_usuario_logado()
    nome = request.form['nome'].strip().upper()
    cargo = request.form['cargo'].strip().upper()
    departamento = request.form['departamento'].strip()
    tipo = request.form['tipo'].strip()
    try:
        cur = mysql.connection.cursor()
        cur.execute("UPDATE colaboradores SET nome=%s, cargo=%s, departamento=%s, tipo=%s WHERE id=%s",
                    (nome, cargo, departamento, tipo, colaborador_id))
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

    cur = mysql.connection.cursor()
    cur.execute("SELECT id, nome, usuario, perfil, status FROM usuarios ORDER BY nome ASC")
    usuarios = cur.fetchall()
    cur.close()

    if request.method == 'POST':
        nome = request.form['nome'].strip().upper()
        usuario_form = request.form['usuario'].strip()
        senha = request.form['senha'].strip()
        perfil = request.form['perfil'].strip()

        if not all([nome, usuario_form, senha, perfil]):
            flash("Todos os campos são obrigatórios.", "error")
            return redirect(url_for('cadastro_usuario'))

        cur = mysql.connection.cursor()
        cur.execute("SELECT id FROM usuarios WHERE usuario = %s", (usuario_form,))
        if cur.fetchone():
            flash("Esse nome de usuário já está cadastrado.", "error")
            cur.close()
            return redirect(url_for('cadastro_usuario'))

        try:
            cur.execute("INSERT INTO usuarios (nome, usuario, senha, perfil, status, criado_em) VALUES (%s,%s,%s,%s,1,NOW())",
                        (nome, usuario_form, generate_password_hash(senha), perfil))
            mysql.connection.commit()
            logger.info(f"{usuario_logado} cadastrou usuário '{usuario_form}'.")
            flash("Usuário cadastrado com sucesso!", "success")
        except Exception as e:
            mysql.connection.rollback()
            flash(f"Erro ao cadastrar usuário: {str(e)}", "error")
        finally:
            cur.close()
        return redirect(url_for('cadastro_usuario'))

    return render_template('menu_admin.html', usuarios=usuarios, module='cadastro_usuario', usuario=usuario_logado)


@app.route('/editar_usuario/<int:usuario_id>', methods=['POST'])
def editar_usuario(usuario_id):
    if 'usuario_id' not in session or requer_admin():
        return redirect('/')
    usuario_logado = get_usuario_logado()

    novo_nome    = request.form.get('nome', '').strip().upper()
    novo_login   = request.form.get('usuario_login', '').strip()
    novo_perfil  = request.form.get('perfil', '').strip()
    nova_senha   = request.form.get('nova_senha', '').strip()

    if not all([novo_nome, novo_login, novo_perfil]):
        flash("Nome, usuário e perfil são obrigatórios.", "error")
        return redirect(url_for('cadastro_usuario'))

    if usuario_id == session.get('usuario_id') and novo_perfil != 'admin':
        flash("Você não pode alterar o próprio perfil.", "error")
        return redirect(url_for('cadastro_usuario'))

    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT id FROM usuarios WHERE usuario = %s AND id != %s", (novo_login, usuario_id))
        if cur.fetchone():
            flash("Esse nome de usuário já está em uso.", "error")
            cur.close()
            return redirect(url_for('cadastro_usuario'))

        if nova_senha:
            cur.execute("UPDATE usuarios SET nome=%s, usuario=%s, perfil=%s, senha=%s WHERE id=%s",
                        (novo_nome, novo_login, novo_perfil, generate_password_hash(nova_senha), usuario_id))
        else:
            cur.execute("UPDATE usuarios SET nome=%s, usuario=%s, perfil=%s WHERE id=%s",
                        (novo_nome, novo_login, novo_perfil, usuario_id))
        mysql.connection.commit()
        cur.close()
        msg = f"Usuário '{novo_login}' atualizado." + (" Senha redefinida." if nova_senha else "")
        logger.info(f"{usuario_logado} editou usuário ID {usuario_id}: {msg}")
        flash("Usuário atualizado com sucesso!" + (" Senha redefinida." if nova_senha else ""), "success")
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

    tmpl = 'menu_admin.html' if perfil == 'admin' else 'menu_usuario.html'
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

        def count_colab(h_ini, h_fim):
            cursor.execute(
                "SELECT COUNT(*) FROM emissoes_senha "
                "WHERE TIME(data_hora) BETWEEN %s AND %s "
                "AND cargo != %s AND DATE(data_hora) BETWEEN %s AND %s",
                (h_ini, h_fim, 'VISITANTE', data_inicio, data_fim)
            )
            return cursor.fetchone()[0]

        def count_visit(h_ini, h_fim):
            cursor.execute(
                "SELECT COUNT(*) FROM emissoes_senha "
                "WHERE TIME(data_hora) BETWEEN %s AND %s "
                "AND cargo = %s AND DATE(data_hora) BETWEEN %s AND %s",
                (h_ini, h_fim, 'VISITANTE', data_inicio, data_fim)
            )
            return cursor.fetchone()[0]

        t = get_turnos()
        CAFE_INI   = t['turno_cafe_ini'].strftime('%H:%M:00')
        CAFE_FIM   = t['turno_cafe_fim'].strftime('%H:%M:59')
        ALMOCO_INI = t['turno_almoco_ini'].strftime('%H:%M:00')
        ALMOCO_FIM = t['turno_almoco_fim'].strftime('%H:%M:59')
        JANTA_INI  = t['turno_janta_ini'].strftime('%H:%M:00')
        JANTA_FIM  = t['turno_janta_fim'].strftime('%H:%M:59')

        total_senhas      = q("SELECT COUNT(*) FROM emissoes_senha WHERE DATE(data_hora) BETWEEN %s AND %s", (data_inicio, data_fim))
        total_visitantes  = q("SELECT COUNT(*) FROM emissoes_senha WHERE cargo = %s  AND DATE(data_hora) BETWEEN %s AND %s", ('VISITANTE', data_inicio, data_fim))
        total_colaborador = q("SELECT COUNT(*) FROM emissoes_senha WHERE cargo != %s AND DATE(data_hora) BETWEEN %s AND %s", ('VISITANTE', data_inicio, data_fim))

        cafe_colab   = count_colab(CAFE_INI,   CAFE_FIM)
        cafe_visit   = count_visit(CAFE_INI,   CAFE_FIM)
        almoco_colab = count_colab(ALMOCO_INI, ALMOCO_FIM)
        almoco_visit = count_visit(ALMOCO_INI, ALMOCO_FIM)
        janta_colab  = count_colab(JANTA_INI,  JANTA_FIM)
        janta_visit  = count_visit(JANTA_INI,  JANTA_FIM)

        # breakdown por departamento com contagem por turno numa única query
        cursor.execute(
            """SELECT departamento,
                      SUM(TIME(data_hora) BETWEEN %s AND %s) AS cafe,
                      SUM(TIME(data_hora) BETWEEN %s AND %s) AS almoco,
                      SUM(TIME(data_hora) BETWEEN %s AND %s) AS janta,
                      COUNT(*) AS total
               FROM emissoes_senha
               WHERE DATE(data_hora) BETWEEN %s AND %s
               GROUP BY departamento
               ORDER BY total DESC""",
            (CAFE_INI, CAFE_FIM, ALMOCO_INI, ALMOCO_FIM, JANTA_INI, JANTA_FIM, data_inicio, data_fim)
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
        pdf = pdfkit.from_string(html, False, configuration=config_pdf)
        logger.info(f"{usuario_logado} emitiu relatório total ({periodo}).")
        return send_file(BytesIO(pdf), download_name='relatorio_totalEmissao.pdf', as_attachment=True)

    tmpl = 'menu_admin.html' if perfil == 'admin' else 'menu_usuario.html'
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
            pdf = pdfkit.from_string(html, False, configuration=config_pdf)
            logger.info(f"{usuario_logado} emitiu relatório diário (PDF).")
            return send_file(BytesIO(pdf), download_name='relatorio_emissoesDiarias.pdf', as_attachment=True)

    tmpl = 'menu_admin.html' if perfil == 'admin' else 'menu_usuario.html'
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

        departamento = request.form.get('departamento')
        tipo_relatorio = request.form.get('tipo_relatorio')
        dt_inicio = datetime.combine(data_inicial, time(0, 0))
        dt_fim = datetime.combine(data_final, time(23, 59))

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT numero_senha,cpf,nome,cargo,departamento,data_hora FROM emissoes_senha WHERE data_hora BETWEEN %s AND %s AND departamento=%s ORDER BY data_hora ASC", (dt_inicio, dt_fim, departamento))
        registros = [dict(zip([d[0] for d in cursor.description], r)) for r in cursor.fetchall()]
        cursor.close()

        t = get_turnos()
        total_geral = len(registros)
        total_cafe = total_almoco = total_janta = 0
        for r in registros:
            h = r['data_hora'].time()
            if t['turno_cafe_ini'] <= h <= t['turno_cafe_fim']: total_cafe += 1
            elif t['turno_almoco_ini'] <= h <= t['turno_almoco_fim']: total_almoco += 1
            else: total_janta += 1

        periodo = f"{data_inicial.strftime('%d/%m/%Y')} até {data_final.strftime('%d/%m/%Y')}"
        agora = datetime.now().strftime('%d/%m/%Y %H:%M')

        if tipo_relatorio == 'excel':
            df = pd.DataFrame(registros)
            output = BytesIO()
            with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                wb = writer.book; ws = wb.add_worksheet("Relatório"); writer.sheets['Relatório'] = ws
                bold = wb.add_format({'bold': True})
                ws.write('A1','Relatório de Emissões de Visitantes', bold)
                ws.write('A3','Localização:', bold); ws.write('B3', departamento)
                ws.write('A4','Período:', bold); ws.write('B4', periodo)
                ws.write('A6','Total Café:', bold); ws.write('B6', total_cafe)
                ws.write('A7','Total Almoço:', bold); ws.write('B7', total_almoco)
                ws.write('A8','Total Janta:', bold); ws.write('B8', total_janta)
                ws.write('A9','Total Geral:', bold); ws.write('B9', total_geral)
                df.to_excel(writer, sheet_name='Relatório', startrow=10, index=False)
                for i, col in enumerate(df.columns):
                    ws.set_column(i, i, max(df[col].astype(str).map(len).max(), len(col)) + 2)
            output.seek(0)
            return send_file(output, download_name='relatorio_totalVisitantes.xlsx', as_attachment=True)
        else:
            html = render_template('relatorio_totalVisitantes.html', registros=registros,
                                   data_geracao=periodo, agora=agora, departamento=departamento,
                                   total_cafe=total_cafe, total_almoco=total_almoco,
                                   total_janta=total_janta, total_geral=total_geral,
                                   nome_instituicao=get_instituicao())
            pdf = pdfkit.from_string(html, False, configuration=config_pdf)
            return send_file(BytesIO(pdf), download_name='relatorio_totalVisitantes.pdf', as_attachment=True)

    tmpl = 'menu_admin.html' if perfil == 'admin' else 'menu_usuario.html'
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
        dt_fim = datetime.combine(data_final, time(23, 59))

        cursor = mysql.connection.cursor()
        if departamento == 'TODOS':
            cursor.execute("SELECT numero_senha,cpf,nome,cargo,departamento,data_hora FROM emissoes_senha WHERE data_hora BETWEEN %s AND %s ORDER BY data_hora ASC", (dt_inicio, dt_fim))
        else:
            cursor.execute("SELECT numero_senha,cpf,nome,cargo,departamento,data_hora FROM emissoes_senha WHERE data_hora BETWEEN %s AND %s AND departamento=%s ORDER BY data_hora ASC", (dt_inicio, dt_fim, departamento))

        registros = [dict(zip([d[0] for d in cursor.description], r)) for r in cursor.fetchall()]
        cursor.close()

        t = get_turnos()
        total_geral = len(registros)
        total_cafe = total_almoco = total_janta = 0
        for r in registros:
            h = r['data_hora'].time()
            if t['turno_cafe_ini'] <= h <= t['turno_cafe_fim']: total_cafe += 1
            elif t['turno_almoco_ini'] <= h <= t['turno_almoco_fim']: total_almoco += 1
            else: total_janta += 1

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
                ws.write('A8','Total Janta:', bold); ws.write('B8', total_janta)
                ws.write('A9','Total Geral:', bold); ws.write('B9', total_geral)
                df.to_excel(writer, sheet_name='Relatório', startrow=10, index=False)
                for i, col in enumerate(df.columns):
                    ws.set_column(i, i, max(df[col].astype(str).map(len).max(), len(col)) + 2)
            output.seek(0)
            return send_file(output, download_name='relatorio_totalDepartamentos.xlsx', as_attachment=True)
        else:
            html = render_template('relatorio_totalDepartamentos.html', registros=registros,
                                   data_geracao=periodo, agora=agora, departamento=departamento,
                                   total_cafe=total_cafe, total_almoco=total_almoco,
                                   total_janta=total_janta, total_geral=total_geral,
                                   nome_instituicao=get_instituicao())
            pdf = pdfkit.from_string(html, False, configuration=config_pdf)
            return send_file(BytesIO(pdf), download_name='relatorio_totalDepartamentos.pdf', as_attachment=True)

    tmpl = 'menu_admin.html' if perfil == 'admin' else 'menu_usuario.html'
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
        cur.execute("SELECT nome, cpf, cargo, departamento, tipo FROM colaboradores WHERE cpf = %s", (cpf,))
        colaborador = cur.fetchone()

        if colaborador:
            nome, cpf, cargo, departamento, limite_diario = colaborador
            data_hoje = date.today()
            cur.execute("SELECT COUNT(*) FROM emissoes_senha WHERE cpf=%s AND DATE(data_hora)=%s", (cpf, data_hoje))
            if cur.fetchone()[0] >= limite_diario:
                flash("Você atingiu o limite diário de emissões.", "error")
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
            finally:
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

    cardapios_hoje = []
    if tipo_emissao == 'cardapio':
        cur.execute("""
            SELECT id, tipo_refeicao, descricao, foto
            FROM cardapios
            WHERE ativo = 1 AND data_cardapio = CURDATE()
            ORDER BY FIELD(tipo_refeicao,'Café da Manhã','Almoço','Lanche','Jantar')
        """)
        cardapios_hoje = [
            {'id': r[0], 'tipo_refeicao': r[1], 'descricao': r[2], 'foto': r[3]}
            for r in cur.fetchall()
        ]
    cur.close()

    if request.method == 'POST':
        nome       = request.form['nome'].strip().upper()
        cpf        = request.form['cpf'].strip()
        localizacao = request.form['localizacoes'].strip().upper()

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
            cardapio_id, c_tipo, c_descricao = cardapio

        cur = mysql.connection.cursor()
        data_hoje = date.today()
        limite_diario = 3 if localizacao == "ACOMPANHANTE" else 1
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
        finally:
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


@app.route('/cardapio')
def cardapio_publico():
    from datetime import date as _date
    hoje = _date.today()
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT id, data_cardapio, tipo_refeicao, descricao, foto
        FROM cardapios
        WHERE ativo = 1
          AND data_cardapio = %s
        ORDER BY FIELD(tipo_refeicao,'Café da Manhã','Almoço','Lanche','Jantar')
    """, (hoje,))
    rows = cur.fetchall()
    cur.close()

    _DIAS_PT = {
        'Monday': 'Segunda-feira', 'Tuesday': 'Terça-feira',
        'Wednesday': 'Quarta-feira', 'Thursday': 'Quinta-feira',
        'Friday': 'Sexta-feira', 'Saturday': 'Sábado', 'Sunday': 'Domingo'
    }
    dia_en  = hoje.strftime('%A')
    dia_pt  = _DIAS_PT.get(dia_en, dia_en)
    dia_fmt = f"{dia_pt}, {hoje.strftime('%d/%m/%Y')}"

    cardapios_hoje = [
        {'id': r[0], 'tipo_refeicao': r[2], 'descricao': r[3], 'foto': r[4]}
        for r in rows
    ]

    agora = datetime.now().strftime('%d/%m/%Y %H:%M')
    return render_template(
        'cardapio_publico.html',
        cardapios_hoje=cardapios_hoje,
        dia_fmt=dia_fmt,
        agora=agora
    )

@app.route('/admin/cardapio')
def cardapio_admin():
    if 'usuario_id' not in session:
        return redirect('/')
    if requer_admin():
        flash("Acesso restrito a administradores.", "error")
        return redirect('/usuario')
    usuario_logado = get_usuario_logado()
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT id, data_cardapio, tipo_refeicao, descricao, foto, ativo
        FROM cardapios
        ORDER BY data_cardapio DESC, FIELD(tipo_refeicao,'Café da Manhã','Almoço','Lanche','Jantar')
    """)
    cardapios = cur.fetchall()
    cur.close()
    return render_template('menu_admin.html', module='cardapio_lista',
                           cardapios=cardapios, usuario=usuario_logado)


@app.route('/admin/cardapio/novo')
def cardapio_novo():
    if 'usuario_id' not in session:
        return redirect('/')
    if requer_admin():
        flash("Acesso restrito a administradores.", "error")
        return redirect('/usuario')
    return render_template('menu_admin.html', module='cardapio_novo',
                           usuario=get_usuario_logado())


@app.route('/admin/cardapio/editar/<int:cardapio_id>')
def cardapio_editar(cardapio_id):
    if 'usuario_id' not in session:
        return redirect('/')
    if requer_admin():
        flash("Acesso restrito a administradores.", "error")
        return redirect('/usuario')
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, data_cardapio, tipo_refeicao, descricao, foto, ativo FROM cardapios WHERE id = %s", (cardapio_id,))
    cardapio_edit = cur.fetchone()
    cur.close()
    if not cardapio_edit:
        flash("Cardápio não encontrado.", "error")
        return redirect(url_for('cardapio_admin'))
    return render_template('menu_admin.html', module='cardapio_editar',
                           cardapio_edit=cardapio_edit, usuario=get_usuario_logado())


@app.route('/admin/cardapio/salvar', methods=['POST'])
@app.route('/admin/cardapio/salvar/<int:cardapio_id>', methods=['POST'])
def cardapio_salvar(cardapio_id=None):
    if 'usuario_id' not in session:
        return redirect('/')
    if requer_admin():
        flash("Acesso restrito a administradores.", "error")
        return redirect('/usuario')

    usuario_logado = get_usuario_logado()
    data_cardapio  = request.form.get('data_cardapio', '').strip()
    tipo_refeicao  = request.form.get('tipo_refeicao', '').strip()
    descricao      = request.form.get('descricao', '').strip()
    ativo          = int(request.form.get('ativo', 1))

    if not all([data_cardapio, tipo_refeicao, descricao]):
        flash("Preencha todos os campos obrigatórios.", "error")
        redir = url_for('cardapio_editar', cardapio_id=cardapio_id) if cardapio_id else url_for('cardapio_novo')
        return redirect(redir)

    foto_nome = None
    foto_file = request.files.get('foto')
    if foto_file and foto_file.filename:
        foto_nome = _cardapio_upload_foto(foto_file)
        if foto_nome is None:
            flash("Foto inválida. Use JPG/PNG/WEBP com no máximo 5 MB.", "error")
            redir = url_for('cardapio_editar', cardapio_id=cardapio_id) if cardapio_id else url_for('cardapio_novo')
            return redirect(redir)

    try:
        cur = mysql.connection.cursor()
        if cardapio_id:
            if foto_nome:
                cur.execute("""
                    UPDATE cardapios SET data_cardapio=%s, tipo_refeicao=%s, descricao=%s, foto=%s, ativo=%s
                    WHERE id=%s
                """, (data_cardapio, tipo_refeicao, descricao, foto_nome, ativo, cardapio_id))
            else:
                cur.execute("""
                    UPDATE cardapios SET data_cardapio=%s, tipo_refeicao=%s, descricao=%s, ativo=%s
                    WHERE id=%s
                """, (data_cardapio, tipo_refeicao, descricao, ativo, cardapio_id))
            logger.info(f"{usuario_logado} editou cardápio ID {cardapio_id}.")
            flash("Cardápio atualizado com sucesso!", "success")
        else:
            cur.execute("""
                INSERT INTO cardapios (data_cardapio, tipo_refeicao, descricao, foto, ativo, criado_em)
                VALUES (%s, %s, %s, %s, %s, NOW())
            """, (data_cardapio, tipo_refeicao, descricao, foto_nome, ativo))
            logger.info(f"{usuario_logado} criou novo cardápio ({tipo_refeicao} / {data_cardapio}).")
            flash("Cardápio cadastrado com sucesso!", "success")
        mysql.connection.commit()
        cur.close()
    except Exception as e:
        mysql.connection.rollback()
        flash(f"Erro ao salvar cardápio: {str(e)}", "error")
    return redirect(url_for('cardapio_admin'))


@app.route('/admin/cardapio/toggle/<int:cardapio_id>', methods=['POST'])
def cardapio_toggle(cardapio_id):
    if 'usuario_id' not in session or requer_admin():
        return redirect('/')
    try:
        cur = mysql.connection.cursor()
        cur.execute("UPDATE cardapios SET ativo = NOT ativo WHERE id = %s", (cardapio_id,))
        mysql.connection.commit()
        cur.close()
        flash("Status atualizado.", "success")
    except Exception as e:
        mysql.connection.rollback()
        flash("Erro ao atualizar status.", "error")
    return redirect(url_for('cardapio_admin'))


@app.route('/admin/cardapio/excluir/<int:cardapio_id>', methods=['POST'])
def cardapio_excluir(cardapio_id):
    if 'usuario_id' not in session or requer_admin():
        return redirect('/')
    usuario_logado = get_usuario_logado()
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT foto FROM cardapios WHERE id = %s", (cardapio_id,))
        row = cur.fetchone()
        if row and row[0]:
            foto_path = os.path.join(CARDAPIO_UPLOAD_FOLDER, row[0])
            if os.path.exists(foto_path):
                os.remove(foto_path)
        cur.execute("DELETE FROM cardapios WHERE id = %s", (cardapio_id,))
        mysql.connection.commit()
        cur.close()
        logger.info(f"{usuario_logado} excluiu cardápio ID {cardapio_id}.")
        flash("Cardápio excluído com sucesso.", "success")
    except Exception as e:
        mysql.connection.rollback()
        flash("Erro ao excluir cardápio.", "error")
    return redirect(url_for('cardapio_admin'))



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

            if t['turno_cafe_ini'] <= h <= t['turno_cafe_fim']:
                dados[g][dept]['qtd_cafe'] += 1
            elif t['turno_almoco_ini'] <= h <= t['turno_almoco_fim']:
                dados[g][dept]['qtd_almoco'] += 1
            else:
                dados[g][dept]['qtd_janta'] += 1

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
            pdf = pdfkit.from_string(html_str, False, configuration=config_pdf)
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

    tmpl = 'menu_admin.html' if perfil == 'admin' else 'menu_usuario.html'
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
            pdf = pdfkit.from_string(html, False, configuration=config_pdf)
            return send_file(BytesIO(pdf), download_name='relatorio_cardapio.pdf', as_attachment=True)

    tmpl = 'menu_admin.html' if perfil == 'admin' else 'menu_usuario.html'
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
    cur.execute("""
        SELECT id, tipo_refeicao, descricao, foto
        FROM cardapios
        WHERE ativo = 1 AND data_cardapio = CURDATE()
        ORDER BY FIELD(tipo_refeicao,'Café da Manhã','Almoço','Lanche','Jantar')
    """)
    cardapios_hoje = [
        {'id': r[0], 'tipo_refeicao': r[1], 'descricao': r[2], 'foto': r[3]}
        for r in cur.fetchall()
    ]
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

        cur.execute("SELECT nome, cpf, cargo, departamento, tipo FROM colaboradores WHERE cpf = %s", (cpf,))
        colaborador = cur.fetchone()
        if not colaborador:
            flash("CPF não encontrado na base de colaboradores.", "error")
            cur.close()
            return redirect(url_for('senha_colaborador_cardapio', **extra))

        nome, cpf_db, cargo, departamento, limite_diario = colaborador
        data_hoje = date.today()

        cur.execute("SELECT COUNT(*) FROM emissoes_senha WHERE cpf=%s AND DATE(data_hora)=%s", (cpf_db, data_hoje))
        if cur.fetchone()[0] >= limite_diario:
            flash("Você atingiu o limite diário de emissões.", "error")
            cur.close()
            return redirect(url_for('senha_colaborador_cardapio', **extra))

        cur.execute(
            "SELECT id, tipo_refeicao, descricao FROM cardapios WHERE id=%s AND ativo=1 AND data_cardapio=CURDATE()",
            (cardapio_id,)
        )
        cardapio = cur.fetchone()
        if not cardapio:
            flash("Cardápio inválido ou indisponível.", "error")
            cur.close()
            return redirect(url_for('senha_colaborador_cardapio', **extra))

        c_id, c_tipo, c_descricao = cardapio

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
        finally:
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
        "nome,cpf,cargo,departamento,tipo\n"
        "JOAO DA SILVA,123.456.789-09,ANALISTA,TECNOLOGIA,1\n"
        "MARIA SOUZA,987.654.321-00,GERENTE,RECURSOS HUMANOS,1\n"
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
    faltando = {'nome', 'cpf', 'cargo', 'departamento', 'tipo'} - set(df.columns)
    if faltando:
        flash(f"Colunas ausentes no CSV: {', '.join(sorted(faltando))}", "error")
        return redirect(url_for('cadastro'))

    cur = mysql.connection.cursor()
    cur.execute("SELECT cpf FROM colaboradores")
    cpfs_banco = {row[0] for row in cur.fetchall()}
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
        tipo        = str(row.get('tipo', '')        or '').strip()

        campos = [nome, cpf_raw, cargo, departamento, tipo]
        if not all(campos) or any(v in ('NAN', 'NONE') for v in campos):
            resultados.append({'linha': linha, 'nome': nome or '—', 'status': 'erro', 'motivo': 'Campo obrigatório vazio'})
            continue

        if tipo not in ('1', '2', '3', '4'):
            resultados.append({'linha': linha, 'nome': nome, 'status': 'erro', 'motivo': f'Tipo "{tipo}" inválido — use 1, 2, 3 ou 4'})
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
                "INSERT INTO colaboradores (nome, cpf, cargo, departamento, tipo) VALUES (%s,%s,%s,%s,%s)",
                (nome, cpf_raw, cargo, departamento, tipo)
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
    cur.execute("SELECT * FROM colaboradores ORDER BY nome LIMIT %s OFFSET %s", (per_page, 0))
    colaboradores = cur.fetchall()
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
        module='cadastro',
        usuario=usuario_logado,
        import_result={'inseridos': inseridos, 'total': len(df), 'linhas': resultados}
    )


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')