from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, make_response, send_file
from flask_mysqldb import MySQL
from datetime import datetime, date, timedelta
from io import BytesIO
import pdfkit
import matplotlib.pyplot as plt
import base64
import io
import pandas as pd


from log_config import get_logger

##################################CONFIGS##################################
# Inicializa o logger antes de criar o app
logger = get_logger()

app = Flask(__name__)
app.secret_key = 'gtr_hmpa'
logger.info("🚀 Aplicação iniciada.")

# Configuração de navegador, para não armazenar dados no cache
@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

#Validação de CPF
def validar_cpf(cpf):
    """
    Valida CPF com ou sem formatação.
    """
    import re

    # Remove pontuação
    cpf = re.sub(r'\D', '', cpf)

    # Verifica se tem 11 dígitos ou todos iguais (ex: 111.111.111-11)
    if len(cpf) != 11 or cpf == cpf[0] * 11:
        return False

    # Valida os dois dígitos verificadores
    for i in range(9, 11):
        soma = sum(int(cpf[j]) * ((i + 1) - j) for j in range(i))
        digito = ((soma * 10) % 11) % 10
        if digito != int(cpf[i]):
            return False

    return True

#Armazena a sessão do usuario
def get_usuario_logado():
    return session.get('usuario_nome', 'Usuário não autenticado')

#Indicadores tela inicial
def get_dashboard_data():
    cursor = mysql.connection.cursor()

    cursor.execute("SELECT COUNT(*) FROM emissoes_senha WHERE DATE(data_hora) = CURDATE()")
    total_hoje = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM emissoes_senha")
    total_senhas = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM colaboradores")  # Ajusta se o nome da tabela for outro
    total_colaboradores = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM departamentos")
    total_departamentos = cursor.fetchone()[0]

    cursor.execute("SELECT MAX(data_hora) FROM emissoes_senha")
    ultima_emissao = cursor.fetchone()[0]

    cursor.close()

    return {
        'total_hoje': total_hoje,
        'total_senhas': total_senhas,
        'total_colaboradores': total_colaboradores,
        'total_departamentos': total_departamentos,
        'ultima_emissao': ultima_emissao.strftime('%d/%m/%Y %H:%M') if ultima_emissao else 'N/A'
    }


# Diretório do PDFKIT
config_pdf = pdfkit.configuration(wkhtmltopdf='/usr/bin/wkhtmltopdf')  

# Configuração do MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'gtruser'
app.config['MYSQL_PASSWORD'] = 'Psm@cqua'
app.config['MYSQL_DB'] = 'gtr'
mysql = MySQL(app)

##################################APP##################################


@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usuario = request.form['usuario']
        senha = request.form['senha']

        # Consulta o usuário no banco
        cur = mysql.connection.cursor()
        cur.execute("SELECT id, nome, senha, perfil FROM usuarios WHERE usuario = %s AND status = TRUE", (usuario,))
        logger.info(f"Consultando se o {usuario} existe no banco de dados...")
        usuario_db = cur.fetchone()
        cur.close()

         # Verifica se o usuário foi encontrado
        if usuario_db and senha == usuario_db[2]:
            id, nome, senha_db, perfil = usuario_db  # Extrai os dados
            session.update({
                'usuario_id': id,
                'usuario_nome': nome,
                'usuario_perfil': perfil
            })

            # Redireciona com base no perfil
            if perfil == 'admin':
                logger.info(f"{usuario} logando com sucesso!")
                return redirect('/admin')
            
            elif perfil == 'usuario':
                logger.info(f"{usuario} logando com sucesso!")
                return redirect('/usuario')
            
            elif perfil == 'totem_desktop':
                logger.info(f"{usuario} logando com sucesso!")
                return redirect('/emissao_senha')
            
            elif perfil == 'totem_tablet':
                logger.info(f"{usuario} logando com sucesso!")
                return redirect('/emissao_senha_tablet')
            
            else:
                flash("Perfil não reconhecido.")
                logger.info(f"perfil do {usuario} não foi reconhecido.")
                return redirect('/')

        else:
            logger.info("Usuário não encontrado ou senha incorreta.")
            flash("Usuário não encontrado ou senha incorreta.")  # Erro genérico
            

    return render_template('login.html')

@app.route('/admin')
def admin():
    if 'usuario_id' not in session:
        return redirect('/')
    
    usuario_logado = get_usuario_logado()
    dashboard_data = get_dashboard_data()
    return render_template('menu_admin.html', module=None, usuario=usuario_logado, dashboard_data=dashboard_data)

@app.route('/usuario')
def usuario(): 
    if 'usuario_id' not in session:
        return redirect('/')
    
    usuario_logado = get_usuario_logado()
    dashboard_data = get_dashboard_data()
    return render_template('menu_usuario.html', module=None, usuario=usuario_logado, dashboard_data=dashboard_data)

@app.route('/emissao_senha', methods=['GET', 'POST'])
def emissao_senha():
    if 'usuario_id' not in session:
        return redirect('/')
    return render_template('emissao_senha.html', tipo_senha='menu')

@app.route('/emissao_senha_tablet', methods=['GET', 'POST'])
def emissao_senha_tablet():
    if 'usuario_id' not in session:
        return redirect('/')
    return render_template('emissao_senha_tablet.html', tipo_senha='menu')

@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    usuario_logado = get_usuario_logado()
    logger.info(f"{usuario_logado} Acessou a tela de cadastro de colaborador")

    # Obtendo o valor de pesquisa de colaborador, se houver
    search = request.args.get('search', '').strip()

    # Configuração da paginação da lista de colaboradores
    page = request.args.get('page', 1, type=int)
    per_page = 20 # Quantidade de colaboradores por página
    offset = (page - 1) * per_page

    cur = mysql.connection.cursor()  # <-- Criar o cursor no MySQL

    # Obtem o total de colaboradores para calcular o total de páginas
    if search:
        # Se houver uma pesquisa, vamos filtrar pelo nome ou CPF
        logger.info(f"{usuario_logado} pesquisou por um colaborador usando '{search}'")
        cur.execute("""
            SELECT COUNT(*) FROM colaboradores
            WHERE nome LIKE %s OR cpf LIKE %s;
        """, (f"%{search}%", f"%{search}%"))
    else:
        # Caso contrário, contar todos os colaboradores
        cur.execute("SELECT COUNT(*) FROM colaboradores;")
        
    total_colaboradores = cur.fetchone()[0]
    total_pages = (total_colaboradores + per_page - 1) // per_page

    # Busca colaboradores da página atual, considerando a pesquisa
    if search:
        cur.execute("""
            SELECT * FROM colaboradores
            WHERE nome LIKE %s OR cpf LIKE %s
            LIMIT %s OFFSET %s;
        """, (f"%{search}%", f"%{search}%", per_page, offset))
    else:
        cur.execute("""
            SELECT * FROM colaboradores
            LIMIT %s OFFSET %s;
        """, (per_page, offset))

    colaboradores = cur.fetchall()

    # Buscar departamentos
    cur.execute("SELECT nome FROM departamentos ORDER BY nome;")
    departamentos = [row[0] for row in cur.fetchall()]
    cur.close()

    if request.method == 'POST':
        nome = request.form['nome'].strip().upper()
        cpf = request.form['cpf'].strip()
        cargo = request.form['cargo'].strip().upper()
        departamento = request.form['departamento'].strip()
        tipo = request.form['tipo'].strip()
        
        # Verificação de campos vazios ou com espaços
        if not all([nome, cpf, cargo, departamento, tipo]):
            flash("Todos os campos são obrigatórios e não podem conter apenas espaços em branco.", "error")
            logger.error(f"{usuario_logado} tentou cadastrar um usuário, porém não foi preenchido todos os campos ou foi deixado um espaço em branco")
            return redirect(url_for('cadastro'))
        
        # Validação do CPF
        if not validar_cpf(cpf):
            flash("CPF inválido. Verifique os dígitos.", "error")
            logger.error(f"{usuario_logado} inseriu o CPF: {cpf} que está inválido.")
            return redirect(url_for('cadastro'))

        # Verificar se o CPF já existe no banco de dados
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM colaboradores WHERE cpf = %s", (cpf,))
        cpf_existente = cur.fetchone()  # Retorna uma linha se CPF já existir
        cur.close()

        if cpf_existente:
            flash("Esse CPF já está cadastrado. Tente outro.", "error")
            logger.error(f"{usuario_logado} inseriu o CPF: {cpf} que já está cadastrado.")
            return redirect(url_for('cadastro'))

        # Inserir novo colaborador no banco de dados
        try:
            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO colaboradores (nome, cpf, cargo, departamento, tipo) VALUES (%s, %s, %s, %s, %s)",
                        (nome, cpf, cargo, departamento, tipo))
            mysql.connection.commit()
            cur.close()
            logger.info(f"{usuario_logado} cadastrou o colaborador {nome} com sucesso.")
            flash("Colaborador cadastrado com sucesso!", "success")
            
        except Exception as e:
            mysql.connection.rollback()
            flash(f"Erro ao cadastrar colaborador: {str(e)}", "error")
            logger.error(f"{usuario_logado} enfrentou este erro na aplicação: {str(e)}")

        return redirect(url_for('cadastro'))

    return render_template('menu_admin.html', colaboradores=colaboradores, departamentos=departamentos, page=page, total_pages=total_pages, search=search, module='cadastro', usuario=usuario_logado)

@app.route('/cadastro_usuario', methods=['GET', 'POST'])
def cadastro_usuario():
    usuario_logado = get_usuario_logado()
    logger.info(f"{usuario_logado} acessou a tela de cadastro de usuário")

    cur = mysql.connection.cursor()

    # Buscar lista de usuários existentes para exibição
    cur.execute("SELECT id, nome, usuario, perfil FROM usuarios ORDER BY id DESC;")
    usuarios = cur.fetchall()
    cur.close()

    if request.method == 'POST':
        nome = request.form['nome'].strip().upper()
        usuario = request.form['usuario'].strip()
        senha = request.form['senha'].strip()
        perfil = request.form['perfil'].strip()

        # Verificar campos obrigatórios
        if not all([nome, usuario, senha, perfil]):
            flash("Todos os campos são obrigatórios.", "error")
            logger.error(f"{usuario_logado} tentou cadastrar um usuário com campos faltando.")
            return redirect(url_for('cadastro_usuario'))

        # Verificar se o nome de usuário já existe
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM usuarios WHERE usuario = %s", (usuario,))
        usuario_existente = cur.fetchone()
        cur.close()

        if usuario_existente:
            flash("Esse nome de usuário já está cadastrado. Escolha outro.", "error")
            logger.warning(f"{usuario_logado} tentou cadastrar o usuário '{usuario}' já existente.")
            return redirect(url_for('cadastro_usuario'))

        # Inserir novo usuário
        try:
            cur = mysql.connection.cursor()
            cur.execute("""
                INSERT INTO usuarios (nome, usuario, senha, perfil, status, criado_em)
                VALUES (%s, %s, %s, %s, 1, NOW());
            """, (nome, usuario, senha, perfil))
            mysql.connection.commit()
            cur.close()
            logger.info(f"{usuario_logado} cadastrou o usuário '{usuario}' com sucesso.")
            flash("Usuário cadastrado com sucesso!", "success")

        except Exception as e:
            mysql.connection.rollback()
            flash(f"Erro ao cadastrar usuário: {str(e)}", "error")
            logger.error(f"{usuario_logado} enfrentou erro ao cadastrar usuário: {str(e)}")

        return redirect(url_for('cadastro_usuario'))

    return render_template(
        'menu_admin.html',
        usuarios=usuarios,
        module='cadastro_usuario',
        usuario=usuario_logado
    )

@app.route('/excluir_usuario/<int:usuario_id>', methods=['POST'])
def excluir_usuario(usuario_id):
    usuario_logado = get_usuario_logado()
    try:
        cur = mysql.connection.cursor()
        cur.execute("DELETE FROM usuarios WHERE id = %s", (usuario_id,))
        mysql.connection.commit()
        cur.close()

        logger.info(f"{usuario_logado} excluiu o usuário com ID {usuario_id}")
        flash("Usuário excluído com sucesso.", "success")
    except Exception as e:
        mysql.connection.rollback()
        logger.error(f"{usuario_logado} teve erro ao excluir usuário ID {usuario_id}: {str(e)}")
        flash("Erro ao excluir usuário.", "error")
    return redirect(url_for('cadastro_usuario'))

@app.route('/excluir_colaborador/<int:colaborador_id>', methods=['POST'])
def excluir_colaborador(colaborador_id):
    usuario_logado = get_usuario_logado()
    try:
        cur = mysql.connection.cursor()
        cur.execute("DELETE FROM colaboradores WHERE id = %s", (colaborador_id,))
        mysql.connection.commit()
        cur.close()

        logger.info(f"{usuario_logado} excluiu o colaborador com ID {colaborador_id}")
        flash("Colaborador excluído com sucesso.", "success")
    except Exception as e:
        mysql.connection.rollback()
        logger.error(f"{usuario_logado} teve erro ao excluir colaborador ID {colaborador_id}: {str(e)}")
        flash("Erro ao excluir colaborador.", "error")

    return redirect(url_for('cadastro'))

@app.route('/relatorio/total', methods=['GET', 'POST'])
def relatorio_totalEmissao():
    usuario_logado = get_usuario_logado()
    perfil = session.get('usuario_perfil', 'desconhecido')  # Exemplo: 'totem_desktop' ou 'totem_tablet'
    logger.info(f"{usuario_logado} Acessou a tela de relatório total de senhas emitidas")

    if request.method == 'POST':
        data_inicial = request.form.get('data_inicial')
        data_final = request.form.get('data_final')

        # Converte para objetos datetime (garantindo formato correto)
        try:
            data_inicio = datetime.strptime(data_inicial, "%Y-%m-%d").date()
            data_fim = datetime.strptime(data_final, "%Y-%m-%d").date()
        except ValueError:
            logger.error(f"{usuario_logado} tentou emitir o relatório, porém preencheu com datas inválidas.")
            flash("Datas inválidas.")
            return redirect(url_for('relatorio_totalEmissao'))

        cursor = mysql.connection.cursor()

        # Total de senhas emitidas no período
        cursor.execute("""
            SELECT COUNT(*) FROM emissoes_senha 
            WHERE DATE(data_hora) BETWEEN %s AND %s
        """, (data_inicio, data_fim))
        total_senhas = cursor.fetchone()[0]

        # Total de visitantes no período
        cursor.execute("""
            SELECT COUNT(*) FROM emissoes_senha 
            WHERE cargo = 'VISITANTE' AND DATE(data_hora) BETWEEN %s AND %s
        """, (data_inicio, data_fim))
        total_visitantes = cursor.fetchone()[0]

        # Total de colaborador no período
        cursor.execute("""
            SELECT COUNT(*) FROM emissoes_senha 
            WHERE cargo != 'VISITANTE' AND DATE(data_hora) BETWEEN %s AND %s
        """, (data_inicio, data_fim))
        total_colaborador = cursor.fetchone()[0]

        # Total de colaboradores cadastrados (não depende de data)
        cursor.execute("SELECT COUNT(DISTINCT cpf) FROM colaboradores")
        base_colaboradores = cursor.fetchone()[0]
        
        # Total de senhas cafe colaborador
        cursor.execute("""
            SELECT COUNT(*) FROM emissoes_senha
            WHERE TIME(data_hora) BETWEEN '02:00:00' AND '10:59:59'
            AND cargo != 'VISITANTE'
            AND DATE(data_hora) BETWEEN %s AND %s
        """, (data_inicio, data_fim))
        senhas_cafe_colaborador = cursor.fetchone()[0]

        # Total de senhas cafe visitante
        cursor.execute("""
            SELECT COUNT(*) FROM emissoes_senha
            WHERE TIME(data_hora) BETWEEN '00:00:00' AND '10:59:59'
            AND cargo = 'VISITANTE'
            AND DATE(data_hora) BETWEEN %s AND %s
        """, (data_inicio, data_fim))
        senhas_cafe_visitante = cursor.fetchone()[0]

        # Total de senhas almoço colaborador
        cursor.execute("""
            SELECT COUNT(*) FROM emissoes_senha
            WHERE TIME(data_hora) BETWEEN '11:00:00' AND '17:59:59'
            AND cargo != 'VISITANTE'
            AND DATE(data_hora) BETWEEN %s AND %s
        """, (data_inicio, data_fim))
        senhas_almoco_colaborador = cursor.fetchone()[0]

        # Total de senhas almoço visitante
        cursor.execute("""
            SELECT COUNT(*) FROM emissoes_senha
            WHERE TIME(data_hora) BETWEEN '11:00:00' AND '17:59:59'
            AND cargo = 'VISITANTE'
            AND DATE(data_hora) BETWEEN %s AND %s
        """, (data_inicio, data_fim))
        senhas_almoco_visitante = cursor.fetchone()[0]

        # Total de senhas janta colaborador
        cursor.execute("""
            SELECT COUNT(*) FROM emissoes_senha
            WHERE TIME(data_hora) BETWEEN '18:00:00' AND '23:59:59'
            AND cargo != 'VISITANTE'
            AND DATE(data_hora) BETWEEN %s AND %s
        """, (data_inicio, data_fim))
        senhas_janta_colaborador = cursor.fetchone()[0]

        # Total de senhas janta visitante
        cursor.execute("""
            SELECT COUNT(*) FROM emissoes_senha
            WHERE TIME(data_hora) BETWEEN '18:00:00' AND '23:59:59'
            AND cargo = 'VISITANTE'
            AND DATE(data_hora) BETWEEN %s AND %s
        """, (data_inicio, data_fim))
        senhas_janta_visitante = cursor.fetchone()[0]

        # Top 5 departamentos no período
        cursor.execute("""
            SELECT departamento, COUNT(*) as quantidade
            FROM emissoes_senha
            WHERE DATE(data_hora) BETWEEN %s AND %s
            GROUP BY departamento
            ORDER BY quantidade DESC
            LIMIT 5
        """, (data_inicio, data_fim))
        departamentos = [{"nome": nome, "quantidade": qtd} for nome, qtd in cursor.fetchall()]

        # Lista de departamentos no período
        cursor.execute("""
            SELECT departamento, COUNT(*) as quantidade
            FROM emissoes_senha
            WHERE DATE(data_hora) BETWEEN %s AND %s
            GROUP BY departamento
            ORDER BY quantidade DESC
        """, (data_inicio, data_fim))
        lista_departamentos = [{"nome": nome, "quantidade": qtd} for nome, qtd in cursor.fetchall()]

        cursor.close()

        # Monta o dicionário com os totais
        dados_total = {
            "base_colaboradores": base_colaboradores,
            "total_senhas": total_senhas,
            "senhas_cafe_colaborador": senhas_cafe_colaborador,
            "senhas_cafe_visitante": senhas_cafe_visitante,
            "senhas_almoco_colaborador": senhas_almoco_colaborador,
            "senhas_almoco_visitante": senhas_almoco_visitante,
            "senhas_janta_colaborador": senhas_janta_colaborador,
            "senhas_janta_visitante": senhas_janta_visitante,
            "total_visitantes": total_visitantes,
            "total_colaborador": total_colaborador,
            "lista_departamentos": lista_departamentos,
            "data_geracao": f"{data_inicio.strftime('%d/%m/%Y')} até {data_fim.strftime('%d/%m/%Y')}"
        }

        # Gráfico de barras
        labels = [d['nome'] for d in departamentos]
        valores = [d['quantidade'] for d in departamentos]

        fig, ax = plt.subplots()
        ax.bar(labels, valores, color=['#4A90E2'] * len(labels))
        ax.set_title('Top 5 Emissões por Departamento')
        ax.set_ylabel('Quantidade')

        img_barras = io.BytesIO()
        fig.savefig(img_barras, format='png')
        img_barras.seek(0)
        grafico_barras = base64.b64encode(img_barras.getvalue()).decode('utf-8')

        # Gráfico de meta
        
        dias_filtrados = (data_fim - data_inicio).days + 1
        meta = base_colaboradores * dias_filtrados
        atingido = total_senhas

        fig_meta, ax_meta = plt.subplots()
        ax_meta.pie(
            [atingido, max(meta - atingido, 0)],
            labels=['Atingido', 'Restante'],
            autopct='%1.1f%%',
            colors=['limegreen', 'lightgray'],
            startangle=90
        )
        ax_meta.set_title(f'Meta no Período ({atingido}/{meta})')
        ax_meta.axis('equal')

        img_meta = io.BytesIO()
        fig_meta.savefig(img_meta, format='png')
        img_meta.seek(0)
        grafico_meta = base64.b64encode(img_meta.getvalue()).decode('utf-8')

        # Renderiza e gera PDF
        html = render_template('relatorio_totalEmissao.html',
                               total=dados_total,
                               departamentos=departamentos,
                               lista_departamentos=lista_departamentos,
                               grafico_barras=grafico_barras,
                               grafico_meta=grafico_meta)

        pdf = pdfkit.from_string(html, False, configuration=config_pdf)
        logger.info(f"{usuario_logado} emitiu o relatório com sucesso!")

        return send_file(BytesIO(pdf), download_name='relatorio_totalEmissao.pdf', as_attachment=True)

    if perfil == 'admin':
        return render_template('menu_admin.html', modulo='relatorio_totalEmissao', usuario=usuario_logado)
    else:
        return render_template('menu_usuario.html', modulo='relatorio_totalEmissao', usuario=usuario_logado)# Renderização baseada no perfil
    
@app.route('/relatorio/diario', methods=['GET', 'POST'])
def relatorio_emissaoDiaria():
    usuario_logado = get_usuario_logado()
    perfil = session.get('usuario_perfil', 'desconhecido')
    logger.info(f"{usuario_logado} Acessou a tela de relatório relação de emissões diárias")

    if request.method == 'POST':
        data_unica = request.form.get('data_unica')
        tipo_relatorio = request.form.get('tipo_relatorio')  # 'pdf' ou 'excel'

        try:
            data_ref = datetime.strptime(data_unica, "%Y-%m-%d").date()
        except ValueError:
            logger.error(f"{usuario_logado} tentou emitir o relatório com data inválida.")
            flash("Data inválida.")
            return redirect(url_for('relatorio_emissaoDiaria'))

        cursor = mysql.connection.cursor()
        cursor.execute("""
            SELECT numero_senha, cpf, nome, cargo, departamento, data_hora
            FROM emissoes_senha
            WHERE DATE(data_hora) = %s
            ORDER BY data_hora ASC
        """, (data_ref,))

        results = cursor.fetchall()
        colunas = [desc[0] for desc in cursor.description]
        registros = [dict(zip(colunas, row)) for row in results]
        cursor.close()

        data_geracao = data_ref.strftime('%d/%m/%Y')
        agora = datetime.now().strftime('%d/%m/%Y %H:%M')

        if tipo_relatorio == 'excel':
            df = pd.DataFrame(registros)
            output = BytesIO()

            with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                workbook = writer.book
                worksheet = workbook.add_worksheet("Relatório")
                writer.sheets['Relatório'] = worksheet

                bold = workbook.add_format({'bold': True})
                worksheet.write('A1', 'Relatório de Emissões Diárias', bold)
                worksheet.write('A3', 'Data:', bold)
                worksheet.write('B3', data_geracao)

                worksheet.write('A4', 'Gerado em:', bold)
                worksheet.write('B4', agora)

                df.to_excel(writer, sheet_name='Relatório', startrow=6, index=False)

                for i, col in enumerate(df.columns):
                    max_length = max(df[col].astype(str).map(len).max(), len(col))
                    worksheet.set_column(i, i, max_length + 2)

            output.seek(0)
            logger.info(f"{usuario_logado} emitiu o relatório de emissões diárias (EXCEL) com sucesso!")
            return send_file(output, download_name='relatorio_emissoesDiarias.xlsx', as_attachment=True)

        else:
            html = render_template('relatorio_emissoesDiarias.html',
                                   registros=registros,
                                   data_geracao=data_geracao,
                                   agora=agora)

            pdf = pdfkit.from_string(html, False, configuration=config_pdf)
            logger.info(f"{usuario_logado} emitiu o relatório de emissões diárias (PDF) com sucesso!")

            return send_file(BytesIO(pdf), download_name='relatorio_emissoesDiarias.pdf', as_attachment=True)

    if perfil == 'admin':
        return render_template('menu_admin.html', modulo='relatorio_emissaoDiaria', usuario=usuario_logado)
    else:
        return render_template('menu_usuario.html', modulo='relatorio_emissaoDiaria', usuario=usuario_logado)

@app.route('/relatorio/totalVisitantes', methods=['GET', 'POST'])
def relatorio_totalVisitantes():
    usuario_logado = get_usuario_logado()
    perfil = session.get('usuario_perfil', 'desconhecido')
    logger.info(f"{usuario_logado} Acessou a tela de relatório total de visitantes")

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT nome FROM localizacoes ORDER BY nome ASC")
    localizacoes = [row[0] for row in cursor.fetchall()]
    cursor.close()

    if request.method == 'POST':
        data_inicial_str = request.form.get('data_inicial')
        data_final_str = request.form.get('data_final')
        departamento = request.form.get('departamento')
        tipo_relatorio = request.form.get('tipo_relatorio')

        try:
            data_inicial = datetime.strptime(data_inicial_str, "%Y-%m-%d")
            data_final = datetime.strptime(data_final_str, "%Y-%m-%d")
        except ValueError:
            flash("Datas inválidas.")
            logger.error(f"{usuario_logado} tentou emitir o relatório com datas inválidas.")
            return redirect(url_for('relatorio_totalVisitantes'))

        if data_final < data_inicial:
            flash("Data final não pode ser anterior à inicial.")
            return redirect(url_for('relatorio_totalVisitantes'))

        cursor = mysql.connection.cursor()

        dt_inicio = datetime.combine(data_inicial, datetime.min.time()) + timedelta(hours=2)  # 02:00
        dt_fim = datetime.combine(data_final + timedelta(days=1), datetime.min.time()) + timedelta(hours=1, minutes=59)  # 01:59 do dia seguinte

        def contar_periodo(inicio, fim):
            cursor.execute("""
                SELECT COUNT(*) FROM emissoes_senha
                WHERE data_hora BETWEEN %s AND %s AND departamento = %s
            """, (inicio, fim, departamento))
            return cursor.fetchone()[0]

        total_cafe = contar_periodo(dt_inicio.replace(hour=2, minute=0), dt_fim.replace(hour=10, minute=59))
        total_almoco = contar_periodo(dt_inicio.replace(hour=11, minute=0), dt_fim.replace(hour=17, minute=59))
        total_janta = contar_periodo(dt_inicio.replace(hour=18, minute=0), dt_fim)

        # Registros completos
        cursor.execute("""
            SELECT numero_senha, cpf, nome, cargo, departamento, data_hora
            FROM emissoes_senha
            WHERE data_hora BETWEEN %s AND %s AND departamento = %s
            ORDER BY data_hora ASC
        """, (dt_inicio, dt_fim, departamento))

        results = cursor.fetchall()
        colunas = [desc[0] for desc in cursor.description]
        registros = [dict(zip(colunas, row)) for row in results]
        cursor.close()

        periodo_formatado = f"{data_inicial.strftime('%d/%m/%Y')} até {data_final.strftime('%d/%m/%Y')}"
        agora = datetime.now().strftime('%d/%m/%Y %H:%M')

        if tipo_relatorio == 'excel':
            df = pd.DataFrame(registros)
            output = BytesIO()

            with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                workbook = writer.book
                worksheet = workbook.add_worksheet("Relatório")
                writer.sheets['Relatório'] = worksheet

                bold = workbook.add_format({'bold': True})
                worksheet.write('A1', 'Relatório de Emissões de Visitantes', bold)
                worksheet.write('A3', 'Localização:', bold)
                worksheet.write('B3', departamento)

                worksheet.write('A4', 'Período:', bold)
                worksheet.write('B4', periodo_formatado)

                worksheet.write('A6', 'Total Café:', bold)
                worksheet.write('B6', total_cafe)

                worksheet.write('A7', 'Total Almoço:', bold)
                worksheet.write('B7', total_almoco)

                worksheet.write('A8', 'Total Janta:', bold)
                worksheet.write('B8', total_janta)

                df.to_excel(writer, sheet_name='Relatório', startrow=10, index=False)

                for i, col in enumerate(df.columns):
                    max_length = max(df[col].astype(str).map(len).max(), len(col))
                    worksheet.set_column(i, i, max_length + 2)

            output.seek(0)
            logger.info(f"{usuario_logado} emitiu o relatório total de visitantes (EXCEL) com sucesso!")
            return send_file(output, download_name='relatorio_totalVisitantes.xlsx', as_attachment=True)

        else:
            html = render_template('relatorio_totalVisitantes.html',
                                   registros=registros,
                                   data_geracao=periodo_formatado,
                                   agora=agora,
                                   departamento=departamento,
                                   total_cafe=total_cafe,
                                   total_almoco=total_almoco,
                                   total_janta=total_janta)

            pdf = pdfkit.from_string(html, False, configuration=config_pdf)
            logger.info(f"{usuario_logado} emitiu o relatório total de visitantes (PDF) com sucesso!")
            return send_file(BytesIO(pdf), download_name='relatorio_totalVisitantes.pdf', as_attachment=True)

    if perfil == 'admin':
        return render_template('menu_admin.html', modulo='relatorio_totalVisitantes',
                               usuario=usuario_logado, localizacoes=localizacoes)
    else:
        return render_template('menu_usuario.html', modulo='relatorio_totalVisitantes',
                               usuario=usuario_logado, localizacoes=localizacoes)

@app.route('/relatorio/totalDepartamento', methods=['GET', 'POST'])
def relatorio_totalDepartamento():
    usuario_logado = get_usuario_logado()
    perfil = session.get('usuario_perfil', 'desconhecido')
    logger.info(f"{usuario_logado} Acessou a tela de relatório total por Departamento")

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT nome FROM departamentos ORDER BY nome ASC")
    departamentos = [row[0] for row in cursor.fetchall()]
    cursor.close()

    if request.method == 'POST':
        data_inicial_str = request.form.get('data_inicial')
        data_final_str = request.form.get('data_final')
        departamento = request.form.get('departamento')
        tipo_relatorio = request.form.get('tipo_relatorio')

        try:
            data_inicial = datetime.strptime(data_inicial_str, "%Y-%m-%d")
            data_final = datetime.strptime(data_final_str, "%Y-%m-%d")
        except ValueError:
            logger.error(f"{usuario_logado} tentou emitir o relatório com datas inválidas.")
            flash("Datas inválidas.")
            return redirect(url_for('relatorio_totalDepartamento'))

        if data_final < data_inicial:
            flash("Data final não pode ser anterior à data inicial.")
            return redirect(url_for('relatorio_totalDepartamento'))

        cursor = mysql.connection.cursor()

        dt_inicio = datetime.combine(data_inicial, datetime.min.time()) + timedelta(hours=2)  # 02:00
        dt_fim = datetime.combine(data_final + timedelta(days=1), datetime.min.time()) + timedelta(hours=1, minutes=59)  # dia seguinte 01:59

        # Totais por período no intervalo
        def contar_periodo(inicio, fim):
            cursor.execute("""
                SELECT COUNT(*) FROM emissoes_senha 
                WHERE data_hora BETWEEN %s AND %s AND departamento = %s
            """, (inicio, fim, departamento))
            return cursor.fetchone()[0]

        total_cafe = contar_periodo(dt_inicio.replace(hour=2, minute=0), dt_fim.replace(hour=10, minute=59))
        total_almoco = contar_periodo(dt_inicio.replace(hour=11, minute=0), dt_fim.replace(hour=17, minute=59))
        total_janta = contar_periodo(dt_inicio.replace(hour=18, minute=0), dt_fim)

        # Registros completos
        cursor.execute("""
            SELECT numero_senha, cpf, nome, cargo, departamento, data_hora
            FROM emissoes_senha
            WHERE data_hora BETWEEN %s AND %s AND departamento = %s
            ORDER BY data_hora ASC
        """, (dt_inicio, dt_fim, departamento))

        results = cursor.fetchall()
        colunas = [desc[0] for desc in cursor.description]
        registros = [dict(zip(colunas, row)) for row in results]
        cursor.close()

        periodo_formatado = f"{data_inicial.strftime('%d/%m/%Y')} até {data_final.strftime('%d/%m/%Y')}"
        agora = datetime.now().strftime('%d/%m/%Y %H:%M')

        if tipo_relatorio == 'excel':
            df = pd.DataFrame(registros)
            output = BytesIO()

            with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                workbook = writer.book
                worksheet = workbook.add_worksheet("Relatório")
                writer.sheets['Relatório'] = worksheet

                # Cabeçalho customizado
                bold = workbook.add_format({'bold': True})
                worksheet.write('A1', 'Relatório de Emissões por Departamento', bold)
                worksheet.write('A3', 'Departamento:', bold)
                worksheet.write('B3', departamento)

                worksheet.write('A4', 'Período:', bold)
                worksheet.write('B4', f"{data_inicial.strftime('%d/%m/%Y')} até {data_final.strftime('%d/%m/%Y')}")

                worksheet.write('A6', 'Total Café:', bold)
                worksheet.write('B6', total_cafe)

                worksheet.write('A7', 'Total Almoço:', bold)
                worksheet.write('B7', total_almoco)

                worksheet.write('A8', 'Total Janta:', bold)
                worksheet.write('B8', total_janta)

                # Dados da tabela (a partir da linha 10)
                df_start_row = 10
                df.to_excel(writer, sheet_name='Relatório', startrow=df_start_row, index=False)

                # Ajusta colunas automaticamente
                for i, col in enumerate(df.columns):
                    max_length = max(df[col].astype(str).map(len).max(), len(col))
                    worksheet.set_column(i, i, max_length + 2)

            output.seek(0)
            logger.info(f"{usuario_logado} emitiu o relatório total por departamentos (EXCEL) com cabeçalho completo!")
            return send_file(output, download_name='relatorio_totalDepartamentos.xlsx', as_attachment=True)

        else:
            html = render_template('relatorio_totalDepartamentos.html',
                                   registros=registros,
                                   data_geracao=periodo_formatado,
                                   agora=agora,
                                   departamento=departamento,
                                   total_cafe=total_cafe,
                                   total_almoco=total_almoco,
                                   total_janta=total_janta)

            pdf = pdfkit.from_string(html, False, configuration=config_pdf)
            logger.info(f"{usuario_logado} emitiu o relatório total por departamentos (PDF) com sucesso!")
            return send_file(BytesIO(pdf), download_name='relatorio_totalDepartamentos.pdf', as_attachment=True)

    if perfil == 'admin':
        return render_template('menu_admin.html', modulo='relatorio_totalDepartamento',
                               usuario=usuario_logado, departamentos=departamentos)
    else:
        return render_template('menu_usuario.html', modulo='relatorio_totalDepartamento',
                               usuario=usuario_logado, departamentos=departamentos)

@app.route('/senha/colaborador', methods=['GET', 'POST'])
def senha_colaborador():
    usuario_logado = get_usuario_logado()
    perfil = session.get('usuario_perfil', 'desconhecido')  # Exemplo: 'totem_desktop' ou 'totem_tablet'

    if request.method == 'POST':
        cpf = request.form['cpf']

        if not validar_cpf(cpf):
            logger.error(f"{usuario_logado}: {cpf} é inválido.")
            flash("CPF inválido. Por favor, insira um CPF válido.", "error")
            return redirect(url_for('senha_colaborador'))

        cur = mysql.connection.cursor()
        cur.execute("SELECT nome, cpf, cargo, departamento, tipo FROM colaboradores WHERE cpf = %s", (cpf,))
        colaborador = cur.fetchone()

        if colaborador:
            nome, cpf, cargo, departamento, limite_diario = colaborador
            data_hoje = date.today()

            cur.execute("""
                SELECT COUNT(*) FROM emissoes_senha
                WHERE cpf = %s AND DATE(data_hora) = %s
            """, (cpf, data_hoje))
            qtd_emissoes_hoje = cur.fetchone()[0]

            if qtd_emissoes_hoje >= limite_diario:
                logger.error(f"{usuario_logado}: {cpf} atingiu o limite diário.")
                flash("Você atingiu o limite diário de emissões.", "error")
                cur.close()
                return redirect(url_for('senha_colaborador'))

            cur.execute("""
                SELECT COALESCE(MAX(numero_senha), 0) FROM emissoes_senha
                WHERE DATE(data_hora) = %s
            """, (data_hoje,))
            ultimo_numero = cur.fetchone()[0]
            novo_numero = ultimo_numero + 1

            data_hora = datetime.now()

            try:
                cur.execute("""
                    INSERT INTO emissoes_senha (nome, cpf, cargo, departamento, data_hora, numero_senha)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (nome, cpf, cargo, departamento, data_hora, novo_numero))
                mysql.connection.commit()
                logger.info(f"{usuario_logado}: Senha Nº {novo_numero:03d} registrada para {cpf}.")
            except Exception as e:
                logger.error(f"{usuario_logado}: erro ao registrar senha: {e}")
                flash("Erro ao registrar a senha.", "error")
                mysql.connection.rollback()
                cur.close()
                return redirect(url_for('senha_colaborador'))
            finally:
                cur.close()

            # Remove a parte de impressão da senha física
            # O código de impressão foi removido abaixo:

            # try:
            #     printer = Network("10.10.4.70")
            #     printer.profile.media['width']['pixels'] = 512
            #     printer.set(align='center')
            #     printer.image("static/images/logo_gtr.png")
            #     printer.text("\n\n")
            #     printer.set(align='center', width=5, height=5)
            #     printer.text(f"SENHA {novo_numero:03d}\n")
            #     printer.text("\n")
            #     printer.set(align='left', width=1, height=1)
            #     printer.text(f"Nome: {nome}\n")
            #     printer.text(f"Cargo: {cargo}\n")
            #     printer.text(f"Departamento: {departamento}\n")
            #     printer.text(f"Data/Hora: {data_hora.strftime('%d/%m/%Y %H:%M:%S')}\n")
            #     printer.cut()
            #     printer.close()

            flash(f"Senha Nº {novo_numero:03d} emitida com sucesso!", "success")

            return redirect(url_for('senha_colaborador'))
        else:
            logger.info(f"{usuario_logado}: CPF {cpf} não encontrado.")
            flash("CPF não encontrado na base de colaboradores.", "error")
            cur.close()
            return redirect(url_for('senha_colaborador'))

    # Renderização baseada no perfil
    if perfil == 'totem_tablet':
        return render_template('emissao_senha_tablet.html', tipo_senha='colaborador')
    else:
        return render_template('emissao_senha.html', tipo_senha='colaborador')

@app.route('/senha/visitante', methods=['GET', 'POST'])
def senha_visitante():
    usuario_logado = get_usuario_logado()
    perfil = session.get('usuario_perfil', 'desconhecido')  # Exemplo: 'totem_desktop' ou 'totem_tablet'

    #Busca a localização no Banco para exibir na tela visitantes
    cur = mysql.connection.cursor()
    cur.execute("SELECT nome FROM localizacoes ORDER BY nome ASC")  # Suponho que você tenha uma tabela `localizacoes`
    localizacoes = [row[0] for row in cur.fetchall()]
    cur.close()

    if request.method == 'POST':
        nome = request.form['nome'].strip().upper()
        cpf = request.form['cpf'].strip()
        localizacoes = request.form['localizacoes'].strip().upper()
        
        if not validar_cpf(cpf):
            logger.error(f"{usuario_logado}: {cpf} é inválido.")
            flash("CPF inválido. Por favor, insira um CPF válido.", "error")
            return redirect(url_for('senha_visitante'))

        cur = mysql.connection.cursor()
        data_hoje = date.today()

        # Definir limite de emissão com base na localização
        limite_diario = 3 if localizacoes == "ACOMPANHANTE" else 1

        # Verificar se já atingiu o limite de senhas hoje
        cur.execute("""
            SELECT COUNT(*) FROM emissoes_senha
            WHERE cpf = %s AND DATE(data_hora) = %s
        """, (cpf, data_hoje))
        qtd_emissoes_hoje = cur.fetchone()[0]

        if qtd_emissoes_hoje >= limite_diario:
            logger.error(f"{usuario_logado}: {cpf} ({localizacoes}) atingiu o limite de {limite_diario} senhas hoje.")
            flash(f"Você atingiu o limite diário de {limite_diario} senha(s) para este tipo de visitante.", "error")
            cur.close()
            return redirect(url_for('senha_visitante'))

        # Buscar o maior número de senha do dia para gerar o próximo
        cur.execute("""
            SELECT COALESCE(MAX(numero_senha), 0) FROM emissoes_senha
            WHERE DATE(data_hora) = %s
        """, (data_hoje,))
        ultimo_numero = cur.fetchone()[0]
        novo_numero = ultimo_numero + 1

        data_hora = datetime.now()
        cargo = "VISITANTE"
        departamento = localizacoes

        try:
            # Registrar emissão no banco
            cur.execute("""
                INSERT INTO emissoes_senha (nome, cpf, cargo, departamento, data_hora, numero_senha)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (nome, cpf, cargo, departamento, data_hora, novo_numero))
            mysql.connection.commit()
            logger.info(f"{usuario_logado}: Senha Nº {novo_numero:03d} registrada para visitante CPF {cpf}.")

        except Exception as e:
            logger.error(f"{usuario_logado}: erro ao registrar senha do visitante no banco: {e}")
            flash("Erro ao registrar a senha no sistema.", "error")
            mysql.connection.rollback()
            cur.close()
            return redirect(url_for('senha_visitante'))

        finally:
            cur.close()
            
        flash(f"Senha Nº {novo_numero:03d} emitida com sucesso!", "success")

        return redirect(url_for('senha_visitante'))

    # Renderização baseada no perfil
    if perfil == 'totem_tablet':
        return render_template('emissao_senha_tablet.html', tipo_senha='visitante', localizacoes=localizacoes)
    else:
        return render_template('emissao_senha.html', tipo_senha='visitante', localizacoes=localizacoes)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
