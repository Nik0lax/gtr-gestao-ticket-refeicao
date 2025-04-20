from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, make_response, send_file
from flask_mysqldb import MySQL
from datetime import datetime, date
from escpos.printer import Network
from io import BytesIO
import os
import re
import pandas as pd
import pdfkit
import matplotlib.pyplot as plt
import base64
import io
import time

from log_config import logger  # Importar o logger

##################################CONFIGS##################################
app = Flask(__name__)
app.secret_key = 'gtr_hmpa'


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


config_pdf = pdfkit.configuration(wkhtmltopdf='/usr/bin/wkhtmltopdf')  # ajuste conforme o caminho da sua instalação

# Configuração do MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'gtruser'
app.config['MYSQL_PASSWORD'] = 'Hmsn@cqua'
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
    return render_template('menu_admin.html', module=None, usuario=usuario_logado)

@app.route('/usuario')
def usuario(): 
    if 'usuario_id' not in session:
        return redirect('/')
    
    usuario_logado = get_usuario_logado()
    return render_template('menu_usuario.html', module=None, usuario=usuario_logado)

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

    # Obtendo o valor de pesquisa de colaborador, se houver
    search = request.args.get('search', '').strip()

    # Configuração da paginação da lista de colaboradores
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page

    cur = mysql.connection.cursor()  # <-- Criar o cursor no MySQL

    # Obtem o total de colaboradores para calcular o total de páginas
    if search:
        # Se houver uma pesquisa, vamos filtrar pelo nome ou CPF
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

        return redirect(url_for('cadastro'))

    return render_template('menu_admin.html', colaboradores=colaboradores, departamentos=departamentos, page=page, total_pages=total_pages, search=search, module='cadastro')

@app.route('/relatorio/total', methods=['GET', 'POST'])
def relatorio_totalEmissao():
    usuario_logado = get_usuario_logado()
    perfil = session.get('usuario_perfil', 'desconhecido')  # Exemplo: 'totem_desktop' ou 'totem_tablet'

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
            WHERE departamento = 'VISITANTE' AND DATE(data_hora) BETWEEN %s AND %s
        """, (data_inicio, data_fim))
        total_visitantes = cursor.fetchone()[0]

        # Total de colaborador no período
        cursor.execute("""
            SELECT COUNT(*) FROM emissoes_senha 
            WHERE departamento != 'VISITANTE' AND DATE(data_hora) BETWEEN %s AND %s
        """, (data_inicio, data_fim))
        total_colaborador = cursor.fetchone()[0]

        # Total de colaboradores cadastrados (não depende de data)
        cursor.execute("SELECT COUNT(DISTINCT cpf) FROM colaboradores")
        base_colaboradores = cursor.fetchone()[0]
        
        # Total de senhas cafe
        cursor.execute("""
            SELECT COUNT(*) FROM emissoes_senha
            WHERE TIME(data_hora) BETWEEN '06:00:00' AND '09:00:00'
            AND DATE(data_hora) BETWEEN %s AND %s
        """, (data_inicio, data_fim))
        senhas_cafe = cursor.fetchone()[0]

        # Total de senhas almoço
        cursor.execute("""
            SELECT COUNT(*) FROM emissoes_senha
            WHERE TIME(data_hora) BETWEEN '11:00:00' AND '15:00:00'
            AND DATE(data_hora) BETWEEN %s AND %s
        """, (data_inicio, data_fim))
        senhas_almoco = cursor.fetchone()[0]

        # Total de senhas janta
        cursor.execute("""
            SELECT COUNT(*) FROM emissoes_senha
            WHERE TIME(data_hora) BETWEEN '18:00:00' AND '23:59:00'
            AND DATE(data_hora) BETWEEN %s AND %s
        """, (data_inicio, data_fim))
        senhas_janta = cursor.fetchone()[0]

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
            "senhas_cafe": senhas_cafe,
            "senhas_almoco": senhas_almoco,
            "senhas_janta": senhas_janta,
            "senhas_visitantes": total_visitantes,
            "senhas_colaborador": total_colaborador,
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
        return render_template('menu_admin.html', modulo='relatorio_totalEmissao')
    else:
        return render_template('menu_usuario.html', modulo='relatorio_totalEmissao')# Renderização baseada no perfil
    
@app.route('/relatorio/diario', methods=['GET', 'POST'])
def relatorio_emissaoDiaria():
    usuario_logado = get_usuario_logado()
    perfil = session.get('usuario_perfil', 'desconhecido')  # Exemplo: 'totem_desktop' ou 'totem_tablet'

    if request.method == 'POST':
        data_unica = request.form.get('data_unica')

        try:
            data_ref = datetime.strptime(data_unica, "%Y-%m-%d").date()
        except ValueError:
            logger.error(f"{usuario_logado} tentou emitir o relatório, porém preencheu com datas inválidas.")
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

        data_geracao = f"{data_ref.strftime('%d/%m/%Y')}"
        agora = datetime.now().strftime('%d/%m/%Y %H:%M')

        html = render_template('relatorio_emissoesDiarias.html',
                               registros=registros,
                               data_geracao=data_geracao,
                               agora=agora)
        
        pdf = pdfkit.from_string(html, False, configuration=config_pdf)
        logger.info(f"{usuario_logado} emitiu o relatório com sucesso!")
        
        return send_file(BytesIO(pdf), download_name='relatorio_emissoesDiarias.pdf', as_attachment=True)

    if perfil == 'admin':
        return render_template('menu_admin.html', modulo='relatorio_emissaoDiaria')
    else:
        return render_template('menu_usuario.html', modulo='relatorio_emissaoDiaria')# Renderização baseada no perfil

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

            try:
                printer = Network("10.10.4.70")
                printer.profile.media['width']['pixels'] = 512
                printer.set(align='center')
                printer.image("static/images/logo_gtr.png")
                printer.text("\n\n")
                printer.set(align='center', width=5, height=5)
                printer.text(f"SENHA {novo_numero:03d}\n")
                printer.text("\n")
                printer.set(align='left', width=1, height=1)
                printer.text(f"Nome: {nome}\n")
                printer.text(f"Cargo: {cargo}\n")
                printer.text(f"Departamento: {departamento}\n")
                printer.text(f"Data/Hora: {data_hora.strftime('%d/%m/%Y %H:%M:%S')}\n")
                printer.cut()
                printer.close()

                flash(f"Senha Nº {novo_numero:03d} emitida com sucesso!", "success")
            except Exception as e:
                logger.warning(f"{usuario_logado}: erro na impressão: {e}")
                flash(f"Senha Nº {novo_numero:03d} registrada, mas houve erro na impressão.", "warning")

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

    if request.method == 'POST':
        nome = request.form['nome'].strip().upper()
        cpf = request.form['cpf'].strip()

        if not validar_cpf(cpf):
            logger.error(f"{usuario_logado}: {cpf} é inválido.")
            flash("CPF inválido. Por favor, insira um CPF válido.", "error")
            return redirect(url_for('senha_visitante'))

        cur = mysql.connection.cursor()
        data_hoje = date.today()

        # Verificar se já emitiu senha hoje
        cur.execute("""
            SELECT COUNT(*) FROM emissoes_senha
            WHERE cpf = %s AND DATE(data_hora) = %s
        """, (cpf, data_hoje))
        qtd_emissoes_hoje = cur.fetchone()[0]

        if qtd_emissoes_hoje >= 1:
            logger.error(f"{usuario_logado}: {cpf} de visitante atingiu a quantidade máxima de emissões por hoje")
            flash(f"Você atingiu o limite diário de emissões por visitante.", "error")
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
        departamento = "VISITANTE"

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

        # Impressão separada, não afeta o banco
        try:
            printer = Network("10.10.4.70")

            printer.set(align='center')
            printer.image("static/images/logo_gtr.png")
            printer.text("\n\n")

            printer.set(align='center', width=5, height=5)
            printer.text(f"SENHA {novo_numero:03d}\n")
            printer.text("\n")

            printer.set(align='left', width=1, height=1)
            printer.text(f"Nome: {nome}\n")
            printer.text(f"Cargo: {cargo}\n")
            printer.text(f"Data/Hora: {data_hora.strftime('%d/%m/%Y %H:%M:%S')}\n")

            printer.cut()
            printer.close()

            logger.info(f"{usuario_logado}: Impressão da senha {novo_numero:03d} para visitante CPF {cpf} concluída.")
            flash(f"Senha Nº {novo_numero:03d} emitida com sucesso!", "success")

        except Exception as e:
            logger.warning(f"{usuario_logado}: Erro ao imprimir senha {novo_numero:03d} para visitante CPF {cpf}. Registro feito. Erro: {e}")
            flash(f"Senha Nº {novo_numero:03d} registrada com sucesso, mas houve erro na impressão.", "warning")

        return redirect(url_for('senha_visitante'))

    # Renderização baseada no perfil
    if perfil == 'totem_tablet':
        return render_template('emissao_senha_tablet.html', tipo_senha='visitante')
    else:
        return render_template('emissao_senha.html', tipo_senha='visitante')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
