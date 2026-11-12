"""Migra cardápios antigos (texto livre) para o catálogo de pratos.

Para cada cardápio sem itens, quebra a descrição em pratos por categoria,
cria os pratos que faltam no catálogo e vincula os itens. A foto do cardápio
vira a foto do primeiro prato principal (se ele ainda não tiver foto).

Idempotente: cardápios que já têm itens são ignorados.

Uso (na raiz do projeto, com as variáveis MYSQL_* do ambiente):
    venv/bin/python scripts/migrar_cardapio_catalogo.py            # simulação, não grava nada
    venv/bin/python scripts/migrar_cardapio_catalogo.py --aplicar  # grava
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, mysql, init_cardapio_catalogo, _gravar_cardapio, _normalizar_nome_prato  # noqa: E402

# Correções de digitação encontradas nos cardápios antigos
CORRECOES = {
    'COZIDÃO CE CARNE': 'COZIDÃO DE CARNE',
    'MELÇAO': 'MELÃO',
}

RE_SOBREMESA = re.compile(r'^SOBREMESAS?\s*:\s*(.*)$')
RE_BEBIDA = re.compile(r'^(?:BEBIDAS?|BABIDAS?|SUCOS?)\s*:\s*(.*)$')
RE_SALADA = re.compile(r'^(?:MIX DE\s+)?SALADAS?\b[^:]*:\s*(.*)$')
RE_SALADA_SIMPLES = re.compile(r'^SALADAS?\s+(.+)$')
RE_ACOMP = re.compile(r'^(ARROZ|FEIJ|FAROFA|MACARR|PUR[EÊ]|VINAGRETE|CUSCUZ|BATATA|MANDIOCA|AIPIM|POLENTA|LEGUMES|FEIJOADA)')


def _limpar(nome):
    nome = _normalizar_nome_prato(nome).rstrip('.').strip()
    return CORRECOES.get(nome, nome)


def _opcoes(texto, sep=r'\s+OU\s+'):
    vistos = []
    for parte in re.split(sep, texto):
        n = _limpar(parte)
        if n and n not in vistos:
            vistos.append(n)
    return vistos


def interpretar(descricao):
    """Retorna lista de (categoria, nome) na ordem de exibição."""
    itens = []
    linhas = [_normalizar_nome_prato(l) for l in (descricao or '').split('\n')]
    linhas = [l for l in linhas if l]
    for idx, linha in enumerate(linhas):
        m = RE_SOBREMESA.match(linha)
        if m:
            itens += [('sobremesa', n) for n in _opcoes(m.group(1))]
            continue
        m = RE_BEBIDA.match(linha)
        if m:
            itens += [('bebida', n) for n in _opcoes(m.group(1))]
            continue
        m = RE_SALADA.match(linha)
        if m:
            itens += [('salada', n) for n in _opcoes(m.group(1), sep=r'\s*,\s*')]
            continue
        if idx > 0 and RE_ACOMP.match(linha):
            itens.append(('acompanhamento', _limpar(linha)))
            continue
        m = RE_SALADA_SIMPLES.match(linha)
        if m and idx > 0:
            itens.append(('salada', _limpar(m.group(1))))
            continue
        # 1ª linha e linhas não reconhecidas: prato principal (com opções "OU")
        itens += [('principal', n) for n in _opcoes(linha)]
    # remove duplicados mantendo a ordem
    unicos = []
    for it in itens:
        if it not in unicos:
            unicos.append(it)
    return unicos


def main(aplicar):
    with app.app_context():
        init_cardapio_catalogo()
        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT c.id, c.data_cardapio, c.tipo_refeicao, c.descricao, c.foto, c.ativo
            FROM cardapios c
            WHERE NOT EXISTS (SELECT 1 FROM cardapio_itens ci WHERE ci.cardapio_id = c.id)
            ORDER BY c.data_cardapio, c.id
        """)
        legados = cur.fetchall()
        print(f"{len(legados)} cardápio(s) no formato antigo.\n")
        novos_pratos = 0
        for cid, dref, tipo, desc, foto, ativo in legados:
            itens = interpretar(desc)
            print(f"#{cid} {dref} {tipo}")
            for cat, nome in itens:
                print(f"    {cat:<15} {nome}")
            if not itens:
                print("    (sem itens reconhecidos — ignorado)")
                continue
            if not aplicar:
                continue
            prato_ids = []
            principal_id = None
            for cat, nome in itens:
                cur.execute("SELECT id, foto FROM pratos WHERE nome=%s AND categoria=%s", (nome, cat))
                row = cur.fetchone()
                if row:
                    pid = row[0]
                else:
                    cur.execute("INSERT INTO pratos (nome, categoria) VALUES (%s, %s)", (nome, cat))
                    pid = cur.lastrowid
                    novos_pratos += 1
                if cat == 'principal' and principal_id is None:
                    principal_id = pid
                prato_ids.append(pid)
            if foto and principal_id:
                cur.execute("UPDATE pratos SET foto=%s WHERE id=%s AND foto IS NULL", (foto, principal_id))
            _gravar_cardapio(cur, dref, tipo, prato_ids, ativo)
        if aplicar:
            mysql.connection.commit()
            print(f"\nMigração aplicada. {novos_pratos} prato(s) criado(s) no catálogo.")
        else:
            print("\nSimulação: nada foi gravado. Rode com --aplicar para gravar.")
        cur.close()


if __name__ == '__main__':
    main('--aplicar' in sys.argv)
