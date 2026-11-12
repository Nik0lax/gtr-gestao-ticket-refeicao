"""GTR — cliente da API da Salutem (prescrições de dieta para a Dispensa).

Mesma lógica do cliente do Dashboard Salutem (/var/www/html/dashboards_salutem/app/salutem/client.py):
login com usuário de serviço (POST /public/login), token Bearer renovado quando expira, espera de 15 min
depois de um login recusado (para não bloquear o usuário na Salutem) e WHITELIST: só os campos listados
saem daqui; o resto da resposta é descartado antes de qualquer uso. Do detalhe da prescrição, só a observação
do nutricionista e o "liberado para acompanhante" de cada dieta (pedido do usuário em 12/11/2026).

Só biblioteca padrão (sem requests): funciona em qualquer instalação do GTR sem instalar nada.
Conexão HTTPS sempre com verificação do certificado. Permite chamar o IP interno conferindo o certificado
pelo nome do servidor (ex.: https://10.0.0.20:9004 com o certificado de cliente.sistemasalutem.com.br).
"""
import http.client
import json
import socket
import ssl
import threading
import time
import urllib.parse

# ── whitelist (campos autorizados) ──
PRESCRICAO_LISTA = ('id', 'dataHoraRegistro', 'estado', 'tipoAtendimento', 'quarto', 'leito', 'registroAtendimento',
                    'dataHoraInternacao', 'nomeDieta', 'paciente', 'prontuario')
# Internados (identificação do paciente para a cozinha, a etiqueta e a 2ª checagem). Não usar /paciente/{id}:
# traz pai, cônjuge, CPF do representante etc.
INTERNADO = ('registroAtendimento', 'nomePacientePainel', 'paciente', 'nomeMae', 'dataNascimento')
PRESCRICAO_DETALHE = ('id', 'pacienteId', 'internacaoId', 'atendimentoId', 'dataHoraRegistro', 'tipoAtendimento',
                      'estado', 'possuiAltaAdmnistrativa', 'possuiAltaAClinica', 'dietas', 'dispensas')
_DESCARTAR = {'observacao', 'profissional'}          # + qualquer chave que comece com "justificativa"
# Dieta da prescrição (detalhe): a observação do nutricionista e a liberação para o acompanhante
DIETA_ITEM = ('observacao', 'liberadoParaAcompanhante', 'dataHoraSuspensao', 'statusItemPrescricao')


def filtrar(reg, campos):
    return {c: (reg or {}).get(c) for c in campos}


def _limpar(obj):
    """Remove observação, justificativas e profissional em qualquer nível (detalhe da prescrição)."""
    if isinstance(obj, dict):
        return {k: _limpar(v) for k, v in obj.items()
                if k not in _DESCARTAR and not k.lower().startswith('justificativa')}
    if isinstance(obj, list):
        return [_limpar(x) for x in obj]
    return obj


class SalutemErro(Exception):
    pass


class SalutemAutenticacaoErro(SalutemErro):
    pass


class _HTTPSNome(http.client.HTTPSConnection):
    """HTTPS para um IP, conferindo o certificado pelo nome do servidor (SNI + verificação de hostname)."""

    def __init__(self, host, port, nome_certificado, timeout):
        self._nome = nome_certificado
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())

    def connect(self):
        sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self._nome or self.host)


class SalutemCliente:
    ROTA_LOGIN = '/public/login'
    ESPERA_APOS_LOGIN_RECUSADO = 15 * 60
    MAX_PAGINAS = 60
    _recusado_em = {}            # por usuário, compartilhado no processo
    _tokens = {}
    _lock = threading.Lock()

    def __init__(self, base_url, usuario, senha, empresa_id=1, nome_certificado='', timeout=25):
        u = urllib.parse.urlsplit(base_url.rstrip('/'))
        if u.scheme != 'https':
            raise SalutemErro("A URL da Salutem precisa ser HTTPS (dados de paciente não podem trafegar sem criptografia).")
        self.host, self.port, self.prefixo = u.hostname, u.port or 443, u.path
        self.nome_cert = (nome_certificado or '').strip() or self.host
        self.usuario = (usuario or '').strip().upper()
        self.senha = senha or ''
        self.empresa_id = empresa_id
        self.timeout = timeout
        self._chave = (self.host, self.port, self.usuario)

    # ── HTTP ──
    def _req(self, metodo, rota, params=None, corpo=None, token=None):
        caminho = self.prefixo + rota + ('?' + urllib.parse.urlencode(params) if params else '')
        cab = {'Accept': 'application/json, text/plain, */*', 'Host': self.nome_cert}
        dados = None
        if corpo is not None:
            dados = json.dumps(corpo).encode()
            cab['Content-Type'] = 'application/json'
        if token:
            cab['Authorization'] = 'Bearer ' + token
        conn = _HTTPSNome(self.host, self.port, self.nome_cert, self.timeout)
        try:
            conn.request(metodo, caminho, body=dados, headers=cab)
            r = conn.getresponse()
            texto = r.read().decode('utf-8', 'replace')
            return r.status, texto
        except ssl.SSLCertVerificationError as e:
            raise SalutemErro(f"Certificado da Salutem não confere ({e.verify_message}). Confira o 'nome do certificado'.")
        except (OSError, http.client.HTTPException) as e:
            raise SalutemErro(f"Sem resposta da Salutem ({e.__class__.__name__}). Confira a URL e a rede.")
        finally:
            conn.close()

    def _login(self, recusado=None):
        with self._lock:
            tok = self._tokens.get(self._chave)
            if tok and tok != recusado:
                return tok
            quando = self._recusado_em.get(self._chave)
            if quando and time.monotonic() - quando < self.ESPERA_APOS_LOGIN_RECUSADO:
                raise SalutemAutenticacaoErro("Login na Salutem recusado há pouco; nova tentativa em alguns minutos "
                                              "(para não bloquear o usuário). Confira usuário e senha.")
            if not (self.usuario and self.senha):
                raise SalutemAutenticacaoErro("Configure o usuário e a senha da Salutem em Configurações › Integração Salutem.")
            st, txt = self._req('POST', self.ROTA_LOGIN, corpo={'usuario': self.usuario, 'senha': self.senha,
                                                               'empresa': self.empresa_id})
            try:
                d = json.loads(txt)
            except ValueError:
                d = {}
            tok = (d.get('retorno') or {}).get('token') if st == 200 and d.get('status') else None
            if not tok:
                self._recusado_em[self._chave] = time.monotonic()
                raise SalutemAutenticacaoErro(f"A Salutem recusou o login de {self.usuario}: {d.get('mensagem') or 'HTTP ' + str(st)}")
            self._recusado_em.pop(self._chave, None)
            self._tokens[self._chave] = tok
            return tok

    def get(self, rota, params=None):
        tok = self._login()
        st, txt = self._req('GET', rota, params, token=tok)
        if st in (401, 403) or (st != 200 and 'token expirado' in txt.lower()):
            tok = self._login(recusado=tok)
            st, txt = self._req('GET', rota, params, token=tok)
        if st in (401, 403):
            raise SalutemAutenticacaoErro(f"A Salutem recusou o acesso a {rota} (HTTP {st}). O usuário tem permissão nessa tela?")
        if st != 200:
            raise SalutemErro(f"A Salutem respondeu HTTP {st} em {rota}.")
        try:
            return json.loads(txt)
        except ValueError:
            raise SalutemErro("A Salutem respondeu algo que não é JSON.")

    # ── consultas ──
    def testar(self):
        """Login + uma consulta leve. Retorna texto de sucesso ou lança SalutemErro."""
        d = self.get('/refeicao/pesquisar', {'size': 1, 'page': 0})
        return f"Conectado. Login aceito para {self.usuario}; consulta respondeu ({d.get('totalElements', '?')} refeições cadastradas)."

    def prescricoes(self, dia, estado='', tipo='INTERNACAO', tamanho=500):
        # página grande: a Salutem leva ~6 s por página; 2 páginas de 100 = 12 s, 1 de 500 = 4 s
        """Todas as páginas de /prescricaoDieta/pesquisar de um dia, só com os campos autorizados."""
        base = {'prescricaoId': '', 'descricao': '', 'dataInicial': dia.isoformat(), 'dataFinal': dia.isoformat(),
                'profissionalId': '', 'paciente': '', 'registroAtendimento': '', 'tipoAtendimento': tipo,
                'unidadeInternacao': '', 'estadoDispensa': estado, 'size': tamanho}
        itens = []
        for pagina in range(self.MAX_PAGINAS):
            d = self.get('/prescricaoDieta/pesquisar', {**base, 'page': pagina})
            lote = d.get('content') or []
            itens.extend(filtrar(r, PRESCRICAO_LISTA) for r in lote)
            if not lote or d.get('last') is True or (d.get('totalPages') is not None and pagina + 1 >= d['totalPages']):
                break
        return itens

    def prescricao(self, pid):
        return _limpar(filtrar(self.get(f'/prescricaoDieta/{int(pid)}'), PRESCRICAO_DETALHE))

    def dieta_da_prescricao(self, pid):
        """Observação do nutricionista e liberação para o acompanhante das dietas ativas da prescrição."""
        dietas = [filtrar(d, DIETA_ITEM) for d in (self.get(f'/prescricaoDieta/{int(pid)}') or {}).get('dietas') or []]
        ativas = [d for d in dietas if not d.get('dataHoraSuspensao')
                  and str(d.get('statusItemPrescricao') or '').upper() not in ('SUSPENSO', 'CANCELADO', 'CANCELADA')]
        obs = []
        for d in ativas:
            o = ' '.join(str(d.get('observacao') or '').split())
            if o and o not in obs:
                obs.append(o)
        return {'observacao': ' | '.join(obs)[:1000], 'acomp': any(d.get('liberadoParaAcompanhante') is True for d in ativas)}


    def unidades_por_leito(self):
        """{leitoId: nome da unidade de internação} a partir do mapa de leitos. Só isso sai daqui
        (o mapa também traz idade do paciente, datas etc., descartados)."""
        params = {k: '' for k in ('registroInternacao', 'statusLeito', 'sexo', 'previsaoAlta', 'paciente',
                                  'quarto', 'leito', 'tipo', 'tipoAcomodacao')}
        params.update(empresaId=self.empresa_id, pesquisaUnidadeInternacaoApenasPorId='true')
        out = {}
        for u in self.get('/mapaLeito', params) or []:
            nome = ' '.join(str((u.get('unidadeInternacao') or {}).get('descricao') or '').split())
            for l in u.get('leitos') or []:
                if l.get('leitoId') is not None:
                    out[int(l['leitoId'])] = nome
        return out

    def internados(self, tamanho=500):
        """Pacientes internados agora (mesma consulta do Dashboard), só com os campos autorizados."""
        params = {'empresaId': self.empresa_id, 'situacaoAtendimento': 'EM_ATENDIMENTO', 'origem': 'PEP_INTERNACAO',
                  'internacao': 'true', 'avaliacaoEspecialista': 'false', 'size': tamanho}
        itens = []
        for pagina in range(self.MAX_PAGINAS):
            d = self.get('/atendimento/pesquisaReduzida/internacao', {**params, 'page': pagina})
            lote = d.get('atendimentos') or []
            itens.extend(filtrar(a, INTERNADO) for a in lote)
            if not lote or len(itens) >= (d.get('totalElementos') or 0):
                break
        return itens


def nome_limpo(txt):
    """'16714 - RAIMUNDO BANDEIRA - 73 ANOS (MARIA ...)' -> 'RAIMUNDO BANDEIRA' (formato de exibição da Salutem).
    Texto que já é só o nome volta igual."""
    import re
    t = ' '.join(str(txt or '').split())
    m = re.match(r'^\d+\s*[-–]\s*(.+?)\s*[-–]\s*\d+\s*(?:ANOS?|M[EÊ]S(?:ES)?|DIAS?)\b', t, re.I)
    if m:
        return m.group(1)
    m = re.match(r'^\d+\s*[-–]\s*(.+)$', t)          # '16714 - NOME' (nome reduzido)
    return m.group(1) if m else t


def _sem_codigo(txt):
    """'204 - UI-PA ADULTO  (BOX 3 - B)' -> 'UI-PA ADULTO (BOX 3 - B)'."""
    import re
    return ' '.join(re.sub(r'^\s*\d+\s*-\s*', '', txt or '').split())


def prescricoes_para_dispensa(cliente, dia):
    """Linhas no MESMO formato da leitura do CSV (para a mesma prévia da importação).
    Uma linha por atendimento: a prescrição ativa mais recente do dia. Retorna (linhas, erros, avisos)."""
    import re
    from concurrent.futures import ThreadPoolExecutor
    cliente._login()                       # login antes, para as três consultas usarem o mesmo token
    with ThreadPoolExecutor(max_workers=3) as ex:   # consultas independentes: em paralelo (o servidor corta em 30 s)
        f_pres, f_int, f_uni = ex.submit(cliente.prescricoes, dia), ex.submit(cliente.internados), ex.submit(cliente.unidades_por_leito)
        pres = f_pres.result()
        intern = {str(i['registroAtendimento']): i for i in f_int.result()}
        try:
            unidades = f_uni.result()
        except SalutemErro:
            unidades = {}                  # sem o mapa de leitos, segue sem a unidade (não bloqueia a importação)
    def unidade_de(p):
        m = re.match(r'\s*(\d+)\s*-', p.get('leito') or '')
        return unidades.get(int(m.group(1)), '') if m else ''
    por_atend = {}
    for p in pres:
        por_atend.setdefault(str(p.get('registroAtendimento') or ''), []).append(p)
    # a prescrição ativa mais recente de cada atendimento; o detalhe dela traz a observação do nutricionista
    escolhida = {}
    for atend, lista in por_atend.items():
        ativas = [p for p in lista if p.get('estado') not in ('SUSPENSO', 'CANCELADA')]
        if atend and ativas:
            escolhida[atend] = max(ativas, key=lambda x: x.get('dataHoraRegistro') or '')
    def _detalhe(p):
        try:
            return p.get('id'), cliente.dieta_da_prescricao(p['id'])
        except (SalutemErro, KeyError, TypeError, ValueError):
            return p.get('id'), None
    with ThreadPoolExecutor(max_workers=6) as ex:   # ~0,35 s cada; 6 em paralelo: ~20 s para 150 pacientes
        detalhes = dict(ex.map(_detalhe, escolhida.values()))
    sem_detalhe = sum(1 for v in detalhes.values() if v is None)
    linhas, erros, avisos, suspensos = [], [], [], []
    for n, (atend, lista) in enumerate(sorted(por_atend.items()), start=1):
        if not atend:
            erros.append(f"Prescrição {lista[0].get('id')}: sem número de atendimento na Salutem.")
            continue
        ativas = [p for p in lista if p.get('estado') not in ('SUSPENSO', 'CANCELADA')]
        if not ativas:
            suspensos.append(atend)
            continue
        p = escolhida[atend]
        det = detalhes.get(p.get('id')) or {}
        i = intern.get(atend, {})
        nome = nome_limpo(i.get('nomePacientePainel') or i.get('paciente') or p.get('paciente')).upper()
        leito = _sem_codigo(p.get('leito')) or _sem_codigo(p.get('quarto'))
        if not nome or not leito:
            erros.append(f"Atendimento {atend}: {'nome' if not nome else 'leito'} não veio da Salutem.")
            continue
        dn = str(i.get('dataNascimento') or '')[:10] or None
        linhas.append({'linha': n, 'nome': nome[:200], 'nome_mae': ' '.join(str(i.get('nomeMae') or '').split()).upper()[:200],
                       'data_nascimento': dn, 'prontuario': str(p.get('prontuario') or '')[:40], 'atendimento': atend[:40],
                       'data_prescricao': dia.isoformat(), 'leito': leito.upper()[:60],
                       'dieta': ' '.join(str(p.get('nomeDieta') or '').split()).upper()[:200],
                       'unidade': unidade_de(p).upper()[:80],
                       'observacao': det.get('observacao', ''), 'acomp_liberado': bool(det.get('acomp')),
                       'tem_obs': detalhes.get(p.get('id')) is not None})   # sem detalhe: mantém a observação anterior
        if not i:
            avisos.append(f"Atendimento {atend} ({leito}): não está na lista de internados — sem nome da mãe e nascimento.")
    if sem_detalhe:
        avisos.append(f"{sem_detalhe} prescrição(ões) sem resposta da Salutem no detalhe: a observação do nutricionista "
                      "não foi carregada para elas (a observação anterior, se houver, é mantida).")
    if suspensos:
        avisos.append(f"{len(suspensos)} atendimento(s) só com prescrição SUSPENSA ou CANCELADA hoje — ficaram de fora: "
                      + ', '.join(suspensos[:15]) + (' …' if len(suspensos) > 15 else '') + '.')
    return linhas, erros, avisos
