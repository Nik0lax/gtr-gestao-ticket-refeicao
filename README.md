<p align="center">
  <a>
	<img width="789" height="227" alt="GTR" src="https://github.com/user-attachments/assets/fee102a7-4c15-4f2e-bf01-7d0f3ce5f251" />
  </a>
</p>

<h1 align="center">GTR - Gestão de Ticket Refeição</h1>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/-Python-3776AB?style=flat-square&logo=python&logoColor=white" />
  <img alt="Flask" src="https://img.shields.io/badge/-Flask-000000?style=flat-square&logo=flask&logoColor=white" />
  <img alt="MariaDB" src="https://img.shields.io/badge/MariaDB-003545?style=flat-square&logo=mariadb&logoColor=white" />
  <img alt="Docker" src="https://img.shields.io/badge/Docker-2496ED?style=flat-square&logo=docker&logoColor=white" />
</p>

---

## Sobre o GTR

O GTR é uma aplicação web em Flask para controlar as refeições servidas em hospitais e empresas e dar base confiável ao faturamento da empresa terceirizada de alimentação.

Ele cobre dois fluxos:

- **Refeitório:** colaboradores e visitantes retiram a senha de refeição no totem (CPF), com regras de direito por escala de trabalho, limites diários e cardápio do dia.
- **Dispensa no leito:** a nutrição importa as prescrições dos pacientes (CSV ou API da Salutem) e autoriza as refeições; a dispenseira entrega leito a leito pelo totem tablet, conferindo o QR da etiqueta do leito ou da pulseira.

Tudo fica registrado e auditado, e os relatórios financeiros consolidam colaboradores, visitantes, pacientes e acompanhantes.

---

## Índice

- [Novidades desta versão](#novidades-desta-versão)
- [Perfis de acesso e permissões](#perfis-de-acesso-e-permissões)
- [Painel e cadastros](#painel-e-cadastros)
- [Escalas de trabalho](#escalas-de-trabalho)
- [Emissão de senhas (refeitório)](#emissão-de-senhas-refeitório)
- [Cardápio](#cardápio)
- [Dispensa de refeições para pacientes](#dispensa-de-refeições-para-pacientes)
- [Relatórios](#relatórios)
- [Parâmetros](#parâmetros)
- [Configurações (somente Administrador)](#configurações-somente-administrador)
- [Segurança](#segurança)
- [Instalação](#instalação)
- [Atualização de uma unidade existente](#atualização-de-uma-unidade-existente)
- [Estrutura do projeto](#estrutura-do-projeto)
- [Tecnologias](#tecnologias)

---

## Novidades desta versão

| Área | O que mudou |
|---|---|
| **Visual** | Novo layout em todo o sistema: painel, login, totens (desktop e tablet), página pública do cardápio e relatórios em PDF com cabeçalho e rodapé padronizados. |
| **Perfis** | Perfis criados pela tela, com permissão de ver, incluir, editar e excluir por módulo. O painel antigo do perfil "Usuário" foi substituído pelo painel único com menus filtrados. |
| **Escalas** | Direito a refeição definido pela escala de trabalho do colaborador (tipos e quantidade de refeições), com aplicação em lote e importação por CSV. |
| **Emissão** | Limite de senhas do visitante configurável; CPF de colaborador recusado como visitante; trava contra senhas duplicadas (clique duplo e concorrência); regra única de classificação da refeição em todo o sistema. |
| **Cardápio** | Catálogo de pratos, montagem do cardápio do dia com "copiar de ontem", visão da semana e página pública com destaque "Servindo agora". |
| **Dispensa (novo)** | Módulo completo de refeições para pacientes: importação de prescrições, autorização por período, acompanhante, totem de entrega com QR, etiquetas do leito, acompanhamento ao vivo, correções, fechamento de período e relatório financeiro. |
| **Relatórios** | Novos: Financeiro Dispensa e Faturamento consolidado. Todos os PDFs seguem o mesmo padrão e aguentam relatórios grandes. |
| **Segurança** | Chave de sessão segura, encerramento por inatividade, bloqueio de login após tentativas, política de senha, proteção CSRF e auditoria de todas as alterações. |
| **Backup** | Backup automático diário e restauração pela própria tela, com backup de segurança antes de restaurar. |
| **Configuração** | Senhas, IPs e endereços saíram do código e ficam no arquivo `.env` de cada unidade (modelo em `.env.example`). |

---

## Perfis de acesso e permissões

Os perfis são cadastrados em **Cadastro › Perfis**. Cada perfil define:

- **Tela inicial:** painel, totem desktop, totem tablet ou totem de dispensa;
- **Permissões por módulo:** ver, incluir, editar e excluir (Cadastros, Cardápio, Dispensa Refeição, Relatórios e Parâmetros).

Regras:

- O perfil **Administrador** é protegido: tem acesso total, não pode ser excluído nem desativado, e o sistema não deixa ficar sem um Administrador ativo.
- Perfil com usuários vinculados não pode ser excluído, e ninguém altera o próprio perfil.
- A checagem é central, feita em toda requisição. Rota sem regra de permissão é exclusiva do Administrador.

Na primeira execução, os perfis antigos (Administrador, Usuário, Totem Desktop, Totem Tablet) são recriados automaticamente com o mesmo acesso que tinham, e o perfil **Dispensa** é criado para o totem de entrega.

---

## Painel e cadastros

- **Dashboard:** senhas de hoje e do mês, comparativo com o mês anterior, últimos 7 dias e departamentos com mais emissões.
- **Colaboradores:** cadastro com CPF validado, cargo, departamento e escala; importação por CSV.
- **Usuários:** cadastro com perfil, ativação e troca de senha obrigatória no próximo acesso.
- **Departamentos** e **Grupos SND:** agrupamentos usados nos relatórios.
- **Minha senha:** qualquer usuário troca a própria senha clicando no nome, no topo da tela.

---

## Escalas de trabalho

Em **Cadastro › Escalas de trabalho**, cada escala define quantas senhas por dia o colaborador tem em cada refeição (café, almoço e jantar; 0 = sem direito) e, opcionalmente, um máximo diário.

- A escala é aplicada no cadastro do colaborador, em lote (por departamento ou cargo) ou por **importação de CSV**. O modelo de CSV já sai com todos os colaboradores, e o RH só preenche a coluna "escala"; antes de gravar, o sistema mostra uma prévia.
- **Transição:** colaborador sem escala continua com a regra antiga (quantidade de refeições por dia, em qualquer turno).

---

## Emissão de senhas (refeitório)

Totens em layout **desktop** e **tablet** (paisagem e retrato). O colaborador informa o CPF; o visitante informa nome, CPF e localização.

- **Qual refeição é a senha** é decidido por uma regra única, pelos **Horários de turno**: café e almoço nas faixas configuradas, e o restante é jantar. Os relatórios usam a mesma regra.
- **Colaborador:** pode retirar a senha se a escala dele dá direito à refeição do horário, até o limite do dia.
- **Visitante:**
  - limite diário configurável (padrão e por localização);
  - a contagem soma todas as senhas do CPF no dia;
  - CPF cadastrado como colaborador é recusado.
- **Modo com cardápio:** o totem mostra só o cardápio da refeição do horário.
- **Concorrência:** a contagem e a numeração da senha são travadas no banco, e o totem bloqueia clique duplo.

---

## Cardápio

- **Catálogo de pratos:** cada prato tem nome, categoria e foto e é cadastrado uma única vez.
- **Montar cardápio do dia:** monta café, almoço e jantar a partir do catálogo, com a opção **"copiar de ontem"**.
- **Visão da semana:** mostra a semana inteira, com a opção de copiar uma semana para outra.
- **Página pública** (`/cardapio`): mostra o cardápio do dia e destaca a refeição que está sendo servida.

O totem continua lendo o cardápio no mesmo formato de antes. Para converter os cardápios antigos para o catálogo, use `scripts/migrar_cardapio_catalogo.py` (veja [Atualização](#atualização-de-uma-unidade-existente)).

---

## Dispensa de refeições para pacientes

Menu **Dispensa Refeição**. Os dados de pacientes são sensíveis (LGPD): tudo exige login, nada é público, e as prévias temporárias são apagadas automaticamente.

### Fluxo

1. **Importar prescrições:** a nutrição importa por **CSV** ou pelo botão **"Buscar na Salutem"** (API). As duas fontes caem na mesma prévia.
   - **Período:** a importação é feita duas vezes ao dia. A da **manhã** cobre Almoço e Lanche da Tarde. A da **noite** cobre Jantar ou Jantar (Sopa), Ceia, e o Desjejum e a Colação do dia seguinte.
   - **Autorização:** na prévia, as refeições do período já vêm marcadas, e a nutricionista desmarca ou troca o que for preciso. Só a nutrição autoriza; a cozinha apenas consulta o que produzir.
   - **Alertas da prévia:**
     - dietas ZERO, JEJUM ou SUSPENSA;
     - data de prescrição diferente de hoje ou amanhã;
     - período fechado;
     - pacientes que **não vieram na nova importação** (provável alta ou transferência). Os marcados têm as refeições pendentes encerradas como "não entregue".
   - **Dietas sem refeição:** dietas que não recebem refeição (configuráveis, por exemplo hidratação ou suplemento) ficam fora da importação.
2. **Acompanhante:** pode receber refeição (padrão até 3 por dia; lactante até 5, configurável), com os mesmos tipos e valores do paciente.
3. **Pacientes do dia:** lista somente leitura para a cozinha, com filtros por dieta e por unidade e contadores. Ajustes posteriores são feitos pela nutrição, com motivo.
4. **Etiquetas QR do leito:**
   - impressão em impressora térmica de 100×40 mm, com unidade, leito, nome, nascimento e nome da mãe;
   - o código é assinado por HMAC, então não dá para forjar;
   - o sistema avisa quando um paciente está sem etiqueta ou mudou de leito.
5. **Totem de dispensa** (tablet, perfil Dispensa):
   - **Navegação:** a dispenseira escolhe a refeição e a unidade e vê a lista de leitos.
   - **Conferência:** a entrega é conferida pela **câmera**, lendo o QR da etiqueta ou da pulseira. Pulseira de outro paciente é detectada e recusada.
   - **Entrega sem QR:** exige motivo e a digitação de prontuário e atendimento. "Não entregue" exige motivo.
   - **Registro definitivo:** não há "desfazer" no totem. Os tablets se sincronizam a cada 8 s e avisam quando outro tablet já registrou o leito.
   - **Inatividade:** depois de 10 minutos sem uso, o totem sai sozinho.
   - **Virada do dia:** o jantar e a ceia do dia anterior continuam aceitos até **03:00**.
   - **HTTPS:** a câmera do tablet só funciona com HTTPS (veja `GTR_URL_HTTPS` no `.env`).
6. **Acompanhamento da entrega:** tela ao vivo para a cozinha. Quem tem permissão faz a **correção de registros** do totem, com motivo e histórico.
7. **Tipos de refeição:**
   - valor de cada tipo, período, "dia seguinte" e alternativa (um OU outro, como Jantar ou Jantar (Sopa));
   - **reajuste auditado** de valores. Os itens pendentes acompanham o valor novo; o valor de cada refeição congela na entrega.
8. **Fechamento de período:** livre, por datas. Antes de fechar, o sistema confere as pendências (sem registro, valor R$ 0,00, % de entregas sem QR). Período fechado bloqueia qualquer alteração e só é reaberto com permissão e motivo.

---

## Relatórios

Todos geram **PDF** e, quando aplicável, **Excel**. Os PDFs usam o cabeçalho e o rodapé padrão (`templates/_relatorio_padrao.html`).

| Relatório | Conteúdo |
|---|---|
| Total de senhas | Visão analítica do período: por refeição, por tipo de pessoa, top departamentos e atingimento da base |
| Lista de senhas emitidas | Uma linha por senha (número, CPF, nome, cargo, departamento, data e hora) |
| Total de visitantes | Emissões de visitantes por localização |
| Por departamento | Emissões por departamento, separadas por refeição |
| Emissões com cardápio | Emissões feitas no modo com cardápio, por prato e refeição |
| Financeiro SND | Valores do refeitório por grupo SND, com os custos de refeição vigentes |
| Financeiro Dispensa | Refeições **entregues** a pacientes e acompanhantes, pelo valor congelado na entrega, com alertas (R$ 0,00, pendentes, % sem QR, correções) e selo de período fechado |
| Faturamento (consolidado) | Colaboradores, visitantes, pacientes e acompanhantes em um único relatório |

---

## Parâmetros

Menu **Parâmetros**. Cada item pode ser liberado para outros perfis.

- **Localizações** (dos visitantes)
- **Emissão de senha:** modo padrão ou com cardápio
- **Custos de refeição**, com histórico de vigência
- **Horários de turno:** definem a classificação café, almoço ou jantar
- **Limite de senhas (visitante):** limite padrão e por localização, de 1 a 10

---

## Configurações (somente Administrador)

| Tela | Função |
|---|---|
| **Identidade** | Nome da instituição exibido nas telas e nos relatórios |
| **Segurança** | Bloqueio de login (tentativas por usuário e por IP, janela e tempo de bloqueio), lista de bloqueios e política de senha |
| **Auditoria** | Quem fez o quê e quando, com antes e depois das alterações e exportação para Excel; retenção de 730 dias |
| **Backup** | Backup manual e automático diário (horário e retenção configuráveis), download, exclusão e restauração |
| **Integração Salutem** | URL da API, nome do certificado, empresa e usuário de serviço, com teste de conexão |

---

## Segurança

- **Sessão:**
  - a chave vem de `SECRET_KEY` (32+ caracteres) ou é gerada uma única vez em `instance/secret_key` (permissão 600, fora do Git);
  - cookies `HttpOnly` e `SameSite=Lax`, e `Secure` quando configurado;
  - logout por inatividade, exceto nos totens.
- **Login:**
  - bloqueio por usuário e por IP, sem revelar se o usuário existe;
  - senhas sempre com hash; senhas antigas em texto puro são convertidas automaticamente.
- **Política de senha:** tamanho mínimo e exigência de maiúscula, minúscula e número, configuráveis. Também dá para obrigar a troca da senha no próximo acesso.
- **CSRF:** um token por sessão é conferido em todo POST e injetado automaticamente nos formulários. Chamadas `fetch` enviam o token no cabeçalho `X-CSRF-Token`.
- **Auditoria:** todo POST fica registrado. CPF, prontuário e atendimento aparecem parcialmente mascarados, e senhas e QR nunca são gravados.
- **Segredos fora do código:** banco, endereços e integração ficam no `.env`. A credencial da Salutem fica em `instance/salutem.json` (permissão 600).

---

## Instalação

### 1. Configuração (`.env`)

```bash
cp .env.example .env
chmod 600 .env
# edite o .env: senha do banco, endereço HTTPS da unidade, dados da Salutem etc.
```

Sem `MYSQL_PASSWORD`, o GTR não sobe e avisa o motivo. As variáveis definidas no ambiente (systemd, Docker) prevalecem sobre o `.env`.

### 2a. Instalação nativa (Linux)

```bash
sudo apt install python3-venv wkhtmltopdf libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b default-libmysqlclient-dev
python3 -m venv venv
venv/bin/pip install -r requirements.txt
venv/bin/python -m gunicorn -w 2 --timeout 120 -b 0.0.0.0:8000 app:app
```

Use `--timeout 120`: as consultas à Salutem e os relatórios grandes passam dos 30 s padrão do gunicorn.

Exemplo de serviço systemd (`/etc/systemd/system/gtr.service`):

```ini
[Unit]
Description=GTR - Gestão de Ticket Refeição
After=network.target mariadb.service

[Service]
User=www-data
Group=www-data
WorkingDirectory=/caminho/do/gtr
ExecStart=/caminho/do/gtr/venv/bin/python -m gunicorn -w 2 --timeout 120 -b 0.0.0.0:8000 app:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

**HTTPS** (necessário para a câmera do totem de dispensa): acrescente `--certfile` e `--keyfile` ao gunicorn, ou use um proxy reverso. Depois, informe o endereço em `GTR_URL_HTTPS` e defina `SESSION_COOKIE_SECURE=1` na instância HTTPS.

### 2b. Docker

```bash
cp .env.example .env    # preencha MYSQL_PASSWORD e MYSQL_ROOT_PASSWORD
docker compose up -d --build
```

Volumes que guardam os dados fora do container: `./uploads`, `./instance` (chave de sessão e credencial da Salutem), `./backups` e `./static/uploads` (fotos do cardápio). O banco fica no volume `db_data`.

As tabelas novas são criadas automaticamente pelo próprio GTR na primeira execução.

---

## Atualização de uma unidade existente

1. **Backup antes de tudo:** faça um `mysqldump` do banco e uma cópia de `static/uploads/`, `instance/` e dos certificados.
2. **Atualize o código** (`git pull` ou cópia dos arquivos) e instale as dependências novas: `venv/bin/pip install -r requirements.txt` (entre elas `pypdf` e `weasyprint`, e as bibliotecas pango/harfbuzz do sistema).
3. **Crie o `.env`** a partir do `.env.example`. A versão nova **não sobe sem ele**, porque a senha do banco saiu do código.
4. **Reinicie o serviço.** As tabelas e colunas novas são criadas automaticamente, e os perfis antigos são convertidos com o mesmo acesso.
5. **Converta o cardápio antigo** para o catálogo de pratos. Rode primeiro em simulação e depois aplique:
   ```bash
   venv/bin/python scripts/migrar_cardapio_catalogo.py            # simulação
   venv/bin/python scripts/migrar_cardapio_catalogo.py --aplicar
   ```
6. **Depois da atualização:**
   - todos os usuários precisam **entrar de novo** uma vez, porque a sessão foi trocada;
   - senhas que não atendem à política são trocadas no próximo acesso;
   - distribua as **escalas** dos colaboradores. Até lá, vale a regra antiga.

---

## Estrutura do projeto

```
app.py                     aplicação Flask (rotas, regras, permissões, auditoria)
backup_gtr.py              backup e restauração (processo separado, sem mysqldump)
salutem_gtr.py             cliente da API da Salutem (biblioteca padrão, HTTPS verificado)
log_config.py              log da aplicação (logs/gtr.log)
schema.sql                 estrutura inicial do banco (Docker)
scripts/                   migrações pontuais (cardápio → catálogo)
templates/                 telas (menu_admin.html = painel), totens e relatórios em PDF
static/                    CSS, JS, sons e imagens
.env.example               modelo de configuração da unidade
Dockerfile, docker-compose.yml
```

Não vão para o Git: `.env`, `instance/`, `certs/`, `backups/`, `logs/`, `uploads/` e `static/uploads/`.

---

## Tecnologias

- **Python 3 e Flask**, com gunicorn
- **MariaDB/MySQL** (Flask-MySQLdb)
- **WeasyPrint, wkhtmltopdf e pypdf**: relatórios em PDF
- **pandas e XlsxWriter**: relatórios em Excel
- **matplotlib**: gráficos dos relatórios
- **qrcode**: etiquetas do leito; leitura no totem por BarcodeDetector/jsQR
- **HTML, CSS e JavaScript** puros nos totens e no painel
