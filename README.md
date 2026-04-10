<p align="center">
  <a>
	<img width="789" height="227" alt="image" src="https://github.com/user-attachments/assets/fee102a7-4c15-4f2e-bf01-7d0f3ce5f251" />
  </a>
</p>

<h1 align="center">GTR - Gestão de Ticket Refeição | Desenvolvido em Flask</h1>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/-Python-3776AB?style=flat-square&logo=python&logoColor=white" />
  <img alt="Flask" src="https://img.shields.io/badge/-Flask-000000?style=flat-square&logo=flask&logoColor=white" />
  <img alt="HTML5" src="https://img.shields.io/badge/-HTML5-E34F26?style=flat-square&logo=html5&logoColor=white" />
  <img alt="CSS" src="https://img.shields.io/badge/CSS-239120?style=flat-square&logo=css3&logoColor=white" />
  <img alt="Javascript" src="https://img.shields.io/badge/Javascript-FF0000?style=flat-square&logo=javascript&logoColor=white" />
  <img alt="MySQL" src="https://img.shields.io/badge/MySQL-BD00FF?style=flat-square&logo=sqlite&logoColor=white" />
</p>

---

## Sobre o GTR

GTR é uma aplicação web construída com Flask, visando facilitar o registro quantitativo de pessoas que almoçam no ambiente corporativo e fornecendo uma visão administrativa sobre esses dados. Além de fornecer insights valiosos em relatórios para tomada de decisões.

Pensado para melhorar o processo de faturamento, automatizar os processos e garantir a autenticidade dos dados no momento de tratar a contabilidade com terceirizados.

---

## Índice

- [Tela de Login](#tela-de-login)
- [Perfis de Acesso](#perfis-de-acesso)
- [Dashboard](#dashboard)
- [Módulo de Colaboradores](#módulo-de-colaboradores)
- [Módulo de Usuários do Sistema](#módulo-de-usuários-do-sistema)
- [Módulo de Departamentos](#módulo-de-departamentos)
- [Cardápio](#cardápio)
- [Emissão de Senhas](#emissão-de-senhas)
- [Relatórios](#relatórios)
- [Configurações](#configurações)
- [Tecnologias Utilizadas](#tecnologias-utilizadas)

---

## Tela de Login

<img width="1586" height="726" alt="image" src="https://github.com/user-attachments/assets/99f5153e-580e-45f8-a4f0-10f872d3c49f" />


Autenticação via banco de dados com armazenamento de sessão no back-end. Ao realizar o login, o sistema identifica o perfil do usuário e redireciona automaticamente para a rota correspondente.

---

## Perfis de Acesso

O GTR conta com quatro perfis distintos, cada um com sua rota e conjunto de permissões:

| Perfil | Rota | Descrição |
|---|---|---|
| `admin` | `/admin` | Acesso total ao sistema |
| `usuario` | `/usuario` | Acesso a relatórios e dashboard |
| `totem_desktop` | `/emissao_senha` | Interface de totem para desktop |
| `totem_tablet` | `/emissao_senha_tablet` | Interface de totem adaptada para tablet |

---

## Dashboard

<img width="1586" height="731" alt="image" src="https://github.com/user-attachments/assets/24c6a6e9-8003-43fc-98d9-83fbf56dd734" />


O dashboard está disponível tanto para o perfil **Admin** quanto para o perfil **Usuário** e exibe os seguintes indicadores em tempo real:

- Total de senhas emitidas **hoje**
- Total de senhas emitidas **no mês atual**
- Total de **colaboradores cadastrados**
- Total de **departamentos**
- **Última emissão** registrada
- **Gráfico de barras** com emissões dos últimos 7 dias
- **Gráfico de pizza** com o Top 5 departamentos com mais emissões no mês

---

## Módulo de Colaboradores

Gerenciamento completo (CRUD) da base de colaboradores.

**Cadastro:** Registra nome, CPF, cargo, departamento e tipo (limite diário de emissões). A validação de CPF é feita tanto no formato quanto na unicidade, impedindo duplicidades.

**Listagem:** Exibe todos os colaboradores com paginação (20 por página) e busca por nome ou CPF.

**Edição e Exclusão:** Permite atualizar ou remover registros de colaboradores diretamente pela listagem.

---

## Módulo de Usuários do Sistema

Permite ao administrador gerenciar os usuários que acessam o sistema.

- Cadastro com nome, usuário, senha e perfil de acesso
- Listagem de todos os usuários com status ativo/inativo
- Exclusão de usuários (com proteção para não excluir o próprio usuário logado)

---

## Módulo de Departamentos

Gerenciamento completo (CRUD) dos departamentos da organização.

- Cadastro e listagem com busca
- Exibe o **total de colaboradores vinculados** a cada departamento
- Ao renomear um departamento, o sistema atualiza automaticamente os vínculos nos colaboradores
- Impede exclusão de departamentos com colaboradores associados

---

## Cardápio

<img width="1586" height="729" alt="image" src="https://github.com/user-attachments/assets/17bb8cb0-b790-48c7-8e80-ee6f1cda8a77" />


Módulo para cadastro e gestão do cardápio diário, com suporte a foto.

**Cadastro:** Permite registrar itens de cardápio com data, tipo de refeição (Café da Manhã, Almoço, Lanche, Jantar), descrição e foto (JPG/PNG/WEBP, até 5 MB).

**Visualização pública:** Rota `/cardapio` exibe o cardápio do dia agrupado por tipo de refeição, acessível para consulta no totem.

**Gerenciamento:** Listagem com filtro por período, ativação/desativação e exclusão de itens.

<img width="1587" height="728" alt="image" src="https://github.com/user-attachments/assets/70358aba-409d-42f3-b52c-e5c0364ff2b4" />


---

## Emissão de Senhas

<img width="1588" height="728" alt="image" src="https://github.com/user-attachments/assets/ad1ed6e1-6be3-4841-a3d5-78e120b48f71" />


Rota operacional usada nos totens para que colaboradores e visitantes retirem a senha de refeição. Disponível em duas versões de layout: **desktop** e **tablet**.

### Modo de Emissão

O administrador pode alternar entre dois modos pelo painel de configurações:

**Modo Padrão:** O colaborador informa apenas o CPF. O sistema valida, verifica o limite diário e emite a senha numerada.
<img width="1591" height="728" alt="image" src="https://github.com/user-attachments/assets/4c34442f-02b9-4a62-9d59-5ffff1ee7365" />


**Modo com Cardápio:** Além do CPF, o usuário seleciona a refeição desejada no cardápio do dia antes de emitir a senha. O item escolhido fica registrado na emissão.
<img width="1581" height="719" alt="image" src="https://github.com/user-attachments/assets/feb758ce-45a9-4078-83a3-cfba6f38ecee" />

### Emissão para Colaborador

- Validação de CPF (formato e existência no banco)
- Verificação do limite diário configurado no cadastro
- Registro do nome, cargo, departamento e número sequencial da senha
- Suporte ao modo com cardápio

### Emissão para Visitante

- Informação de nome, CPF e localização
- Validação de CPF
- Limite diário: **1 senha** (padrão) ou **3 senhas** para o tipo "Acompanhante"
- Suporte ao modo com cardápio

---

## Relatórios

Todos os relatórios podem ser exportados em **PDF** ou **Excel (.xlsx)**, conforme o tipo.

<!-- Adicione prints dos relatórios aqui -->

### Relatório Analítico de Emissões

Visão estatística completa de um período selecionado:

- Total de colaboradores cadastrados na base
- Totais por período do dia: Café, Almoço e Janta — separados por colaborador e visitante
- Totais por tipo de pessoa (colaborador / visitante)
- Top 5 departamentos por volume de emissões (gráfico de barras)
- Percentual de atingimento em relação à base cadastrada (gráfico de pizza)
- Listagem por departamento
- Exportação em **PDF**

### Relatório de Emissões Diárias

Listagem detalhada de todas as emissões em um período, contendo: número da senha, CPF, nome, cargo, departamento, data e hora. Exportação em **PDF** ou **Excel**.

### Relatório por Departamento

Emissões filtradas por departamento (ou todos), com totalizadores por período do dia (Café / Almoço / Janta). Exportação em **PDF** ou **Excel**.

### Relatório de Visitantes por Localização

Emissões de visitantes filtradas por localização/localização cadastrada, com totalizadores por período. Exportação em **PDF** ou **Excel**.

### Relatório de Cardápio

Relatório específico para emissões realizadas no modo com cardápio. Permite filtrar por período, departamento, tipo de refeição e tipo de pessoa (colaborador / visitante). Apresenta:

- Resumo de emissões por tipo de refeição (colaborador / visitante / total)
- Detalhamento por item de cardápio com subtotais por refeição
- Listagem completa de registros
- Exportação em **PDF** ou **Excel** (com duas abas: detalhamento geral e total por cardápio)

---

## Configurações

Painel de configurações acessível apenas pelo perfil **Admin**.

### Tipo de Emissão de Senha

Alterna o modo de operação dos totens entre **Padrão** (só CPF) e **Com Cardápio** (CPF + seleção do cardápio do dia).
<img width="1582" height="723" alt="image" src="https://github.com/user-attachments/assets/a1407507-6acb-4055-a4af-dae624bcfef1" />


### Localizações

Gerenciamento das localizações utilizadas no cadastro de visitantes. Permite cadastrar, editar, buscar e excluir localizações.

---

## Tecnologias Utilizadas

- **Python & Flask** — back-end e roteamento da aplicação
- **HTML5, CSS3 & Javascript** — front-end e interfaces dos totens
- **MySQL** — banco de dados relacional
- **pdfkit / wkhtmltopdf** — geração de relatórios em PDF
- **matplotlib** — geração de gráficos nos relatórios analíticos
- **pandas & xlsxwriter** — geração de relatórios em Excel
- **Logging customizado** — rastreamento de ações dos usuários via `log_config.py`
