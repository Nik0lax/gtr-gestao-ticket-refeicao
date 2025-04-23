<p align="center">
  <a>
    <img src="https://github.com/user-attachments/assets/de38cf9a-0904-474d-b001-91e705fe8510">


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
<br>

### V1.3:
Adicionado o nome do usuário na barra superior na tela de admin/usuário
<br>Adicionado bloqueio de números no input de Nome na tela de Senha Visitante
<br>Adicionado som de sucesso e falha ao emitir senha nas rotas de Senha
<br>Corrigido bug do log que não registrava o conteúdo e apagava o histórico
<br>Adicionado campo de busca de colaborador na tela de Cadastro
<br>Ocultado o botão de sair do Totem
<br>Removido a lógica da impressora térmica

## Sobre o GTR

<p align="center">
  <p>Rota Admin</p>
  <img src="https://github.com/user-attachments/assets/de377f0a-d788-46aa-bfa7-69ccd5589b40"/>
  <p>Rota Totem</p>
	<img src="https://github.com/user-attachments/assets/303e0dcd-f5c7-494a-a120-b6d36c8f9179"/>
</p>
<p align="center">

GTR é uma aplicação web construída com Flask, visado facilitar o registro de quantitativo de pessoas que almoçam no ambiente corporativo e fornecendo uma visão administrativa sobre estes dados. Além de fornecer insights valiosos em relatórios para tomada de decisões.

<br>Pensado para melhorar o processo de faturamento, automatizar os processos e garantir a autenticidade dos dados no momento de tratar a contabilidade com terceirizados.
</p>

### Funcionalidades
#### Tela de Login

<p align="center">
  <img src="https://github.com/user-attachments/assets/007aca78-619b-45ab-90a2-73f3b205dab9" width="600">
</p>

A tela de login com validação via banco de dados e armazenamento de sessão no back end para direcionamento das rotas da aplicação.

### Rota Admin
<p align="center">
  <img src="https://github.com/user-attachments/assets/c79f1ed8-8378-4050-94f7-73859e0e056c" width="600">
</p>

A rota do Admin permite o Cadastro de novos colaboradores e a emissão de Relatórios com as senhas que foram emitidas. A rota de configuração ainda está em desenvolvimento.

#### Cadastro de Colaboradores
<p align="center">
  <img src="https://github.com/user-attachments/assets/c615f618-95f0-43ae-aa42-139f682fd21b" width="600">  
</p>
O módulo de Cadastro permite o registro deu um novo colaborador, onde é definido o departamento e o Tipo(Quantidade de emissões de senha refeição) pode emitir por dia.
A validação do CPF é única, permitindo apenas um CPF por cadastro, evitando duplicidade e garantindo a eficiência do controle de emissões.

#### Relatórios
<p align="center">
  <img src="https://github.com/user-attachments/assets/d96f0185-f2ea-403d-a651-8d8849447973" alt="Relatório 1" width="45%" />
  <img src="https://github.com/user-attachments/assets/d3a33b4c-149b-484f-aaf8-6a8aaf3d6b70" alt="Relatório 2" width="45%" />
</p> 

**Relatório Total de Senhas Emitidas**
- Exibe uma listagem detalhada de todas as senhas geradas no período selecionado.
- Informações incluídas:
  - Número da senha
  - CPF do colaborador/visitante
  - Nome
  - Cargo
  - Departamento
  - Data e hora da emissão
- Indicado para auditoria e conferência individual das emissões.

**Relatório Analítico com Gráficos**
- Apresenta uma visão estatística das senhas emitidas em determinado período, com:
  - Total de colaboradores cadastrados
  - Resumo de senhas por período (diurno/noturno)
  - Quantidade por tipo (visitante/colaborador)
  - Quantidade por departamento
- Inclui gráficos de:
  - Barras: Top 5 departamentos com mais emissões
  - Pizza: Proporção de senhas emitidas vs base de colaboradores cadastrados
- Ideal para análise gerencial e planejamento.


### Rota Emissões de Senha
<p align="center">
  <img src="https://github.com/user-attachments/assets/5c9d3118-30ec-4b4b-b35d-715d03bd3a3e" width="45%" />
  <img src="https://github.com/user-attachments/assets/a31e4ad8-2fb9-41ab-994e-da09ad42e8d0" width="45%" />
</p>
<p align="center">
  <img src="https://github.com/user-attachments/assets/0db3abf7-3c0f-4dd3-ad24-40a938dd400a" width="45%" />
  <img src="https://github.com/user-attachments/assets/beb3e6dc-9ff8-418f-8dd8-782ffb80a364" width="45%" />
</p>
A rota de Emissões de senha é o fluxo operacional usado pelos colaboradores/visitantes para emitir a senha e poder retirar a refeição.
Foi definido duas rotas: Colaborador para os funcionários fixos e visitantes para usuários temporários ou exporádicos.
Como parâmetros de controle, foi definido: validação de CPF, verificação se o CPF existe no banco para o colaborador, verificação de limite de emissão.


## Tecnologias utilizadas

- <strong>Python, Flask</strong>
  
- <strong>HTML5, CSS3 e Javascript</strong>
  
- <strong>MySQL</strong>
  