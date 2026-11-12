/*M!999999\- enable the sandbox mode */ 
-- MariaDB dump 10.19  Distrib 10.11.13-MariaDB, for debian-linux-gnu (x86_64)
--
-- Host: localhost    Database: gtr
-- ------------------------------------------------------
-- Server version	10.11.13-MariaDB-0ubuntu0.24.04.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `cardapios`
--

DROP TABLE IF EXISTS `cardapios`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `cardapios` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `data_cardapio` date NOT NULL,
  `tipo_refeicao` varchar(50) NOT NULL,
  `descricao` text NOT NULL,
  `foto` varchar(255) DEFAULT NULL,
  `ativo` tinyint(1) NOT NULL DEFAULT 1,
  `criado_em` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_data_ativo` (`data_cardapio`,`ativo`)
) ENGINE=InnoDB AUTO_INCREMENT=23 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `colaboradores`
--

DROP TABLE IF EXISTS `colaboradores`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `colaboradores` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `nome` varchar(255) NOT NULL,
  `cpf` varchar(14) NOT NULL,
  `cargo` varchar(100) DEFAULT NULL,
  `departamento` varchar(100) DEFAULT NULL,
  `tipo` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `cpf` (`cpf`)
) ENGINE=InnoDB AUTO_INCREMENT=4743 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `configuracoes_sistema`
--

DROP TABLE IF EXISTS `configuracoes_sistema`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `configuracoes_sistema` (
  `chave` varchar(100) NOT NULL,
  `valor` varchar(255) NOT NULL,
  `descricao` varchar(255) DEFAULT NULL,
  `atualizado_em` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`chave`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `custos_historico`
--

DROP TABLE IF EXISTS `custos_historico`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `custos_historico` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `tipo_refeicao` varchar(20) NOT NULL,
  `descricao` varchar(100) DEFAULT NULL,
  `custo_unitario` decimal(10,2) NOT NULL,
  `vigente_desde` datetime NOT NULL,
  `alterado_por` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `custos_refeicao`
--

DROP TABLE IF EXISTS `custos_refeicao`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `custos_refeicao` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `tipo_refeicao` varchar(50) NOT NULL COMMENT 'cafe | almoco | janta',
  `descricao` varchar(100) NOT NULL COMMENT 'Rótulo exibido (ex: Café da Manhã)',
  `custo_unitario` decimal(10,2) NOT NULL DEFAULT 0.00 COMMENT 'Custo por refeição (R$)',
  `ativo` tinyint(1) NOT NULL DEFAULT 1,
  `atualizado_em` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_tipo_refeicao` (`tipo_refeicao`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='Custo unitário de cada tipo de refeição para uso nos relatórios';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `departamentos`
--

DROP TABLE IF EXISTS `departamentos`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `departamentos` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `nome` varchar(100) NOT NULL,
  `grupo` varchar(50) NOT NULL DEFAULT 'Administrativos' COMMENT 'Produtivos | Auxiliares | Administrativos | Não Operacional',
  PRIMARY KEY (`id`),
  UNIQUE KEY `nome` (`nome`)
) ENGINE=InnoDB AUTO_INCREMENT=79 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `emissoes_senha`
--

DROP TABLE IF EXISTS `emissoes_senha`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `emissoes_senha` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `nome` varchar(255) NOT NULL,
  `cpf` varchar(14) NOT NULL,
  `cargo` varchar(255) NOT NULL,
  `departamento` varchar(255) NOT NULL,
  `data_hora` datetime NOT NULL,
  `numero_senha` int(11) DEFAULT NULL,
  `cardapio_id` int(11) DEFAULT NULL COMMENT 'FK → cardapios.id',
  `tipo_refeicao` varchar(50) DEFAULT NULL COMMENT 'Snapshot do tipo_refeicao',
  `descricao_cardapio` text DEFAULT NULL COMMENT 'Snapshot da descrição',
  PRIMARY KEY (`id`),
  KEY `idx_cardapio_id` (`cardapio_id`)
) ENGINE=InnoDB AUTO_INCREMENT=78673 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `grupos`
--

DROP TABLE IF EXISTS `grupos`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `grupos` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `nome` varchar(100) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `nome` (`nome`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `localizacoes`
--

DROP TABLE IF EXISTS `localizacoes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `localizacoes` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `nome` varchar(100) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `usuarios`
--

DROP TABLE IF EXISTS `usuarios`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `usuarios` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `nome` varchar(100) NOT NULL,
  `usuario` varchar(50) NOT NULL,
  `senha` varchar(255) NOT NULL,
  `perfil` enum('admin','usuario','totem_desktop','totem_tablet') NOT NULL,
  `status` tinyint(1) DEFAULT 1,
  `criado_em` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `usuario` (`usuario`)
) ENGINE=InnoDB AUTO_INCREMENT=22 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping routines for database 'gtr'
--
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2026-06-10 14:27:14

--
-- Catálogo de pratos e itens do cardápio (módulo de cardápio v2)
-- Também criadas automaticamente pela aplicação (init_cardapio_catalogo).
--
CREATE TABLE IF NOT EXISTS `pratos` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `nome` varchar(150) NOT NULL,
  `categoria` varchar(30) NOT NULL COMMENT 'principal | acompanhamento | padaria | salada | sobremesa | bebida',
  `foto` varchar(255) DEFAULT NULL,
  `ativo` tinyint(1) NOT NULL DEFAULT 1,
  `criado_em` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_prato_nome_cat` (`nome`,`categoria`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `cardapio_itens` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `cardapio_id` int(11) NOT NULL,
  `prato_id` int(11) NOT NULL,
  `ordem` int(11) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `idx_ci_cardapio` (`cardapio_id`),
  KEY `idx_ci_prato` (`prato_id`),
  CONSTRAINT `fk_ci_cardapio` FOREIGN KEY (`cardapio_id`) REFERENCES `cardapios` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_ci_prato` FOREIGN KEY (`prato_id`) REFERENCES `pratos` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Módulo Dispensa Refeição (pacientes) — também criadas automaticamente pela aplicação (init_dispensa_tables)
--
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `nome` varchar(80) NOT NULL,
  `descricao` varchar(255) DEFAULT NULL,
  `valor` decimal(10,2) NOT NULL DEFAULT 0.00,
  `ordem` int(11) NOT NULL DEFAULT 0,
  `ativo` tinyint(1) NOT NULL DEFAULT 1,
  `criado_em` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_dispensa_tipo_nome` (`nome`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `tipo_id` int(11) NOT NULL,
  `valor` decimal(10,2) NOT NULL,
  `alterado_em` timestamp NULL DEFAULT current_timestamp(),
  `alterado_por` varchar(120) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_dth_tipo` (`tipo_id`),
  CONSTRAINT `fk_dth_tipo` FOREIGN KEY (`tipo_id`) REFERENCES `dispensa_tipos` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `arquivo_nome` varchar(255) NOT NULL,
  `importado_em` timestamp NULL DEFAULT current_timestamp(),
  `importado_por` varchar(120) DEFAULT NULL,
  `total_linhas` int(11) NOT NULL DEFAULT 0,
  `inseridos` int(11) NOT NULL DEFAULT 0,
  `atualizados` int(11) NOT NULL DEFAULT 0,
  `ignorados` int(11) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `atendimento` varchar(40) NOT NULL,
  `data_prescricao` date NOT NULL,
  `nome` varchar(200) NOT NULL,
  `nome_mae` varchar(200) DEFAULT NULL,
  `data_nascimento` date DEFAULT NULL,
  `prontuario` varchar(40) DEFAULT NULL,
  `leito` varchar(60) NOT NULL,
  `dieta` varchar(200) DEFAULT NULL,
  `importacao_id` int(11) DEFAULT NULL,
  `criado_em` timestamp NULL DEFAULT current_timestamp(),
  `atualizado_em` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_dispensa_pac` (`atendimento`,`data_prescricao`),
  KEY `idx_dp_data` (`data_prescricao`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `paciente_id` int(11) NOT NULL,
  `tipo_id` int(11) NOT NULL,
  `valor_unitario` decimal(10,2) NOT NULL DEFAULT 0.00 COMMENT 'Snapshot do valor no momento da definição',
  `status` varchar(20) NOT NULL DEFAULT 'pendente' COMMENT 'pendente | entregue | nao_entregue',
  `definido_por` varchar(120) DEFAULT NULL,
  `definido_em` timestamp NULL DEFAULT current_timestamp(),
  `entregue_em` datetime DEFAULT NULL,
  `entregue_por` varchar(120) DEFAULT NULL,
  `motivo` varchar(255) DEFAULT NULL,
  `validacao` varchar(20) DEFAULT NULL COMMENT 'qr | manual',
  `ajuste_id` int(11) DEFAULT NULL COMMENT 'Reajuste de valor aplicado depois da entrega',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_dispensa_item` (`paciente_id`,`tipo_id`),
  KEY `idx_di_tipo` (`tipo_id`),
  CONSTRAINT `fk_di_paciente` FOREIGN KEY (`paciente_id`) REFERENCES `dispensa_pacientes` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_di_tipo` FOREIGN KEY (`tipo_id`) REFERENCES `dispensa_tipos` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Perfil 'dispensa' (totem de dispensa de pacientes). Também aplicado automaticamente pela aplicação (init_dispensa_fase2).
-- ALTER TABLE `usuarios` MODIFY `perfil` ENUM('admin','usuario','totem_desktop','totem_tablet','dispensa') NOT NULL;

CREATE TABLE IF NOT EXISTS `dispensa_ajustes_valor` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `tipo_id` int(11) NOT NULL,
  `valor_antigo` decimal(10,2) NOT NULL,
  `valor_novo` decimal(10,2) NOT NULL,
  `qtd_itens` int(11) NOT NULL,
  `data_ini` date DEFAULT NULL,
  `data_fim` date DEFAULT NULL,
  `motivo` varchar(255) NOT NULL,
  `feito_por` varchar(120) DEFAULT NULL,
  `feito_em` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_dav_tipo` (`tipo_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;


--
-- Perfis e permissões configuráveis (Cadastro › Perfis). Também criadas/migradas automaticamente
-- pela aplicação no primeiro login (init_perfis): usuarios.perfil vira VARCHAR e ganha usuarios.perfil_id.
--
CREATE TABLE IF NOT EXISTS `perfis` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `chave` varchar(40) DEFAULT NULL COMMENT 'Perfis de sistema (admin, usuario, ...)',
  `nome` varchar(80) NOT NULL,
  `descricao` varchar(255) DEFAULT NULL,
  `inicio` varchar(20) NOT NULL DEFAULT 'painel' COMMENT 'painel | totem_desktop | totem_tablet | dispensa',
  `protegido` tinyint(1) NOT NULL DEFAULT 0 COMMENT 'Administrador: acesso total, não pode ser alterado/excluído',
  `ativo` tinyint(1) NOT NULL DEFAULT 1,
  `criado_em` timestamp NULL DEFAULT current_timestamp(),
  `atualizado_em` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_perfil_nome` (`nome`),
  UNIQUE KEY `uk_perfil_chave` (`chave`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `perfil_permissoes` (
  `perfil_id` int(11) NOT NULL,
  `modulo` varchar(40) NOT NULL,
  `ver` tinyint(1) NOT NULL DEFAULT 0,
  `incluir` tinyint(1) NOT NULL DEFAULT 0,
  `editar` tinyint(1) NOT NULL DEFAULT 0,
  `excluir` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`perfil_id`,`modulo`),
  CONSTRAINT `fk_pp_perfil` FOREIGN KEY (`perfil_id`) REFERENCES `perfis` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Fechamento de período (livre) da dispensa. Também criada automaticamente (init_dispensa_fechamentos).
CREATE TABLE IF NOT EXISTS `dispensa_fechamentos` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `data_ini` date NOT NULL,
  `data_fim` date NOT NULL,
  `status` varchar(20) NOT NULL DEFAULT 'fechado' COMMENT 'fechado | reaberto',
  `qtd_previstas` int(11) NOT NULL DEFAULT 0,
  `qtd_entregues` int(11) NOT NULL DEFAULT 0,
  `qtd_sem_qr` int(11) NOT NULL DEFAULT 0,
  `qtd_nao` int(11) NOT NULL DEFAULT 0,
  `qtd_pendentes` int(11) NOT NULL DEFAULT 0,
  `valor_total` decimal(12,2) NOT NULL DEFAULT 0.00,
  `observacao` varchar(255) DEFAULT NULL,
  `fechado_por` varchar(120) DEFAULT NULL,
  `fechado_em` timestamp NULL DEFAULT current_timestamp(),
  `reaberto_por` varchar(120) DEFAULT NULL,
  `reaberto_em` datetime DEFAULT NULL,
  `motivo_reabertura` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_df_periodo` (`data_ini`,`data_fim`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ─── Segurança: proteção do login (Configurações › Segurança) ───────────────
-- Parâmetros em configuracoes_sistema: seg_login_max_usuario (5), seg_login_max_ip (20),
-- seg_login_janela_min (15), seg_login_bloqueio_min (15). Tentativas guardadas por 180 dias.
CREATE TABLE IF NOT EXISTS login_tentativas (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    usuario VARCHAR(100) NOT NULL,
    ip VARCHAR(45) NOT NULL,
    sucesso TINYINT(1) NOT NULL DEFAULT 0,
    resultado VARCHAR(20) NOT NULL,            -- ok | senha | bloqueado
    criado_em DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY idx_lt_usuario (usuario, criado_em),
    KEY idx_lt_ip (ip, criado_em),
    KEY idx_lt_data (criado_em)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ─── Segurança: política de senha (Configurações › Segurança) ───────────────
-- Parâmetros em configuracoes_sistema: seg_senha_min (8), seg_senha_maiusc_minusc (1), seg_senha_numero (1),
-- seg_senha_especial (0), seg_senha_validade_dias (0 = não vence), seg_senha_exigir_fora (1).
-- Senhas só em hash: as legadas em texto puro são convertidas na inicialização (init_politica_senha).
ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS trocar_senha TINYINT(1) NOT NULL DEFAULT 0;
ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS senha_alterada_em DATETIME DEFAULT NULL;

-- ─── Segurança: política de senha (Configurações › Segurança) ───────────────
-- Parâmetros em configuracoes_sistema: seg_senha_min (8), seg_senha_maiusc_minusc (1), seg_senha_numero (1),
-- seg_senha_especial (0), seg_senha_validade_dias (0 = não vence), seg_senha_exigir_fora (1).
-- Senhas sempre em hash (werkzeug); texto puro legado é convertido na inicialização e não entra mais.
ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS trocar_senha TINYINT(1) NOT NULL DEFAULT 0;
ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS senha_alterada_em DATETIME DEFAULT NULL;

-- ─── Auditoria (Configurações › Auditoria) ──────────────────────────────────
-- Uma linha por ação que altera dados (POST) + login/saída/sessão vencida/acessos negados/CSRF.
-- Só INSERT pelo sistema; limpeza apenas por retenção (730 dias). Senhas e QR nunca são guardados;
-- CPF/prontuário/atendimento ficam parciais. `detalhes` = JSON {campos, mudancas{campo:[antes,depois]}, removido, mensagens, motivo}.
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
    resultado VARCHAR(10) NOT NULL DEFAULT 'ok',   -- ok | erro | negado
    detalhes LONGTEXT,
    KEY idx_aud_data (criado_em),
    KEY idx_aud_usuario (usuario, criado_em),
    KEY idx_aud_modulo (modulo, criado_em),
    KEY idx_aud_resultado (resultado, criado_em)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
