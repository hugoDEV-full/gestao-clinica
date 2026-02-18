-- Schema (structure only) for database: gestao_clinica
-- Generated at: 2025-02-18T15:20:00.000Z
SET FOREIGN_KEY_CHECKS=0;

DROP TABLE IF EXISTS `access_logs`;
CREATE TABLE `access_logs` (
  `id` int NOT NULL AUTO_INCREMENT,
  `colaborador_id` int DEFAULT NULL,
  `status` varchar(16) NOT NULL,
  `tipo` varchar(16) NOT NULL DEFAULT 'acesso',
  `motivo` varchar(255) DEFAULT NULL,
  `local` varchar(120) DEFAULT NULL,
  `ip_address` varchar(64) DEFAULT NULL,
  `device_id` varchar(128) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_access_log_colaborador` (`colaborador_id`),
  KEY `idx_access_log_status` (`status`),
  KEY `idx_access_log_tipo` (`tipo`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

DROP TABLE IF EXISTS `access_tokens`;
CREATE TABLE `access_tokens` (
  `id` int NOT NULL AUTO_INCREMENT,
  `colaborador_id` int NOT NULL,
  `token_hash` char(64) NOT NULL,
  `device_id` varchar(128) DEFAULT NULL,
  `expires_at` datetime NOT NULL,
  `used_at` datetime DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_access_token` (`token_hash`),
  KEY `idx_access_colaborador` (`colaborador_id`),
  KEY `idx_access_expires` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

DROP TABLE IF EXISTS `agenda`;
CREATE TABLE `agenda` (
  `id` int NOT NULL AUTO_INCREMENT,
  `paciente_id` int DEFAULT NULL,
  `profissional_id` int DEFAULT NULL,
  `data_hora` datetime NOT NULL,
  `duracao_minutos` int DEFAULT '60',
  `tipo_consulta` enum('avaliacao','retorno','emergencia','procedimento') DEFAULT NULL,
  `status` enum('agendado','confirmado','em_andamento','concluido','cancelado','nao_compareceu') DEFAULT 'agendado',
  `valor` decimal(10,2) DEFAULT NULL,
  `forma_pagamento` enum('dinheiro','cartao','convenio','pix') DEFAULT NULL,
  `observacoes` text,
  `data_cadastro` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `lembrete_dia_enviado` tinyint(1) DEFAULT '0',
  `lembrete_hora_enviado` tinyint(1) DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `paciente_id` (`paciente_id`),
  KEY `profissional_id` (`profissional_id`),
  CONSTRAINT `agenda_ibfk_1` FOREIGN KEY (`paciente_id`) REFERENCES `pacientes` (`id`),
  CONSTRAINT `agenda_ibfk_2` FOREIGN KEY (`profissional_id`) REFERENCES `profissionais` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

DROP TABLE IF EXISTS `agendamentos`;
CREATE TABLE `agendamentos` (
  `id` int NOT NULL AUTO_INCREMENT,
  `paciente_id` int NOT NULL,
  `profissional_id` int NOT NULL,
  `data_hora` datetime NOT NULL,
  `duracao_minutos` int DEFAULT '60',
  `tipo_consulta` varchar(64) DEFAULT NULL,
  `status` varchar(32) NOT NULL DEFAULT 'agendado',
  `valor` decimal(10,2) DEFAULT NULL,
  `forma_pagamento` varchar(32) DEFAULT NULL,
  `observacoes` text,
  `data_cadastro` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `paciente_nome` varchar(255) DEFAULT NULL,
  `paciente_cpf` varchar(32) DEFAULT NULL,
  `profissional_nome` varchar(255) DEFAULT NULL,
  `status_pagamento` varchar(32) DEFAULT NULL,
  `convenio` varchar(64) DEFAULT NULL,
  `enviar_lembrete` tinyint(1) NOT NULL DEFAULT '1',
  `confirmar_whatsapp` tinyint(1) NOT NULL DEFAULT '1',
  PRIMARY KEY (`id`),
  KEY `idx_data_hora` (`data_hora`),
  KEY `idx_paciente` (`paciente_id`),
  KEY `idx_profissional` (`profissional_id`),
  KEY `idx_paciente_id` (`paciente_id`),
  KEY `idx_profissional_id` (`profissional_id`),
  CONSTRAINT `agendamentos_ibfk_1` FOREIGN KEY (`paciente_id`) REFERENCES `pacientes` (`id`),
  CONSTRAINT `agendamentos_ibfk_2` FOREIGN KEY (`profissional_id`) REFERENCES `profissionais` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

DROP TABLE IF EXISTS `app_config`;
CREATE TABLE `app_config` (
  `chave` varchar(64) NOT NULL,
  `valor` text,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`chave`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

DROP TABLE IF EXISTS `colaborador_devices`;
CREATE TABLE `colaborador_devices` (
  `id` int NOT NULL AUTO_INCREMENT,
  `colaborador_id` int NOT NULL,
  `device_id` varchar(128) NOT NULL,
  `label` varchar(120) DEFAULT NULL,
  `last_seen` datetime DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_colab_device` (`colaborador_id`,`device_id`),
  KEY `idx_colab_device` (`colaborador_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

DROP TABLE IF EXISTS `colaboradores`;
CREATE TABLE `colaboradores` (
  `id` int NOT NULL AUTO_INCREMENT,
  `usuario_id` int DEFAULT NULL,
  `nome` varchar(150) NOT NULL,
  `cpf` varchar(14) NOT NULL,
  `empresa` varchar(150) DEFAULT NULL,
  `cargo` varchar(120) DEFAULT NULL,
  `foto_url` varchar(255) DEFAULT NULL,
  `status` varchar(16) NOT NULL DEFAULT 'ativo',
  `qr_seed` varchar(64) NOT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `qr_static_token` varchar(64) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_colaborador_cpf` (`cpf`),
  UNIQUE KEY `uniq_colaborador_qr_static` (`qr_static_token`),
  KEY `idx_colaborador_status` (`status`),
  KEY `idx_colaborador_usuario` (`usuario_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

DROP TABLE IF EXISTS `configuracoes`;
CREATE TABLE `configuracoes` (
  `id` int NOT NULL AUTO_INCREMENT,
  `whatsapp_numero` varchar(20) DEFAULT '61982976481',
  `nome_clinica` varchar(100) DEFAULT 'Clínica Andreia Ballejo Fisioterapia',
  `telefone_clinica` varchar(20) DEFAULT '(61) 9829-7648',
  `email_clinica` varchar(100) DEFAULT 'andreia.ballejo@clinica.com',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

DROP TABLE IF EXISTS `financeiro`;
CREATE TABLE `financeiro` (
  `id` int NOT NULL AUTO_INCREMENT,
  `tipo` enum('receita','despesa') NOT NULL,
  `descricao` varchar(200) NOT NULL,
  `categoria` varchar(100) DEFAULT NULL,
  `valor` decimal(10,2) NOT NULL,
  `data_vencimento` date DEFAULT NULL,
  `data_pagamento` date DEFAULT NULL,
  `forma_pagamento` enum('dinheiro','cartao','transferencia','pix','convenio') DEFAULT NULL,
  `status` enum('pendente','pago','atrasado','cancelado') DEFAULT 'pendente',
  `paciente_id` int DEFAULT NULL,
  `profissional_id` int DEFAULT NULL,
  `observacoes` text,
  `data_cadastro` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `lembrete_enviado` tinyint(1) DEFAULT '0',
  `paciente_nome` varchar(255) DEFAULT NULL,
  `agendamento_id` int DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_financeiro_agendamento` (`agendamento_id`),
  KEY `paciente_id` (`paciente_id`),
  KEY `profissional_id` (`profissional_id`),
  KEY `idx_financeiro_data` (`data_cadastro`),
  KEY `idx_financeiro_tipo` (`tipo`),
  CONSTRAINT `financeiro_ibfk_1` FOREIGN KEY (`paciente_id`) REFERENCES `pacientes` (`id`),
  CONSTRAINT `financeiro_ibfk_2` FOREIGN KEY (`profissional_id`) REFERENCES `profissionais` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

DROP TABLE IF EXISTS `lembretes`;
CREATE TABLE `lembretes` (
  `id` int NOT NULL AUTO_INCREMENT,
  `paciente_id` int DEFAULT NULL,
  `profissional_id` int DEFAULT NULL,
  `tipo` enum('consulta','medicamento','exame','pagamento','outro','aniversario') DEFAULT NULL,
  `titulo` varchar(200) NOT NULL,
  `mensagem` text,
  `data_envio` datetime DEFAULT NULL,
  `status` enum('pendente','enviado','erro') DEFAULT 'pendente',
  `via_whatsapp` tinyint(1) DEFAULT '0',
  `via_email` tinyint(1) DEFAULT '0',
  `data_cadastro` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `data_envio_real` datetime DEFAULT NULL,
  `agenda_id` int DEFAULT NULL,
  `tentativas` int NOT NULL DEFAULT '0',
  `ultimo_erro` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `paciente_id` (`paciente_id`),
  KEY `profissional_id` (`profissional_id`),
  KEY `fk_lembretes_agenda` (`agenda_id`),
  CONSTRAINT `fk_lembretes_agenda` FOREIGN KEY (`agenda_id`) REFERENCES `agenda` (`id`) ON DELETE SET NULL,
  CONSTRAINT `lembretes_ibfk_1` FOREIGN KEY (`paciente_id`) REFERENCES `pacientes` (`id`),
  CONSTRAINT `lembretes_ibfk_2` FOREIGN KEY (`profissional_id`) REFERENCES `profissionais` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

DROP TABLE IF EXISTS `logs_lgpd`;
CREATE TABLE `logs_lgpd` (
  `id` int NOT NULL AUTO_INCREMENT,
  `usuario_id` int DEFAULT NULL,
  `acao` varchar(100) NOT NULL,
  `tabela_afetada` varchar(50) DEFAULT NULL,
  `registro_id` int DEFAULT NULL,
  `dados_anteriores` text,
  `dados_novos` text,
  `ip_address` varchar(45) DEFAULT NULL,
  `data_acao` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `usuario_id` (`usuario_id`),
  CONSTRAINT `logs_lgpd_ibfk_1` FOREIGN KEY (`usuario_id`) REFERENCES `usuarios` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

DROP TABLE IF EXISTS `pacientes`;
CREATE TABLE `pacientes` (
  `id` int NOT NULL AUTO_INCREMENT,
  `nome` varchar(100) NOT NULL,
  `cpf` varchar(14) NOT NULL,
  `rg` varchar(20) DEFAULT NULL,
  `data_nascimento` date DEFAULT NULL,
  `sexo` enum('M','F','Outro') DEFAULT NULL,
  `telefone` varchar(20) DEFAULT NULL,
  `email` varchar(100) DEFAULT NULL,
  `endereco` text,
  `cidade` varchar(50) DEFAULT NULL,
  `estado` varchar(2) DEFAULT NULL,
  `cep` varchar(9) DEFAULT NULL,
  `convenio` varchar(100) DEFAULT NULL,
  `numero_convenio` varchar(50) DEFAULT NULL,
  `validade_convenio` date DEFAULT NULL,
  `alergias` text,
  `medicamentos` text,
  `historico_familiar` text,
  `observacoes` text,
  `data_cadastro` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `ativo` tinyint(1) DEFAULT '1',
  PRIMARY KEY (`id`),
  UNIQUE KEY `cpf` (`cpf`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

DROP TABLE IF EXISTS `password_resets`;
CREATE TABLE `password_resets` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `email` varchar(191) NOT NULL,
  `token_hash` char(64) NOT NULL,
  `code_hash` varchar(255) NOT NULL,
  `expires_at` datetime NOT NULL,
  `used_at` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `ip_address` varchar(64) DEFAULT NULL,
  `user_agent` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_pr_user` (`user_id`),
  KEY `idx_pr_email` (`email`),
  KEY `idx_pr_token` (`token_hash`),
  KEY `idx_pr_expires` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

DROP TABLE IF EXISTS `ponto_logs`;
CREATE TABLE `ponto_logs` (
  `id` int NOT NULL AUTO_INCREMENT,
  `colaborador_id` int NOT NULL,
  `tipo` varchar(16) NOT NULL,
  `ip_address` varchar(64) DEFAULT NULL,
  `device_id` varchar(128) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_ponto_colaborador` (`colaborador_id`),
  KEY `idx_ponto_tipo` (`tipo`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

DROP TABLE IF EXISTS `profissionais`;
CREATE TABLE `profissionais` (
  `id` int NOT NULL AUTO_INCREMENT,
  `nome` varchar(100) NOT NULL,
  `cpf` varchar(14) NOT NULL,
  `especialidade` varchar(100) DEFAULT NULL,
  `registro_profissional` varchar(50) DEFAULT NULL,
  `telefone` varchar(20) DEFAULT NULL,
  `email` varchar(100) DEFAULT NULL,
  `data_contratacao` date DEFAULT NULL,
  `salario` decimal(10,2) DEFAULT NULL,
  `ativo` tinyint(1) DEFAULT '1',
  PRIMARY KEY (`id`),
  UNIQUE KEY `cpf` (`cpf`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

DROP TABLE IF EXISTS `prontuario_evolucoes`;
CREATE TABLE `prontuario_evolucoes` (
  `id` int NOT NULL AUTO_INCREMENT,
  `prontuario_id` int NOT NULL,
  `texto` text NOT NULL,
  `data_evolucao` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_pe_prontuario` (`prontuario_id`),
  KEY `idx_pe_data` (`data_evolucao`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

DROP TABLE IF EXISTS `prontuarios`;
CREATE TABLE `prontuarios` (
  `id` int NOT NULL AUTO_INCREMENT,
  `paciente_id` int NOT NULL,
  `profissional_id` int NOT NULL,
  `data_atendimento` date NOT NULL,
  `queixa_principal` text,
  `historico_doencas` text,
  `exames_fisicos` text,
  `diagnostico` text,
  `tratamento` text,
  `evolucao` text,
  `proxima_consulta` date DEFAULT NULL,
  `anexos` varchar(255) DEFAULT NULL,
  `data_cadastro` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `tipo_atendimento` varchar(64) NOT NULL,
  `historia_doenca` text NOT NULL,
  `historia_patologica` text,
  `historia_fisiologica` text,
  `exame_fisico` text,
  `plano_tratamento` text NOT NULL,
  `prognostico` text,
  `observacoes` text,
  `status` varchar(32) NOT NULL DEFAULT 'em_andamento',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_prontuarios_paciente` (`paciente_id`),
  KEY `idx_prontuarios_profissional` (`profissional_id`),
  KEY `idx_prontuarios_data` (`data_atendimento`),
  CONSTRAINT `prontuarios_ibfk_1` FOREIGN KEY (`paciente_id`) REFERENCES `pacientes` (`id`),
  CONSTRAINT `prontuarios_ibfk_2` FOREIGN KEY (`profissional_id`) REFERENCES `profissionais` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

DROP TABLE IF EXISTS `usuarios`;
CREATE TABLE `usuarios` (
  `id` int NOT NULL AUTO_INCREMENT,
  `nome` varchar(100) NOT NULL,
  `email` varchar(100) NOT NULL,
  `senha` varchar(255) NOT NULL,
  `tipo` enum('admin','medico','secretaria','paciente') DEFAULT 'secretaria',
  `cpf` varchar(14) DEFAULT NULL,
  `telefone` varchar(20) DEFAULT NULL,
  `data_cadastro` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `ativo` tinyint(1) DEFAULT '1',
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`),
  UNIQUE KEY `cpf` (`cpf`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

SET FOREIGN_KEY_CHECKS=1;
