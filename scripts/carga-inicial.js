require('dotenv').config();
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');

async function carregarDadosIniciais() {
    console.log('🚀 Iniciando carga de dados iniciais...');
    
    // Conexão com o banco
    const connection = await mysql.createConnection({
        host: process.env.DB_HOST || 'localhost',
        user: process.env.DB_USER || 'root',
        password: process.env.DB_PASSWORD || '',
        database: process.env.DB_NAME || 'gestao_clinica',
        multipleStatements: true
    });

    try {
        // Limpar dados existentes (cuidado!)
        console.log('🧹 Limpando dados existentes...');
        await connection.execute('SET FOREIGN_KEY_CHECKS = 0');
        
        const tables = [
            'prontuario_evolucoes', 'prontuarios', 'financeiro', 'lembretes', 
            'agendamentos', 'agenda', 'ponto_logs', 'access_logs', 'password_resets',
            'colaborador_devices', 'access_tokens', 'colaboradores', 
            'pacientes', 'profissionais', 'usuarios', 'logs_lgpd', 'app_config'
        ];
        
        for (const table of tables) {
            await connection.execute(`DELETE FROM ${table}`);
        }
        
        await connection.execute('SET FOREIGN_KEY_CHECKS = 1');
        console.log('✅ Dados limpos com sucesso!');

        // 1. Usuários Admin
        console.log('👤 Criando usuários admin...');
        const adminSenha = await bcrypt.hash('Bento1617@*', 10);
        
        await connection.execute(`
            INSERT INTO usuarios (id, nome, email, senha, tipo, ativo, created_at) VALUES
            (1, 'Hugo Admin', 'hugo.leonardo.jobs@gmail.com', ?, 'admin', 1, NOW()),
            (2, 'Andreia Ballejo', 'andreia@clinica.com', ?, 'admin', 1, NOW())
        `, [adminSenha, adminSenha]);

        // 2. Profissionais (Médicos)
        console.log('👨‍⚕️ Criando profissionais...');
        await connection.execute(`
            INSERT INTO profissionais (id, nome, especialidade, registro_profissional, telefone, email, ativo) VALUES
            (1, 'Dr. Carlos Silva', 'Clínico Geral', 'CRM-DF 12345', '61982976481', 'carlos@clinica.com', 1),
            (2, 'Dra. Andreia Ballejo', 'Fisioterapeuta', 'CREFITO 12345', '61982976482', 'andreia@clinica.com', 1),
            (3, 'Dr. Pedro Oliveira', 'Ortopedista', 'CRM-DF 67890', '61982976483', 'pedro@clinica.com', 1),
            (4, 'Dra. Maria Santos', 'Cardiologista', 'CRM-DF 11111', '61982976484', 'maria@clinica.com', 1)
        `);

        // 3. Pacientes
        console.log('👥 Criando pacientes...');
        await connection.execute(`
            INSERT INTO pacientes (id, nome, cpf, rg, data_nascimento, telefone, email, endereco, cidade, uf, cep, convenio, cartao_convenio, observacoes, ativo, created_at) VALUES
            (1, 'João da Silva', '12345678901', 'MG-12.345.678', '1985-03-15', '61982976481', 'joao.silva@email.com', 'Quadra 102 Norte, Bloco A, Apt 301', 'Brasília', 'DF', '70722-520', 'Unimed', '123456789', 'Alergico a penicilina', 1, NOW()),
            (2, 'Maria Oliveira', '98765432109', 'DF-98.765.432', '1990-07-22', '61982976485', 'maria.oliveira@email.com', 'SGAS 605, Conjunto D', 'Brasília', 'DF', '70200-660', 'Amil', '987654321', 'Hipertensa', 1, NOW()),
            (3, 'Pedro Santos', '45678912301', 'GO-45.678.912', '1978-11-30', '61982976486', 'pedro.santos@email.com', 'CLN 405, Bloco B, Sala 201', 'Brasília', 'DF', '70845-520', 'Bradesco', '456789123', 'Diabético', 1, NOW()),
            (4, 'Ana Costa', '78912345601', 'BA-78.912.345', '1995-05-18', '61982976487', 'ana.costa@email.com', 'SIA Trecho 3, Lote 850', 'Brasília', 'DF', '71200-030', 'SulAmérica', '789123456', 'Nenhuma', 1, NOW()),
            (5, 'Carlos Ferreira', '32165498701', 'RJ-32.165.498', '1982-09-10', '61982976488', 'carlos.ferreira@email.com', 'EQS 406/407, Bloco A, Sala 101', 'Brasília', 'DF', '70630-000', 'Porto Seguro', '321654987', 'Asmático', 1, NOW())
        `);

        // 4. Agenda e Agendamentos
        console.log('📅 Criando agenda e agendamentos...');
        
        // Criar agenda para os profissionais
        await connection.execute(`
            INSERT INTO agenda (id, profissional_id, dia_semana, hora_inicio, hora_fim, intervalo_minutos, ativo, created_at) VALUES
            (1, 1, 2, '08:00:00', '18:00:00', 30, 1, NOW()),  Dr. Carlos - Segunda
            (2, 1, 3, '08:00:00', '18:00:00', 30, 1, NOW()),  Dr. Carlos - Terça
            (3, 1, 4, '08:00:00', '18:00:00', 30, 1, NOW()),  Dr. Carlos - Quarta
            (4, 2, 2, '07:00:00', '19:00:00', 40, 1, NOW()),  Dra. Andreia - Segunda
            (5, 2, 4, '07:00:00', '19:00:00', 40, 1, NOW()),  Dra. Andreia - Quarta
            (6, 2, 6, '07:00:00', '19:00:00', 40, 1, NOW()),  Dra. Andreia - Sexta
            (7, 3, 3, '09:00:00', '17:00:00', 45, 1, NOW()),  Dr. Pedro - Terça
            (8, 3, 5, '09:00:00', '17:00:00', 45, 1, NOW()),  Dr. Pedro - Quinta
            (9, 4, 2, '08:00:00', '16:00:00', 60, 1, NOW()),  Dra. Maria - Segunda
            (10, 4, 4, '08:00:00', '16:00:00', 60, 1, NOW())   Dra. Maria - Quarta
        `);

        // Criar agendamentos
        await connection.execute(`
            INSERT INTO agendamentos (id, paciente_id, profissional_id, data_hora, duracao_minutos, tipo_consulta, status, valor, forma_pagamento, status_pagamento, convenio, observacoes, enviar_lembrete, confirmar_whatsapp, created_at) VALUES
            (1, 1, 1, '2026-02-24 09:00:00', 30, 'consulta', 'confirmado', 200.00, 'dinheiro', 'pago', 'Unimed', 'Paciente retorna para acompanhamento', 1, 1, NOW()),
            (2, 2, 2, '2026-02-24 10:00:00', 40, 'avaliacao', 'confirmado', 150.00, 'cartao', 'pago', 'Amil', 'Primeira sessão de fisioterapia', 1, 1, NOW()),
            (3, 3, 3, '2026-02-24 14:00:00', 45, 'retorno', 'agendado', 250.00, 'pix', 'pendente', 'Bradesco', 'Retorno pós-cirurgia', 1, 1, NOW()),
            (4, 4, 4, '2026-02-24 15:00:00', 60, 'consulta', 'agendado', 300.00, 'cartao', 'pendente', 'SulAmérica', 'Consulta de rotina', 1, 1, NOW()),
            (5, 5, 1, '2026-02-25 08:30:00', 30, 'consulta', 'agendado', 200.00, 'dinheiro', 'pendente', 'Porto Seguro', 'Consulta de emergência', 1, 1, NOW()),
            (6, 1, 2, '2026-02-25 14:00:00', 40, 'sessao', 'agendado', 150.00, 'pix', 'pendente', 'Unimed', 'Sessão de alongamento', 1, 1, NOW()),
            (7, 2, 3, '2026-02-26 10:00:00', 45, 'avaliacao', 'agendado', 250.00, 'cartao', 'pendente', 'Amil', 'Avaliação ortopédica', 1, 1, NOW()),
            (8, 3, 4, '2026-02-26 11:00:00', 60, 'exame', 'agendado', 400.00, 'dinheiro', 'pendente', 'Bradesco', 'Teste de esforço', 1, 1, NOW())
        `);

        // 5. Prontuários
        console.log('📋 Criando prontuários...');
        await connection.execute(`
            INSERT INTO prontuarios (id, paciente_id, profissional_id, data_abertura, queixa_principal, historico_doenca_atual, antecedentes_pessoais, antecedentes_familiares, hábitos_vida, alergias, medicamentos_em_uso, exames_realizados, hipotese_diagnostica, tratamento, evolucao, created_at) VALUES
            (1, 1, 1, '2026-01-15', 'Dor lombar crônica', 'Paciente refere dor na região lombar há 6 meses', 'Hipertensão controlada', 'Pai diabético', 'Sedentário, fumante (10 cigarros/dia)', 'Penicilina', 'Losartana 50mg/dia', 'RX coluna lombar', 'Hérnia de disco L4-L5', 'Fisioterapia + AINE', 'Paciente apresentando melhora da dor com fisioterapia', NOW()),
            (2, 2, 2, '2026-01-20', 'Limitação de movimento no ombro direito', 'Após queda da própria altura há 2 meses', 'Nenhum', 'Mãe com artrite reumatoide', 'Pratica natação 3x/semana', 'Nenhuma', 'Anticoncepcional', 'Ressonância magnética do ombro', 'Lesão do manguito rotador', 'Fisioterapia intensiva', 'Recuperação lenta mas progressiva', NOW()),
            (3, 3, 3, '2026-01-10', 'Dor no joelho esquerdo', 'Dor progressiva ao caminhar', 'Diabetes tipo 2', 'Nenhum', 'Sedentário', 'Nenhuma', 'Metformina 850mg 2x/dia, Insulina NPH', 'RX joelho, Glicemia', 'Artrose grau II', 'Perda de peso + Fisioterapia', 'Paciente aderindo ao tratamento', NOW()),
            (4, 4, 4, '2026-01-25', 'Palpitações', 'Episódios de taquicardia ao esforço', 'Nenhum', 'Pai com cardiopatia isquêmica', 'Corredora amadora', 'Nenhuma', 'Nenhum', 'ECG, Holter, Eco', 'Arritmia benigna', 'Beta-bloqueador se necessário', 'Exames normais, manter observação', NOW()),
            (5, 5, 1, '2026-02-01', 'Dor abdominal', 'Dor epigástrica pós-prandial', 'Asma leve', 'Nenhum', 'Ex-fumante', 'AAS', 'Salbutamol spray', 'Endoscopia digestiva', 'Gastrite leve', 'Omeprazol + dieta', 'Sintomas melhoraram com medicação', NOW())
        `);

        // 6. Evoluções dos prontuários
        console.log('📝 Adicionando evoluções...');
        await connection.execute(`
            INSERT INTO prontuario_evolucoes (id, prontuario_id, profissional_id, data, tipo_atendimento, descricao, prescricao, exames_solicitados, proxima_consulta, created_at) VALUES
            (1, 1, 1, '2026-01-15', 'consulta', 'Paciente queixa-se de dor lombar VAS 7/10. Movimentação limitada', 'Dipirona 500mg SOS, Iniciar fisioterapia', 'RX coluna lombar', '15 dias', NOW()),
            (2, 1, 1, '2026-01-30', 'retorno', 'Paciente refere melhora da dor VAS 4/10. Melhora da mobilidade', 'Manter dipirona, continuar fisioterapia', 'Nenhum', '30 dias', NOW()),
            (3, 2, 2, '2026-01-20', 'avaliacao', 'Limitação de abdução do ombro direito a 60 graus. Dor ao movimento', 'Cinesioterapia, crioterapia pós-sessão', 'Ressonância magnética', '7 dias', NOW()),
            (4, 2, 2, '2026-01-27', 'sessao', 'Melhora da amplitude para 90 graus. Paciente relatando menos dor', 'Continuar cinesioterapia, adicionar exercícios ativos', 'Nenhum', '14 dias', NOW()),
            (5, 3, 3, '2026-01-10', 'consulta', 'Dor joelho ao caminhar > 500m. Crepitação ao exame', 'Perda de peso, fortalecimento quadríceps', 'RX joelho, Glicemia em jejum', '15 dias', NOW()),
            (6, 4, 4, '2026-01-25', 'consulta', 'Paciente refere palpitações aos esforços. Ausculta cardíaca normal', 'Realizar exames complementares', 'ECG, Holter 24h, Ecocardiograma', '7 dias para resultados', NOW()),
            (7, 5, 1, '2026-02-01', 'consulta', 'Dor epigástrica pós-prandial há 2 meses. Pirose', 'Omeprazol 20mg/dia, dieta fracionada', 'Endoscopia digestiva alta', '30 dias', NOW())
        `);

        // 7. Financeiro
        console.log('💰 Criando registros financeiros...');
        await connection.execute(`
            INSERT INTO financeiro (id, paciente_id, profissional_id, agendamento_id, tipo, descricao, valor, forma_pagamento, status, data_vencimento, data_pagamento, parcelas, observacoes, created_at) VALUES
            (1, 1, 1, 1, 'receita', 'Consulta clínica', 200.00, 'dinheiro', 'pago', '2026-02-24', '2026-02-24', 1, 'Pago em dinheiro', NOW()),
            (2, 2, 2, 2, 'receita', 'Avaliação fisioterapia', 150.00, 'cartao', 'pago', '2026-02-24', '2026-02-24', 1, 'Cartão de crédito', NOW()),
            (3, 3, 3, 3, 'receita', 'Retorno ortopédico', 250.00, 'pix', 'pendente', '2026-02-24', NULL, 1, 'Aguardando pagamento', NOW()),
            (4, 4, 4, 4, 'receita', 'Consulta cardiológica', 300.00, 'cartao', 'pendente', '2026-02-24', NULL, 1, 'Pagamento no dia da consulta', NOW()),
            (5, 5, 1, 5, 'receita', 'Consulta de emergência', 200.00, 'dinheiro', 'pendente', '2026-02-25', NULL, 1, 'Pagar no local', NOW()),
            (6, 1, 2, 6, 'receita', 'Sessão de fisioterapia', 150.00, 'pix', 'pendente', '2026-02-25', NULL, 1, 'Paciente particular', NOW()),
            (7, 2, 3, 7, 'receita', 'Avaliação ortopédica', 250.00, 'cartao', 'pendente', '2026-02-26', NULL, 1, 'Autorização da Amil', NOW()),
            (8, 3, 4, 8, 'receita', 'Teste de esforço', 400.00, 'dinheiro', 'pendente', '2026-02-26', NULL, 1, 'Exame especializado', NOW()),
            (9, NULL, NULL, NULL, 'despesa', 'Aluguel do consultório', 3000.00, 'transferencia', 'pago', '2026-02-01', '2026-02-01', 1, 'Aluguel fevereiro', NOW()),
            (10, NULL, NULL, NULL, 'despesa', 'Material de consumo', 450.00, 'dinheiro', 'pago', '2026-02-15', '2026-02-15', 1, 'Luvas, seringas, algodão', NOW()),
            (11, NULL, NULL, NULL, 'despesa', 'Internet e telefone', 200.00, 'debito', 'pago', '2026-02-10', '2026-02-10', 1, 'Conta fevereiro', NOW())
        `);

        // 8. Lembretes
        console.log('⏰ Criando lembretes...');
        await connection.execute(`
            INSERT INTO lembretes (id, paciente_id, profissional_id, tipo, titulo, mensagem, data_envio, status, via_whatsapp, via_email, agenda_id, created_at) VALUES
            (1, 1, 1, 'consulta', 'Lembrete: Consulta Dr. Carlos', 'Olá João! Lembrete da sua consulta amanhã às 09:00 com Dr. Carlos Silva. Chegue 15 minutos antes.', '2026-02-23 18:00:00', 'enviado', 1, 1, 1, NOW()),
            (2, 2, 2, 'consulta', 'Lembrete: Fisioterapia', 'Olá Maria! Sua sessão de fisioterapia amanhã às 10:00 com Dra. Andreia. Use roupas confortáveis.', '2026-02-23 18:00:00', 'enviado', 1, 1, 2, NOW()),
            (3, 3, 3, 'consulta', 'Lembrete: Retorno Ortopedia', 'Olá Pedro! Seu retorno com Dr. Pedro está confirmado para 14:00 de 24/02. Traga exames anteriores.', '2026-02-23 18:00:00', 'pendente', 1, 1, 3, NOW()),
            (4, 4, 4, 'consulta', 'Lembrete: Consulta Cardiologia', 'Olá Ana! Sua consulta cardiológica dia 24/02 às 15:00. Evite café antes do exame.', '2026-02-23 18:00:00', 'pendente', 1, 1, 4, NOW()),
            (5, 5, 1, 'consulta', 'Lembrete: Consulta Emergência', 'Olá Carlos! Sua consulta de emergência dia 25/02 às 08:30. Aguardamos você.', '2026-02-24 18:00:00', 'pendente', 1, 1, 5, NOW()),
            (6, 1, 2, 'exame', 'Lembrete: Exame', 'Olá João! Não se esqueça de trazer o resultado do RX para sua sessão dia 25/02.', '2026-02-24 20:00:00', 'pendente', 1, 0, 6, NOW()),
            (7, 2, 3, 'pagamento', 'Lembrete: Pagamento', 'Olá Maria! Lembrete de confirmar sua autorização da Amil para a consulta de 26/02.', '2026-02-25 10:00:00', 'pendente', 1, 0, 7, NOW()),
            (8, 3, 4, 'preparo', 'Lembrete: Preparo Exame', 'Olá Pedro! Para seu teste de esforço dia 26/02: use roupas leves, não cafeína 4h antes.', '2026-02-25 20:00:00', 'pendente', 1, 1, 8, NOW())
        `);

        // 9. Configurações do sistema
        console.log('⚙️ Configurando sistema...');
        await connection.execute(`
            INSERT INTO app_config (chave, valor, descricao, created_at) VALUES
            ('CLINICA_NOME', 'Clínica Andreia Ballejo', 'Nome da clínica', NOW()),
            ('CLINICA_TELEFONE', '61982976481', 'Telefone da clínica', NOW()),
            ('CLINICA_EMAIL', 'contato@clinicaballejo.com', 'Email da clínica', NOW()),
            ('CLINICA_ENDERECO', 'SGAS 605, Conjunto D - Asa Sul, Brasília - DF', 'Endereço da clínica', NOW()),
            ('CLINICA_CNPJ', '12.345.678/0001-90', 'CNPJ da clínica', NOW()),
            ('HORARIO_FUNCIONAMENTO', 'Seg-Sex: 07:00-19:00 | Sáb: 08:00-12:00', 'Horário de funcionamento', NOW()),
            ('VALOR_CONSULTA_PADRAO', '200.00', 'Valor padrão da consulta', NOW()),
            ('TEMPO_LEMBRETE_ANTES', '24', 'Horas antes do envio de lembrete', NOW()),
            ('CONFIRMACAO_AUTOMATICA', 'false', 'Confirmar agendamentos automaticamente', NOW())
        `);

        // 10. Logs LGPD (exemplo)
        console.log('📋 Criando logs LGPD...');
        await connection.execute(`
            INSERT INTO logs_lgpd (usuario_id, tabela, registro_id, operacao, dados_anteriores, dados_novos, motivo, ip_address, user_agent, created_at) VALUES
            (1, 'pacientes', 1, 'INSERT', NULL, '{"nome":"João da Silva","cpf":"12345678901"}', 'Cadastro de novo paciente', '192.168.1.100', 'Mozilla/5.0...', NOW()),
            (1, 'agendamentos', 1, 'INSERT', NULL, '{"paciente_id":1,"profissional_id":1,"data_hora":"2026-02-24 09:00:00"}', 'Novo agendamento', '192.168.1.100', 'Mozilla/5.0...', NOW()),
            (2, 'prontuarios', 1, 'INSERT', NULL, '{"paciente_id":1,"queixa_principal":"Dor lombar crônica"}', 'Abertura de prontuário', '192.168.1.101', 'Mozilla/5.0...', NOW())
        `);

        console.log('\n🎉 CARGA DE DADOS CONCLUÍDA COM SUCESSO!');
        console.log('\n📊 RESUMO DOS DADOS CRIADOS:');
        console.log('👤 Usuários Admin: 2');
        console.log('👨‍⚕️ Profissionais: 4');
        console.log('👥 Pacientes: 5');
        console.log('📅 Agenda: 10 horários semanais');
        console.log('📋 Agendamentos: 8');
        console.log('🏥 Prontuários: 5');
        console.log('📝 Evoluções: 7');
        console.log('💰 Financeiro: 11 registros');
        console.log('⏰ Lembretes: 8');
        console.log('⚙️ Configurações: 9');
        console.log('📋 Logs LGPD: 3');
        
        console.log('\n🔑 ACESSOS PARA TESTE:');
        console.log('Admin 1: hugo.leonardo.jobs@gmail.com / Bento1617@*');
        console.log('Admin 2: andreia@clinica.com / Bento1617@*');
        console.log('Telefone principal: 61982976481');
        
        console.log('\n✨ Sistema pronto para uso!');

    } catch (error) {
        console.error('❌ Erro na carga de dados:', error);
        throw error;
    } finally {
        await connection.end();
    }
}

// Executar carga
carregarDadosIniciais().catch(console.error);
