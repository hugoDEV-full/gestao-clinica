const mysql = require('mysql2/promise');
const fs = require('fs');

// Forçar carregamento das Railway Variables
require('dotenv').config();

// Fallback para Railway's built-in variables
const dbHost = process.env.DB_HOST || process.env.RAILWAY_DB_HOST;
const dbPort = process.env.DB_PORT || process.env.RAILWAY_DB_PORT || 3306;
const dbUser = process.env.DB_USER || process.env.RAILWAY_DB_USER;
const dbPassword = process.env.DB_PASSWORD || process.env.RAILWAY_DB_PASSWORD;
const dbName = process.env.DB_NAME || process.env.RAILWAY_DB_NAME;

async function setup() {
  console.log('🔧 Iniciando setup do banco de dados Railway...');
  
  // Debug: verificar se as Variáveis estão disponíveis
  console.log('=== DEBUG SETUP Railway Variables ===');
  console.log('DB_HOST:', dbHost);
  console.log('DB_USER:', dbUser);
  console.log('DB_NAME:', dbName);
  console.log('DB_PORT:', dbPort);
  console.log('=====================================');
  
  if (!dbHost || !dbUser || !dbPassword) {
    console.error('❌ Railway Variables não encontradas. Verifique configuração no Railway.');
    console.error('Tentando variáveis:', { dbHost, dbUser, dbName, dbPort });
    process.exit(1);
  }
  
  try {
    const connection = await mysql.createConnection({
      host: dbHost,
      port: dbPort,
      user: dbUser,
      password: dbPassword,
      database: dbName,
      ssl: { rejectUnauthorized: false }
    });

    console.log('📡 Conectado ao MySQL Railway');
    
    // Ler schema-full.sql
    const schemaPath = './schema-full.sql';
    if (!fs.existsSync(schemaPath)) {
      throw new Error(`Arquivo schema não encontrado: ${schemaPath}`);
    }
    
    const schema = fs.readFileSync(schemaPath, 'utf8');
    console.log('📄 Schema carregado, executando...');
    
    // Dividir o schema em statements individuais
    const statements = schema
      .split(';')
      .map(s => s.trim())
      .filter(s => s.length > 0 && !s.startsWith('--'));
    
    console.log(`📊 Executando ${statements.length} statements...`);
    
    // Executar cada statement separadamente
    for (const statement of statements) {
      if (statement.trim()) {
        console.log('🔧 Executando:', statement.substring(0, 80) + '...');
        try {
          await connection.query(statement);
        } catch (err) {
          // Ignorar erro de tabela já existente, mas mostrar outros
          if (err.code === 'ER_TABLE_EXISTS_ERROR' || err.message.includes('already exists')) {
            console.log('⚠️ Tabela já existe, ignorando...');
          } else {
            throw err;
          }
        }
      }
    }
    await connection.end();
    
    console.log('✅ Schema importado com sucesso!');
    console.log('🎉 Banco de dados pronto para uso.');
    
    // Criar usuário admin padrão se não existir
    await createDefaultAdmin();
    
  } catch (error) {
    console.error('❌ Erro no setup:', error.message);
    process.exit(1);
  }
}

async function createDefaultAdmin() {
  const bcrypt = require('bcrypt');
  const mysql = require('mysql2/promise');
  
  // Configuração do banco com fallback Railway
  const dbConfig = {
    host: process.env.DB_HOST || process.env.RAILWAY_MYSQLHOST || 'localhost',
    port: process.env.DB_PORT || process.env.RAILWAY_MYSQLPORT || 3306,
    user: process.env.DB_USER || process.env.RAILWAY_MYSQLUSER || 'root',
    password: process.env.DB_PASSWORD || process.env.RAILWAY_MYSQLPASSWORD || '',
    database: process.env.DB_NAME || process.env.RAILWAY_MYSQLDATABASE || 'railway',
    timezone: process.env.DB_TIMEZONE || '+00:00'
  };
  
  const connection = await mysql.createConnection(dbConfig);
  
  try {
    const email = 'hugo.leonardo.jobs@gmail.com';
    const plainPassword = 'Bento1617@*';
    const nome = 'Hugo Admin';
    const tipo = 'admin';
    
    console.log('🔧 Verificando usuário admin padrão...');
    
    // Verificar se usuário já existe
    const [existing] = await connection.execute(
      'SELECT id FROM usuarios WHERE email = ?',
      [email]
    );
    
    if (existing.length > 0) {
      console.log('🔄 Usuário admin padrão já existe. Atualizando senha...');
      const hashedPassword = await bcrypt.hash(plainPassword, 10);
      await connection.execute(
        'UPDATE usuarios SET senha = ?, tipo = ?, ativo = 1 WHERE email = ?',
        [hashedPassword, tipo, email]
      );
      console.log('✅ Senha do admin atualizada com sucesso!');
    } else {
      // Hash da senha
      const hashedPassword = await bcrypt.hash(plainPassword, 10);
      
      // Inserir usuário admin
      await connection.execute(
        `INSERT INTO usuarios (nome, email, senha, tipo, ativo) VALUES (?, ?, ?, ?, 1)`,
        [nome, email, hashedPassword, tipo]
      );
      
      console.log('👤 Usuário admin padrão criado com sucesso!');
      console.log('📧 Email:', email);
      console.log('🔑 Senha:', plainPassword);
      console.log('👤 Tipo:', tipo);
    }
    
  } catch (error) {
    console.error('❌ Erro ao criar usuário admin:', error.message);
  } finally {
    await connection.end();
  }
  
  // CARGA INICIAL AUTOMÁTICA (se solicitado)
  console.log('\n🔍 VERIFICANDO CARGA INICIAL...');
  console.log('CARGA_INICIAL (environment):', process.env.CARGA_INICIAL);
  console.log('typeof CARGA_INICIAL:', typeof process.env.CARGA_INICIAL);
  console.log('CARGA_INICIAL === "true":', process.env.CARGA_INICIAL === 'true');
  console.log('CARGA_INICIAL == true:', process.env.CARGA_INICIAL == true);
  
  if (process.env.CARGA_INICIAL === 'true' || process.env.CARGA_INICIAL === true) {
    console.log('\n🚀 INICIANDO CARGA INICIAL DE DADOS...');
    console.log('Variável CARGA_INICIAL detectada como:', process.env.CARGA_INICIAL);
    await carregarDadosIniciais();
  } else {
    console.log('\n💡 Para carregar dados iniciais, defina CARGA_INICIAL=true nas variáveis de ambiente');
    console.log('Valor atual de CARGA_INICIAL:', process.env.CARGA_INICIAL);
  }
}

async function carregarDadosIniciais() {
  const bcrypt = require('bcrypt');
  const mysql = require('mysql2/promise');
  
  // Configuração do banco
  const dbConfig = {
    host: process.env.DB_HOST || process.env.RAILWAY_MYSQLHOST || 'localhost',
    port: process.env.DB_PORT || process.env.RAILWAY_MYSQLPORT || 3306,
    user: process.env.DB_USER || process.env.RAILWAY_MYSQLUSER || 'root',
    password: process.env.DB_PASSWORD || process.env.RAILWAY_MYSQLPASSWORD || '',
    database: process.env.DB_NAME || process.env.RAILWAY_MYSQLDATABASE || 'railway',
    timezone: process.env.DB_TIMEZONE || '+00:00'
  };
  
  const connection = await mysql.createConnection(dbConfig);
  
  try {
    // Limpar dados existentes (cuidado!)
    console.log('🧹 Limpando dados existentes...');
    await connection.execute('SET FOREIGN_KEY_CHECKS = 0');
    
    const tables = [
      'prontuario_evolucoes', 'prontuarios', 'financeiro', 'lembretes', 
      'agendamentos', 'agenda', 'ponto_logs', 'access_logs', 'password_resets',
      'colaborador_devices', 'access_tokens', 'colaboradores', 
      'pacientes', 'profissionais', 'logs_lgpd'
    ];
    
    for (const table of tables) {
      await connection.execute(`DELETE FROM ${table}`);
    }
    
    await connection.execute('SET FOREIGN_KEY_CHECKS = 1');
    console.log('✅ Dados limpos com sucesso!');

    // 1. Profissionais
    console.log('👨‍⚕️ Criando profissionais...');
    await connection.execute(`
      INSERT INTO profissionais (id, nome, especialidade, registro_profissional, telefone, email, ativo) VALUES
      (1, 'Dr. Carlos Silva', 'Clínico Geral', 'CRM-DF 12345', '61982976481', 'carlos@clinica.com', 1),
      (2, 'Dra. Andreia Ballejo', 'Fisioterapeuta', 'CREFITO 12345', '61982976482', 'andreia@clinica.com', 1),
      (3, 'Dr. Pedro Oliveira', 'Ortopedista', 'CRM-DF 67890', '61982976483', 'pedro@clinica.com', 1),
      (4, 'Dra. Maria Santos', 'Cardiologista', 'CRM-DF 11111', '61982976484', 'maria@clinica.com', 1)
    `);

    // 2. Pacientes
    console.log('👥 Criando pacientes...');
    await connection.execute(`
      INSERT INTO pacientes (id, nome, cpf, rg, data_nascimento, telefone, email, endereco, cidade, uf, cep, convenio, cartao_convenio, observacoes, ativo, created_at) VALUES
      (1, 'João da Silva', '12345678901', 'MG-12.345.678', '1985-03-15', '61982976481', 'joao.silva@email.com', 'Quadra 102 Norte, Bloco A, Apt 301', 'Brasília', 'DF', '70722-520', 'Unimed', '123456789', 'Alergico a penicilina', 1, NOW()),
      (2, 'Maria Oliveira', '98765432109', 'DF-98.765.432', '1990-07-22', '61982976485', 'maria.oliveira@email.com', 'SGAS 605, Conjunto D', 'Brasília', 'DF', '70200-660', 'Amil', '987654321', 'Hipertensa', 1, NOW()),
      (3, 'Pedro Santos', '45678912301', 'GO-45.678.912', '1978-11-30', '61982976486', 'pedro.santos@email.com', 'CLN 405, Bloco B, Sala 201', 'Brasília', 'DF', '70845-520', 'Bradesco', '456789123', 'Diabético', 1, NOW()),
      (4, 'Ana Costa', '78912345601', 'BA-78.912.345', '1995-05-18', '61982976487', 'ana.costa@email.com', 'SIA Trecho 3, Lote 850', 'Brasília', 'DF', '71200-030', 'SulAmérica', '789123456', 'Nenhuma', 1, NOW()),
      (5, 'Carlos Ferreira', '32165498701', 'RJ-32.165.498', '1982-09-10', '61982976488', 'carlos.ferreira@email.com', 'EQS 406/407, Bloco A, Sala 101', 'Brasília', 'DF', '70630-000', 'Porto Seguro', '321654987', 'Asmático', 1, NOW())
    `);

    // 3. Agenda
    console.log('📅 Criando agenda...');
    await connection.execute(`
      INSERT INTO agenda (id, profissional_id, dia_semana, hora_inicio, hora_fim, intervalo_minutos, ativo, created_at) VALUES
      (1, 1, 2, '08:00:00', '18:00:00', 30, 1, NOW()),
      (2, 1, 3, '08:00:00', '18:00:00', 30, 1, NOW()),
      (3, 1, 4, '08:00:00', '18:00:00', 30, 1, NOW()),
      (4, 2, 2, '07:00:00', '19:00:00', 40, 1, NOW()),
      (5, 2, 4, '07:00:00', '19:00:00', 40, 1, NOW()),
      (6, 2, 6, '07:00:00', '19:00:00', 40, 1, NOW()),
      (7, 3, 3, '09:00:00', '17:00:00', 45, 1, NOW()),
      (8, 3, 5, '09:00:00', '17:00:00', 45, 1, NOW()),
      (9, 4, 2, '08:00:00', '16:00:00', 60, 1, NOW()),
      (10, 4, 4, '08:00:00', '16:00:00', 60, 1, NOW())
    `);

    // 4. Agendamentos
    console.log('📋 Criando agendamentos...');
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
    console.log('🏥 Criando prontuários...');
    await connection.execute(`
      INSERT INTO prontuarios (id, paciente_id, profissional_id, data_abertura, queixa_principal, historico_doenca_atual, antecedentes_pessoais, antecedentes_familiares, hábitos_vida, alergias, medicamentos_em_uso, exames_realizados, hipotese_diagnostica, tratamento, evolucao, created_at) VALUES
      (1, 1, 1, '2026-01-15', 'Dor lombar crônica', 'Paciente refere dor na região lombar há 6 meses', 'Hipertensão controlada', 'Pai diabético', 'Sedentário, fumante (10 cigarros/dia)', 'Penicilina', 'Losartana 50mg/dia', 'RX coluna lombar', 'Hérnia de disco L4-L5', 'Fisioterapia + AINE', 'Paciente apresentando melhora da dor com fisioterapia', NOW()),
      (2, 2, 2, '2026-01-20', 'Limitação de movimento no ombro direito', 'Após queda da própria altura há 2 meses', 'Nenhum', 'Mãe com artrite reumatoide', 'Pratica natação 3x/semana', 'Nenhuma', 'Anticoncepcional', 'Ressonância magnética do ombro', 'Lesão do manguito rotador', 'Fisioterapia intensiva', 'Recuperação lenta mas progressiva', NOW()),
      (3, 3, 3, '2026-01-10', 'Dor no joelho esquerdo', 'Dor progressiva ao caminhar', 'Diabetes tipo 2', 'Nenhum', 'Sedentário', 'Nenhuma', 'Metformina 850mg 2x/dia, Insulina NPH', 'RX joelho, Glicemia', 'Artrose grau II', 'Perda de peso + Fisioterapia', 'Paciente aderindo ao tratamento', NOW()),
      (4, 4, 4, '2026-01-25', 'Palpitações', 'Episódios de taquicardia ao esforço', 'Nenhum', 'Pai com cardiopatia isquêmica', 'Corredora amadora', 'Nenhuma', 'Nenhum', 'ECG, Holter, Eco', 'Arritmia benigna', 'Beta-bloqueador se necessário', 'Exames normais, manter observação', NOW()),
      (5, 5, 1, '2026-02-01', 'Dor abdominal', 'Dor epigástrica pós-prandial', 'Asma leve', 'Nenhum', 'Ex-fumante', 'AAS', 'Salbutamol spray', 'Endoscopia digestiva', 'Gastrite leve', 'Omeprazol + dieta', 'Sintomas melhoraram com medicação', NOW())
    `);

    // 6. Financeiro
    console.log('💰 Criando registros financeiros...');
    await connection.execute(`
      INSERT INTO financeiro (id, paciente_id, profissional_id, agendamento_id, tipo, descricao, valor, forma_pagamento, status, data_vencimento, data_pagamento, parcelas, observacoes, created_at) VALUES
      (1, 1, 1, 1, 'receita', 'Consulta clínica', 200.00, 'dinheiro', 'pago', '2026-02-24', '2026-02-24', 1, 'Pago em dinheiro', NOW()),
      (2, 2, 2, 2, 'receita', 'Avaliação fisioterapia', 150.00, 'cartao', 'pago', '2026-02-24', '2026-02-24', 1, 'Cartão de crédito', NOW()),
      (3, 3, 3, 3, 'receita', 'Retorno ortopédico', 250.00, 'pix', 'pendente', '2026-02-24', NULL, 1, 'Aguardando pagamento', NOW()),
      (4, 4, 4, 4, 'receita', 'Consulta cardiológica', 300.00, 'cartao', 'pendente', '2026-02-24', NULL, 1, 'Pagamento no dia da consulta', NOW()),
      (5, 5, 1, 5, 'receita', 'Consulta de emergência', 200.00, 'dinheiro', 'pendente', '2026-02-25', NULL, 1, 'Pagar no local', NOW()),
      (6, NULL, NULL, NULL, 'despesa', 'Aluguel do consultório', 3000.00, 'transferencia', 'pago', '2026-02-01', '2026-02-01', 1, 'Aluguel fevereiro', NOW()),
      (7, NULL, NULL, NULL, 'despesa', 'Material de consumo', 450.00, 'dinheiro', 'pago', '2026-02-15', '2026-02-15', 1, 'Luvas, seringas, algodão', NOW())
    `);

    // 7. Lembretes
    console.log('⏰ Criando lembretes...');
    await connection.execute(`
      INSERT INTO lembretes (id, paciente_id, profissional_id, tipo, titulo, mensagem, data_envio, status, via_whatsapp, via_email, agenda_id, created_at) VALUES
      (1, 1, 1, 'consulta', 'Lembrete: Consulta Dr. Carlos', 'Olá João! Lembrete da sua consulta amanhã às 09:00 com Dr. Carlos Silva. Chegue 15 minutos antes.', '2026-02-23 18:00:00', 'enviado', 1, 1, 1, NOW()),
      (2, 2, 2, 'consulta', 'Lembrete: Fisioterapia', 'Olá Maria! Sua sessão de fisioterapia amanhã às 10:00 com Dra. Andreia. Use roupas confortáveis.', '2026-02-23 18:00:00', 'enviado', 1, 1, 2, NOW()),
      (3, 3, 3, 'consulta', 'Lembrete: Retorno Ortopedia', 'Olá Pedro! Seu retorno com Dr. Pedro está confirmado para 14:00 de 24/02. Traga exames anteriores.', '2026-02-23 18:00:00', 'pendente', 1, 1, 3, NOW()),
      (4, 4, 4, 'consulta', 'Lembrete: Consulta Cardiologia', 'Olá Ana! Sua consulta cardiológica dia 24/02 às 15:00. Evite café antes do exame.', '2026-02-23 18:00:00', 'pendente', 1, 1, 4, NOW()),
      (5, 5, 1, 'consulta', 'Lembrete: Consulta Emergência', 'Olá Carlos! Sua consulta de emergência dia 25/02 às 08:30. Aguardamos você.', '2026-02-24 18:00:00', 'pendente', 1, 1, 5, NOW())
    `);

    // 8. Configurações
    console.log('⚙️ Configurando sistema...');
    await connection.execute(`
      INSERT INTO app_config (chave, valor, descricao, created_at) VALUES
      ('CLINICA_NOME', 'Clínica Andreia Ballejo', 'Nome da clínica', NOW()),
      ('CLINICA_TELEFONE', '61982976481', 'Telefone da clínica', NOW()),
      ('CLINICA_EMAIL', 'contato@clinicaballejo.com', 'Email da clínica', NOW()),
      ('CLINICA_ENDERECO', 'SGAS 605, Conjunto D - Asa Sul, Brasília - DF', 'Endereço da clínica', NOW()),
      ('VALOR_CONSULTA_PADRAO', '200.00', 'Valor padrão da consulta', NOW())
      ON DUPLICATE KEY UPDATE valor = VALUES(valor)
    `);

    console.log('\n🎉 CARGA INICIAL CONCLUÍDA COM SUCESSO!');
    console.log('📊 Dados criados:');
    console.log('  👥 Pacientes: 5');
    console.log('  👨‍⚕️ Profissionais: 4');
    console.log('  📅 Agendamentos: 8');
    console.log('  🏥 Prontuários: 5');
    console.log('  💰 Financeiro: 7');
    console.log('  ⏰ Lembretes: 5');
    console.log('  📱 Telefone principal: 61982976481');
    console.log('\n🔑 Acessos:');
    console.log('  Admin: hugo.leonardo.jobs@gmail.com / Bento1617@*');
    
  } catch (error) {
    console.error('❌ Erro na carga inicial:', error.message);
  } finally {
    await connection.end();
  }
}

// Executar se chamado diretamente
if (require.main === module) {
  setup();
}

module.exports = { setup };
