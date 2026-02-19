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
}

// Executar se chamado diretamente
if (require.main === module) {
  setup();
}

module.exports = { setup };
