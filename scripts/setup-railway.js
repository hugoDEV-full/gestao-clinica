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
    
  } catch (error) {
    console.error('❌ Erro no setup:', error.message);
    process.exit(1);
  }
}

// Executar se chamado diretamente
if (require.main === module) {
  setup();
}

module.exports = { setup };
