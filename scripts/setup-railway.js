const mysql = require('mysql2/promise');
const fs = require('fs');

// Forçar carregamento das Railway Variables
require('dotenv').config();

async function setup() {
  console.log('🔧 Iniciando setup do banco de dados Railway...');
  
  // Debug: verificar se as Variáveis estão disponíveis
  console.log('=== DEBUG SETUP Railway Variables ===');
  console.log('DB_HOST:', process.env.DB_HOST);
  console.log('DB_USER:', process.env.DB_USER);
  console.log('DB_NAME:', process.env.DB_NAME);
  console.log('=====================================');
  
  if (!process.env.DB_HOST || !process.env.DB_USER || !process.env.DB_PASSWORD) {
    console.error('❌ Railway Variables não encontradas. Verifique configuração no Railway.');
    process.exit(1);
  }
  
  try {
    const connection = await mysql.createConnection({
      host: process.env.DB_HOST,
      port: process.env.DB_PORT || 3306,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
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
    
    // Executar schema
    await connection.query(schema);
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
