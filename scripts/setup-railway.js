const mysql = require('mysql2/promise');
const fs = require('fs');
require('dotenv').config();

async function setup() {
  console.log('🔧 Iniciando setup do banco de dados Railway...');
  
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
