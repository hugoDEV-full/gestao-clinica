const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
require('dotenv').config();

async function createAdmin() {
  console.log('🔧 Criando usuário admin...');

  // Configuração do banco com fallback Railway
  const dbConfig = {
    host: process.env.DB_HOST || process.env.RAILWAY_MYSQLHOST || 'localhost',
    port: process.env.DB_PORT || process.env.RAILWAY_MYSQLPORT || 3306,
    user: process.env.DB_USER || process.env.RAILWAY_MYSQLUSER || 'root',
    password: process.env.DB_PASSWORD || process.env.RAILWAY_MYSQLPASSWORD || '',
    database: process.env.DB_NAME || process.env.RAILWAY_MYSQLDATABASE || 'railway',
    timezone: process.env.DB_TIMEZONE || '+00:00'
  };

  console.log('=== DEBUG Conexão ===');
  console.log('Host:', dbConfig.host);
  console.log('Port:', dbConfig.port);
  console.log('User:', dbConfig.user);
  console.log('Database:', dbConfig.database);
  console.log('=========================');

  const connection = await mysql.createConnection(dbConfig);

  try {
    const email = 'hugo.leonardo.jobs@gmail.com';
    const plainPassword = 'Bento1617@*';
    const nome = 'Hugo Admin';
    const tipo = 'admin';

    // Hash da senha
    const hashedPassword = await bcrypt.hash(plainPassword, 10);

    // Verificar se usuário já existe
    const [existing] = await connection.execute(
      'SELECT id FROM usuarios WHERE email = ?',
      [email]
    );

    if (existing.length > 0) {
      console.log('⚠️ Usuário já existe. Atualizando senha e tipo...');
      await connection.execute(
        'UPDATE usuarios SET senha = ?, tipo = ?, nome = ?, ativo = 1 WHERE email = ?',
        [hashedPassword, tipo, nome, email]
      );
      console.log('✅ Usuário atualizado com sucesso!');
    } else {
      // Inserir novo usuário
      await connection.execute(
        `INSERT INTO usuarios (nome, email, senha, tipo, ativo) VALUES (?, ?, ?, ?, 1)`,
        [nome, email, hashedPassword, tipo]
      );
      console.log('✅ Usuário admin criado com sucesso!');
    }

    console.log('📧 Email:', email);
    console.log('🔑 Senha:', plainPassword);
    console.log('👤 Tipo:', tipo);
    console.log('');
    console.log('🎉 Pronto! Você já pode fazer login no sistema.');

  } catch (error) {
    console.error('❌ Erro ao criar usuário:', error.message);
    process.exit(1);
  } finally {
    await connection.end();
  }
}

createAdmin();
