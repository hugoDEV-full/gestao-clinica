const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
require('dotenv').config();

async function debugPassword() {
  console.log('🔍 Debug da senha do admin...');
  
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
    const email = 'hugo.leonardo.jobs@gmail.com';
    const plainPassword = 'Bento1617@*';
    
    // Buscar usuário
    const [users] = await connection.execute(
      'SELECT id, nome, email, senha, tipo, ativo FROM usuarios WHERE email = ?',
      [email]
    );
    
    if (users.length === 0) {
      console.log('❌ Usuário não encontrado!');
      return;
    }
    
    const user = users[0];
    console.log('👤 Usuário encontrado:');
    console.log('  ID:', user.id);
    console.log('  Nome:', user.nome);
    console.log('  Email:', user.email);
    console.log('  Tipo:', user.tipo);
    console.log('  Ativo:', user.ativo);
    console.log('  Senha (hash):', user.senha);
    console.log('  Senha começa com $2a$ ou $2b$?', user.senha.startsWith('$2a$') || user.senha.startsWith('$2b$'));
    
    // Testar hash atual
    console.log('\n🔐 Testando hash atual...');
    const isValid = await bcrypt.compare(plainPassword, user.senha);
    console.log('  Senha válida?', isValid);
    
    // Criar novo hash para teste
    console.log('\n🔧 Criando novo hash...');
    const newHash = await bcrypt.hash(plainPassword, 10);
    console.log('  Novo hash:', newHash);
    
    // Testar novo hash
    const newHashValid = await bcrypt.compare(plainPassword, newHash);
    console.log('  Novo hash válido?', newHashValid);
    
    // Atualizar no banco
    console.log('\n💾 Atualizando senha no banco...');
    await connection.execute(
      'UPDATE usuarios SET senha = ? WHERE email = ?',
      [newHash, email]
    );
    console.log('✅ Senha atualizada!');
    
    // Verificar após atualização
    const [updatedUsers] = await connection.execute(
      'SELECT senha FROM usuarios WHERE email = ?',
      [email]
    );
    
    const isNowValid = await bcrypt.compare(plainPassword, updatedUsers[0].senha);
    console.log('\n🎯 Senha agora válida?', isNowValid);
    
  } catch (error) {
    console.error('❌ Erro:', error);
  } finally {
    await connection.end();
  }
}

debugPassword();
