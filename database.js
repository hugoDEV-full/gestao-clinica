const mysql = require('mysql2/promise');

let pool;

// Configuração do banco de dados
const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 3306,
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'gestao_fisio',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};

// Inicializar conexão com o banco de dados
async function initDB() {
    try {
        console.log('Conectando ao banco de dados...');
        
        // Criar pool de conexões
        pool = mysql.createPool(dbConfig);
        
        // Testar conexão
        const connection = await pool.getConnection();
        console.log('Conectado ao MySQL com sucesso!');
        
        // Verificar se o banco existe
        await connection.query('USE ' + dbConfig.database);
        
        connection.release();
        
        console.log('Banco de dados inicializado com sucesso!');
        return true;
    } catch (error) {
        console.error('Erro ao conectar ao banco de dados:', error);
        
        // Se o banco não existir, tentar criar
        if (error.code === 'ER_BAD_DB_ERROR') {
            console.log('Banco de dados não encontrado. Criando...');
            try {
                const tempPool = mysql.createPool({
                    host: dbConfig.host,
                    port: dbConfig.port,
                    user: dbConfig.user,
                    password: dbConfig.password,
                    waitForConnections: true,
                    connectionLimit: 1,
                    queueLimit: 0
                });
                
                const connection = await tempPool.getConnection();
                await connection.query(`CREATE DATABASE ${dbConfig.database} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
                connection.release();
                await tempPool.end();
                
                console.log('Banco de dados criado com sucesso!');
                return await initDB(); // Tentar conectar novamente
            } catch (createError) {
                console.error('Erro ao criar banco de dados:', createError);
                throw createError;
            }
        }
        
        throw error;
    }
}

// Obter conexão do pool
function getDB() {
    if (!pool) {
        throw new Error('Banco de dados não inicializado. Chame initDB() primeiro.');
    }
    return pool;
}

// Fechar conexões
async function closeDB() {
    if (pool) {
        await pool.end();
        console.log('Conexões com o banco de dados fechadas.');
    }
}

module.exports = {
    initDB,
    getDB,
    closeDB
};
