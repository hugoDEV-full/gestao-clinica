const mysql = require('mysql2/promise');
const fs = require('fs');

async function generateSchema() {
    const config = {
        host: process.env.DB_HOST || 'localhost',
        port: process.env.DB_PORT || 3306,
        user: process.env.DB_USER || 'root',
        password: process.env.DB_PASSWORD || '',
        database: process.env.DB_NAME || 'gestao_fisio'
    };

    try {
        const connection = await mysql.createConnection(config);

        // Listar todas as tabelas
        const [tables] = await connection.execute("SHOW TABLES");

        let schema = `-- Schema for gestao_fisio database\n`;
        schema += `-- Generated on ${new Date().toISOString()}\n\n`;

        for (const row of tables) {
            const tableName = Object.values(row)[0];
            const [createResult] = await connection.execute(`SHOW CREATE TABLE \`${tableName}\``);
            const createStmt = createResult[0]['Create Table'];
            schema += `-- Table: ${tableName}\n`;
            schema += createStmt + ';\n\n';
        }

        fs.writeFileSync('schema.sql', schema);
        console.log('Schema saved to schema.sql');

        await connection.end();
    } catch (error) {
        console.error('Error generating schema:', error);
    }
}

generateSchema();
