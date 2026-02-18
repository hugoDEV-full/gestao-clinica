const mysql = require('mysql2/promise');
const fs = require('fs');
const path = require('path');
const readline = require('readline');

function ask(question) {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    return new Promise((resolve) => rl.question(question, (ans) => { rl.close(); resolve(ans); }));
}

async function main() {
    const host = process.env.DB_HOST || (await ask('DB_HOST (default: localhost): ')) || 'localhost';
    const portRaw = process.env.DB_PORT || (await ask('DB_PORT (default: 3306): ')) || '3306';
    const port = Number(portRaw) || 3306;
    const user = process.env.DB_USER || (await ask('DB_USER (default: root): ')) || 'root';
    const password = process.env.DB_PASSWORD !== undefined ? process.env.DB_PASSWORD : await ask('DB_PASSWORD (deixe vazio se não tiver): ');
    const database = process.env.DB_NAME || (await ask('DB_NAME (default: gestao_fisio): ')) || 'gestao_fisio';

    const outFile = process.env.SCHEMA_OUT || path.join(process.cwd(), 'schema-full.sql');

    const conn = await mysql.createConnection({
        host,
        port,
        user,
        password,
        database,
        multipleStatements: false
    });

    const [tables] = await conn.execute('SHOW FULL TABLES WHERE Table_type = \"BASE TABLE\"');

    let sql = '';
    sql += `-- Schema (structure only) for database: ${database}\n`;
    sql += `-- Generated at: ${new Date().toISOString()}\n\n`;
    sql += 'SET FOREIGN_KEY_CHECKS=0;\n\n';

    for (const row of tables) {
        const tableName = row[Object.keys(row)[0]];
        const [createRows] = await conn.execute(`SHOW CREATE TABLE \`${tableName}\``);
        const createStmt = createRows && createRows[0] ? createRows[0]['Create Table'] : null;
        if (!createStmt) continue;

        sql += `DROP TABLE IF EXISTS \`${tableName}\`;\n`;
        sql += createStmt + ';\n\n';
    }

    sql += 'SET FOREIGN_KEY_CHECKS=1;\n';

    fs.writeFileSync(outFile, sql, 'utf8');
    await conn.end();

    console.log(`OK: schema gerado em ${outFile}`);
}

main().catch((err) => {
    console.error('Erro ao exportar schema:', err && err.message ? err.message : err);
    process.exitCode = 1;
});
