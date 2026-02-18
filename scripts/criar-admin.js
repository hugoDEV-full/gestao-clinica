require('dotenv').config();

const bcrypt = require('bcrypt');
const { initDB, getDB } = require('../database');

async function ensureUsuariosTipoColumn(db) {
    const dbName = (process.env.DB_NAME || 'gestao_fisio').toString();
    const [cols] = await db.execute(
        'SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND COLUMN_NAME = ? LIMIT 1',
        [dbName, 'usuarios', 'tipo']
    );
    if (cols && cols.length) return;
    await db.execute("ALTER TABLE usuarios ADD COLUMN tipo ENUM('admin','medico','secretaria','paciente') NOT NULL DEFAULT 'secretaria'");
}

async function main() {
    const email = (process.env.ADMIN_SEED_EMAIL || 'hugo.leonardo.jobs@gmail.com').toString().trim().toLowerCase();
    const nome = (process.env.ADMIN_SEED_NOME || 'Hugo Admin').toString().trim();
    const tipo = 'admin';

    const tmpPass = 'Admin@' + Math.random().toString(36).slice(2, 8) + '9';
    const senhaHash = await bcrypt.hash(tmpPass, 10);

    await initDB();
    const db = getDB();

    await ensureUsuariosTipoColumn(db);

    const [rows] = await db.execute('SELECT id FROM usuarios WHERE email = ? LIMIT 1', [email]);
    if (rows && rows.length) {
        await db.execute(
            'UPDATE usuarios SET nome = ?, senha = ?, tipo = ?, ativo = TRUE WHERE id = ? LIMIT 1',
            [nome, senhaHash, tipo, rows[0].id]
        );
        console.log('OK: usuário admin atualizado');
    } else {
        await db.execute(
            'INSERT INTO usuarios (nome, email, senha, tipo, cpf, telefone, ativo) VALUES (?, ?, ?, ?, ?, ?, TRUE)',
            [nome, email, senhaHash, tipo, null, null]
        );
        console.log('OK: usuário admin criado');
    }

    console.log('EMAIL:', email);
    console.log('SENHA:', tmpPass);
}

main().then(() => process.exit(0)).catch((e) => {
    console.error('ERRO:', e);
    process.exit(1);
});
