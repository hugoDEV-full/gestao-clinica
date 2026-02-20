// Só carregar .env em desenvolvimento
if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config();
}

// Fallback para Railway's built-in variables
const dbHost = process.env.DB_HOST || process.env.RAILWAY_DB_HOST;
const dbPort = process.env.DB_PORT || process.env.RAILWAY_DB_PORT || 3306;
const dbUser = process.env.DB_USER || process.env.RAILWAY_DB_USER;
const dbPassword = process.env.DB_PASSWORD || process.env.RAILWAY_DB_PASSWORD;
const dbName = process.env.DB_NAME || process.env.RAILWAY_DB_NAME;
const sessionSecret = process.env.SESSION_SECRET || process.env.RAILWAY_SESSION_SECRET;
const accessHmacSecret = process.env.ACCESS_HMAC_SECRET || process.env.RAILWAY_ACCESS_HMAC_SECRET;

// Debug: mostrar se Railway Variables estão sendo l1das
console.log('=== DEBUG Railway Variables ===');
console.log('DB_HOST:', dbHost);
console.log('DB_USER:', dbUser);
console.log('DB_NAME:', dbName);
console.log('SESSION_SECRET:', sessionSecret);
console.log('NODE_ENV:', process.env.NODE_ENV);
console.log('================================');

process.env.TZ = process.env.TZ || 'America/Sao_Paulo';
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const moment = require('moment');
const fs = require('fs');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const cron = require('node-cron');
const expressLayouts = require('express-ejs-layouts');
moment.locale('pt-br');

const archiver = require('archiver');
const unzipper = require('unzipper');

const os = require('os');

// Importar serviços
const { initDB, getDB } = require('./database');

function nowLabel() {
    return moment().format('YYYY-MM-DD HH:mm:ss');
}

async function ensureColaboradorStaticTokenColumn(db) {
    try {
        const [cols] = await db.execute(
            `SELECT COLUMN_NAME
             FROM INFORMATION_SCHEMA.COLUMNS
             WHERE TABLE_SCHEMA = DATABASE()
               AND TABLE_NAME = 'colaboradores'
               AND COLUMN_NAME = 'qr_static_token'
             LIMIT 1`
        );
        if (!cols || !cols.length) {
            await db.execute('ALTER TABLE colaboradores ADD COLUMN qr_static_token VARCHAR(64) NULL');
            await db.execute('ALTER TABLE colaboradores ADD UNIQUE KEY uniq_colaborador_qr_static (qr_static_token)');
        }
    } catch (e) {
        console.error('Erro ao garantir coluna qr_static_token:', e);
    }
}

function nowIsoLocal() {
    return moment().format('YYYY-MM-DDTHH:mm:ss.SSSZ');
}

const systemLogBuffer = [];
const SYSTEM_LOG_MAX = Number(process.env.SYSTEM_LOG_MAX || 500);
function pushSystemLog(level, parts) {
    try {
        const msg = parts.map(p => {
            if (p == null) return '';
            if (typeof p === 'string') return p;
            if (p instanceof Error) return (p.stack || p.message || String(p));
            try { return JSON.stringify(p); } catch { return String(p); }
        }).join(' ');
        systemLogBuffer.push({
            ts: Date.now(),
            at: nowLabel(),
            level: String(level || 'log'),
            message: msg
        });
        while (systemLogBuffer.length > SYSTEM_LOG_MAX) systemLogBuffer.shift();
    } catch {
        // ignore
    }
}

const _consoleLog = console.log.bind(console);
const _consoleInfo = console.info.bind(console);
const _consoleWarn = console.warn.bind(console);
const _consoleError = console.error.bind(console);

console.log = (...args) => {
    pushSystemLog('log', args);
    _consoleLog(...args);
};
console.info = (...args) => {
    pushSystemLog('info', args);
    _consoleInfo(...args);
};
console.warn = (...args) => {
    pushSystemLog('warn', args);
    _consoleWarn(...args);
};
console.error = (...args) => {
    pushSystemLog('error', args);
    _consoleError(...args);
};

const pontoRateLimit = new Map();
function checkPontoRateLimit(key, limit = 10, windowMs = 60 * 1000) {
    const now = Date.now();
    const current = pontoRateLimit.get(key);
    if (!current || (now - current.resetAt) > windowMs) {
        pontoRateLimit.set(key, { count: 1, resetAt: now });
        return true;
    }
    if (current.count >= limit) return false;
    current.count += 1;
    return true;
}

function sha256Hex(value) {
    return crypto.createHash('sha256').update(String(value || '')).digest('hex');
}

function generateResetCode() {
    return String(Math.floor(100000 + Math.random() * 900000));
}

function getAppBaseUrl(req) {
    const envBase = (process.env.APP_BASE_URL || '').toString().trim();
    if (envBase) return envBase.replace(/\/$/, '');
    const proto = (req && (req.headers['x-forwarded-proto'] || req.protocol)) ? String(req.headers['x-forwarded-proto'] || req.protocol) : 'http';
    const host = req && req.get ? req.get('host') : null;
    if (!host) return '';
    return `${proto}://${host}`;
}

async function getAppBaseUrlFromConfig(db, req) {
    const envBase = (process.env.APP_BASE_URL || '').toString().trim();
    if (envBase) return envBase.replace(/\/$/, '');
    const cfgBase = await getAppConfigValue(db, 'APP_BASE_URL');
    const cfg = (cfgBase == null ? '' : String(cfgBase)).trim();
    if (cfg) return cfg.replace(/\/$/, '');
    return getAppBaseUrl(req);
}

function getMailerTransporter() {
    const host = (process.env.EMAIL_HOST || process.env.SMTP_HOST || '').toString().trim();
    const port = Number(process.env.EMAIL_PORT || process.env.SMTP_PORT || 587);
    const user = (process.env.EMAIL_USER || process.env.SMTP_USER || '').toString().trim();
    const pass = (process.env.EMAIL_PASS || process.env.SMTP_PASS || '').toString();
    const secure = String(process.env.EMAIL_SECURE || process.env.SMTP_SECURE || '').toLowerCase() === 'true' || String(process.env.EMAIL_SECURE || process.env.SMTP_SECURE || '') === '1';

    if (!host || !user || !pass) return null;

    return nodemailer.createTransport({
        host,
        port,
        secure,
        auth: { user, pass }
    });
}

async function notifyBlockedAccessAttempt(db, colaborador, motivo, req) {
    try {
        const cfgAlert = await getAppConfigValue(db, 'ALERTA_ACESSO_EMAIL');
        let recipients = [];
        if (cfgAlert && String(cfgAlert).trim()) {
            recipients = String(cfgAlert)
                .split(',')
                .map((v) => v.trim())
                .filter(Boolean);
        } else {
            const [admins] = await db.execute(
                "SELECT email FROM usuarios WHERE tipo = 'admin' AND ativo = TRUE AND email IS NOT NULL"
            );
            recipients = (admins || []).map((a) => a.email).filter(Boolean);
        }

        if (!recipients.length) return;

        const transporter = await getMailerTransporterFromConfig(db);
        if (!transporter) return;

        const baseUrl = await getAppBaseUrlFromConfig(db, req);
        const fromCfg = await getAppConfigValue(db, 'SMTP_FROM');
        const from = (fromCfg != null && String(fromCfg).trim())
            ? String(fromCfg).trim()
            : (process.env.SMTP_FROM || process.env.EMAIL_FROM || process.env.EMAIL_USER || process.env.SMTP_USER || 'no-reply@localhost').toString();

        const subject = 'Alerta de acesso bloqueado - Controle de Acesso';
        const link = baseUrl ? `${baseUrl}/colaboradores/${colaborador.id}` : '';
        const text = `Tentativa de acesso bloqueado.\n\nNome: ${colaborador.nome}\nCPF: ${colaborador.cpf}\nEmpresa: ${colaborador.empresa || '-'}\nCargo: ${colaborador.cargo || '-'}\nMotivo: ${motivo}\nData/Hora: ${nowLabel()}\nDetalhes: ${link || 'sem link'}`;

        await transporter.sendMail({
            from,
            to: recipients.join(','),
            subject,
            text
        });
    } catch (e) {
        console.error('Erro ao enviar alerta de acesso bloqueado:', e);
    }
}

async function notifyBlockedAccessAttemptWhatsapp(db, colaborador, motivo) {
    try {
        const cfgWhats = await getAppConfigValue(db, 'ALERTA_ACESSO_WHATSAPP');
        const cfgDefault = await getAppConfigValue(db, 'WHATSAPP_NUMBER');
        const raw = (cfgWhats || cfgDefault || '').toString().trim();
        if (!raw) return;

        const status = whatsappService.getStatus();
        if (!status || !status.isConnected) return;

        const text = `⚠️ Alerta de acesso bloqueado\nNome: ${colaborador.nome}\nCPF: ${colaborador.cpf}\nEmpresa: ${colaborador.empresa || '-'}\nCargo: ${colaborador.cargo || '-'}\nMotivo: ${motivo}\nData/Hora: ${nowLabel()}`;
        await whatsappService.sendMessage(raw, text);
    } catch (e) {
        console.error('Erro ao enviar alerta WhatsApp de acesso bloqueado:', e);
    }
}

async function getMailerTransporterFromConfig(db) {
    // Priorizar variáveis de ambiente
    const envHost = (process.env.EMAIL_HOST || process.env.SMTP_HOST || '').toString().trim();
    // Forçar porta 465 para Railway (SSL funciona melhor)
    const envPort = process.env.EMAIL_PORT || process.env.SMTP_PORT || 465;
    const envUser = (process.env.EMAIL_USER || process.env.SMTP_USER || '').toString().trim();
    const envPass = (process.env.EMAIL_PASS || process.env.SMTP_PASS || '').toString();
    // Forçar secure=true para porta 465
    const envSecure = Number(envPort) === 465 ? true : (
        String(process.env.EMAIL_SECURE || process.env.SMTP_SECURE || '').toLowerCase() === 'true' || 
        String(process.env.EMAIL_SECURE || process.env.SMTP_SECURE || '') === '1'
    );

    // Se variáveis de ambiente estiverem configuradas, usar elas
    if (envHost && envUser && envPass) {
        console.log('✅ Usando SMTP das variáveis de ambiente:', { 
            host: envHost, 
            port: envPort, 
            user: envUser,
            secure: envSecure
        });
        return nodemailer.createTransport({
            host: envHost,
            port: Number(envPort),
            secure: envSecure,
            auth: { user: envUser, pass: envPass },
            // Timeout maior para Railway
            connectionTimeout: 10000,
            greetingTimeout: 10000,
            socketTimeout: 10000
        });
    }

    // Fallback: tentar configurações do banco (só se não tiver env)
    try {
        const cfgHost = await getAppConfigValue(db, 'SMTP_HOST');
        const cfgPort = await getAppConfigValue(db, 'SMTP_PORT');
        const cfgUser = await getAppConfigValue(db, 'SMTP_USER');
        const cfgPass = await getAppConfigValue(db, 'SMTP_PASS');
        const cfgSecure = await getAppConfigValue(db, 'SMTP_SECURE');

        const host = (cfgHost != null && String(cfgHost).trim()) ? String(cfgHost).trim() : '';
        const port = Number((cfgPort != null && String(cfgPort).trim()) ? String(cfgPort).trim() : 465);
        const user = (cfgUser != null && String(cfgUser).trim()) ? String(cfgUser).trim() : '';
        const pass = (cfgPass != null && String(cfgPass)) ? String(cfgPass) : '';
        const secure = Number(port) === 465 ? true : (
            (cfgSecure != null && String(cfgSecure).trim() !== '') ? 
            String(cfgSecure).trim().toLowerCase() === 'true' || String(cfgSecure).trim() === '1' : false
        );

        if (host && user && pass) {
            console.log('✅ Usando SMTP do banco de dados:', { host, port, user, secure });
            return nodemailer.createTransport({
                host,
                port,
                secure,
                auth: { user, pass },
                connectionTimeout: 10000,
                greetingTimeout: 10000,
                socketTimeout: 10000
            });
        }
    } catch (error) {
        console.error('Erro ao ler SMTP do banco:', error);
    }

    console.log('❌ SMTP não configurado em nenhum lugar');
    return null;
}

// WhatsApp Service
const whatsappService = require('./whatsappService.js');

const app = express();

// Middleware de segurança com CSP ajustada
app.use((req, res, next) => {
    // Proteção contra XSS
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    
    // Content Security Policy ajustada para permitir scripts externos necessários
    const csp = [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://code.jquery.com",
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com",
        "img-src 'self' data: https:",
        "font-src 'self' https://cdn.jsdelivr.net",
        "connect-src 'self' https://cdn.jsdelivr.net https://code.jquery.com",
        "frame-src 'none'",
        "object-src 'none'"
    ].join('; ');
    
    res.setHeader('Content-Security-Policy', csp);
    
    // Rate limiting simples
    const now = Date.now();
    req.requestTime = now;
    
    next();
});

const PORT = process.env.PORT || 3000;

// Configuração de segurança (sem helmet para usar CSP personalizada)
const corsOriginEnv = process.env.CORS_ORIGIN;
const corsOrigins = corsOriginEnv ? corsOriginEnv.split(',').map(o => o.trim()).filter(Boolean) : null;
app.use(cors({
    origin: (origin, callback) => {
        if (!origin) return callback(null, true);
        if (!corsOrigins || corsOrigins.length === 0) return callback(null, true);
        if (corsOrigins.includes(origin)) return callback(null, true);
        return callback(new Error('CORS bloqueado'), false);
    },
    credentials: true
}));

// Configurar trust proxy para rate limiting funcionar corretamente
app.set('trust proxy', 1);

// Rate limiting - desativado temporariamente para debug
const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: Number(process.env.RATE_LIMIT_MAX || 300),
    standardHeaders: true,
    legacyHeaders: false,
});
app.use(generalLimiter);

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: Number(process.env.RATE_LIMIT_AUTH_MAX || 20),
    standardHeaders: true,
    legacyHeaders: false,
});

const passwordResetLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: Number(process.env.RATE_LIMIT_RESET_MAX || 8),
    standardHeaders: true,
    legacyHeaders: false,
});

// Configuração do Multer para uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const allowedMimeEnv = process.env.UPLOAD_ALLOWED_MIME;
const allowedMime = allowedMimeEnv
    ? allowedMimeEnv.split(',').map(v => v.trim()).filter(Boolean)
    : [
        'application/pdf',
        'image/jpeg',
        'image/png',
        'image/webp',
        'image/gif'
    ];
const upload = multer({
    storage: storage,
    limits: {
        fileSize: Number(process.env.UPLOAD_MAX_BYTES || 10 * 1024 * 1024)
    },
    fileFilter: (req, file, cb) => {
        if (!file || !file.mimetype) return cb(new Error('Arquivo inválido'));
        if (!allowedMime.includes(file.mimetype)) return cb(new Error('Tipo de arquivo não permitido'));
        return cb(null, true);
    }
});

// Configuração do EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(expressLayouts);
app.set('layout', 'layouts/main');

// Adicionar moment como variável global para uso nos templates
app.use((req, res, next) => {
    res.locals.moment = moment;
    next();
});

// Middlewares
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static('uploads'));
app.use('/generated_backups', express.static(path.join(__dirname, 'generated_backups')));

// Configuração de sessão melhorada
const isProd = process.env.NODE_ENV === 'production';
const sessionSecretFinal = sessionSecret || 'segredo_padrao_muito_secreto';
if (isProd && sessionSecretFinal === 'segredo_padrao_muito_secreto') {
    console.warn('SESSION_SECRET não configurado em produção. Configure SESSION_SECRET no .env');
}
app.use(session({
    secret: sessionSecretFinal,
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: isProd,
        maxAge: 24 * 60 * 60 * 1000, // 24 horas
        httpOnly: true,
        sameSite: 'lax'
    },
    name: 'clinica_session',
    rolling: false, // Mudar para false para evitar problemas
    proxy: isProd
}));

// Defaults globais para as views/layouts
app.use((req, res, next) => {
    res.locals.usuario = (req.session && req.session.usuario) ? req.session.usuario : null;
    res.locals.currentPage = res.locals.currentPage || '';
    res.locals.title = res.locals.title || null;
    next();
});

let appConfigCache = null;
let appConfigCacheAtMs = 0;
async function getAppConfigValue(db, chave) {
    const ttlMs = 60 * 1000;
    const now = Date.now();
    if (!appConfigCache || (now - appConfigCacheAtMs) > ttlMs) {
        try {
            const [rows] = await db.execute('SELECT chave, valor FROM app_config');
            const map = {};
            for (const r of rows) {
                if (!r || !r.chave) continue;
                map[String(r.chave)] = r.valor;
            }
            appConfigCache = map;
            appConfigCacheAtMs = now;
        } catch {
            appConfigCache = {};
            appConfigCacheAtMs = now;
        }
    }
    return appConfigCache ? appConfigCache[String(chave)] : null;
}

app.use(async (req, res, next) => {
    try {
        const db = getDB();
        // Carrega e expõe todas as configs para qualquer view (EJS)
        await getAppConfigValue(db, 'CLINICA_LOGO_URL');
        res.locals.appConfig = appConfigCache || {};
        res.locals.clinicaLogoUrl = res.locals.appConfig.CLINICA_LOGO_URL || null;
    } catch {
        res.locals.appConfig = {};
        res.locals.clinicaLogoUrl = null;
    }
    next();
});

// Middleware global para garantir que req.session sempre exista
app.use((req, res, next) => {
    if (!req.session) {
        req.session = {};
    }
    next();
});

// Middleware de autenticação simplificado
function requireAuth(req, res, next) {
    if (!req.session || !req.session.usuario) {
        return res.redirect('/login');
    }
    next();
}

app.use('/anamnese', requireAuth, (req, res) => {
    return res.redirect('/dashboard?error=modulo_desativado');
});
app.use('/atestados', requireAuth, (req, res) => {
    return res.redirect('/dashboard?error=modulo_desativado');
});
app.use('/exames', requireAuth, (req, res) => {
    return res.redirect('/dashboard?error=modulo_desativado');
});
app.use('/evolucoes', requireAuth, (req, res) => {
    return res.redirect('/dashboard?error=modulo_desativado');
});
app.use('/estoque', requireAuth, (req, res) => {
    return res.redirect('/dashboard?error=modulo_desativado');
});
app.use('/receitas', requireAuth, (req, res) => {
    return res.redirect('/dashboard?error=modulo_desativado');
});
app.use('/relatorios-medicos', requireAuth, (req, res) => {
    return res.redirect('/dashboard?error=modulo_desativado');
});


// Processamento automático de lembretes pendentes
let reminderCronStarted = false;
async function processarLembretesPendentes() {
    try {
        const db = getDB();
        const retryMinutes = Number(process.env.REMINDER_RETRY_INTERVAL_MINUTES || 5);
        const maxAttempts = Number(process.env.REMINDER_MAX_ATTEMPTS || 20);
        const [rows] = await db.execute(
            `SELECT l.id, l.mensagem, l.via_whatsapp, l.status, l.data_envio, l.tentativas,
                    p.telefone AS paciente_telefone
             FROM lembretes l
             LEFT JOIN pacientes p ON p.id = l.paciente_id
             WHERE l.status = 'pendente'
               AND l.data_envio IS NOT NULL
               AND l.data_envio <= NOW()
             ORDER BY l.data_envio ASC
             LIMIT 50`
        );

        if (!rows.length) return;

        const status = whatsappService.getStatus();
        const canSendWhats = status && status.isConnected;

        for (const r of rows) {
            if (!r.via_whatsapp) continue;
            if (!canSendWhats) continue;

            if (!r.paciente_telefone) {
                await db.execute(
                    "UPDATE lembretes SET status = 'erro', data_envio_real = NOW() WHERE id = ?",
                    [r.id]
                );
                continue;
            }

            try {
                await whatsappService.sendMessage(r.paciente_telefone, r.mensagem || 'Lembrete');
                await db.execute(
                    "UPDATE lembretes SET status = 'enviado', data_envio_real = NOW() WHERE id = ?",
                    [r.id]
                );
            } catch (sendErr) {
                const attempts = Number(r.tentativas || 0) + 1;
                const errMsg = sendErr && sendErr.message ? String(sendErr.message).slice(0, 250) : 'Erro ao enviar';
                console.error('Falha ao enviar lembrete WhatsApp:', r.id, errMsg, `tentativa ${attempts}/${maxAttempts}`);

                if (attempts >= maxAttempts) {
                    await db.execute(
                        "UPDATE lembretes SET status = 'erro', data_envio_real = NOW(), tentativas = ?, ultimo_erro = ? WHERE id = ?",
                        [attempts, errMsg, r.id]
                    );
                } else {
                    await db.execute(
                        "UPDATE lembretes SET status = 'pendente', tentativas = ?, ultimo_erro = ?, data_envio = DATE_ADD(NOW(), INTERVAL ? MINUTE) WHERE id = ?",
                        [attempts, errMsg, retryMinutes, r.id]
                    );
                }
            }
        }
    } catch (error) {
        console.error('Erro no processamento de lembretes:', error);
    }
}

async function criarLembretesAniversarioInternos() {
    try {
        const db = getDB();

        await db.execute(
            `INSERT INTO lembretes (
                paciente_id,
                profissional_id,
                tipo,
                titulo,
                mensagem,
                data_envio,
                status,
                via_whatsapp,
                via_email
            )
            SELECT
                p.id,
                NULL,
                'aniversario',
                'Aniversário do paciente',
                CONCAT('Hoje é aniversário de ', p.nome, '.'),
                NOW(),
                'pendente',
                0,
                0
            FROM pacientes p
            WHERE p.ativo = 1
              AND p.data_nascimento IS NOT NULL
              AND DAY(p.data_nascimento) = DAY(CURDATE())
              AND MONTH(p.data_nascimento) = MONTH(CURDATE())
              AND NOT EXISTS (
                  SELECT 1
                  FROM lembretes l
                  WHERE l.paciente_id = p.id
                    AND l.tipo = 'aniversario'
                    AND DATE(l.data_envio) = CURDATE()
              )`
        );
    } catch (error) {
        console.error('Erro ao criar lembretes internos de aniversário:', error);
    }
}

function removeDirRecursive(dirPath) {
    if (!fs.existsSync(dirPath)) return;
    try {
        fs.rmSync(dirPath, { recursive: true, force: true });
    } catch (e) {
        // ignore
    }
}

function findFirstFileRecursive(dirPath, predicate) {
    if (!fs.existsSync(dirPath)) return null;
    const entries = fs.readdirSync(dirPath, { withFileTypes: true });
    for (const entry of entries) {
        const full = path.join(dirPath, entry.name);
        if (entry.isDirectory()) {
            const found = findFirstFileRecursive(full, predicate);
            if (found) return found;
        } else if (entry.isFile()) {
            if (predicate(full)) return full;
        }
    }
    return null;
}

function validateStrongPassword(password) {
    const s = (password || '').toString();
    if (s.length < 8) return 'Senha deve ter pelo menos 8 caracteres';
    if (/\s/.test(s)) return 'Senha não pode conter espaços';
    if (!/[a-z]/.test(s)) return 'Senha deve conter pelo menos 1 letra minúscula';
    if (!/[A-Z]/.test(s)) return 'Senha deve conter pelo menos 1 letra maiúscula';
    if (!/[0-9]/.test(s)) return 'Senha deve conter pelo menos 1 número';
    if (!/[^A-Za-z0-9]/.test(s)) return 'Senha deve conter pelo menos 1 caractere especial';
    return null;
}

function normalizeUsuarioTipo(raw) {
    const t0 = (raw == null ? '' : String(raw)).trim().toLowerCase();
    const t = t0 === 'profissional' ? 'medico' : t0;
    const allowed = new Set(['admin', 'medico', 'secretaria', 'paciente']);
    if (!allowed.has(t)) {
        return { tipo: null, error: 'Tipo inválido. Use: admin, medico, secretaria, paciente' };
    }
    return { tipo: t, error: null };
}

function normalizeTelefone(raw) {
    if (raw == null) return null;
    const s0 = String(raw).trim();
    if (!s0) return null;
    const cleaned = s0.replace(/[^0-9+]/g, '');
    const maxLen = 20;
    if (cleaned.length > maxLen) {
        return { error: `Telefone muito longo (máx. ${maxLen} caracteres)` };
    }
    return { telefone: cleaned };
}

function generateAccessToken(bytes = 24) {
    return crypto.randomBytes(bytes).toString('hex');
}

let accessHmacSecretCache = null;
async function getAccessHmacSecret(db) {
    if (accessHmacSecretCache) return accessHmacSecretCache;
    const fromConfig = await getAppConfigValue(db, 'ACCESS_HMAC_SECRET');
    const secret = (fromConfig || process.env.ACCESS_HMAC_SECRET || sessionSecret || 'access_hmac_default').toString();
    if (secret === 'access_hmac_default') {
        console.warn('ACCESS_HMAC_SECRET não configurado. Configure no .env ou em Configurações.');
    }
    accessHmacSecretCache = secret;
    return secret;
}

function buildAccessTokenHash(token, deviceId, qrSeed, secret) {
    const base = `${token}.${deviceId || ''}.${qrSeed || ''}`;
    return crypto.createHmac('sha256', secret).update(base).digest('hex');
}

function haversineMeters(lat1, lon1, lat2, lon2) {
    const toRad = (v) => (Number(v) * Math.PI) / 180;
    const r = 6371000;
    const dLat = toRad(lat2 - lat1);
    const dLon = toRad(lon2 - lon1);
    const a = Math.sin(dLat / 2) ** 2 + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
    return 2 * r * Math.asin(Math.sqrt(a));
}

function toShortDateTime(dt) {
    return dt ? moment(dt).format('DD/MM/YYYY HH:mm:ss') : '';
}

let usuariosTipoColumnChecked = false;
async function ensureUsuariosTipoColumn(db) {
    if (usuariosTipoColumnChecked) return;
    usuariosTipoColumnChecked = true;
    try {
        const [cols] = await db.execute(
            `SELECT DATA_TYPE, CHARACTER_MAXIMUM_LENGTH
             FROM INFORMATION_SCHEMA.COLUMNS
             WHERE TABLE_SCHEMA = DATABASE()
               AND TABLE_NAME = 'usuarios'
               AND COLUMN_NAME = 'tipo'
             LIMIT 1`
        );
        const col = cols && cols[0] ? cols[0] : null;
        const dataType = col && col.DATA_TYPE ? String(col.DATA_TYPE).toLowerCase() : '';
        const maxLen = col && col.CHARACTER_MAXIMUM_LENGTH != null ? Number(col.CHARACTER_MAXIMUM_LENGTH) : null;

        if ((dataType === 'varchar' || dataType === 'char') && Number.isFinite(maxLen) && maxLen < 12) {
            await db.execute('ALTER TABLE usuarios MODIFY COLUMN tipo VARCHAR(32)');
        }
    } catch (e) {
        usuariosTipoColumnChecked = false;
    }
}

async function ensureAccessControlTables(db) {
    await db.execute(`
        CREATE TABLE IF NOT EXISTS colaboradores (
            id INT AUTO_INCREMENT PRIMARY KEY,
            usuario_id INT NULL,
            nome VARCHAR(150) NOT NULL,
            cpf VARCHAR(14) NOT NULL,
            empresa VARCHAR(150) NULL,
            cargo VARCHAR(120) NULL,
            foto_url VARCHAR(255) NULL,
            status VARCHAR(16) NOT NULL DEFAULT 'ativo',
            qr_seed VARCHAR(64) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_colaborador_cpf (cpf),
            INDEX idx_colaborador_status (status),
            INDEX idx_colaborador_usuario (usuario_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    await ensureColaboradorStaticTokenColumn(db);

    await db.execute(`
        CREATE TABLE IF NOT EXISTS access_tokens (
            id INT AUTO_INCREMENT PRIMARY KEY,
            colaborador_id INT NOT NULL,
            token_hash CHAR(64) NOT NULL,
            device_id VARCHAR(128) NULL,
            expires_at DATETIME NOT NULL,
            used_at DATETIME NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_access_token (token_hash),
            INDEX idx_access_colaborador (colaborador_id),
            INDEX idx_access_expires (expires_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    await db.execute(`
        CREATE TABLE IF NOT EXISTS colaborador_devices (
            id INT AUTO_INCREMENT PRIMARY KEY,
            colaborador_id INT NOT NULL,
            device_id VARCHAR(128) NOT NULL,
            label VARCHAR(120) NULL,
            last_seen DATETIME NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_colab_device (colaborador_id, device_id),
            INDEX idx_colab_device (colaborador_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    await db.execute(`
        CREATE TABLE IF NOT EXISTS access_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            colaborador_id INT NULL,
            status VARCHAR(16) NOT NULL,
            tipo VARCHAR(16) NOT NULL DEFAULT 'acesso',
            motivo VARCHAR(255) NULL,
            local VARCHAR(120) NULL,
            ip_address VARCHAR(64) NULL,
            device_id VARCHAR(128) NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_access_log_colaborador (colaborador_id),
            INDEX idx_access_log_status (status),
            INDEX idx_access_log_tipo (tipo)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    await db.execute(`
        CREATE TABLE IF NOT EXISTS ponto_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            colaborador_id INT NOT NULL,
            tipo VARCHAR(16) NOT NULL,
            ip_address VARCHAR(64) NULL,
            device_id VARCHAR(128) NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_ponto_colaborador (colaborador_id),
            INDEX idx_ponto_tipo (tipo)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);
}

async function extractZipToDir(zipPath, outDir) {
    await fs.createReadStream(zipPath)
        .pipe(unzipper.Extract({ path: outDir }))
        .promise();
}

function restoreUploadsFromExtract(extractedUploadsDir) {
    if (!fs.existsSync(extractedUploadsDir)) return;

    const targetUploads = path.join(__dirname, 'uploads');
    const backupRoot = path.join(__dirname, 'generated_backups');
    if (!fs.existsSync(backupRoot)) fs.mkdirSync(backupRoot, { recursive: true });
    const snapshotName = `uploads-before-restore-${moment().format('YYYY-MM-DD_HH-mm-ss')}`;
    const snapshotDir = path.join(backupRoot, snapshotName);

    try {
        if (fs.existsSync(targetUploads)) {
            copyDirRecursive(targetUploads, snapshotDir);
        }
    } catch (e) {
        console.error('Erro ao criar snapshot do uploads antes do restore:', e);
    }

    try {
        removeDirRecursive(targetUploads);
        fs.mkdirSync(targetUploads, { recursive: true });
        copyDirRecursive(extractedUploadsDir, targetUploads);
    } catch (e) {
        console.error('Erro ao restaurar uploads:', e);
        throw e;
    }
}

// Middleware de admin simplificado
function requireAdmin(req, res, next) {
    if (!req.session || !req.session.usuario || req.session.usuario.tipo !== 'admin') {
        return res.redirect('/dashboard');
    }
    next();
}

// WhatsApp (rotas precisam estar após session + requireAuth)
app.get('/configuracoes/whatsapp', requireAuth, requireAdmin, (req, res) => {
    res.redirect('/whatsapp');
});

app.get('/whatsapp', requireAuth, requireAdmin, (req, res) => {
    res.render('whatsapp-teste', {
        title: 'WhatsApp',
        currentPage: 'whatsapp',
        usuario: req.session.usuario
    });
});

app.get('/api/whatsapp/status-teste', requireAuth, requireAdmin, (req, res) => {
    try {
        res.json({ success: true, status: whatsappService.getStatus() });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Erro ao obter status do WhatsApp' });
    }
});

app.get('/api/whatsapp/qrcode-teste', requireAuth, requireAdmin, (req, res) => {
    try {
        const qrCode = whatsappService.getQRCode();
        if (qrCode && qrCode !== null && qrCode !== '') {
            res.json({ success: true, qrCode });
        } else {
            res.json({ success: true, qrCode: null, message: 'QR Code não disponível ainda' });
        }
    } catch (error) {
        console.error('Erro ao obter QR Code:', error);
        res.status(500).json({ success: false, qrCode: null, message: 'Erro ao obter QR Code' });
    }
});

app.post('/api/whatsapp/reactivate-teste', requireAuth, requireAdmin, (req, res) => {
    try {
        whatsappService.reactivate();
        res.json({ success: true, message: 'WhatsApp reativado com sucesso!' });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Erro ao reativar WhatsApp' });
    }
});

app.post('/api/whatsapp/start', requireAuth, requireAdmin, async (req, res) => {
    try {
        const st = whatsappService.getStatus();
        if (st && st.isConnected) {
            return res.json({ success: true, message: 'WhatsApp já está conectado' });
        }
        await whatsappService.start();
        return res.json({ success: true, message: 'Inicialização do WhatsApp iniciada' });
    } catch (error) {
        console.error('Erro ao iniciar WhatsApp via API:', error);
        return res.status(500).json({ success: false, message: 'Erro ao iniciar WhatsApp', error: error.message });
    }
});

app.get('/api/whatsapp/teste-voce-mesmo', requireAuth, requireAdmin, async (req, res) => {
    try {
        const st = whatsappService.getStatus();
        if (!st || !st.isConnected) {
            return res.status(400).json({ success: false, message: 'WhatsApp não está conectado' });
        }

        const db = getDB();
        const [rows] = await db.execute('SELECT valor FROM app_config WHERE chave = ? LIMIT 1', ['WHATSAPP_NUMBER']);
        const phoneNumber = rows && rows[0] && rows[0].valor ? String(rows[0].valor).trim() : '';
        if (!phoneNumber) {
            return res.status(400).json({ success: false, message: 'Número de envio não configurado' });
        }

        const msg = `Teste de envio - ${moment().format('DD/MM/YYYY HH:mm:ss')}`;
        await whatsappService.sendMessage(phoneNumber, msg);
        return res.json({ success: true, message: `Mensagem de teste enviada para ${phoneNumber}` });
    } catch (error) {
        console.error('Erro ao enviar teste para você mesmo:', error);
        return res.status(500).json({ success: false, message: error.message || 'Erro ao enviar mensagem' });
    }
});

app.post('/api/whatsapp/teste-numero', requireAuth, requireAdmin, async (req, res) => {
    try {
        const st = whatsappService.getStatus();
        if (!st || !st.isConnected) {
            return res.status(400).json({ success: false, message: 'WhatsApp não está conectado' });
        }

        const phoneNumber = (req.body && req.body.phoneNumber != null) ? String(req.body.phoneNumber).trim() : '';
        const message = (req.body && req.body.message != null) ? String(req.body.message) : '';
        if (!phoneNumber) {
            return res.status(400).json({ success: false, message: 'Informe o número de destino' });
        }

        const msg = message && message.trim() ? message : `Teste de envio - ${moment().format('DD/MM/YYYY HH:mm:ss')}`;
        await whatsappService.sendMessage(phoneNumber, msg);
        return res.json({ success: true, message: `Mensagem enviada para ${phoneNumber}` });
    } catch (error) {
        console.error('Erro ao enviar teste para número:', error);
        return res.status(500).json({ success: false, message: error.message || 'Erro ao enviar mensagem' });
    }
});

app.post('/api/whatsapp/verify', requireAuth, requireAdmin, async (req, res) => {
    try {
        const st = whatsappService.getStatus();
        if (!st || !st.isConnected) {
            return res.status(400).json({ success: false, error: 'WhatsApp não está conectado' });
        }

        const phoneNumber = (req.body && req.body.phoneNumber != null) ? String(req.body.phoneNumber).trim() : '';
        if (!phoneNumber) {
            return res.status(400).json({ success: false, error: 'Informe o número' });
        }

        const exists = await whatsappService.verifyNumberExists(phoneNumber);
        return res.json({ success: true, exists });
    } catch (error) {
        console.error('Erro ao verificar número no WhatsApp:', error);
        return res.status(500).json({ success: false, error: error.message || 'Erro ao verificar número' });
    }
});

app.get('/api/whatsapp/config', requireAuth, requireAdmin, async (req, res) => {
    try {
        const db = getDB();
        const [rows] = await db.execute('SELECT valor FROM app_config WHERE chave = ? LIMIT 1', ['WHATSAPP_NUMBER']);
        const number = rows && rows.length ? rows[0].valor : (whatsappService.getPhoneNumber ? whatsappService.getPhoneNumber() : null);
        res.json({ success: true, config: { phoneNumber: number || '' } });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Erro ao obter configuração' });
    }
});

app.post('/api/whatsapp/config', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { phoneNumber } = req.body || {};
        const cleaned = String(phoneNumber || '').trim();
        if (!cleaned) {
            return res.status(400).json({ success: false, message: 'Informe um número válido' });
        }

        const db = getDB();
        await db.execute(
            'INSERT INTO app_config (chave, valor) VALUES (?, ?) ON DUPLICATE KEY UPDATE valor = VALUES(valor)',
            ['WHATSAPP_NUMBER', cleaned]
        );
        if (whatsappService.setPhoneNumber) whatsappService.setPhoneNumber(cleaned);
        return res.json({ success: true });
    } catch (error) {
        console.error('Erro ao salvar configuração WhatsApp:', error);
        return res.status(500).json({ success: false, message: 'Erro ao salvar configuração' });
    }
});

// Middleware para verificar múltiplos tipos de usuário
function requireRoles(roles) {
    return (req, res, next) => {
        if (!req.session || !req.session.usuario) {
            return res.redirect('/login?error=session_expired');
        }
        
        if (!roles.includes(req.session.usuario.tipo)) {
            return res.redirect('/dashboard?error=access_denied');
        }
        
        next();
    };
}

function isSecretaria(req) {
    return Boolean(req && req.session && req.session.usuario && req.session.usuario.tipo === 'secretaria');
}

function isAdmin(req) {
    return Boolean(req && req.session && req.session.usuario && req.session.usuario.tipo === 'admin');
}

function isMedico(req) {
    return Boolean(req && req.session && req.session.usuario && req.session.usuario.tipo === 'medico');
}

function isPaciente(req) {
    return Boolean(req && req.session && req.session.usuario && req.session.usuario.tipo === 'paciente');
}

function configFlagEnabled(req, key, defaultValue = false) {
    const cfg = req && req.res && req.res.locals ? req.res.locals.appConfig : (req && req.app && req.app.locals ? req.app.locals.appConfig : null);
    const raw = cfg && Object.prototype.hasOwnProperty.call(cfg, key) ? cfg[key] : undefined;
    if (raw == null) return !!defaultValue;
    const s = String(raw).trim().toLowerCase();
    return s === '1' || s === 'true' || s === 'yes' || s === 'on';
}

function canAccessFinanceiro(req) {
    if (isAdmin(req)) return true;
    if (isSecretaria(req)) return true;
    if (isMedico(req)) return configFlagEnabled(req, 'PERM_FINANCEIRO_MEDICO_VER', false);
    return false;
}

function canLancarFinanceiro(req) {
    if (isAdmin(req)) return true;
    if (isSecretaria(req)) return true;
    if (isMedico(req)) return configFlagEnabled(req, 'PERM_FINANCEIRO_MEDICO_LANCAR', false);
    return false;
}

function sanitizeProntuarioForRole(prontuario, usuarioTipo) {
    if (!prontuario || typeof prontuario !== 'object') return prontuario;
    if (usuarioTipo !== 'secretaria') return prontuario;

    const safe = { ...prontuario };
    const fields = [
        'queixa_principal',
        'historia_doenca',
        'historia_patologica',
        'historia_fisiologica',
        'exame_fisico',
        'diagnostico',
        'plano_tratamento',
        'prognostico',
        'observacoes'
    ];
    for (const f of fields) safe[f] = null;
    return safe;
}

function sanitizePacienteForRole(paciente, usuarioTipo) {
    if (!paciente || typeof paciente !== 'object') return paciente;
    if (usuarioTipo !== 'secretaria') return paciente;

    const safe = { ...paciente };
    const fields = ['alergias', 'medicamentos', 'historico_familiar', 'observacoes'];
    for (const f of fields) safe[f] = null;
    return safe;
}

function normalizeDateOnly(value) {
    if (!value) return value;
    try {
        if (value instanceof Date) {
            // DATE vindo do MySQL pode chegar como Date em UTC 00:00:00 e ao aplicar fuso (GMT-3)
            // pode “voltar um dia”. Para DATE (sem hora), tratamos como UTC e extraímos só YYYY-MM-DD.
            return moment(value).utc().format('YYYY-MM-DD');
        }
        const s = String(value);
        if (/^\d{4}-\d{2}-\d{2}/.test(s)) return s.slice(0, 10);
        const m = moment(s);
        if (m.isValid()) return m.utc().format('YYYY-MM-DD');
        return s;
    } catch {
        return value;
    }
}

// Função para formatar datas para input HTML
function formatDateForInput(dateValue) {
    if (!dateValue) return '';
    
    console.log('formatDateForInput - Recebido:', dateValue);
    console.log('formatDateForInput - Tipo:', typeof dateValue);
    
    try {
        let dateString;
        
        // Se for objeto Date, converter para string
        if (dateValue instanceof Date) {
            console.log('formatDateForInput - É objeto Date');
            dateString = moment(dateValue).utc().format('YYYY-MM-DD');
        } else if (typeof dateValue === 'string') {
            console.log('formatDateForInput - É string');
            dateString = dateValue;
        } else {
            console.log('formatDateForInput - Tipo não reconhecido');
            return '';
        }
        
        console.log('formatDateForInput - String processada:', dateString);
        
        const normalized = normalizeDateOnly(dateString);
        if (normalized && /^\d{4}-\d{2}-\d{2}$/.test(String(normalized))) {
            console.log('formatDateForInput - Normalizado:', normalized);
            return String(normalized);
        }

        // fallback: tenta interpretar via moment em UTC
        const m = moment(String(dateString));
        if (!m.isValid()) {
            console.log('formatDateForInput - Data inválida!');
            return '';
        }
        const formatted = m.utc().format('YYYY-MM-DD');
        console.log('formatDateForInput - Formatado:', formatted);
        return formatted;
    } catch (error) {
        console.error('formatDateForInput - Erro ao formatar data:', error);
        return '';
    }
}

let sexoColumnCache = null;
let sexoColumnCacheAtMs = 0;

async function getSexoColumnInfo(db) {
    const ttlMs = 10 * 60 * 1000;
    if (sexoColumnCache && (Date.now() - sexoColumnCacheAtMs) < ttlMs) return sexoColumnCache;

    try {
        const [rows] = await db.execute("SHOW COLUMNS FROM pacientes LIKE 'sexo'");
        const row = rows && rows.length ? rows[0] : null;
        const type = row && row.Type ? String(row.Type) : '';
        const info = { type, enumValues: null };

        const m = type.match(/^enum\((.*)\)$/i);
        if (m && m[1]) {
            const raw = m[1];
            const values = [];
            const re = /'((?:\\'|[^'])*)'/g;
            let match;
            while ((match = re.exec(raw)) !== null) {
                values.push(match[1].replace(/\\'/g, "'"));
            }
            info.enumValues = values.length ? values : null;
        }

        sexoColumnCache = info;
        sexoColumnCacheAtMs = Date.now();
        return info;
    } catch (e) {
        sexoColumnCache = { type: '', enumValues: null };
        sexoColumnCacheAtMs = Date.now();
        return sexoColumnCache;
    }
}

function normalizeSexoForForm(sexoDbValue) {
    if (!sexoDbValue) return sexoDbValue;
    const s = String(sexoDbValue).trim();
    const up = s.toUpperCase();
    if (up === 'M') return 'masculino';
    if (up === 'F') return 'feminino';
    if (up === 'O') return 'outro';
    const low = s.toLowerCase();
    if (low === 'masculino' || low === 'feminino' || low === 'outro') return low;
    return low;
}

async function resolveSexoDbValue(db, sexoFromForm) {
    if (!sexoFromForm) return sexoFromForm;

    const raw = String(sexoFromForm).trim();
    const low = raw.toLowerCase();

    const col = await getSexoColumnInfo(db);
    const enumValues = col && Array.isArray(col.enumValues) ? col.enumValues : null;
    if (!enumValues || enumValues.length === 0) {
        return raw;
    }

    const lookup = new Map(enumValues.map(v => [String(v).toLowerCase(), v]));
    if (lookup.has(low)) return lookup.get(low);

    const first = low[0];
    if (first && lookup.has(first)) return lookup.get(first);

    if (low === 'masculino') {
        if (lookup.has('m')) return lookup.get('m');
        if (lookup.has('masculino')) return lookup.get('masculino');
        if (lookup.has('masculina')) return lookup.get('masculina');
        if (lookup.has('masculino ')) return lookup.get('masculino ');
        if (lookup.has('masculino')) return lookup.get('masculino');
        if (lookup.has('masculino')) return lookup.get('masculino');
        if (lookup.has('masculino')) return lookup.get('masculino');
        if (lookup.has('masculino')) return lookup.get('masculino');
        if (lookup.has('masculino')) return lookup.get('masculino');
        if (lookup.has('masculino')) return lookup.get('masculino');
        if (lookup.has('masculino')) return lookup.get('masculino');
        if (lookup.has('masculino')) return lookup.get('masculino');
        if (lookup.has('masculino')) return lookup.get('masculino');
        if (lookup.has('masculino')) return lookup.get('masculino');
        if (lookup.has('masculino')) return lookup.get('masculino');
        if (lookup.has('masculino')) return lookup.get('masculino');
    }
    if (low === 'feminino') {
        if (lookup.has('f')) return lookup.get('f');
        if (lookup.has('feminino')) return lookup.get('feminino');
        if (lookup.has('feminina')) return lookup.get('feminina');
    }
    if (low === 'outro') {
        if (lookup.has('o')) return lookup.get('o');
        if (lookup.has('outro')) return lookup.get('outro');
    }

    for (const candidate of ['Masculino', 'Feminino', 'Outro', 'M', 'F', 'O']) {
        const cLow = candidate.toLowerCase();
        if (low === cLow && lookup.has(cLow)) return lookup.get(cLow);
        if (lookup.has(cLow) && (low === 'masculino' && cLow.startsWith('masc'))) return lookup.get(cLow);
        if (lookup.has(cLow) && (low === 'feminino' && cLow.startsWith('fem'))) return lookup.get(cLow);
        if (lookup.has(cLow) && (low === 'outro' && cLow.startsWith('out'))) return lookup.get(cLow);
    }

    const fallbacks = ['m', 'f', 'o', 'masculino', 'feminino', 'outro', 'masculino', 'feminino', 'outro'];
    for (const fb of fallbacks) {
        if (lookup.has(fb)) return lookup.get(fb);
    }
    return enumValues[0];
}

// Função para log LGPD
function sanitizeLGPDPayload(payload) {
    if (payload == null) return null;

    const maxLen = Number(process.env.LGPD_LOG_MAX_CHARS || 5000);
    const redactKeys = new Set([
        'senha', 'password', 'token', 'access_token', 'refresh_token',
        'cpf', 'rg', 'telefone', 'email', 'endereco', 'cidade', 'estado', 'cep',
        'alergias', 'medicamentos', 'historico_familiar', 'observacoes',
        'mensagem'
    ]);

    const redactValue = (v) => {
        if (v == null) return v;
        const s = String(v);
        if (s.length <= 4) return '***';
        return s.slice(0, 2) + '***' + s.slice(-2);
    };

    const sanitizeObject = (obj) => {
        if (!obj || typeof obj !== 'object') return obj;
        if (Array.isArray(obj)) return obj.slice(0, 50).map(sanitizeObject);
        const out = {};
        for (const [k, v] of Object.entries(obj)) {
            if (redactKeys.has(k)) {
                out[k] = redactValue(v);
            } else if (typeof v === 'string' && v.length > 500) {
                out[k] = v.slice(0, 500) + '...';
            } else {
                out[k] = sanitizeObject(v);
            }
        }
        return out;
    };

    try {
        if (typeof payload === 'string') {
            try {
                const parsed = JSON.parse(payload);
                const sanitized = JSON.stringify(sanitizeObject(parsed));
                return sanitized.length > maxLen ? sanitized.slice(0, maxLen) : sanitized;
            } catch (e) {
                return payload.length > maxLen ? payload.slice(0, maxLen) : payload;
            }
        }
        const asString = JSON.stringify(sanitizeObject(payload));
        return asString.length > maxLen ? asString.slice(0, maxLen) : asString;
    } catch (e) {
        return null;
    }
}

async function logLGPD(usuario_id, acao, tabela, registro_id, dados_anteriores, dados_novos, req = null) {
    try {
        const db = getDB();
        const safeAntes = sanitizeLGPDPayload(dados_anteriores);
        const safeNovos = sanitizeLGPDPayload(dados_novos);
        await db.execute(
            'INSERT INTO logs_lgpd (usuario_id, acao, tabela_afetada, registro_id, dados_anteriores, dados_novos, ip_address) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [usuario_id, acao, tabela, registro_id, safeAntes, safeNovos, req ? req.ip : null]
        );
    } catch (error) {
        console.error('Erro ao registrar log LGPD:', error);
    }
}

// ROTAS DE AUTENTICAÇÃO
app.get('/', (req, res) => {
    try {
        if (req.session && req.session.usuario && req.session.usuario.nome) {
            return res.redirect('/dashboard');
        }
    } catch (e) {
        // ignore
    }
    return res.redirect('/login');
});

app.get('/login', (req, res) => {
    try {
        if (req.session && req.session.usuario && req.session.usuario.nome) {
            return res.redirect('/dashboard');
        }
    } catch (e) {
        // ignore
    }
    const registrar = String(req.query.registrar || '').trim();
    const info = registrar ? 'O cadastro de novos usuários é feito pelo administrador. Após entrar como admin, acesse o menu Usuários.' : null;
    res.render('login', { error: null, info, usuario: null, currentPage: '' });
});

app.get('/forgot-password', (req, res) => {
    try {
        if (req.session && req.session.usuario && req.session.usuario.nome) {
            return res.redirect('/dashboard');
        }
    } catch (e) {
        // ignore
    }
    res.render('forgot-password', { error: null, info: null, usuario: null, currentPage: '' });
});

app.post('/forgot-password', passwordResetLimiter, async (req, res) => {
    const emailRaw = req.body ? req.body.email : undefined;
    const email = (emailRaw == null ? '' : String(emailRaw)).trim().toLowerCase();
    const ttlMinutes = Number(process.env.RESET_PASSWORD_TTL_MINUTES || 15);

    try {
        const db = getDB();

        const [users] = await db.execute(
            'SELECT id, email, nome, ativo, tipo FROM usuarios WHERE email = ? LIMIT 1',
            [email]
        );
        if (!users.length || !users[0] || !users[0].ativo) {
            return res.render('forgot-password', {
                error: 'Não existe usuário ativo com esse e-mail.',
                info: null
            });
        }

        const user = users[0];

        // Verificar se é admin - apenas admins podem resetar senha
        if (user.tipo !== 'admin') {
            console.warn(`[${nowLabel()}] TENTATIVA DE RESET DE SENHA - usuário não-admin: ${user.email} (${user.nome}) tipo: ${user.tipo}`);
            return res.render('forgot-password', {
                error: 'Apenas administradores podem redefinir senhas. Entre em contato com o administrador do sistema.',
                info: null
            });
        }

        const token = crypto.randomBytes(32).toString('hex');
        const code = generateResetCode();
        const tokenHash = sha256Hex(token);
        const codeHash = await bcrypt.hash(code, 10);

        await db.execute(
            `INSERT INTO password_resets
                (user_id, email, token_hash, code_hash, expires_at, used_at, created_at, ip_address, user_agent)
             VALUES
                (?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL ? MINUTE), NULL, NOW(), ?, ?)`,
            [
                user.id,
                user.email,
                tokenHash,
                codeHash,
                ttlMinutes,
                req.ip || null,
                req.get('User-Agent') || null
            ]
        );

        const baseUrl = await getAppBaseUrlFromConfig(db, req);
        const resetLink = baseUrl ? `${baseUrl}/reset-password?token=${encodeURIComponent(token)}&email=${encodeURIComponent(user.email)}` : '';

        // Sempre tentar SMTP primeiro
        const transporter = await getMailerTransporterFromConfig(db);
        
        if (!transporter) {
            // Sem SMTP - mostrar código na tela com aviso
            console.error('❌ SMTP não configurado - variáveis:', {
                EMAIL_HOST: process.env.EMAIL_HOST,
                EMAIL_USER: process.env.EMAIL_USER,
                EMAIL_PASS: process.env.EMAIL_PASS ? 'SIM' : 'NÃO'
            });
            
            return res.render('forgot-password', {
                error: null,
                info: `📧 <strong>Redefinição de Senha</strong><br><br>
                       <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 10px 0;">
                           <strong>Código de Recuperação:</strong><br>
                           <span style="font-size: 1.5em; font-weight: bold; color: #007bff; font-family: monospace;">${code}</span><br>
                           <small style="color: #6c757d;">Válido por ${ttlMinutes} minutos</small>
                       </div>
                       
                       <div style="background: #e7f3ff; padding: 10px; border-radius: 5px; margin: 10px 0;">
                           <strong>Link Direto:</strong><br>
                           <a href="${resetLink}" style="word-break: break-all;">${resetLink}</a>
                       </div>
                       
                       <div style="background: #fff3cd; padding: 10px; border-radius: 5px; margin: 10px 0;">
                           <small>💡 <strong>Como usar:</strong><br>
                           1. Anote o código: <strong>${code}</strong><br>
                           2. Clique no link acima ou copie e cole no navegador<br>
                           3. Digite o código e sua nova senha</small>
                       </div>`,
                usuario: user,
                currentPage: ''
            });
        }

        // Com email - enviar normalmente
        const cfgFrom = await getAppConfigValue(db, 'SMTP_FROM');
        const from = (cfgFrom != null && String(cfgFrom).trim())
            ? String(cfgFrom).trim()
            : (process.env.SMTP_FROM || process.env.EMAIL_FROM || process.env.EMAIL_USER || process.env.SMTP_USER || 'no-reply@localhost').toString();

        const subject = 'Redefinição de Senha - Clínica Andreia Ballejo';
        const text = `Olá ${user.nome},\n\nRecebemos uma solicitação para redefinir sua senha.\n\nCódigo: ${code}\nLink: ${resetLink}\n\nEste código expira em ${ttlMinutes} minutos.\n\nSe não solicitou, ignore este email.`;
        const html = `
            <h2>Redefinição de Senha</h2>
            <p>Olá <strong>${user.nome}</strong>,</p>
            <p>Recebemos uma solicitação para redefinir sua senha.</p>
            <p><strong>Código:</strong> <code style="font-size: 1.2em; background: #f0f0f0; padding: 5px;">${code}</code></p>
            <p><a href="${resetLink}">Clique aqui para redefinir</a></p>
            <p><small>Válido por ${ttlMinutes} minutos.</small></p>
            <p><em>Se não solicitou, ignore este email.</em></p>
        `;

        try {
            await transporter.sendMail({
                from,
                to: user.email,
                subject,
                text,
                html
            });
            
            console.log('✅ Email enviado com sucesso para:', user.email);
            
            return res.render('forgot-password', {
                error: null,
                info: 'Email de redefinição enviado! Verifique sua caixa de entrada (e spam/promoções).',
                usuario: user,
                currentPage: ''
            });
            
        } catch (emailError) {
            console.error('❌ Erro ao enviar email:', emailError);
            
            return res.render('forgot-password', {
                error: `Erro ao enviar email: ${emailError.message}`,
                info: `Código de emergência: <strong>${code}</strong><br>Link: <a href="${resetLink}">${resetLink}</a>`,
                usuario: user,
                currentPage: ''
            });
        }

    } catch (e) {
        console.error('Erro no forgot-password:', e);
        return res.render('forgot-password', { error: 'Não foi possível processar a solicitação agora. Tente novamente.', info: null });
    }
});

app.get('/reset-password', (req, res) => {
    const token = (req.query && req.query.token) ? String(req.query.token) : '';
    const email = (req.query && req.query.email) ? String(req.query.email).trim().toLowerCase() : '';
    res.render('reset-password', { error: null, info: null, token, email });
});

app.post('/reset-password', passwordResetLimiter, async (req, res) => {
    const token = req.body ? String(req.body.token || '') : '';
    const email = req.body ? String(req.body.email || '').trim().toLowerCase() : '';
    const code = req.body ? String(req.body.code || '').trim() : '';
    const senha = req.body ? String(req.body.senha || '') : '';
    const confirmar = req.body ? String(req.body.confirmar || '') : '';

    if (!token || !email || !code || !senha || !confirmar) {
        return res.render('reset-password', { error: 'Preencha todos os campos.', info: null, token, email });
    }
    if (senha !== confirmar) {
        return res.render('reset-password', { error: 'As senhas não conferem.', info: null, token, email });
    }
    const senhaErr = validateStrongPassword(senha);
    if (senhaErr) {
        return res.render('reset-password', { error: senhaErr, info: null, token, email });
    }

    try {
        const db = getDB();
        const tokenHash = sha256Hex(token);

        const [rows] = await db.execute(
            `SELECT pr.id, pr.user_id, pr.code_hash
             FROM password_resets pr
             WHERE pr.email = ?
               AND pr.token_hash = ?
               AND pr.used_at IS NULL
               AND pr.expires_at >= NOW()
             ORDER BY pr.id DESC
             LIMIT 1`,
            [email, tokenHash]
        );

        if (!rows.length) {
            return res.render('reset-password', { error: 'Token inválido ou expirado. Solicite novamente.', info: null, token, email });
        }

        const pr = rows[0];
        const codeOk = await bcrypt.compare(code, String(pr.code_hash || ''));
        if (!codeOk) {
            return res.render('reset-password', { error: 'Código inválido.', info: null, token, email });
        }

        const senhaHash = await bcrypt.hash(senha, 10);
        await db.execute('UPDATE usuarios SET senha = ? WHERE id = ? LIMIT 1', [senhaHash, pr.user_id]);

        await db.execute('UPDATE password_resets SET used_at = NOW() WHERE id = ? LIMIT 1', [pr.id]);
        await db.execute('UPDATE password_resets SET used_at = NOW() WHERE user_id = ? AND used_at IS NULL', [pr.user_id]);

        return res.render('login', { error: null, info: 'Senha redefinida com sucesso. Faça login.' });
    } catch (e) {
        console.error('Erro no reset-password:', e);
        return res.render('reset-password', { error: 'Erro ao redefinir senha. Tente novamente.', info: null, token, email });
    }
});

app.post('/login', authLimiter, async (req, res) => {
    const emailRaw = req.body ? req.body.email : undefined;
    const senhaRaw = req.body ? req.body.senha : undefined;
    const email = (emailRaw == null ? '' : String(emailRaw)).trim().toLowerCase();
    const senha = (senhaRaw == null ? '' : String(senhaRaw));
    try {
        const db = getDB();
        const [usuarios] = await db.execute('SELECT * FROM usuarios WHERE email = ? AND ativo = TRUE', [email]);
        if (usuarios.length === 0) {
            console.warn(`[${nowLabel()}] LOGIN FALHOU: usuário não encontrado/inativo (${email || '-'})`);
            return res.render('login', { error: 'Usuário ou senha inválidos', info: null });
        }
        
        const usuario = usuarios[0];

        const senhaBanco = usuario && usuario.senha != null ? String(usuario.senha) : '';
        const pareceBcrypt = senhaBanco.startsWith('$2a$') || senhaBanco.startsWith('$2b$') || senhaBanco.startsWith('$2y$');
        let senhaValida = false;
        if (pareceBcrypt) {
            senhaValida = await bcrypt.compare(senha, senhaBanco);
        } else {
            // Compatibilidade: caso tenha sido salvo em texto puro (legado)
            senhaValida = senha === senhaBanco;
            if (senhaValida) {
                try {
                    const novoHash = await bcrypt.hash(senha, 10);
                    await db.execute('UPDATE usuarios SET senha = ? WHERE id = ? LIMIT 1', [novoHash, usuario.id]);
                } catch (e) {
                    console.error('Erro ao migrar senha legada para bcrypt:', e);
                }
            }
        }
        
        if (!senhaValida) {
            console.warn(`[${nowLabel()}] LOGIN FALHOU: senha inválida (${email || '-'})`);
            return res.render('login', { error: 'Usuário ou senha inválidos', info: null });
        }
        
        // Criar sessão com informações completas
        req.session.usuario = {
            id: usuario.id,
            nome: usuario.nome,
            email: usuario.email,
            tipo: usuario.tipo,
            cpf: usuario.cpf,
            telefone: usuario.telefone
        };
        
        // Registrar tempo de login
        req.session.loginTime = Date.now();
        req.session.loginIP = req.ip;
        req.session.userAgent = req.get('User-Agent');
        
        // Registrar login no log
        console.log(`[${nowLabel()}] LOGIN: ${usuario.nome} (${usuario.email})`);
        
        // Registrar no log LGPD
        try {
            await logLGPD(
                usuario.id, 
                'sessao', 
                null, 
                null, 
                JSON.stringify({ 
                    login_time: nowIsoLocal(),
                    ip: req.ip,
                    user_agent: req.get('User-Agent')
                }),
                null,
                req
            );
        } catch (logError) {
            console.error('Erro ao registrar login no LGPD:', logError);
        }
        
        res.redirect('/dashboard');
    } catch (error) {
        console.error('Erro no login:', error);
        return res.render('login', { error: 'Erro ao fazer login. Tente novamente.', info: null });
    }
});

// Debug SMTP endpoint (remover em produção)
app.get('/debug-smtp', (req, res) => {
    const debug = {
        environment: {
            EMAIL_HOST: process.env.EMAIL_HOST || '❌ Não configurado',
            EMAIL_PORT: process.env.EMAIL_PORT || '❌ Não configurado',
            EMAIL_USER: process.env.EMAIL_USER || '❌ Não configurado',
            EMAIL_PASS: process.env.EMAIL_PASS ? '✅ Configurado' : '❌ Não configurado',
            EMAIL_FROM: process.env.EMAIL_FROM || '❌ Não configurado',
            APP_BASE_URL: process.env.APP_BASE_URL || '❌ Não configurado',
            NODE_ENV: process.env.NODE_ENV || 'development'
        },
        smtp_test: null
    };
    
    // Testar se SMTP está configurado
    const host = (process.env.EMAIL_HOST || '').toString().trim();
    const user = (process.env.EMAIL_USER || '').toString().trim();
    const pass = (process.env.EMAIL_PASS || '').toString();
    
    if (host && user && pass) {
        debug.smtp_test = {
            status: '✅ SMTP parece configurado',
            next_step: 'Teste forgot-password para verificar envio real'
        };
    } else {
        debug.smtp_test = {
            status: '❌ SMTP não configurado',
            missing: [
                !process.env.EMAIL_HOST ? 'EMAIL_HOST' : null,
                !process.env.EMAIL_USER ? 'EMAIL_USER' : null,
                !process.env.EMAIL_PASS ? 'EMAIL_PASS' : null
            ].filter(Boolean)
        };
    }
    
    res.json(debug);
});

// Rota pública de registro de usuário
app.get('/register', (req, res) => {
    res.render('register', { 
        error: null, 
        success: null,
        nome: '',
        email: '',
        cpf: '',
        telefone: ''
    });
});

// Processar registro de usuário
app.post('/register', async (req, res) => {
    const { nome, email, senha, confirmarSenha, cpf, telefone } = req.body;
    
    // Validações básicas
    if (!nome || !email || !senha || !confirmarSenha) {
        return res.render('register', { 
            error: 'Preencha todos os campos obrigatórios', 
            success: null,
            nome: nome || '',
            email: email || '',
            cpf: cpf || '',
            telefone: telefone || ''
        });
    }
    
    if (senha !== confirmarSenha) {
        return res.render('register', { 
            error: 'As senhas não coincidem', 
            success: null,
            nome: nome || '',
            email: email || '',
            cpf: cpf || '',
            telefone: telefone || ''
        });
    }
    
    if (senha.length < 6) {
        return res.render('register', { 
            error: 'A senha deve ter pelo menos 6 caracteres', 
            success: null,
            nome: nome || '',
            email: email || '',
            cpf: cpf || '',
            telefone: telefone || ''
        });
    }
    
    const emailTrim = email.trim().toLowerCase();
    const nomeTrim = nome.trim();
    const cpfTrim = cpf ? cpf.replace(/\D/g, '') : '';
    const telefoneTrim = telefone ? telefone.replace(/\D/g, '') : '';
    
    try {
        const db = getDB();
        
        // Verificar se email já existe
        const [emailExistente] = await db.execute(
            'SELECT id FROM usuarios WHERE email = ?',
            [emailTrim]
        );
        
        if (emailExistente.length > 0) {
            return res.render('register', { 
                error: 'Este email já está cadastrado', 
                success: null,
                nome: nomeTrim,
                email: emailTrim,
                cpf: cpf,
                telefone: telefone
            });
        }
        
        // Verificar se CPF já existe (se informado)
        if (cpfTrim) {
            const [cpfExistente] = await db.execute(
                'SELECT id FROM usuarios WHERE cpf = ?',
                [cpfTrim]
            );
            
            if (cpfExistente.length > 0) {
                return res.render('register', { 
                    error: 'Este CPF já está cadastrado', 
                    success: null,
                    nome: nomeTrim,
                    email: emailTrim,
                    cpf: cpf,
                    telefone: telefone
                });
            }
        }
        
        // Hash da senha
        const senhaHash = await bcrypt.hash(senha, 10);
        
        // Inserir usuário com tipo 'admin' por padrão
        await db.execute(
            `INSERT INTO usuarios (nome, email, senha, tipo, cpf, telefone, ativo) 
             VALUES (?, ?, ?, 'admin', ?, ?, 1)`,
            [nomeTrim, emailTrim, senhaHash, cpfTrim || null, telefoneTrim || null]
        );
        
        console.log(`[${nowLabel()}] NOVO USUÁRIO ADMIN REGISTRADO: ${emailTrim} (${nomeTrim})`);
        
        return res.render('register', { 
            error: null, 
            success: 'Usuário cadastrado com sucesso! Você já pode fazer login.',
            nome: '',
            email: '',
            cpf: '',
            telefone: ''
        });
        
    } catch (error) {
        console.error('Erro no registro:', error);
        return res.render('register', { 
            error: 'Erro ao cadastrar usuário. Tente novamente.', 
            success: null,
            nome: nomeTrim,
            email: emailTrim,
            cpf: cpf,
            telefone: telefone
        });
    }
});

app.get('/logout', (req, res) => {
    try {
        const usuarioId = req && req.session && req.session.usuario ? req.session.usuario.id : null;
        const usuarioTipo = req && req.session && req.session.usuario ? req.session.usuario.tipo : null;
        const usuarioNome = req && req.session && req.session.usuario ? req.session.usuario.nome : null;

        try {
            if (usuarioId) {
                logLGPD(
                    usuarioId,
                    'sessao',
                    null,
                    null,
                    JSON.stringify({
                        logout_time: nowIsoLocal(),
                        tipo: usuarioTipo,
                        nome: usuarioNome
                    }),
                    null,
                    req
                );
            }
        } catch (e) {
            // ignore
        }

        if (req && req.session) {
            req.session.destroy(() => {
                try {
                    res.clearCookie('clinica_session');
                } catch (e) {
                    // ignore
                }
                return res.redirect('/login');
            });
            return;
        }
    } catch (e) {
        // ignore
    }
    try {
        res.clearCookie('clinica_session');
    } catch (e) {
        // ignore
    }
    return res.redirect('/login');
});

// DASHBOARD
app.get('/dashboard', requireAuth, async (req, res) => {
    try {
        if (isSecretaria(req)) {
            return res.redirect('/agenda');
        }

        const db = getDB();

        const [pacientesCount] = await db.execute('SELECT COUNT(*) as count FROM pacientes WHERE ativo = TRUE');
        const [consultasHoje] = await db.execute(
            'SELECT COUNT(*) as count FROM agendamentos WHERE DATE(data_hora) = CURDATE()'
        );

        const [proximasConsultas] = await db.execute(
            `SELECT id, paciente_nome, profissional_nome, data_hora, tipo_consulta
             FROM agendamentos
             WHERE data_hora >= NOW()
             ORDER BY data_hora ASC
             LIMIT 10`
        );

        const [consultasRecentes] = await db.execute(
            `SELECT id, paciente_nome, profissional_nome, data_hora, tipo_consulta
             FROM agendamentos
             WHERE data_hora <= NOW()
             ORDER BY data_hora DESC
             LIMIT 10`
        );

        const [lembretesPendentesRows] = await db.execute(
            "SELECT COUNT(*) as count FROM lembretes WHERE LOWER(status) = 'pendente'"
        );
        const [lembretesRecentes] = await db.execute(
            `SELECT l.id, l.paciente_id, p.nome AS paciente_nome, l.titulo, l.data_envio, l.status
             FROM lembretes l
             LEFT JOIN pacientes p ON p.id = l.paciente_id
             ORDER BY l.data_envio DESC, l.id DESC
             LIMIT 10`
        );

        const [acessosRecentes] = await db.execute(
            `SELECT a.id, a.status, a.tipo, a.motivo, a.local, a.created_at,
                    c.nome AS colaborador_nome, c.cpf AS colaborador_cpf
             FROM access_logs a
             LEFT JOIN colaboradores c ON c.id = a.colaborador_id
             ORDER BY a.created_at DESC, a.id DESC
             LIMIT 8`
        );

        const [receitasMes] = await db.execute(
            `SELECT COALESCE(SUM(valor), 0) as total
             FROM financeiro
             WHERE tipo = 'receita'
               AND MONTH(data_cadastro) = MONTH(CURDATE())
               AND YEAR(data_cadastro) = YEAR(CURDATE())`
        );

        const [consultasSemanaRows] = await db.execute(
            `SELECT DAYOFWEEK(data_hora) as dow, COUNT(*) as total
             FROM agendamentos
             WHERE data_hora >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
             GROUP BY DAYOFWEEK(data_hora)`
        );
        const week = [0, 0, 0, 0, 0, 0, 0]; // Seg..Dom
        for (const r of (consultasSemanaRows || [])) {
            const dow = Number(r.dow || 0); // 1=Dom ... 7=Sáb
            const total = Number(r.total || 0);
            const idx = dow === 1 ? 6 : dow - 2; // 0=Seg ... 6=Dom
            if (idx >= 0 && idx <= 6) week[idx] = total;
        }

        return res.render('dashboard/index', {
            title: 'Dashboard',
            currentPage: 'dashboard',
            usuario: req.session.usuario,
            estatisticas: {
                totalPacientes: Number(pacientesCount?.[0]?.count || 0),
                consultasHoje: Number(consultasHoje?.[0]?.count || 0),
                proximasConsultas: Array.isArray(proximasConsultas) ? proximasConsultas.length : 0,
                faturamentoMes: Number(receitasMes?.[0]?.total || 0),
                consultasSemana: week
            },
            lembretesPendentes: Number(lembretesPendentesRows?.[0]?.count || 0),
            lembretesRecentes: lembretesRecentes || [],
            proximasConsultas: proximasConsultas || [],
            consultasRecentes: consultasRecentes || [],
            acessosRecentes: acessosRecentes || []
        });
    } catch (error) {
        console.error('Erro ao carregar dashboard:', error);
        return res.render('dashboard/index', {
            title: 'Dashboard',
            currentPage: 'dashboard',
            usuario: req.session.usuario,
            estatisticas: {
                totalPacientes: 0,
                consultasHoje: 0,
                proximasConsultas: 0,
                faturamentoMes: 0,
                consultasSemana: [0, 0, 0, 0, 0, 0, 0]
            },
            lembretesPendentes: 0,
            lembretesRecentes: [],
            proximasConsultas: [],
            consultasRecentes: [],
            acessosRecentes: [],
            error: 'Erro ao carregar dashboard'
        });
    }
});

app.get('/dashboard/export', requireAuth, async (req, res) => {
    try {
        if (isSecretaria(req)) {
            return res.redirect('/agenda');
        }

        const db = getDB();

        const [pacientesCount] = await db.execute('SELECT COUNT(*) as count FROM pacientes WHERE ativo = TRUE');
        const [consultasHoje] = await db.execute(
            'SELECT COUNT(*) as count FROM agendamentos WHERE DATE(data_hora) = CURDATE()'
        );
        const [receitasMes] = await db.execute(
            `SELECT COALESCE(SUM(valor), 0) as total
             FROM financeiro
             WHERE tipo = 'receita'
               AND MONTH(data_cadastro) = MONTH(CURDATE())
               AND YEAR(data_cadastro) = YEAR(CURDATE())`
        );

        const payload = {
            exported_at: nowIsoLocal(),
            estatisticas: {
                totalPacientes: Number(pacientesCount?.[0]?.count || 0),
                consultasHoje: Number(consultasHoje?.[0]?.count || 0),
                faturamentoMes: Number(receitasMes?.[0]?.total || 0)
            }
        };

        const format = String(req.query?.format || 'json').toLowerCase();
        if (format === 'csv') {
            const csv = [
                'chave,valor',
                `totalPacientes,${payload.estatisticas.totalPacientes}`,
                `consultasHoje,${payload.estatisticas.consultasHoje}`,
                `faturamentoMes,${payload.estatisticas.faturamentoMes}`
            ].join('\n');

            res.setHeader('Content-Type', 'text/csv; charset=utf-8');
            res.setHeader('Content-Disposition', 'attachment; filename="dashboard.csv"');
            return res.send(csv);
        }

        res.setHeader('Content-Type', 'application/json; charset=utf-8');
        res.setHeader('Content-Disposition', 'attachment; filename="dashboard.json"');
        return res.send(JSON.stringify(payload, null, 2));
    } catch (error) {
        console.error('Erro ao exportar dashboard:', error);
        return res.status(500).send('Erro ao exportar dashboard');
    }
});

app.get('/perfil', requireAuth, (req, res) => {
    res.render('perfil', {
        title: 'Meu Perfil',
        currentPage: 'perfil',
        usuario: req.session.usuario
    });
});

app.get('/perfil/export', requireAuth, async (req, res) => {
    try {
        const uid = req.session?.usuario?.id;
        if (!uid) return res.redirect('/perfil');

        const db = getDB();
        const [rows] = await db.execute(
            'SELECT id, nome, email, tipo, cpf, telefone, ativo FROM usuarios WHERE id = ? LIMIT 1',
            [uid]
        );
        if (!rows || !rows.length) return res.redirect('/perfil');

        const payload = {
            exported_at: nowIsoLocal(),
            usuario: rows[0]
        };

        res.setHeader('Content-Type', 'application/json; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename="meus-dados-${uid}.json"`);
        return res.status(200).send(JSON.stringify(payload, null, 2));
    } catch (error) {
        console.error('Erro ao exportar dados do perfil:', error);
        return res.redirect('/perfil');
    }
});

app.get('/ajuda', requireAuth, (req, res) => {
    if (isSecretaria(req) || isPaciente(req)) {
        return res.redirect('/dashboard?error=access_denied');
    }
    res.render('ajuda', {
        title: 'Ajuda',
        currentPage: 'ajuda',
        usuario: req.session.usuario
    });
});

app.get('/relatorio-hugo', requireAuth, (req, res) => {
    const email = (req.session?.usuario?.email || '').toString().trim().toLowerCase();
    if (email !== 'hugo.leonardo.jobs@gmail.com') {
        return res.redirect('/dashboard?error=access_denied');
    }
    return res.render('relatorio-hugo', {
        title: 'Relatório de Funcionalidades',
        currentPage: 'relatorio-hugo',
        usuario: req.session.usuario
    });
});

app.get('/estatisticas', requireAuth, requireAdmin, async (req, res) => {
    try {
        const db = getDB();

        const [pacientesCount] = await db.execute('SELECT COUNT(*) as count FROM pacientes WHERE ativo = TRUE');

        const [agendamentosHoje] = await db.execute(
            'SELECT COUNT(*) as count FROM agendamentos WHERE DATE(data_hora) = CURDATE()'
        );

        const [agendamentosMes] = await db.execute(
            'SELECT COUNT(*) as count FROM agendamentos WHERE MONTH(data_hora) = MONTH(CURDATE()) AND YEAR(data_hora) = YEAR(CURDATE())'
        );

        const [statusMesRows] = await db.execute(`
            SELECT LOWER(COALESCE(status, '')) as status, COUNT(*) as count
            FROM agendamentos
            WHERE MONTH(data_hora) = MONTH(CURDATE()) AND YEAR(data_hora) = YEAR(CURDATE())
            GROUP BY LOWER(COALESCE(status, ''))
            ORDER BY count DESC
        `);

        const statusMes = (statusMesRows || []).reduce((acc, row) => {
            acc[row.status || ''] = Number(row.count || 0);
            return acc;
        }, {});

        const [receitasMes] = await db.execute(`
            SELECT COALESCE(SUM(valor), 0) as total
            FROM financeiro
            WHERE tipo = 'receita'
              AND MONTH(data_cadastro) = MONTH(CURDATE())
              AND YEAR(data_cadastro) = YEAR(CURDATE())
        `);

        const [despesasMes] = await db.execute(`
            SELECT COALESCE(SUM(valor), 0) as total
            FROM financeiro
            WHERE tipo = 'despesa'
              AND MONTH(data_cadastro) = MONTH(CURDATE())
              AND YEAR(data_cadastro) = YEAR(CURDATE())
        `);

        const [lembretesStatusRows] = await db.execute(`
            SELECT LOWER(COALESCE(status, '')) as status, COUNT(*) as count
            FROM lembretes
            GROUP BY LOWER(COALESCE(status, ''))
            ORDER BY count DESC
        `);

        const lembretesStatus = (lembretesStatusRows || []).reduce((acc, row) => {
            acc[row.status || ''] = Number(row.count || 0);
            return acc;
        }, {});

        const [topProfissionais30] = await db.execute(`
            SELECT COALESCE(profissional_nome, 'Não informado') as profissional_nome, COUNT(*) as total
            FROM agendamentos
            WHERE data_hora >= DATE_SUB(NOW(), INTERVAL 30 DAY)
            GROUP BY COALESCE(profissional_nome, 'Não informado')
            ORDER BY total DESC, profissional_nome ASC
            LIMIT 5
        `);

        const [receitaCategoriaMes] = await db.execute(`
            SELECT COALESCE(categoria, 'Sem categoria') as categoria, COALESCE(SUM(valor), 0) as total
            FROM financeiro
            WHERE tipo = 'receita'
              AND MONTH(data_cadastro) = MONTH(CURDATE())
              AND YEAR(data_cadastro) = YEAR(CURDATE())
            GROUP BY COALESCE(categoria, 'Sem categoria')
            ORDER BY total DESC, categoria ASC
            LIMIT 8
        `);

        const [proximos7Dias] = await db.execute(`
            SELECT DATE(data_hora) as dia, COUNT(*) as total
            FROM agendamentos
            WHERE data_hora >= CURDATE()
              AND data_hora < DATE_ADD(CURDATE(), INTERVAL 7 DAY)
            GROUP BY DATE(data_hora)
            ORDER BY dia ASC
        `);

        let topPacientesFieis = [];
        try {
            const [rows] = await db.execute(`
                SELECT paciente_id, COALESCE(paciente_nome, 'Não informado') as paciente_nome, COUNT(*) as total
                FROM agendamentos
                WHERE data_hora >= DATE_SUB(NOW(), INTERVAL 180 DAY)
                  AND COALESCE(LOWER(status), '') <> 'cancelado'
                GROUP BY paciente_id, COALESCE(paciente_nome, 'Não informado')
                ORDER BY total DESC, paciente_nome ASC
                LIMIT 10
            `);
            topPacientesFieis = rows || [];
        } catch (e) {
            console.error('Erro ao calcular topPacientesFieis:', e);
        }

        let pacientesEmRisco = [];
        try {
            const [rows] = await db.execute(`
                SELECT p.id, p.nome, MAX(a.data_hora) as ultima_visita
                FROM pacientes p
                LEFT JOIN agendamentos a
                  ON a.paciente_id = p.id
                 AND COALESCE(LOWER(a.status), '') <> 'cancelado'
                WHERE p.ativo = TRUE
                GROUP BY p.id, p.nome
                HAVING (ultima_visita IS NULL OR ultima_visita < DATE_SUB(NOW(), INTERVAL 60 DAY))
                ORDER BY ultima_visita ASC
                LIMIT 10
            `);
            pacientesEmRisco = rows || [];
        } catch (e) {
            console.error('Erro ao calcular pacientesEmRisco:', e);
        }

        let aniversariantesSemana = [];
        let aniversariantesMes = [];
        try {
            const [rowsSemana] = await db.execute(`
                SELECT id, nome, data_nascimento
                FROM pacientes
                WHERE ativo = TRUE
                  AND data_nascimento IS NOT NULL
                  AND DATE_FORMAT(data_nascimento, '%m-%d') BETWEEN DATE_FORMAT(CURDATE(), '%m-%d') AND DATE_FORMAT(DATE_ADD(CURDATE(), INTERVAL 7 DAY), '%m-%d')
                ORDER BY DATE_FORMAT(data_nascimento, '%m-%d') ASC, nome ASC
                LIMIT 20
            `);
            aniversariantesSemana = rowsSemana || [];
        } catch (e) {
            console.error('Erro ao calcular aniversariantesSemana:', e);
        }
        try {
            const [rowsMes] = await db.execute(`
                SELECT id, nome, data_nascimento
                FROM pacientes
                WHERE ativo = TRUE
                  AND data_nascimento IS NOT NULL
                  AND MONTH(data_nascimento) = MONTH(CURDATE())
                ORDER BY DAY(data_nascimento) ASC, nome ASC
                LIMIT 50
            `);
            aniversariantesMes = rowsMes || [];
        } catch (e) {
            console.error('Erro ao calcular aniversariantesMes:', e);
        }

        let lembretesProximos = [];
        try {
            const [rows] = await db.execute(`
                SELECT l.id, l.data_envio, l.status, l.titulo,
                       COALESCE(p.nome, 'Não informado') as paciente_nome
                FROM lembretes l
                LEFT JOIN pacientes p ON p.id = l.paciente_id
                WHERE COALESCE(LOWER(l.status), '') = 'pendente'
                  AND l.data_envio BETWEEN NOW() AND DATE_ADD(NOW(), INTERVAL 24 HOUR)
                ORDER BY l.data_envio ASC
                LIMIT 10
            `);
            lembretesProximos = rows.map(r => ({
                ...r,
                data_envio: r.data_envio ? moment(r.data_envio).format('DD/MM HH:mm') : null
            }));
        } catch (e) {
            console.error('Erro ao calcular lembretesProximos:', e);
        }

        let lembretesFalhasRecentes = [];
        try {
            const [rows] = await db.execute(`
                SELECT l.id, l.data_envio, l.status, l.titulo,
                       COALESCE(l.tentativas, 0) as tentativas,
                       COALESCE(l.ultimo_erro, NULL) as ultimo_erro,
                       COALESCE(p.nome, 'Não informado') as paciente_nome
                FROM lembretes l
                LEFT JOIN pacientes p ON p.id = l.paciente_id
                WHERE COALESCE(LOWER(l.status), '') = 'erro'
                  AND l.data_envio >= DATE_SUB(NOW(), INTERVAL 7 DAY)
                ORDER BY l.data_envio DESC
                LIMIT 10
            `);
            lembretesFalhasRecentes = rows.map(r => ({
                ...r,
                data_envio: r.data_envio ? moment(r.data_envio).format('DD/MM HH:mm') : null
            }));
        } catch (e) {
            console.error('Erro ao calcular lembretesFalhasRecentes:', e);
        }

        const receitas = Number(receitasMes?.[0]?.total || 0);
        const despesas = Number(despesasMes?.[0]?.total || 0);
        const totalMes = Number(agendamentosMes?.[0]?.count || 0);
        const confirmadosMes = (statusMes['confirmado'] || 0) + (statusMes['realizado'] || 0);
        const taxaConfirmacaoMes = totalMes > 0 ? (confirmadosMes / totalMes) : 0;

        res.render('estatisticas/index', {
            title: 'Estatísticas',
            currentPage: 'estatisticas',
            usuario: req.session.usuario,
            kpis: {
                totalPacientes: Number(pacientesCount?.[0]?.count || 0),
                agendamentosHoje: Number(agendamentosHoje?.[0]?.count || 0),
                agendamentosMes: totalMes,
                taxaConfirmacaoMes,
                receitasMes: receitas,
                despesasMes: despesas,
                saldoMes: receitas - despesas,
                lembretesPendentes: (lembretesStatus['pendente'] || 0),
                lembretesEnviados: (lembretesStatus['enviado'] || 0),
                lembretesErro: (lembretesStatus['erro'] || 0)
            },
            statusMes,
            topProfissionais30,
            topPacientesFieis,
            pacientesEmRisco,
            aniversariantesSemana,
            aniversariantesMes,
            receitaCategoriaMes,
            proximos7Dias,
            lembretesProximos,
            lembretesFalhasRecentes
        });
    } catch (error) {
        console.error('Erro ao carregar estatísticas:', error);
        res.render('estatisticas/index', {
            title: 'Estatísticas',
            currentPage: 'estatisticas',
            usuario: req.session.usuario,
            kpis: {
                totalPacientes: 0,
                agendamentosHoje: 0,
                agendamentosMes: 0,
                taxaConfirmacaoMes: 0,
                receitasMes: 0,
                despesasMes: 0,
                saldoMes: 0,
                lembretesPendentes: 0,
                lembretesEnviados: 0,
                lembretesErro: 0
            },
            statusMes: {},
            topProfissionais30: [],
            topPacientesFieis: [],
            pacientesEmRisco: [],
            aniversariantesSemana: [],
            aniversariantesMes: [],
            receitaCategoriaMes: [],
            proximos7Dias: [],
            lembretesProximos: [],
            lembretesFalhasRecentes: [],
            error: 'Erro ao carregar estatísticas'
        });
    }
});

app.get('/prontuarios', requireAuth, requireRoles(['admin', 'medico']), (req, res) => {
    (async () => {
        try {
            const db = getDB();

            const pacienteId = req.query && req.query.paciente_id ? Number(req.query.paciente_id) : null;
            const profissionalId = req.query && req.query.profissional_id ? Number(req.query.profissional_id) : null;
            const periodo = req.query && req.query.periodo ? String(req.query.periodo) : '';

            const where = [];
            const params = [];
            if (pacienteId) {
                where.push('p.paciente_id = ?');
                params.push(pacienteId);
            }
            if (profissionalId) {
                where.push('p.profissional_id = ?');
                params.push(profissionalId);
            }
            if (periodo && /^[0-9]{1,4}$/.test(periodo)) {
                where.push('p.data_atendimento >= DATE_SUB(CURDATE(), INTERVAL ? DAY)');
                params.push(Number(periodo));
            }

            const sqlWhere = where.length ? `WHERE ${where.join(' AND ')}` : '';
            const [prontuarios] = await db.execute(
                `SELECT p.*, 
                        pac.nome AS paciente_nome, pac.cpf AS paciente_cpf,
                        prof.nome AS profissional_nome
                   FROM prontuarios p
                   LEFT JOIN pacientes pac ON pac.id = p.paciente_id
                   LEFT JOIN profissionais prof ON prof.id = p.profissional_id
                   ${sqlWhere}
                   ORDER BY p.data_atendimento DESC, p.id DESC
                   LIMIT 500`,
                params
            );

            const usuarioTipo = req.session && req.session.usuario ? req.session.usuario.tipo : null;
            const prontuariosSafe = Array.isArray(prontuarios)
                ? prontuarios.map(p => {
                    const safe = sanitizeProntuarioForRole(p, usuarioTipo);
                    if (safe && typeof safe === 'object') {
                        safe.data_atendimento = normalizeDateOnly(safe.data_atendimento);
                    }
                    return safe;
                })
                : prontuarios;

            const [pacientes] = await db.execute(
                'SELECT id, nome, cpf FROM pacientes WHERE ativo = 1 ORDER BY nome ASC LIMIT 500'
            );
            const [profissionais] = await db.execute(
                'SELECT id, nome FROM profissionais WHERE ativo = 1 ORDER BY nome ASC LIMIT 200'
            );

            return res.render('prontuarios/index', {
                title: 'Prontuários',
                currentPage: 'prontuarios',
                usuario: req.session.usuario,
                prontuarios: prontuariosSafe,
                pacientes,
                profissionais,
                filtros: {
                    paciente_id: pacienteId ? String(pacienteId) : '',
                    profissional_id: profissionalId ? String(profissionalId) : '',
                    periodo: periodo || ''
                }
            });
        } catch (error) {
            console.error('Erro ao carregar prontuários:', error);
            return res.render('prontuarios/index', {
                title: 'Prontuários',
                currentPage: 'prontuarios',
                usuario: req.session.usuario,
                prontuarios: [],
                pacientes: [],
                profissionais: [],
                filtros: { paciente_id: '', profissional_id: '', periodo: '' },
                error: 'Erro ao carregar prontuários'
            });
        }
    })();
});

app.get('/prontuarios/paciente/:id', requireAuth, requireRoles(['admin', 'medico']), (req, res) => {
    const pid = Number(req.params.id);
    if (!pid) return res.redirect('/pacientes?error=ID%20inv%C3%A1lido');
    return res.redirect(`/prontuarios?paciente_id=${pid}`);
});

app.get('/api/prontuarios/:id', requireAuth, requireRoles(['admin', 'medico']), async (req, res) => {
    try {
        const id = Number(req.params.id);
        if (!id) return res.status(400).json({ success: false, message: 'ID inválido' });

        const db = getDB();
        const [rows] = await db.execute(
            `SELECT p.*, 
                    pac.nome AS paciente_nome, pac.cpf AS paciente_cpf,
                    prof.nome AS profissional_nome
               FROM prontuarios p
               LEFT JOIN pacientes pac ON pac.id = p.paciente_id
               LEFT JOIN profissionais prof ON prof.id = p.profissional_id
              WHERE p.id = ?
              LIMIT 1`,
            [id]
        );
        if (!rows.length) return res.status(404).json({ success: false, message: 'Prontuário não encontrado' });

        const usuarioTipo = req.session && req.session.usuario ? req.session.usuario.tipo : null;
        const prontuarioSafe = sanitizeProntuarioForRole(rows[0], usuarioTipo);
        if (prontuarioSafe && typeof prontuarioSafe === 'object') {
            prontuarioSafe.data_atendimento = normalizeDateOnly(prontuarioSafe.data_atendimento);
        }

        const [evolucoes] = await db.execute(
            'SELECT * FROM prontuario_evolucoes WHERE prontuario_id = ? ORDER BY data_evolucao DESC, id DESC LIMIT 200',
            [id]
        );

        return res.json({ success: true, prontuario: prontuarioSafe, evolucoes });
    } catch (error) {
        console.error('Erro ao carregar prontuário:', error);
        return res.status(500).json({ success: false, message: 'Erro ao carregar prontuário' });
    }
});

app.post('/prontuarios', requireAuth, requireRoles(['admin', 'medico']), async (req, res) => {
    try {
        const {
            id,
            paciente_id,
            profissional_id,
            data_atendimento,
            tipo_atendimento,
            queixa_principal,
            historia_doenca,
            historia_patologica,
            historia_fisiologica,
            exame_fisico,
            diagnostico,
            plano_tratamento,
            prognostico,
            observacoes,
            status
        } = req.body || {};

        const pid = Number(paciente_id);
        const profId = Number(profissional_id);
        const recordId = id ? Number(id) : null;

        if (!pid || !profId || !data_atendimento || !tipo_atendimento || !queixa_principal || !historia_doenca || !diagnostico || !plano_tratamento) {
            return res.redirect('/prontuarios?error=Preencha%20os%20campos%20obrigat%C3%B3rios');
        }

        const db = getDB();

        if (!recordId) {
            await db.execute(
                `INSERT INTO prontuarios (
                    paciente_id, profissional_id, data_atendimento, tipo_atendimento, queixa_principal,
                    historia_doenca, historia_patologica, historia_fisiologica, exame_fisico,
                    diagnostico, plano_tratamento, prognostico, observacoes, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    pid,
                    profId,
                    data_atendimento,
                    String(tipo_atendimento),
                    String(queixa_principal),
                    String(historia_doenca),
                    historia_patologica ? String(historia_patologica) : null,
                    historia_fisiologica ? String(historia_fisiologica) : null,
                    exame_fisico ? String(exame_fisico) : null,
                    String(diagnostico),
                    String(plano_tratamento),
                    prognostico ? String(prognostico) : null,
                    observacoes ? String(observacoes) : null,
                    status ? String(status) : 'em_andamento'
                ]
            );
            return res.redirect('/prontuarios?success=Prontu%C3%A1rio%20salvo%20com%20sucesso');
        }

        await db.execute(
            `UPDATE prontuarios SET
                paciente_id = ?,
                profissional_id = ?,
                data_atendimento = ?,
                tipo_atendimento = ?,
                queixa_principal = ?,
                historia_doenca = ?,
                historia_patologica = ?,
                historia_fisiologica = ?,
                exame_fisico = ?,
                diagnostico = ?,
                plano_tratamento = ?,
                prognostico = ?,
                observacoes = ?,
                status = ?
             WHERE id = ?
             LIMIT 1`,
            [
                pid,
                profId,
                data_atendimento,
                String(tipo_atendimento),
                String(queixa_principal),
                String(historia_doenca),
                historia_patologica ? String(historia_patologica) : null,
                historia_fisiologica ? String(historia_fisiologica) : null,
                exame_fisico ? String(exame_fisico) : null,
                String(diagnostico),
                String(plano_tratamento),
                prognostico ? String(prognostico) : null,
                observacoes ? String(observacoes) : null,
                status ? String(status) : 'em_andamento',
                recordId
            ]
        );

        return res.redirect('/prontuarios?success=Prontu%C3%A1rio%20atualizado%20com%20sucesso');
    } catch (error) {
        console.error('Erro ao salvar prontuário:', error);
        return res.redirect('/prontuarios?error=Erro%20ao%20salvar%20prontu%C3%A1rio');
    }
});

app.post('/prontuarios/:id/evolucoes', requireAuth, requireRoles(['admin', 'medico']), async (req, res) => {
    try {
        const prontuarioId = Number(req.params.id);
        const { texto } = req.body || {};
        if (!prontuarioId) return res.status(400).json({ success: false, message: 'ID inválido' });
        if (!texto || String(texto).trim().length < 2) return res.status(400).json({ success: false, message: 'Texto inválido' });

        const db = getDB();
        await db.execute(
            'INSERT INTO prontuario_evolucoes (prontuario_id, texto, data_evolucao) VALUES (?, ?, NOW())',
            [prontuarioId, String(texto).trim()]
        );
        return res.json({ success: true });
    } catch (error) {
        console.error('Erro ao adicionar evolução:', error);
        return res.status(500).json({ success: false, message: 'Erro ao adicionar evolução' });
    }
});

app.get('/prontuarios/:id/imprimir', requireAuth, requireRoles(['admin', 'medico']), async (req, res) => {
    try {
        const id = Number(req.params.id);
        if (!id) return res.redirect('/prontuarios?error=ID%20inv%C3%A1lido');

        const db = getDB();
        const [rows] = await db.execute(
            `SELECT p.*, 
                    pac.nome AS paciente_nome, pac.cpf AS paciente_cpf,
                    prof.nome AS profissional_nome
               FROM prontuarios p
               LEFT JOIN pacientes pac ON pac.id = p.paciente_id
               LEFT JOIN profissionais prof ON prof.id = p.profissional_id
              WHERE p.id = ?
              LIMIT 1`,
            [id]
        );
        if (!rows.length) return res.redirect('/prontuarios?error=Prontu%C3%A1rio%20n%C3%A3o%20encontrado');

        const [evolucoes] = await db.execute(
            'SELECT * FROM prontuario_evolucoes WHERE prontuario_id = ? ORDER BY data_evolucao DESC, id DESC LIMIT 200',
            [id]
        );

        const p = rows[0];
        const safeAppConfig = res.locals && res.locals.appConfig ? res.locals.appConfig : {};

        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.send(`<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Prontuário - ${String(p.paciente_nome || 'Paciente')}</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" />
  <style>body{padding:24px;} @media print {.no-print{display:none!important;}}</style>
</head>
<body>
  <div class="d-flex justify-content-between align-items-start mb-3">
    <div>
      <h4 class="mb-1">${safeAppConfig.CLINICA_NOME ? String(safeAppConfig.CLINICA_NOME) : 'Clínica'}</h4>
      <div class="text-muted">Prontuário</div>
    </div>
    <button class="btn btn-primary no-print" onclick="window.print()">Imprimir</button>
  </div>

  <div class="card mb-3">
    <div class="card-body">
      <div class="row g-2">
        <div class="col-md-6"><strong>Paciente:</strong> ${String(p.paciente_nome || '')}</div>
        <div class="col-md-6"><strong>Profissional:</strong> ${String(p.profissional_nome || '')}</div>
        <div class="col-md-6"><strong>Data:</strong> ${moment(p.data_atendimento).format('DD/MM/YYYY')}</div>
        <div class="col-md-6"><strong>Tipo:</strong> ${String(p.tipo_atendimento || '')}</div>
      </div>
    </div>
  </div>

  <div class="mb-3"><h6>Queixa Principal</h6><div>${String(p.queixa_principal || '').replace(/\n/g,'<br/>')}</div></div>
  <div class="mb-3"><h6>História da Doença Atual</h6><div>${String(p.historia_doenca || '').replace(/\n/g,'<br/>')}</div></div>
  <div class="mb-3"><h6>Diagnóstico</h6><div>${String(p.diagnostico || '').replace(/\n/g,'<br/>')}</div></div>
  <div class="mb-3"><h6>Plano de Tratamento</h6><div>${String(p.plano_tratamento || '').replace(/\n/g,'<br/>')}</div></div>

  ${p.exame_fisico ? `<div class="mb-3"><h6>Exame Físico</h6><div>${String(p.exame_fisico).replace(/\n/g,'<br/>')}</div></div>` : ''}
  ${p.historia_patologica ? `<div class="mb-3"><h6>História Patológica Pregressa</h6><div>${String(p.historia_patologica).replace(/\n/g,'<br/>')}</div></div>` : ''}
  ${p.historia_fisiologica ? `<div class="mb-3"><h6>História Fisiológica</h6><div>${String(p.historia_fisiologica).replace(/\n/g,'<br/>')}</div></div>` : ''}
  ${p.prognostico ? `<div class="mb-3"><h6>Prognóstico</h6><div>${String(p.prognostico).replace(/\n/g,'<br/>')}</div></div>` : ''}
  ${p.observacoes ? `<div class="mb-3"><h6>Observações</h6><div>${String(p.observacoes).replace(/\n/g,'<br/>')}</div></div>` : ''}

  <hr />
  <h6>Evoluções</h6>
  ${evolucoes.length ? evolucoes.map(ev => `<div class="mb-2"><div class="text-muted small">${moment(ev.data_evolucao).format('DD/MM/YYYY HH:mm')}</div><div>${String(ev.texto || '').replace(/\n/g,'<br/>')}</div></div>`).join('') : '<div class="text-muted">Sem evoluções registradas.</div>'}

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>`);
    } catch (error) {
        console.error('Erro ao imprimir prontuário:', error);
        return res.redirect('/prontuarios?error=Erro%20ao%20gerar%20impress%C3%A3o');
    }
});

app.get('/configuracoes', requireAuth, requireAdmin, (req, res) => {
    res.render('configuracoes/index', {
        title: 'Configurações',
        currentPage: 'configuracoes',
        usuario: req.session.usuario,
        success: req.query && req.query.success ? String(req.query.success) : null,
        error: req.query && req.query.error ? String(req.query.error) : null
    });
});

app.post('/configuracoes/logo', requireAuth, requireAdmin, upload.single('logo'), async (req, res) => {
    try {
        if (!req.file) {
            return res.redirect('/configuracoes?error=Arquivo%20inv%C3%A1lido');
        }

        const fileUrl = '/uploads/' + req.file.filename;
        const db = getDB();
        await db.execute(
            'INSERT INTO app_config (chave, valor) VALUES (?, ?) ON DUPLICATE KEY UPDATE valor = VALUES(valor)',
            ['CLINICA_LOGO_URL', fileUrl]
        );
        appConfigCacheAtMs = 0;
        return res.redirect('/configuracoes?success=Logo%20atualizada%20com%20sucesso');
    } catch (error) {
        console.error('Erro ao salvar logo da clínica:', error);
        return res.redirect('/configuracoes?error=Erro%20ao%20salvar%20logo');
    }
});

app.get('/api/configuracoes', requireAuth, requireAdmin, async (req, res) => {
    try {
        const db = getDB();
        const [rows] = await db.execute('SELECT chave, valor FROM app_config');
        const config = {};
        for (const r of rows) {
            if (!r || !r.chave) continue;
            config[String(r.chave)] = r.valor;
        }
        return res.json({ success: true, config });
    } catch (error) {
        console.error('Erro ao carregar configurações:', error);
        return res.status(500).json({ success: false, message: 'Erro ao carregar configurações' });
    }
});

app.post('/api/configuracoes', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { config } = req.body || {};
        if (!config || typeof config !== 'object') {
            return res.status(400).json({ success: false, message: 'Payload inválido' });
        }

        const db = getDB();
        const entries = Object.entries(config)
            .map(([k, v]) => [String(k), v == null ? null : String(v)])
            .filter(([k]) => k && k.length <= 191);

        for (const [chave, valor] of entries) {
            await db.execute(
                'INSERT INTO app_config (chave, valor) VALUES (?, ?) ON DUPLICATE KEY UPDATE valor = VALUES(valor)',
                [chave, valor]
            );
        }

        appConfigCacheAtMs = 0;

        // Recarregar agendamento de backup automático caso as configs tenham mudado
        try {
            await scheduleAutoBackup();
        } catch {}

        return res.json({ success: true });
    } catch (error) {
        console.error('Erro ao salvar configurações:', error);
        return res.status(500).json({ success: false, message: 'Erro ao salvar configurações' });
    }
});

app.get('/api/logs', requireAuth, requireAdmin, async (req, res) => {
    try {
        const limit = Math.min(500, Math.max(10, Number(req.query && req.query.limit ? req.query.limit : 200)));
        const sinceTs = Number(req.query && req.query.since ? req.query.since : 0);
        const items = systemLogBuffer
            .filter(l => !sinceTs || Number(l.ts) > sinceTs)
            .slice(-limit);
        return res.json({ success: true, logs: items, now: Date.now() });
    } catch (e) {
        return res.status(500).json({ success: false, message: 'Erro ao carregar logs' });
    }
});

function sqlEscape(value) {
    if (value === null || typeof value === 'undefined') return 'NULL';
    if (value instanceof Date) return `'${moment(value).format('YYYY-MM-DD HH:mm:ss')}'`;
    if (typeof value === 'number') return Number.isFinite(value) ? String(value) : 'NULL';
    if (typeof value === 'boolean') return value ? '1' : '0';
    const s = String(value);
    return `'${s.replace(/\\/g, '\\\\').replace(/'/g, "''").replace(/\u0000/g, '')}'`;
}

async function generateDatabaseDumpSql(db, databaseName) {
    const lines = [];
    lines.push('SET NAMES utf8mb4;');
    lines.push('SET FOREIGN_KEY_CHECKS=0;');

    const [tables] = await db.execute(
        'SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? ORDER BY TABLE_NAME',
        [databaseName]
    );

    for (const t of tables) {
        const table = t.TABLE_NAME;
        const [createRows] = await db.execute(`SHOW CREATE TABLE \`${table}\``);
        const createSql = createRows && createRows[0] ? createRows[0]['Create Table'] : null;
        if (createSql) {
            lines.push(`\n-- Table: ${table}`);
            lines.push(`DROP TABLE IF EXISTS \`${table}\`;`);
            lines.push(createSql + ';');
        }

        const [rows] = await db.execute(`SELECT * FROM \`${table}\``);
        if (rows && rows.length) {
            const cols = Object.keys(rows[0]);
            for (const r of rows) {
                const values = cols.map(c => sqlEscape(r[c]));
                lines.push(
                    `INSERT INTO \`${table}\` (${cols.map(c => `\`${c}\``).join(', ')}) VALUES (${values.join(', ')});`
                );
            }
        }
    }

    lines.push('SET FOREIGN_KEY_CHECKS=1;');
    return lines.join('\n');
}

async function upsertAppConfig(db, key, value) {
    await db.execute(
        'INSERT INTO app_config (chave, valor) VALUES (?, ?) ON DUPLICATE KEY UPDATE valor = VALUES(valor)',
        [String(key), value == null ? null : String(value)]
    );
}

function formatBytes(bytes) {
    const b = Number(bytes) || 0;
    if (b <= 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.min(units.length - 1, Math.floor(Math.log(b) / Math.log(1024)));
    const val = b / Math.pow(1024, i);
    return `${val.toFixed(val >= 10 || i === 0 ? 0 : 1)} ${units[i]}`;
}

function copyDirRecursive(srcDir, destDir) {
    if (!fs.existsSync(srcDir)) return;
    if (!fs.existsSync(destDir)) fs.mkdirSync(destDir, { recursive: true });

    const entries = fs.readdirSync(srcDir, { withFileTypes: true });
    for (const entry of entries) {
        const srcPath = path.join(srcDir, entry.name);
        const destPath = path.join(destDir, entry.name);
        if (entry.isDirectory()) {
            copyDirRecursive(srcPath, destPath);
        } else if (entry.isFile()) {
            fs.copyFileSync(srcPath, destPath);
        }
    }
}

let autoBackupTask = null;

async function runAutoBackup(trigger) {
    const db = getDB();
    const dbNameFinal = dbName || 'gestao_fisio';
    const sql = await generateDatabaseDumpSql(db, dbName);

    const dir = path.join(__dirname, 'generated_backups');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

    const backupFolderName = `backup-${dbName}-${moment().format('YYYY-MM-DD_HH-mm-ss')}`;
    const backupFolderPath = path.join(dir, backupFolderName);
    if (!fs.existsSync(backupFolderPath)) fs.mkdirSync(backupFolderPath, { recursive: true });

    const filename = `${backupFolderName}.sql`;
    const filePath = path.join(backupFolderPath, filename);
    fs.writeFileSync(filePath, sql, 'utf8');

    const uploadsDir = path.join(__dirname, 'uploads');
    const uploadsDest = path.join(backupFolderPath, 'uploads');
    try {
        copyDirRecursive(uploadsDir, uploadsDest);
    } catch (e) {
        console.error('Erro ao copiar uploads para o backup:', e);
    }

    const stat = fs.statSync(filePath);
    await upsertAppConfig(db, 'BACKUP_LAST_AT', moment().format('DD/MM/YYYY HH:mm:ss'));
    await upsertAppConfig(db, 'BACKUP_LAST_SIZE', formatBytes(stat.size));
    await upsertAppConfig(db, 'BACKUP_LAST_FILE', `/generated_backups/${backupFolderName}/${filename}`);
    await upsertAppConfig(db, 'BACKUP_LAST_UPLOADS_DIR', `/generated_backups/${backupFolderName}/uploads`);
    await upsertAppConfig(db, 'BACKUP_LAST_TRIGGER', trigger || 'auto');
    appConfigCacheAtMs = 0;
    return { filename, bytes: stat.size };
}

async function scheduleAutoBackup() {
    try {
        const db = getDB();
        const enabled = await getAppConfigValue(db, 'BACKUP_AUTO');
        const freq = (await getAppConfigValue(db, 'BACKUP_FREQUENCIA')) || 'daily';
        const time = (await getAppConfigValue(db, 'BACKUP_HORARIO')) || '02:00';

        if (autoBackupTask) {
            try { autoBackupTask.stop(); } catch {}
            autoBackupTask = null;
        }

        const isEnabled = String(enabled) === '1' || String(enabled).toLowerCase() === 'true';
        if (!isEnabled) return;

        const [hh, mm] = String(time).split(':');
        const hour = Math.min(23, Math.max(0, Number(hh) || 2));
        const minute = Math.min(59, Math.max(0, Number(mm) || 0));

        let cronExpr = `${minute} ${hour} * * *`;
        if (freq === 'weekly') cronExpr = `${minute} ${hour} * * 0`;
        if (freq === 'monthly') cronExpr = `${minute} ${hour} 1 * *`;

        autoBackupTask = cron.schedule(cronExpr, async () => {
            try {
                await runAutoBackup('auto');
            } catch (e) {
                console.error('Erro no backup automático:', e);
            }
        });
    } catch (e) {
        console.error('Erro ao agendar backup automático:', e);
    }
}

app.get('/configuracoes/backup/download', requireAuth, requireAdmin, async (req, res) => {
    try {
        const db = getDB();
        const dbNameFinal = dbName || 'gestao_fisio';
        const sql = await generateDatabaseDumpSql(db, dbName);

        const format = String((req.query && req.query.format) || '').toLowerCase();
        if (format !== 'zip') {
            const filename = `backup-${dbName}-${moment().format('YYYY-MM-DD_HH-mm-ss')}.sql`;
            res.setHeader('Content-Type', 'application/sql; charset=utf-8');
            res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
            return res.send(sql);
        }

        const base = `backup-${dbName}-${moment().format('YYYY-MM-DD_HH-mm-ss')}`;
        const zipName = `${base}.zip`;
        res.setHeader('Content-Type', 'application/zip');
        res.setHeader('Content-Disposition', `attachment; filename="${zipName}"`);

        const archive = archiver('zip', { zlib: { level: 9 } });
        archive.on('error', (err) => {
            throw err;
        });
        archive.pipe(res);
        archive.append(sql, { name: `${base}.sql` });

        const uploadsDir = path.join(__dirname, 'uploads');
        if (fs.existsSync(uploadsDir)) {
            archive.directory(uploadsDir, 'uploads');
        }
        await archive.finalize();
    } catch (error) {
        console.error('Erro ao gerar backup:', error);
        return res.redirect('/configuracoes?error=Erro%20ao%20gerar%20backup');
    }
});

function splitSqlStatements(sqlText) {
    const statements = [];
    let current = '';
    let inString = false;
    let stringChar = '';
    for (let i = 0; i < sqlText.length; i++) {
        const ch = sqlText[i];
        const next = sqlText[i + 1];
        if (!inString && ch === '-' && next === '-') {
            while (i < sqlText.length && sqlText[i] !== '\n') i++;
            continue;
        }
        if (!inString && ch === '#') {
            while (i < sqlText.length && sqlText[i] !== '\n') i++;
            continue;
        }
        if (!inString && (ch === '"' || ch === "'")) {
            inString = true;
            stringChar = ch;
            current += ch;
            continue;
        }
        if (inString) {
            current += ch;
            if (ch === stringChar) {
                const prev = sqlText[i - 1];
                if (prev !== '\\') {
                    inString = false;
                    stringChar = '';
                }
            }
            continue;
        }
        if (ch === ';') {
            const stmt = current.trim();
            if (stmt) statements.push(stmt);
            current = '';
            continue;
        }
        current += ch;
    }
    const tail = current.trim();
    if (tail) statements.push(tail);
    return statements;
}

app.post('/configuracoes/backup/restore', requireAuth, requireAdmin, upload.single('backupFile'), async (req, res) => {
    try {
        const enabled = String(process.env.ENABLE_DB_RESTORE || '').toLowerCase();
        if (enabled !== '1' && enabled !== 'true') {
            return res.redirect('/configuracoes?error=Restaura%C3%A7%C3%A3o%20desabilitada%20por%20seguran%C3%A7a.%20Defina%20ENABLE_DB_RESTORE=1%20no%20.env%20para%20habilitar.');
        }
        if (!req.file) {
            return res.redirect('/configuracoes?error=Arquivo%20inv%C3%A1lido');
        }

        const originalName = String(req.file.originalname || '').toLowerCase();
        const isZip = originalName.endsWith('.zip');

        let sql = '';
        let extractedDir = null;

        if (!isZip) {
            sql = fs.readFileSync(req.file.path, 'utf8');
            if (!sql || sql.length < 10) {
                return res.redirect('/configuracoes?error=Arquivo%20de%20backup%20vazio');
            }
        } else {
            const tmpRoot = path.join(__dirname, 'generated_backups', 'tmp_restore');
            if (!fs.existsSync(tmpRoot)) fs.mkdirSync(tmpRoot, { recursive: true });
            extractedDir = path.join(tmpRoot, `restore-${moment().format('YYYY-MM-DD_HH-mm-ss')}`);
            if (!fs.existsSync(extractedDir)) fs.mkdirSync(extractedDir, { recursive: true });

            await extractZipToDir(req.file.path, extractedDir);

            const sqlPath = findFirstFileRecursive(extractedDir, (p) => p.toLowerCase().endsWith('.sql'));
            if (!sqlPath) {
                removeDirRecursive(extractedDir);
                return res.redirect('/configuracoes?error=ZIP%20inv%C3%A1lido:%20n%C3%A3o%20encontrei%20arquivo%20.sql');
            }
            sql = fs.readFileSync(sqlPath, 'utf8');
            if (!sql || sql.length < 10) {
                removeDirRecursive(extractedDir);
                return res.redirect('/configuracoes?error=Arquivo%20.sql%20do%20ZIP%20est%C3%A1%20vazio');
            }
        }

        const pool = getDB();
        const conn = await pool.getConnection();
        try {
            await conn.query('SET FOREIGN_KEY_CHECKS=0');
            const statements = splitSqlStatements(sql);
            for (const stmt of statements) {
                await conn.query(stmt);
            }
            await conn.query('SET FOREIGN_KEY_CHECKS=1');
        } finally {
            try { conn.release(); } catch {}
        }

        if (isZip && extractedDir) {
            const extractedUploadsDir = path.join(extractedDir, 'uploads');
            try {
                restoreUploadsFromExtract(extractedUploadsDir);
            } finally {
                removeDirRecursive(extractedDir);
            }
        }

        return res.redirect('/configuracoes?success=Backup%20restaurado%20com%20sucesso');
    } catch (error) {
        console.error('Erro ao restaurar backup:', error);
        return res.redirect('/configuracoes?error=Erro%20ao%20restaurar%20backup');
    }
});

app.get('/financeiro', requireAuth, (req, res) => {
    (async () => {
        try {
            if (!canAccessFinanceiro(req)) {
                return res.redirect('/dashboard?error=access_denied');
            }
            const db = getDB();

            const usuarioTipo = req.session && req.session.usuario ? req.session.usuario.tipo : null;
            const isSec = usuarioTipo === 'secretaria';
            const canLancar = canLancarFinanceiro(req);

            const [pacientes] = await db.execute(
                'SELECT id, nome, cpf FROM pacientes WHERE ativo = TRUE ORDER BY nome ASC LIMIT 500'
            );

            if (isSec) {
                return res.render('financeiro/index', {
                    title: 'Financeiro',
                    currentPage: 'financeiro',
                    usuario: req.session.usuario,
                    canLancar,
                    resumo: null,
                    lancamentos: [],
                    pacientes
                });
            }

            const [receitasMes] = await db.execute(`
                SELECT COALESCE(SUM(valor), 0) as total
                FROM financeiro
                WHERE tipo = 'receita'
                  AND MONTH(data_cadastro) = MONTH(CURDATE())
                  AND YEAR(data_cadastro) = YEAR(CURDATE())
            `);

            const [despesasMes] = await db.execute(`
                SELECT COALESCE(SUM(valor), 0) as total
                FROM financeiro
                WHERE tipo = 'despesa'
                  AND MONTH(data_cadastro) = MONTH(CURDATE())
                  AND YEAR(data_cadastro) = YEAR(CURDATE())
            `);

            const [saldoAcumulado] = await db.execute(`
                SELECT
                    COALESCE(SUM(CASE WHEN tipo = 'receita' THEN valor ELSE 0 END), 0)
                    - COALESCE(SUM(CASE WHEN tipo = 'despesa' THEN valor ELSE 0 END), 0) as total
                FROM financeiro
            `);

            const [lancamentos] = await db.execute(`
                SELECT id, tipo, descricao, paciente_id, paciente_nome, agendamento_id, valor, status, data_cadastro, forma_pagamento, categoria
                FROM financeiro
                ORDER BY data_cadastro DESC, id DESC
                LIMIT 200
            `);

            const receitas = Number(receitasMes?.[0]?.total || 0);
            const despesas = Number(despesasMes?.[0]?.total || 0);

            res.render('financeiro/index', {
                title: 'Financeiro',
                currentPage: 'financeiro',
                usuario: req.session.usuario,
                canLancar,
                resumo: {
                    receitasMes: receitas,
                    despesasMes: despesas,
                    saldoMes: receitas - despesas,
                    saldoAcumulado: Number(saldoAcumulado?.[0]?.total || 0)
                },
                lancamentos,
                pacientes
            });
        } catch (error) {
            console.error('Erro ao carregar financeiro:', error);
            res.render('financeiro/index', {
                title: 'Financeiro',
                currentPage: 'financeiro',
                usuario: req.session.usuario,
                canLancar: false,
                resumo: { receitasMes: 0, despesasMes: 0, saldoMes: 0, saldoAcumulado: 0 },
                lancamentos: [],
                pacientes: [],
                error: 'Erro ao carregar financeiro'
            });
        }
    })();
});

app.post('/financeiro/lancamentos', requireAuth, async (req, res) => {
    try {
        if (!canLancarFinanceiro(req)) {
            return res.redirect('/dashboard?error=access_denied');
        }
        const db = getDB();

        const tipo = (req.body?.tipo || '').toString().trim().toLowerCase();
        const descricao = (req.body?.descricao || '').toString().trim();
        const valorRaw = Number(req.body?.valor);
        const status = (req.body?.status || 'pendente').toString().trim().toLowerCase();
        const categoria = (req.body?.categoria || '').toString().trim() || null;
        const formaPagamento = (req.body?.forma_pagamento || '').toString().trim() || null;
        const pacienteId = req.body?.paciente_id ? Number(req.body.paciente_id) : null;
        const dataCadastro = (req.body?.data_cadastro || '').toString().trim();

        if (tipo !== 'receita' && tipo !== 'despesa') {
            return res.redirect('/financeiro?error=Tipo%20inv%C3%A1lido');
        }
        if (!descricao || descricao.length < 2) {
            return res.redirect('/financeiro?error=Descri%C3%A7%C3%A3o%20inv%C3%A1lida');
        }
        if (!Number.isFinite(valorRaw) || valorRaw <= 0) {
            return res.redirect('/financeiro?error=Valor%20inv%C3%A1lido');
        }
        const dt = dataCadastro ? new Date(dataCadastro) : new Date();
        if (isNaN(dt.getTime())) {
            return res.redirect('/financeiro?error=Data%20inv%C3%A1lida');
        }
        const statusDb = status === 'pago' ? 'pago' : 'pendente';

        let pacienteNome = null;
        if (pacienteId) {
            const [pacs] = await db.execute('SELECT nome FROM pacientes WHERE id = ? LIMIT 1', [pacienteId]);
            pacienteNome = pacs && pacs[0] ? String(pacs[0].nome || '') : null;
        }

        await db.execute(
            `INSERT INTO financeiro
                (tipo, descricao, paciente_id, paciente_nome, agendamento_id, valor, status, data_cadastro, forma_pagamento, categoria)
             VALUES
                (?, ?, ?, ?, NULL, ?, ?, ?, ?, ?)`,
            [tipo, descricao, pacienteId, pacienteNome, valorRaw, statusDb, dt, formaPagamento, categoria]
        );

        return res.redirect('/financeiro?success=Lancamento%20criado');
    } catch (error) {
        console.error('Erro ao criar lançamento financeiro:', error);
        return res.redirect('/financeiro?error=Erro%20ao%20criar%20lan%C3%A7amento');
    }
});

async function syncFinanceiroFromAgendamento(db, agendamento) {
    try {
        if (!agendamento) return;
        const statusPagamento = String(agendamento.status_pagamento || '').trim().toLowerCase();
        const valor = agendamento.valor != null ? Number(agendamento.valor) : NaN;
        if (statusPagamento !== 'pago') return;
        if (!Number.isFinite(valor) || valor <= 0) return;

        const agendamentoId = Number(agendamento.id);
        if (!agendamentoId) return;

        const pacienteId = agendamento.paciente_id ? Number(agendamento.paciente_id) : null;
        const pacienteNome = agendamento.paciente_nome ? String(agendamento.paciente_nome) : null;
        const formaPagamento = agendamento.forma_pagamento ? String(agendamento.forma_pagamento) : null;

        const data = agendamento.data_hora ? new Date(agendamento.data_hora) : new Date();
        const dataCadastro = isNaN(data.getTime()) ? new Date() : data;

        const descricao = `Consulta - ${agendamento.tipo_consulta || 'Atendimento'}`;

        await db.execute(
            `INSERT INTO financeiro
                (tipo, descricao, paciente_id, paciente_nome, agendamento_id, valor, status, data_cadastro, forma_pagamento, categoria)
             VALUES
                ('receita', ?, ?, ?, ?, ?, 'pago', ?, ?, 'consulta')
             ON DUPLICATE KEY UPDATE
                tipo = VALUES(tipo),
                descricao = VALUES(descricao),
                paciente_id = VALUES(paciente_id),
                paciente_nome = VALUES(paciente_nome),
                valor = VALUES(valor),
                status = VALUES(status),
                data_cadastro = VALUES(data_cadastro),
                forma_pagamento = VALUES(forma_pagamento),
                categoria = VALUES(categoria)`,
            [descricao, pacienteId, pacienteNome, agendamentoId, valor, dataCadastro, formaPagamento]
        );
    } catch (e) {
        console.error('Erro ao sincronizar financeiro do agendamento:', e);
    }
}

app.get('/profissionais', requireAuth, requireRoles(['admin', 'medico']), (req, res) => {
    (async () => {
        try {
            const db = getDB();
            const q = (req.query && req.query.q ? String(req.query.q) : '').trim();

            const where = [];
            const params = [];
            if (q) {
                where.push('(nome LIKE ? OR cpf LIKE ? OR email LIKE ? OR telefone LIKE ? OR registro_profissional LIKE ? OR especialidade LIKE ?)');
                const like = `%${q}%`;
                params.push(like, like, like, like, like, like);
            }

            const sqlWhere = where.length ? `WHERE ${where.join(' AND ')}` : '';
            const [profissionais] = await db.execute(
                `SELECT id, nome, cpf, especialidade, registro_profissional, telefone, email, data_contratacao, salario, ativo
                   FROM profissionais
                   ${sqlWhere}
                   ORDER BY ativo DESC, nome ASC
                   LIMIT 1000`,
                params
            );

            return res.render('profissionais/index', {
                title: 'Profissionais',
                currentPage: 'profissionais',
                usuario: req.session.usuario,
                profissionais: profissionais || [],
                filtros: { q }
            });
        } catch (error) {
            console.error('Erro ao carregar profissionais:', error);
            return res.render('profissionais/index', {
                title: 'Profissionais',
                currentPage: 'profissionais',
                usuario: req.session.usuario,
                profissionais: [],
                filtros: { q: '' },
                error: 'Erro ao carregar profissionais'
            });
        }
    })();
});

app.post('/api/profissionais', requireAuth, requireRoles(['admin', 'medico']), async (req, res) => {
    try {
        const db = getDB();
        const id = req.body && req.body.id ? Number(req.body.id) : null;

        const nome = (req.body?.nome || '').toString().trim();
        const cpf = (req.body?.cpf || '').toString().trim();
        const especialidade = (req.body?.especialidade || '').toString().trim() || null;
        const registroProfissional = (req.body?.registro_profissional || '').toString().trim() || null;
        const telefone = (req.body?.telefone || '').toString().trim() || null;
        const email = (req.body?.email || '').toString().trim() || null;
        const dataContratacao = (req.body?.data_contratacao || '').toString().trim();
        const salarioRaw = req.body && typeof req.body.salario !== 'undefined' && req.body.salario !== '' ? Number(req.body.salario) : null;

        if (!nome || nome.length < 2) {
            return res.status(400).json({ success: false, message: 'Nome inválido' });
        }
        if (!cpf || cpf.length < 5) {
            return res.status(400).json({ success: false, message: 'CPF inválido' });
        }
        let dtContr = null;
        if (dataContratacao) {
            const dt = new Date(dataContratacao);
            if (isNaN(dt.getTime())) {
                return res.status(400).json({ success: false, message: 'Data de contratação inválida' });
            }
            dtContr = dt;
        }
        let salario = null;
        if (salarioRaw != null) {
            if (!Number.isFinite(salarioRaw) || salarioRaw < 0) {
                return res.status(400).json({ success: false, message: 'Salário inválido' });
            }
            salario = salarioRaw;
        }

        if (id) {
            const [existing] = await db.execute('SELECT id FROM profissionais WHERE id = ? LIMIT 1', [id]);
            if (!existing || !existing.length) {
                return res.status(404).json({ success: false, message: 'Profissional não encontrado' });
            }

            await db.execute(
                `UPDATE profissionais
                    SET nome = ?, cpf = ?, especialidade = ?, registro_profissional = ?, telefone = ?, email = ?, data_contratacao = ?, salario = ?
                  WHERE id = ?`,
                [nome, cpf, especialidade, registroProfissional, telefone, email, dtContr, salario, id]
            );
            return res.json({ success: true, id });
        }

        const [result] = await db.execute(
            `INSERT INTO profissionais (nome, cpf, especialidade, registro_profissional, telefone, email, data_contratacao, salario, ativo)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)`,
            [nome, cpf, especialidade, registroProfissional, telefone, email, dtContr, salario]
        );
        return res.json({ success: true, id: result.insertId });
    } catch (error) {
        if (error && error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ success: false, message: 'Já existe um profissional com este CPF' });
        }
        console.error('Erro ao salvar profissional:', error);
        return res.status(500).json({ success: false, message: 'Erro ao salvar profissional' });
    }
});

app.post('/api/profissionais/:id/ativo', requireAuth, requireRoles(['admin', 'medico']), async (req, res) => {
    try {
        const id = Number(req.params.id);
        if (!id) return res.status(400).json({ success: false, message: 'ID inválido' });

        const ativo = req.body && typeof req.body.ativo !== 'undefined' ? Number(req.body.ativo) : NaN;
        if (ativo !== 0 && ativo !== 1) {
            return res.status(400).json({ success: false, message: 'Valor inválido para ativo' });
        }

        const db = getDB();
        const [existing] = await db.execute('SELECT id FROM profissionais WHERE id = ? LIMIT 1', [id]);
        if (!existing || !existing.length) {
            return res.status(404).json({ success: false, message: 'Profissional não encontrado' });
        }

        await db.execute('UPDATE profissionais SET ativo = ? WHERE id = ?', [ativo, id]);
        return res.json({ success: true });
    } catch (error) {
        console.error('Erro ao alterar status do profissional:', error);
        return res.status(500).json({ success: false, message: 'Erro ao alterar status do profissional' });
    }
});

app.get('/convenios', requireAuth, requireRoles(['admin', 'medico']), (req, res) => {
    return res.redirect('/dashboard?error=modulo_desativado');
});

app.get('/permissoes', requireAuth, requireAdmin, (req, res) => {
    res.render('permissoes/index', {
        title: 'Permissões',
        currentPage: 'permissoes',
        usuario: req.session.usuario
    });
});

app.get('/usuarios', requireAuth, requireAdmin, async (req, res) => {
    try {
        const db = getDB();
        await ensureUsuariosTipoColumn(db);
        const [usuarios] = await db.execute(
            'SELECT id, nome, email, tipo, cpf, telefone, ativo FROM usuarios ORDER BY id DESC'
        );
        res.render('usuarios/index', {
            title: 'Usuários',
            currentPage: 'usuarios',
            usuario: req.session.usuario,
            usuarios
        });
    } catch (error) {
        console.error('Erro ao carregar usuários:', error);
        res.render('usuarios/index', {
            title: 'Usuários',
            currentPage: 'usuarios',
            usuario: req.session.usuario,
            usuarios: [],
            error: 'Erro ao carregar usuários'
        });
    }
});

app.get('/colaboradores', requireAuth, requireAdmin, async (req, res) => {
    try {
        const db = getDB();
        await ensureAccessControlTables(db);
        const [colaboradores] = await db.execute(
            `SELECT id, nome, cpf, empresa, cargo, foto_url, status, created_at
             FROM colaboradores
             ORDER BY id DESC`
        );
        res.render('colaboradores/index', {
            title: 'Colaboradores',
            currentPage: 'colaboradores',
            usuario: req.session.usuario,
            colaboradores
        });
    } catch (error) {
        console.error('Erro ao carregar colaboradores:', error);
        res.render('colaboradores/index', {
            title: 'Colaboradores',
            currentPage: 'colaboradores',
            usuario: req.session.usuario,
            colaboradores: [],
            error: 'Erro ao carregar colaboradores'
        });
    }
});

app.get('/colaboradores/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const id = Number(req.params.id);
        if (!id) return res.redirect('/colaboradores');
        const db = getDB();
        await ensureAccessControlTables(db);

        const [rows] = await db.execute(
            `SELECT id, nome, cpf, empresa, cargo, foto_url, status, created_at
             FROM colaboradores WHERE id = ? LIMIT 1`,
            [id]
        );
        if (!rows.length) return res.redirect('/colaboradores');

        const [logs] = await db.execute(
            `SELECT id, status, tipo, motivo, local, ip_address, device_id, created_at
             FROM access_logs WHERE colaborador_id = ?
             ORDER BY created_at DESC, id DESC LIMIT 40`,
            [id]
        );
        const [pontos] = await db.execute(
            `SELECT id, tipo, ip_address, device_id, created_at
             FROM ponto_logs WHERE colaborador_id = ?
             ORDER BY created_at DESC, id DESC LIMIT 40`,
            [id]
        );

        res.render('colaboradores/show', {
            title: 'Colaborador',
            currentPage: 'colaboradores',
            usuario: req.session.usuario,
            colaborador: rows[0],
            logs,
            pontos
        });
    } catch (error) {
        console.error('Erro ao carregar colaborador:', error);
        res.redirect('/colaboradores');
    }
});

app.post('/api/usuarios', requireAuth, requireAdmin, async (req, res) => {
    try {
        const db = getDB();
        await ensureUsuariosTipoColumn(db);

        const adminSenha = (req.body?.adminSenha || '').toString();
        if (!adminSenha) {
            return res.status(400).json({ success: false, message: 'Senha do admin é obrigatória' });
        }

        const adminId = req.session?.usuario?.id;
        const [admins] = await db.execute('SELECT id, senha FROM usuarios WHERE id = ? AND ativo = TRUE LIMIT 1', [adminId]);
        if (admins.length === 0) {
            return res.status(403).json({ success: false, message: 'Admin inválido' });
        }
        const admin = admins[0];
        const adminSenhaValida = await bcrypt.compare(adminSenha, admin.senha);
        if (!adminSenhaValida) {
            return res.status(403).json({ success: false, message: 'Senha do admin inválida' });
        }

        const nome = (req.body?.nome || '').toString().trim();
        const email = (req.body?.email || '').toString().trim().toLowerCase();
        const senha = (req.body?.senha || '').toString();
        const tipoNorm = normalizeUsuarioTipo(req.body?.tipo);
        if (tipoNorm.error) {
            return res.status(400).json({ success: false, message: tipoNorm.error });
        }
        const tipo = tipoNorm.tipo;
        const cpf = req.body?.cpf != null ? (req.body.cpf || '').toString().trim() : null;
        const telNorm = normalizeTelefone(req.body?.telefone);
        if (telNorm && telNorm.error) {
            return res.status(400).json({ success: false, message: telNorm.error });
        }
        const telefone = telNorm && Object.prototype.hasOwnProperty.call(telNorm, 'telefone') ? telNorm.telefone : null;

        if (!nome || !email || !senha) {
            return res.status(400).json({ success: false, message: 'Campos obrigatórios: nome, email, senha' });
        }
        const senhaErr = validateStrongPassword(senha);
        if (senhaErr) {
            return res.status(400).json({ success: false, message: senhaErr });
        }

        const [existing] = await db.execute('SELECT id FROM usuarios WHERE email = ? LIMIT 1', [email]);
        if (existing.length > 0) {
            return res.status(409).json({ success: false, message: 'Já existe um usuário com este e-mail' });
        }

        const senhaHash = await bcrypt.hash(senha, 10);
        const [result] = await db.execute(
            'INSERT INTO usuarios (nome, email, senha, tipo, cpf, telefone, ativo) VALUES (?, ?, ?, ?, ?, ?, TRUE)',
            [nome, email, senhaHash, tipo, cpf, telefone]
        );

        await logLGPD(admin.id, 'INSERT', 'usuarios', result.insertId, null, JSON.stringify({ nome, email, tipo, cpf, telefone }), req);
        return res.json({ success: true, id: result.insertId });
    } catch (error) {
        if (error && error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ success: false, message: 'Já existe um usuário com este e-mail' });
        }
        console.error('Erro ao criar usuário:', error);
        return res.status(500).json({ success: false, message: 'Erro ao criar usuário' });
    }
});

app.post('/api/usuarios/:id/ativo', requireAuth, requireAdmin, async (req, res) => {
    try {
        const id = Number(req.params.id);
        if (!id) return res.status(400).json({ success: false, message: 'ID inválido' });

        const ativo = req.body && typeof req.body.ativo !== 'undefined' ? Number(req.body.ativo) : NaN;
        if (ativo !== 0 && ativo !== 1) {
            return res.status(400).json({ success: false, message: 'Valor inválido para ativo' });
        }

        const adminId = req.session?.usuario?.id;
        if (adminId && Number(adminId) === id && ativo === 0) {
            return res.status(400).json({ success: false, message: 'Você não pode inativar seu próprio usuário logado' });
        }

        const db = getDB();
        const [existing] = await db.execute('SELECT id, ativo FROM usuarios WHERE id = ? LIMIT 1', [id]);
        if (!existing || !existing.length) {
            return res.status(404).json({ success: false, message: 'Usuário não encontrado' });
        }

        await db.execute('UPDATE usuarios SET ativo = ? WHERE id = ? LIMIT 1', [ativo, id]);

        try {
            await logLGPD(adminId, 'UPDATE', 'usuarios', id, JSON.stringify({ ativo: existing[0].ativo }), JSON.stringify({ ativo }), req);
        } catch {}

        return res.json({ success: true });
    } catch (error) {
        console.error('Erro ao atualizar status do usuário:', error);
        return res.status(500).json({ success: false, message: 'Erro ao atualizar status do usuário' });
    }
});

app.post('/api/colaboradores', requireAuth, requireAdmin, upload.single('foto'), async (req, res) => {
    try {
        const db = getDB();
        await ensureAccessControlTables(db);

        const nome = (req.body?.nome || '').toString().trim();
        const cpf = (req.body?.cpf || '').toString().trim();
        const empresa = (req.body?.empresa || '').toString().trim() || null;
        const cargo = (req.body?.cargo || '').toString().trim() || null;
        const status = (req.body?.status || 'ativo').toString().trim().toLowerCase();
        const statusAllowed = new Set(['ativo', 'inativo', 'bloqueado']);
        if (!statusAllowed.has(status)) {
            return res.status(400).json({ success: false, message: 'Status inválido' });
        }
        if (!nome || !cpf) {
            return res.status(400).json({ success: false, message: 'Nome e CPF são obrigatórios' });
        }

        const fotoUrl = req.file ? `/uploads/${req.file.filename}` : null;
        const qrSeed = generateAccessToken(16);
        const qrStaticToken = generateAccessToken(16);

        const [existing] = await db.execute('SELECT id FROM colaboradores WHERE cpf = ? LIMIT 1', [cpf]);
        if (existing.length) {
            return res.status(409).json({ success: false, message: 'Já existe um colaborador com este CPF' });
        }

        const [result] = await db.execute(
            `INSERT INTO colaboradores (nome, cpf, empresa, cargo, foto_url, status, qr_seed, qr_static_token)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)` ,
            [nome, cpf, empresa, cargo, fotoUrl, status, qrSeed, qrStaticToken]
        );

        try {
            await logLGPD(req.session.usuario.id, 'INSERT', 'colaboradores', result.insertId, null,
                JSON.stringify({ nome, cpf, empresa, cargo, foto_url: fotoUrl, status }), req);
        } catch {}

        return res.json({ success: true, id: result.insertId });
    } catch (error) {
        if (error && error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ success: false, message: 'Já existe um colaborador com este CPF' });
        }
        console.error('Erro ao criar colaborador:', error);
        return res.status(500).json({ success: false, message: 'Erro ao criar colaborador' });
    }
});

app.put('/api/colaboradores/:id', requireAuth, requireAdmin, upload.single('foto'), async (req, res) => {
    try {
        const id = Number(req.params.id);
        if (!id) return res.status(400).json({ success: false, message: 'ID inválido' });
        const db = getDB();
        await ensureAccessControlTables(db);

        const nome = (req.body?.nome || '').toString().trim();
        const cpf = (req.body?.cpf || '').toString().trim();
        const empresa = (req.body?.empresa || '').toString().trim() || null;
        const cargo = (req.body?.cargo || '').toString().trim() || null;
        const status = (req.body?.status || 'ativo').toString().trim().toLowerCase();
        const statusAllowed = new Set(['ativo', 'inativo', 'bloqueado']);
        if (!statusAllowed.has(status)) {
            return res.status(400).json({ success: false, message: 'Status inválido' });
        }
        if (!nome || !cpf) {
            return res.status(400).json({ success: false, message: 'Nome e CPF são obrigatórios' });
        }

        const [existing] = await db.execute('SELECT * FROM colaboradores WHERE id = ? LIMIT 1', [id]);
        if (!existing.length) {
            return res.status(404).json({ success: false, message: 'Colaborador não encontrado' });
        }

        const fotoUrl = req.file ? `/uploads/${req.file.filename}` : existing[0].foto_url;

        await db.execute(
            `UPDATE colaboradores
             SET nome = ?, cpf = ?, empresa = ?, cargo = ?, foto_url = ?, status = ?
             WHERE id = ?`,
            [nome, cpf, empresa, cargo, fotoUrl, status, id]
        );

        try {
            await logLGPD(req.session.usuario.id, 'UPDATE', 'colaboradores', id,
                JSON.stringify(existing[0]), JSON.stringify({ nome, cpf, empresa, cargo, foto_url: fotoUrl, status }), req);
        } catch {}

        return res.json({ success: true });
    } catch (error) {
        console.error('Erro ao atualizar colaborador:', error);
        return res.status(500).json({ success: false, message: 'Erro ao atualizar colaborador' });
    }
});

app.post('/api/colaboradores/:id/status', requireAuth, requireAdmin, async (req, res) => {
    try {
        const id = Number(req.params.id);
        if (!id) return res.status(400).json({ success: false, message: 'ID inválido' });
        const status = (req.body?.status || '').toString().trim().toLowerCase();
        const statusAllowed = new Set(['ativo', 'inativo', 'bloqueado']);
        if (!statusAllowed.has(status)) {
            return res.status(400).json({ success: false, message: 'Status inválido' });
        }

        const db = getDB();
        await ensureAccessControlTables(db);
        const [existing] = await db.execute('SELECT status FROM colaboradores WHERE id = ? LIMIT 1', [id]);
        if (!existing.length) return res.status(404).json({ success: false, message: 'Colaborador não encontrado' });

        await db.execute('UPDATE colaboradores SET status = ? WHERE id = ?', [status, id]);
        try {
            await logLGPD(req.session.usuario.id, 'UPDATE', 'colaboradores', id,
                JSON.stringify({ status: existing[0].status }), JSON.stringify({ status }), req);
        } catch {}

        return res.json({ success: true });
    } catch (error) {
        console.error('Erro ao atualizar status do colaborador:', error);
        return res.status(500).json({ success: false, message: 'Erro ao atualizar status' });
    }
});

app.post('/api/colaboradores/:id/qr', requireAuth, requireAdmin, async (req, res) => {
    try {
        const id = Number(req.params.id);
        if (!id) return res.status(400).json({ success: false, message: 'ID inválido' });
        const db = getDB();
        await ensureAccessControlTables(db);

        const [rows] = await db.execute('SELECT id, qr_seed, qr_static_token FROM colaboradores WHERE id = ? LIMIT 1', [id]);
        if (!rows.length) return res.status(404).json({ success: false, message: 'Colaborador não encontrado' });

        const qrMode = (await getAppConfigValue(db, 'ACCESS_QR_MODE') || 'fixed').toString().toLowerCase();
        if (qrMode === 'fixed') {
            let staticToken = rows[0].qr_static_token;
            if (!staticToken) {
                staticToken = generateAccessToken(16);
                await db.execute('UPDATE colaboradores SET qr_static_token = ? WHERE id = ?', [staticToken, id]);
            }
            return res.json({ success: true, token: staticToken, expiresAt: null, mode: 'fixed' });
        }

        const deviceId = (req.body?.deviceId || '').toString().trim().slice(0, 128);
        if (!deviceId) return res.status(400).json({ success: false, message: 'deviceId obrigatório' });

        const whitelistEnabled = String(await getAppConfigValue(db, 'ACCESS_DEVICE_WHITELIST_ENABLED') || '0') === '1';
        const whitelistAutoAdd = String(await getAppConfigValue(db, 'ACCESS_DEVICE_WHITELIST_AUTO_ADD') || '0') === '1';
        if (whitelistEnabled) {
            const [allowed] = await db.execute(
                'SELECT id FROM colaborador_devices WHERE colaborador_id = ? AND device_id = ? LIMIT 1',
                [id, deviceId]
            );
            if (!allowed.length) {
                if (whitelistAutoAdd) {
                    await db.execute(
                        'INSERT INTO colaborador_devices (colaborador_id, device_id, label, last_seen) VALUES (?, ?, ?, NOW())',
                        [id, deviceId, 'Cadastro automático']
                    );
                } else {
                    return res.status(403).json({ success: false, message: 'Device não autorizado para este colaborador' });
                }
            }
        }

        const token = generateAccessToken(20);
        const secret = await getAccessHmacSecret(db);
        const tokenHash = buildAccessTokenHash(token, deviceId, rows[0].qr_seed, secret);
        const ttlRaw = await getAppConfigValue(db, 'ACCESS_QR_TOKEN_TTL_SEC');
        const ttlSec = Math.min(300, Math.max(10, Number(ttlRaw || 30)));
        const expiresAt = moment().add(ttlSec, 'seconds').format('YYYY-MM-DD HH:mm:ss');
        await db.execute(
            `INSERT INTO access_tokens (colaborador_id, token_hash, device_id, expires_at)
             VALUES (?, ?, ?, ?)` ,
            [id, tokenHash, deviceId, expiresAt]
        );

        return res.json({ success: true, token, expiresAt, mode: 'dynamic' });
    } catch (error) {
        console.error('Erro ao gerar QR token:', error);
        return res.status(500).json({ success: false, message: 'Erro ao gerar QR token' });
    }
});

app.get('/qr/:token', async (req, res) => {
    try {
        const token = (req.params.token || '').toString().trim();
        if (!token) return res.status(400).send('Token inválido');

        const db = getDB();
        await ensureAccessControlTables(db);

        const qrMode = (await getAppConfigValue(db, 'ACCESS_QR_MODE') || 'fixed').toString().toLowerCase();
        let tokens = [];
        if (qrMode === 'fixed') {
            const [rows] = await db.execute(
                `SELECT id AS colaborador_id, nome, cpf, empresa, cargo, status, foto_url, qr_seed, qr_static_token
                 FROM colaboradores WHERE qr_static_token = ? LIMIT 1`,
                [token]
            );
            tokens = rows.map(r => ({
                id: null,
                colaborador_id: r.colaborador_id,
                token_hash: null,
                expires_at: null,
                used_at: null,
                device_id: null,
                nome: r.nome,
                cpf: r.cpf,
                empresa: r.empresa,
                cargo: r.cargo,
                status: r.status,
                foto_url: r.foto_url,
                qr_seed: r.qr_seed,
                qr_static_token: r.qr_static_token
            }));
        } else {
            const [rows] = await db.execute(
                `SELECT t.id, t.colaborador_id, t.token_hash, t.expires_at, t.used_at, t.device_id, c.nome, c.cpf, c.empresa, c.cargo, c.status, c.foto_url, c.qr_seed
                 FROM access_tokens t
                 JOIN colaboradores c ON c.id = t.colaborador_id
                 WHERE t.used_at IS NULL
                 ORDER BY t.id DESC LIMIT 6`
            );
            tokens = rows;
        }

        let found = null;
        if (qrMode === 'fixed') {
            found = tokens && tokens.length ? tokens[0] : null;
        } else {
            const secret = await getAccessHmacSecret(db);
            for (const row of tokens) {
                const hash = buildAccessTokenHash(token, row.device_id || '', row.qr_seed, secret);
                if (hash === row.token_hash) {
                    found = row;
                    break;
                }
            }
        }

        const colaborador = found || null;
        return res.render('acesso/choose', {
            title: 'QR Code',
            currentPage: 'acesso',
            usuario: null,
            token,
            colaborador
        });
    } catch (error) {
        console.error('Erro ao abrir QR:', error);
        return res.status(500).send('Erro ao abrir QR');
    }
});

app.get('/qr/:token/acesso', async (req, res) => {
    try {
        const token = (req.params.token || '').toString().trim();
        if (!token) return res.status(400).send('Token inválido');

        const db = getDB();
        await ensureAccessControlTables(db);

        const qrMode = (await getAppConfigValue(db, 'ACCESS_QR_MODE') || 'fixed').toString().toLowerCase();
        let tokens = [];
        if (qrMode === 'fixed') {
            const [rows] = await db.execute(
                `SELECT id AS colaborador_id, nome, cpf, empresa, cargo, status, foto_url, qr_seed, qr_static_token
                 FROM colaboradores WHERE qr_static_token = ? LIMIT 1`,
                [token]
            );
            tokens = rows.map(r => ({
                id: null,
                colaborador_id: r.colaborador_id,
                token_hash: null,
                expires_at: null,
                used_at: null,
                device_id: null,
                nome: r.nome,
                cpf: r.cpf,
                empresa: r.empresa,
                cargo: r.cargo,
                status: r.status,
                foto_url: r.foto_url,
                qr_seed: r.qr_seed,
                qr_static_token: r.qr_static_token
            }));
        } else {
            const [rows] = await db.execute(
                `SELECT t.id, t.colaborador_id, t.token_hash, t.expires_at, t.used_at, t.device_id, c.nome, c.cpf, c.empresa, c.cargo, c.status, c.foto_url, c.qr_seed
                 FROM access_tokens t
                 JOIN colaboradores c ON c.id = t.colaborador_id
                 WHERE t.used_at IS NULL
                 ORDER BY t.id DESC LIMIT 6`
            );
            tokens = rows;
        }

        let found = null;
        if (qrMode === 'fixed') {
            found = tokens && tokens.length ? tokens[0] : null;
        } else {
            const secret = await getAccessHmacSecret(db);
            for (const row of tokens) {
                const hash = buildAccessTokenHash(token, row.device_id || '', row.qr_seed, secret);
                if (hash === row.token_hash) {
                    found = row;
                    break;
                }
            }
        }

        let status = 'negado';
        let motivo = 'Token inválido ou expirado';
        let colaborador = null;

        if (found) {
            const isExpired = found.expires_at ? moment(found.expires_at).isBefore(moment()) : false;
            colaborador = found;
            if (isExpired) {
                status = 'negado';
                motivo = 'QR expirado';
            } else if (found.status === 'ativo') {
                status = 'autorizado';
                motivo = 'Acesso liberado';
            } else if (found.status === 'inativo') {
                status = 'restrito';
                motivo = 'Acesso restrito';
            } else {
                status = 'negado';
                motivo = 'Colaborador bloqueado';
            }

            if (qrMode !== 'fixed') {
                const [upd] = await db.execute('UPDATE access_tokens SET used_at = NOW() WHERE id = ? AND used_at IS NULL', [found.id]);
                if (!upd || !upd.affectedRows) {
                    status = 'negado';
                    motivo = 'QR já utilizado';
                }
            }
        }

        const ipAddress = (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '').toString();
        const deviceId = (req.query?.deviceId || '').toString().trim() || null;
        await db.execute(
            `INSERT INTO access_logs (colaborador_id, status, tipo, motivo, local, ip_address, device_id)
             VALUES (?, ?, 'acesso', ?, ?, ?, ?)` ,
            [colaborador ? colaborador.colaborador_id : null, status, motivo, req.query?.local || null, ipAddress, deviceId]
        );

        if (colaborador && colaborador.status === 'bloqueado') {
            await notifyBlockedAccessAttempt(db, colaborador, motivo, req);
            await notifyBlockedAccessAttemptWhatsapp(db, colaborador, motivo);
        }

        return res.render('acesso/scan', {
            title: 'Controle de Acesso',
            currentPage: 'acesso',
            usuario: null,
            status,
            motivo,
            colaborador
        });
    } catch (error) {
        console.error('Erro ao validar QR (acesso):', error);
        return res.status(500).send('Erro ao validar QR');
    }
});

app.get('/qr/:token/ponto', async (req, res) => {
    try {
        const token = (req.params.token || '').toString().trim();
        if (!token) return res.status(400).send('Token inválido');

        const db = getDB();
        await ensureAccessControlTables(db);

        const qrMode = (await getAppConfigValue(db, 'ACCESS_QR_MODE') || 'fixed').toString().toLowerCase();
        let tokens = [];
        if (qrMode === 'fixed') {
            const [rows] = await db.execute(
                `SELECT id AS colaborador_id, nome, cpf, empresa, cargo, status, foto_url, qr_seed, qr_static_token
                 FROM colaboradores WHERE qr_static_token = ? LIMIT 1`,
                [token]
            );
            tokens = rows.map(r => ({
                id: null,
                colaborador_id: r.colaborador_id,
                token_hash: null,
                expires_at: null,
                used_at: null,
                device_id: null,
                nome: r.nome,
                cpf: r.cpf,
                empresa: r.empresa,
                cargo: r.cargo,
                status: r.status,
                foto_url: r.foto_url,
                qr_seed: r.qr_seed,
                qr_static_token: r.qr_static_token
            }));
        } else {
            const [rows] = await db.execute(
                `SELECT t.id, t.colaborador_id, t.token_hash, t.expires_at, t.used_at, t.device_id, c.nome, c.cpf, c.empresa, c.cargo, c.status, c.foto_url, c.qr_seed
                 FROM access_tokens t
                 JOIN colaboradores c ON c.id = t.colaborador_id
                 WHERE t.used_at IS NULL
                 ORDER BY t.id DESC LIMIT 6`
            );
            tokens = rows;
        }

        let found = null;
        if (qrMode === 'fixed') {
            found = tokens && tokens.length ? tokens[0] : null;
        } else {
            const secret = await getAccessHmacSecret(db);
            for (const row of tokens) {
                const hash = buildAccessTokenHash(token, row.device_id || '', row.qr_seed, secret);
                if (hash === row.token_hash) {
                    found = row;
                    break;
                }
            }
        }

        return res.render('ponto/registrar', {
            title: 'Marcar Ponto',
            currentPage: 'acesso',
            usuario: null,
            token,
            colaborador: found || null
        });
    } catch (error) {
        console.error('Erro ao abrir QR (ponto):', error);
        return res.status(500).send('Erro ao abrir QR');
    }
});

app.post('/api/ponto/registrar', async (req, res) => {
    try {
        const token = (req.body?.token || '').toString().trim();
        if (!token) return res.status(400).json({ success: false, message: 'Token inválido' });

        const db = getDB();
        await ensureAccessControlTables(db);
        const deviceIdRaw = (req.body?.deviceId || '').toString().trim();
        if (!deviceIdRaw) return res.status(400).json({ success: false, message: 'deviceId obrigatório' });
        const deviceId = deviceIdRaw.slice(0, 128);
        const ipAddress = (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '').toString();
        const rateIpLimitRaw = await getAppConfigValue(db, 'ACCESS_PONTO_RATE_IP_LIMIT');
        const rateIpWindowRaw = await getAppConfigValue(db, 'ACCESS_PONTO_RATE_IP_WINDOW_SEC');
        const rateIpLimit = Math.min(60, Math.max(2, Number(rateIpLimitRaw || 10)));
        const rateIpWindowMs = Math.min(600, Math.max(30, Number(rateIpWindowRaw || 60))) * 1000;
        const rateKey = `${ipAddress}|${deviceId}`;
        if (!checkPontoRateLimit(rateKey, rateIpLimit, rateIpWindowMs)) {
            return res.status(429).json({ success: false, message: 'Muitas tentativas. Aguarde e tente novamente.' });
        }

        const qrMode = (await getAppConfigValue(db, 'ACCESS_QR_MODE') || 'fixed').toString().toLowerCase();
        let found = null;
        if (qrMode === 'fixed') {
            const [rows] = await db.execute(
                'SELECT id AS colaborador_id, status, qr_seed, qr_static_token FROM colaboradores WHERE qr_static_token = ? LIMIT 1',
                [token]
            );
            found = rows && rows.length ? rows[0] : null;
        } else {
            const [tokens] = await db.execute(
                `SELECT t.id, t.colaborador_id, t.token_hash, t.expires_at, t.used_at, t.device_id, c.status, c.qr_seed
                 FROM access_tokens t
                 JOIN colaboradores c ON c.id = t.colaborador_id
                 WHERE t.used_at IS NULL
                 ORDER BY t.id DESC LIMIT 6`
            );

            const secret = await getAccessHmacSecret(db);
            for (const row of tokens) {
                const hash = buildAccessTokenHash(token, row.device_id || '', row.qr_seed, secret);
                if (hash === row.token_hash) {
                    found = row;
                    break;
                }
            }
        }

        if (!found) {
            return res.status(404).json({ success: false, message: 'Token inválido ou expirado' });
        }
        if (found.expires_at && moment(found.expires_at).isBefore(moment())) {
            return res.status(400).json({ success: false, message: 'Token expirado' });
        }
        if (found.device_id && found.device_id !== deviceId) {
            return res.status(403).json({ success: false, message: 'Device inválido' });
        }

        const whitelistEnabled = String(await getAppConfigValue(db, 'ACCESS_DEVICE_WHITELIST_ENABLED') || '0') === '1';
        const whitelistAutoAdd = String(await getAppConfigValue(db, 'ACCESS_DEVICE_WHITELIST_AUTO_ADD') || '0') === '1';
        if (whitelistEnabled) {
            const [allowed] = await db.execute(
                'SELECT id FROM colaborador_devices WHERE colaborador_id = ? AND device_id = ? LIMIT 1',
                [found.colaborador_id, deviceId]
            );
            if (!allowed.length) {
                if (whitelistAutoAdd) {
                    await db.execute(
                        'INSERT INTO colaborador_devices (colaborador_id, device_id, label, last_seen) VALUES (?, ?, ?, NOW())',
                        [found.colaborador_id, deviceId, 'Cadastro automático']
                    );
                } else {
                    return res.status(403).json({ success: false, message: 'Device não autorizado para este colaborador' });
                }
            } else {
                await db.execute('UPDATE colaborador_devices SET last_seen = NOW() WHERE id = ?', [allowed[0].id]);
            }
        }
        if (found.status !== 'ativo') {
            return res.status(403).json({ success: false, message: 'Colaborador sem autorização' });
        }

        const requireGeo = String(await getAppConfigValue(db, 'ACCESS_REQUIRE_GEO') || '0') === '1';
        if (requireGeo) {
            const baseLat = Number(await getAppConfigValue(db, 'ACCESS_GEO_LAT'));
            const baseLng = Number(await getAppConfigValue(db, 'ACCESS_GEO_LNG'));
            const radius = Math.max(10, Number(await getAppConfigValue(db, 'ACCESS_GEO_RADIUS_METERS') || 200));
            const lat = Number(req.body?.geoLat);
            const lng = Number(req.body?.geoLng);
            if (!Number.isFinite(lat) || !Number.isFinite(lng) || !Number.isFinite(baseLat) || !Number.isFinite(baseLng)) {
                return res.status(400).json({ success: false, message: 'Geolocalização obrigatória' });
            }
            const dist = haversineMeters(baseLat, baseLng, lat, lng);
            if (dist > radius) {
                return res.status(403).json({ success: false, message: 'Fora da área autorizada' });
            }
        }

        const requireSsid = String(await getAppConfigValue(db, 'ACCESS_REQUIRE_SSID') || '0') === '1';
        if (requireSsid) {
            const allowedSsid = (await getAppConfigValue(db, 'ACCESS_ALLOWED_SSID') || '').toString().trim();
            const ssid = (req.body?.ssid || '').toString().trim();
            if (!ssid || !allowedSsid || ssid !== allowedSsid) {
                return res.status(403).json({ success: false, message: 'SSID não autorizado' });
            }
        }

        const tipo = (req.body?.tipo || '').toString().trim().toLowerCase();
        const tipoAllowed = new Set(['entrada', 'saida']);
        if (!tipoAllowed.has(tipo)) {
            return res.status(400).json({ success: false, message: 'Tipo inválido' });
        }

        const [lastPontoRows] = await db.execute(
            `SELECT tipo
             FROM ponto_logs
             WHERE colaborador_id = ?
             ORDER BY id DESC
             LIMIT 1`,
            [found.colaborador_id]
        );
        const lastTipo = lastPontoRows && lastPontoRows.length ? (lastPontoRows[0].tipo || '').toString().toLowerCase() : '';
        if (!lastTipo) {
            if (tipo === 'saida') {
                return res.status(409).json({ success: false, message: 'Não é possível registrar saída sem uma entrada anterior.' });
            }
        } else {
            if (lastTipo === tipo) {
                if (tipo === 'entrada') {
                    return res.status(409).json({ success: false, message: 'Entrada já registrada. Registre a saída antes de registrar uma nova entrada.' });
                }
                return res.status(409).json({ success: false, message: 'Saída já registrada. Registre a entrada antes de registrar uma nova saída.' });
            }
        }

        const dupMinutesRaw = await getAppConfigValue(db, 'ACCESS_PONTO_DUP_MINUTES');
        const dupMinutes = Math.min(15, Math.max(1, Number(dupMinutesRaw || 3)));
        const [recentPonto] = await db.execute(
            `SELECT id
             FROM ponto_logs
             WHERE colaborador_id = ?
               AND tipo = ?
               AND created_at >= DATE_SUB(NOW(), INTERVAL ${dupMinutes} MINUTE)
             ORDER BY id DESC
             LIMIT 1`,
            [found.colaborador_id, tipo]
        );
        if (recentPonto && recentPonto.length) {
            return res.status(409).json({ success: false, message: 'Ponto duplicado detectado. Aguarde alguns minutos.' });
        }

        const rateColabLimitRaw = await getAppConfigValue(db, 'ACCESS_PONTO_RATE_COLAB_LIMIT');
        const rateColabWindowRaw = await getAppConfigValue(db, 'ACCESS_PONTO_RATE_COLAB_WINDOW_SEC');
        const rateColabLimit = Math.min(60, Math.max(2, Number(rateColabLimitRaw || 6)));
        const rateColabWindowMs = Math.min(600, Math.max(30, Number(rateColabWindowRaw || 60))) * 1000;
        const rateKeyColab = `colab|${found.colaborador_id}`;
        if (!checkPontoRateLimit(rateKeyColab, rateColabLimit, rateColabWindowMs)) {
            return res.status(429).json({ success: false, message: 'Muitas tentativas para este colaborador. Aguarde e tente novamente.' });
        }

        if (qrMode !== 'fixed' && found.id) {
            await db.execute('UPDATE access_tokens SET used_at = NOW() WHERE id = ? AND used_at IS NULL', [found.id]);
        }
        await db.execute(
            `INSERT INTO ponto_logs (colaborador_id, tipo, ip_address, device_id)
             VALUES (?, ?, ?, ?)` ,
            [found.colaborador_id, tipo, ipAddress, deviceId]
        );

        await db.execute(
            `INSERT INTO access_logs (colaborador_id, status, tipo, motivo, local, ip_address, device_id)
             VALUES (?, 'autorizado', 'ponto', ?, ?, ?, ?)` ,
            [found.colaborador_id, `Ponto ${tipo} registrado`, req.body?.local || null, ipAddress, deviceId]
        );

        return res.json({ success: true });
    } catch (error) {
        console.error('Erro ao registrar ponto:', error);
        return res.status(500).json({ success: false, message: 'Erro ao registrar ponto' });
    }
});

app.get('/api/colaboradores/:id/devices', requireAuth, requireAdmin, async (req, res) => {
    try {
        const id = Number(req.params.id);
        if (!id) return res.status(400).json({ success: false, message: 'ID inválido' });
        const db = getDB();
        await ensureAccessControlTables(db);
        const [rows] = await db.execute(
            'SELECT id, device_id, label, last_seen, created_at FROM colaborador_devices WHERE colaborador_id = ? ORDER BY created_at DESC',
            [id]
        );
        return res.json({ success: true, devices: rows || [] });
    } catch (error) {
        console.error('Erro ao carregar devices do colaborador:', error);
        return res.status(500).json({ success: false, message: 'Erro ao carregar devices' });
    }
});

app.post('/api/colaboradores/:id/devices', requireAuth, requireAdmin, async (req, res) => {
    try {
        const id = Number(req.params.id);
        if (!id) return res.status(400).json({ success: false, message: 'ID inválido' });
        const deviceId = (req.body?.deviceId || '').toString().trim().slice(0, 128);
        if (!deviceId) return res.status(400).json({ success: false, message: 'deviceId obrigatório' });
        const label = (req.body?.label || '').toString().trim().slice(0, 120) || null;
        const db = getDB();
        await ensureAccessControlTables(db);
        await db.execute(
            'INSERT INTO colaborador_devices (colaborador_id, device_id, label, last_seen) VALUES (?, ?, ?, NOW())',
            [id, deviceId, label]
        );
        return res.json({ success: true });
    } catch (error) {
        if (error && error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ success: false, message: 'Device já cadastrado' });
        }
        console.error('Erro ao cadastrar device:', error);
        return res.status(500).json({ success: false, message: 'Erro ao cadastrar device' });
    }
});

app.delete('/api/colaboradores/:id/devices/:deviceId', requireAuth, requireAdmin, async (req, res) => {
    try {
        const id = Number(req.params.id);
        if (!id) return res.status(400).json({ success: false, message: 'ID inválido' });
        const deviceId = (req.params.deviceId || '').toString().trim();
        if (!deviceId) return res.status(400).json({ success: false, message: 'deviceId obrigatório' });
        const db = getDB();
        await ensureAccessControlTables(db);
        await db.execute('DELETE FROM colaborador_devices WHERE colaborador_id = ? AND device_id = ?', [id, deviceId]);
        return res.json({ success: true });
    } catch (error) {
        console.error('Erro ao remover device:', error);
        return res.status(500).json({ success: false, message: 'Erro ao remover device' });
    }
});

app.post('/api/usuarios/:id/tipo', requireAuth, requireAdmin, async (req, res) => {
    try {
        const id = Number(req.params.id);
        if (!id) return res.status(400).json({ success: false, message: 'ID inválido' });

        const adminSenha = (req.body?.adminSenha || '').toString();
        if (!adminSenha) {
            return res.status(400).json({ success: false, message: 'Senha do admin é obrigatória' });
        }

        const tipoNorm = normalizeUsuarioTipo(req.body?.tipo);
        if (tipoNorm.error) {
            return res.status(400).json({ success: false, message: tipoNorm.error });
        }
        const novoTipo = tipoNorm.tipo;

        const adminId = req.session?.usuario?.id;
        const db = getDB();
        await ensureUsuariosTipoColumn(db);

        const [admins] = await db.execute('SELECT id, senha FROM usuarios WHERE id = ? AND ativo = TRUE LIMIT 1', [adminId]);
        if (!admins.length) {
            return res.status(403).json({ success: false, message: 'Admin inválido' });
        }
        const adminSenhaValida = await bcrypt.compare(adminSenha, admins[0].senha);
        if (!adminSenhaValida) {
            return res.status(403).json({ success: false, message: 'Senha do admin inválida' });
        }

        if (adminId && Number(adminId) === id && novoTipo !== 'admin') {
            return res.status(400).json({ success: false, message: 'Você não pode remover seu próprio acesso de admin' });
        }

        const [existing] = await db.execute('SELECT id, tipo FROM usuarios WHERE id = ? LIMIT 1', [id]);
        if (!existing || !existing.length) {
            return res.status(404).json({ success: false, message: 'Usuário não encontrado' });
        }

        await db.execute('UPDATE usuarios SET tipo = ? WHERE id = ? LIMIT 1', [novoTipo, id]);

        try {
            await logLGPD(adminId, 'UPDATE', 'usuarios', id, JSON.stringify({ tipo: existing[0].tipo }), JSON.stringify({ tipo: novoTipo }), req);
        } catch {}

        return res.json({ success: true });
    } catch (error) {
        console.error('Erro ao atualizar tipo do usuário:', error);
        return res.status(500).json({ success: false, message: 'Erro ao atualizar tipo do usuário' });
    }
});

app.get('/auditoria', requireAuth, requireAdmin, async (req, res) => {
    try {
        const db = getDB();

        await db.execute(
            `CREATE TABLE IF NOT EXISTS logs_lgpd (
                id INT AUTO_INCREMENT PRIMARY KEY,
                usuario_id INT NULL,
                acao VARCHAR(32) NOT NULL,
                tabela_afetada VARCHAR(64) NULL,
                registro_id INT NULL,
                dados_anteriores TEXT NULL,
                dados_novos TEXT NULL,
                ip_address VARCHAR(64) NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`
        );

        const [createdAtCols] = await db.execute(
            `SELECT COUNT(*) AS cnt
             FROM INFORMATION_SCHEMA.COLUMNS
             WHERE TABLE_SCHEMA = DATABASE()
               AND TABLE_NAME = 'logs_lgpd'
               AND COLUMN_NAME = 'created_at'`
        );
        const createdAtExists = Number(createdAtCols?.[0]?.cnt || 0) > 0;
        if (!createdAtExists) {
            await db.execute(
                `ALTER TABLE logs_lgpd
                 ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP`
            );
        }

        const q = (req.query.q || '').toString().trim();
        const acao = (req.query.acao || '').toString().trim();
        const tabela = (req.query.tabela || '').toString().trim();
        const limitRaw = Number(req.query.limit || 200);
        const limit = Number.isFinite(limitRaw) ? Math.min(Math.max(limitRaw, 50), 1000) : 200;

        const where = [];
        const params = [];

        if (acao) {
            where.push('l.acao = ?');
            params.push(acao);
        }
        if (tabela) {
            where.push('l.tabela_afetada = ?');
            params.push(tabela);
        }
        if (q) {
            where.push('(l.acao LIKE ? OR l.tabela_afetada LIKE ? OR l.dados_anteriores LIKE ? OR l.dados_novos LIKE ? OR u.nome LIKE ? OR u.email LIKE ?)');
            const like = `%${q}%`;
            params.push(like, like, like, like, like, like);
        }

        const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';
        const sql = `
            SELECT
                l.id,
                l.usuario_id,
                u.nome AS usuario_nome,
                u.email AS usuario_email,
                l.acao,
                l.tabela_afetada,
                l.registro_id,
                l.dados_anteriores,
                l.dados_novos,
                l.ip_address,
                l.created_at
            FROM logs_lgpd l
            LEFT JOIN usuarios u ON u.id = l.usuario_id
            ${whereSql}
            ORDER BY l.created_at DESC, l.id DESC
            LIMIT ${limit}
        `;

        const [logs] = await db.execute(sql, params);

        return res.render('auditoria/index', {
            title: 'Auditoria',
            currentPage: 'auditoria',
            usuario: req.session.usuario,
            logs,
            filtros: { q, acao, tabela, limit }
        });
    } catch (error) {
        console.error('Erro ao carregar auditoria:', error);
        return res.render('auditoria/index', {
            title: 'Auditoria',
            currentPage: 'auditoria',
            usuario: req.session.usuario,
            logs: [],
            filtros: { q: '', acao: '', tabela: '', limit: 200 },
            error: 'Erro ao carregar auditoria'
        });
    }
});

app.get('/acessos', requireAuth, requireAdmin, async (req, res) => {
    try {
        const db = getDB();
        await ensureAccessControlTables(db);

        const q = (req.query?.q || '').toString().trim();
        const status = (req.query?.status || '').toString().trim();
        const tipo = (req.query?.tipo || '').toString().trim();
        const limitRaw = Number(req.query?.limit || 200);
        const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.min(limitRaw, 1000) : 200;

        const where = [];
        const params = [];
        if (q) {
            where.push('(c.nome LIKE ? OR c.cpf LIKE ? OR a.motivo LIKE ? OR a.local LIKE ?)');
            const like = `%${q}%`;
            params.push(like, like, like, like);
        }
        if (status) {
            where.push('a.status = ?');
            params.push(status);
        }
        if (tipo) {
            where.push('a.tipo = ?');
            params.push(tipo);
        }

        const sqlWhere = where.length ? `WHERE ${where.join(' AND ')}` : '';
        const [logs] = await db.execute(
            `SELECT a.id, a.status, a.tipo, a.motivo, a.local, a.ip_address, a.device_id, a.created_at,
                    c.id AS colaborador_id, c.nome AS colaborador_nome, c.cpf AS colaborador_cpf
             FROM access_logs a
             LEFT JOIN colaboradores c ON c.id = a.colaborador_id
             ${sqlWhere}
             ORDER BY a.created_at DESC, a.id DESC
             LIMIT ${limit}`,
            params
        );

        const [chartRows] = await db.execute(
            `SELECT DATE(a.created_at) AS dia, a.status, COUNT(*) AS total
             FROM access_logs a
             WHERE a.created_at >= DATE_SUB(CURDATE(), INTERVAL 6 DAY)
             GROUP BY DATE(a.created_at), a.status
             ORDER BY dia ASC`
        );
        const dias = [];
        for (let i = 6; i >= 0; i -= 1) {
            dias.push(moment().subtract(i, 'days').format('YYYY-MM-DD'));
        }
        const statusList = ['autorizado', 'restrito', 'negado'];
        const chartData = {};
        statusList.forEach((st) => { chartData[st] = dias.map(() => 0); });
        (chartRows || []).forEach((row) => {
            const idx = dias.indexOf(moment(row.dia).format('YYYY-MM-DD'));
            if (idx >= 0 && chartData[row.status]) {
                chartData[row.status][idx] = Number(row.total || 0);
            }
        });

        return res.render('acessos/index', {
            title: 'Acessos',
            currentPage: 'acessos',
            usuario: req.session.usuario,
            logs,
            filtros: { q, status, tipo, limit },
            chart: { dias, series: chartData }
        });
    } catch (error) {
        console.error('Erro ao carregar acessos:', error);
        return res.render('acessos/index', {
            title: 'Acessos',
            currentPage: 'acessos',
            usuario: req.session.usuario,
            logs: [],
            filtros: { q: '', status: '', tipo: '', limit: 200 },
            chart: { dias: [], series: { autorizado: [], restrito: [], negado: [] } },
            error: 'Erro ao carregar acessos'
        });
    }
});

app.get('/acessos/export', requireAuth, requireAdmin, async (req, res) => {
    try {
        const db = getDB();
        await ensureAccessControlTables(db);

        const q = (req.query?.q || '').toString().trim();
        const status = (req.query?.status || '').toString().trim();
        const tipo = (req.query?.tipo || '').toString().trim();

        const where = [];
        const params = [];
        if (q) {
            where.push('(c.nome LIKE ? OR c.cpf LIKE ? OR a.motivo LIKE ? OR a.local LIKE ?)');
            const like = `%${q}%`;
            params.push(like, like, like, like);
        }
        if (status) {
            where.push('a.status = ?');
            params.push(status);
        }
        if (tipo) {
            where.push('a.tipo = ?');
            params.push(tipo);
        }
        const sqlWhere = where.length ? `WHERE ${where.join(' AND ')}` : '';
        const [rows] = await db.execute(
            `SELECT a.created_at, a.status, a.tipo, a.motivo, a.local, a.ip_address, a.device_id,
                    c.nome AS colaborador_nome, c.cpf AS colaborador_cpf
             FROM access_logs a
             LEFT JOIN colaboradores c ON c.id = a.colaborador_id
             ${sqlWhere}
             ORDER BY a.created_at DESC, a.id DESC`,
            params
        );

        const header = 'data_hora;colaborador;cpf;status;tipo;motivo;local;ip;device\n';
        const lines = (rows || []).map((r) => {
            const parts = [
                toShortDateTime(r.created_at),
                r.colaborador_nome || 'Visitante',
                r.colaborador_cpf || '',
                r.status || '',
                r.tipo || '',
                (r.motivo || '').replace(/\n/g, ' '),
                r.local || '',
                r.ip_address || '',
                r.device_id || ''
            ];
            return parts.map((p) => String(p || '').replace(/;/g, ',')).join(';');
        });

        const csv = header + lines.join('\n');
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', 'attachment; filename="acessos.csv"');
        return res.send(csv);
    } catch (error) {
        console.error('Erro ao exportar acessos:', error);
        return res.status(500).send('Erro ao exportar');
    }
});

// PACIENTES
app.get('/pacientes', requireAuth, requireRoles(['admin', 'medico']), async (req, res) => {
    try {
        const db = getDB();
        const usuarioTipo = req.session && req.session.usuario ? req.session.usuario.tipo : null;
        const [pacientes] = await db.execute(
            `SELECT
                id, nome, cpf, rg, data_nascimento, sexo, telefone, email,
                endereco, cidade, estado, cep,
                convenio, numero_convenio, validade_convenio,
                ativo
             FROM pacientes
             WHERE ativo = TRUE
             ORDER BY nome`
        );
        const pacientesSafe = Array.isArray(pacientes)
            ? pacientes.map(p => sanitizePacienteForRole(p, usuarioTipo))
            : pacientes;
        res.render('pacientes/lista', { pacientes: pacientesSafe, usuario: req.session.usuario });
    } catch (error) {
        console.error('Erro ao listar pacientes:', error);
        res.render('pacientes/lista', { pacientes: [], usuario: req.session.usuario });
    }
});

app.get('/pacientes/novo', requireAuth, requireRoles(['admin', 'medico']), (req, res) => {
    const usuarioTipo = req.session && req.session.usuario ? req.session.usuario.tipo : null;
    const pacienteSafe = sanitizePacienteForRole(null, usuarioTipo);
    res.render('pacientes/form', { paciente: pacienteSafe, usuario: req.session.usuario, error: null });
});

app.post('/pacientes', requireAuth, requireRoles(['admin', 'medico']), async (req, res) => {
    try {
        console.log('POST /pacientes - Criando novo paciente');
        console.log('Dados recebidos:', req.body);
        
        const usuarioTipo = req.session && req.session.usuario ? req.session.usuario.tipo : null;
        const isSec = usuarioTipo === 'secretaria';
        const { nome, cpf, rg, data_nascimento, sexo, telefone, email, endereco, cidade, estado, cep, convenio, numero_convenio, validade_convenio } = req.body;
        const alergias = isSec ? null : (req.body ? req.body.alergias : null);
        const medicamentos = isSec ? null : (req.body ? req.body.medicamentos : null);
        const historico_familiar = isSec ? null : (req.body ? req.body.historico_familiar : null);
        const observacoes = isSec ? null : (req.body ? req.body.observacoes : null);
        const db = getDB();
        const sexoDb = await resolveSexoDbValue(db, sexo);
        
        // Validação básica
        if (!nome || !cpf || !data_nascimento || !sexoDb) {
            console.log('Validação falhou:', { nome, cpf, data_nascimento, sexo });
            return res.render('pacientes/form', { 
                paciente: req.body, 
                usuario: req.session.usuario, 
                error: 'Campos obrigatórios: Nome, CPF, Data de Nascimento e Sexo são obrigatórios' 
            });
        }

        const [result] = await db.execute(
            'INSERT INTO pacientes (nome, cpf, rg, data_nascimento, sexo, telefone, email, endereco, cidade, estado, cep, convenio, numero_convenio, validade_convenio, alergias, medicamentos, historico_familiar, observacoes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [nome, cpf, rg, data_nascimento, sexoDb, telefone, email, endereco, cidade, estado, cep, convenio, numero_convenio, validade_convenio, alergias, medicamentos, historico_familiar, observacoes]
        );
        
        console.log('Paciente criado com ID:', result.insertId);
        await logLGPD(req.session.usuario.id, 'INSERT', 'pacientes', result.insertId, null, JSON.stringify(req.body), req);
        res.redirect('/pacientes');
    } catch (error) {
        console.error('Erro ao criar paciente:', error);

        if (error && error.code === 'ER_DUP_ENTRY') {
            return res.render('pacientes/form', {
                paciente: req.body,
                usuario: req.session.usuario,
                error: 'Já existe um paciente cadastrado com este CPF.'
            });
        }

        res.render('pacientes/form', { 
            paciente: req.body, 
            usuario: req.session.usuario, 
            error: 'Erro ao criar paciente' 
        });
    }
});

app.get('/pacientes/:id/editar', requireAuth, requireRoles(['admin', 'medico']), async (req, res) => {
    try {
        console.log('=== GET /pacientes/:id/editar ===');
        console.log('ID do paciente:', req.params.id);
        
        const db = getDB();
        const [pacientes] = await db.execute('SELECT * FROM pacientes WHERE id = ?', [req.params.id]);
        
        console.log('Paciente encontrado no banco:', pacientes.length > 0 ? 'SIM' : 'NÃO');
        if (pacientes.length > 0) {
            const usuarioTipo = req.session && req.session.usuario ? req.session.usuario.tipo : null;
            const paciente = sanitizePacienteForRole(pacientes[0], usuarioTipo);
            paciente.sexo = normalizeSexoForForm(paciente.sexo);
            console.log('Dados do paciente:', {
                id: paciente.id,
                nome: paciente.nome,
                data_nascimento: paciente.data_nascimento,
                validade_convenio: paciente.validade_convenio
            });
            
            // Formatar datas para o formulário
            paciente.data_nascimento = formatDateForInput(paciente.data_nascimento);
            paciente.validade_convenio = formatDateForInput(paciente.validade_convenio);
            
            console.log('Datas formatadas:', {
                data_nascimento: paciente.data_nascimento,
                validade_convenio: paciente.validade_convenio
            });
            
            console.log('Renderizando formulário de edição...');
            res.render('pacientes/form', { paciente, usuario: req.session.usuario, error: null });
        } else {
            console.log('Redirecionando para /pacientes (paciente não encontrado)');
            return res.redirect('/pacientes');
        }
    } catch (error) {
        console.error('Erro ao carregar paciente:', error);
        res.render('pacientes/form', { 
            paciente: req.body, 
            usuario: req.session.usuario, 
            error: 'Erro ao carregar paciente para edição' 
        });
    }
});

app.post('/pacientes/:id/editar', requireAuth, requireRoles(['admin', 'medico']), async (req, res) => {
    try {
        console.log('=== POST /pacientes/:id/editar ===');
        console.log('ID do paciente:', req.params.id);
        console.log('Todos os dados recebidos:', Object.keys(req.body));
        console.log('Dados recebidos:', req.body);

        const usuarioTipo = req.session && req.session.usuario ? req.session.usuario.tipo : null;
        const isSec = usuarioTipo === 'secretaria';
        const { nome, cpf, rg, data_nascimento, sexo, telefone, email, endereco, cidade, estado, cep, convenio, numero_convenio, validade_convenio } = req.body;
        const alergias = isSec ? undefined : (req.body ? req.body.alergias : undefined);
        const medicamentos = isSec ? undefined : (req.body ? req.body.medicamentos : undefined);
        const historico_familiar = isSec ? undefined : (req.body ? req.body.historico_familiar : undefined);
        const observacoes = isSec ? undefined : (req.body ? req.body.observacoes : undefined);
        const db = getDB();
        const sexoDb = await resolveSexoDbValue(db, sexo);
        
        console.log('Campos extraídos:', {
            nome: nome ? 'SIM' : 'NÃO',
            cpf: cpf ? 'SIM' : 'NÃO',
            data_nascimento: data_nascimento ? 'SIM' : 'NÃO',
            sexo: sexo ? 'SIM' : 'NÃO',
            validade_convenio: validade_convenio ? 'SIM' : 'NÃO'
        });
        
        // Validação básica
        if (!nome || !cpf || !data_nascimento || !sexoDb) {
            console.log('❌ Validação falhou:', { nome, cpf, data_nascimento, sexo });
            return res.render('pacientes/form', { 
                paciente: { ...req.body, id: req.params.id }, 
                usuario: req.session.usuario, 
                error: 'Campos obrigatórios: Nome, CPF, Data de Nascimento e Sexo são obrigatórios' 
            });
        }
        
        console.log('Buscando paciente no banco para comparação...');
        const [pacienteAntigo] = await db.execute('SELECT * FROM pacientes WHERE id = ?', [req.params.id]);
        
        if (pacienteAntigo.length === 0) {
            console.log('❌ Paciente não encontrado no banco!');
            return res.render('pacientes/form', { 
                paciente: req.body, 
                usuario: req.session.usuario, 
                error: 'Paciente não encontrado' 
            });
        }
        
        console.log('Paciente encontrado no banco:', pacienteAntigo[0].nome);
        console.log('Executando UPDATE no banco...');
        
        if (isSec) {
            await db.execute(
                'UPDATE pacientes SET nome = ?, cpf = ?, rg = ?, data_nascimento = ?, sexo = ?, telefone = ?, email = ?, endereco = ?, cidade = ?, estado = ?, cep = ?, convenio = ?, numero_convenio = ?, validade_convenio = ? WHERE id = ?',
                [nome, cpf, rg, data_nascimento, sexoDb, telefone, email, endereco, cidade, estado, cep, convenio, numero_convenio, validade_convenio, req.params.id]
            );
        } else {
            await db.execute(
                'UPDATE pacientes SET nome = ?, cpf = ?, rg = ?, data_nascimento = ?, sexo = ?, telefone = ?, email = ?, endereco = ?, cidade = ?, estado = ?, cep = ?, convenio = ?, numero_convenio = ?, validade_convenio = ?, alergias = ?, medicamentos = ?, historico_familiar = ?, observacoes = ? WHERE id = ?',
                [nome, cpf, rg, data_nascimento, sexoDb, telefone, email, endereco, cidade, estado, cep, convenio, numero_convenio, validade_convenio, alergias, medicamentos, historico_familiar, observacoes, req.params.id]
            );
        }
        
        console.log('✅ Update executado com sucesso!');
        
        await logLGPD(req.session.usuario.id, 'UPDATE', 'pacientes', req.params.id, JSON.stringify(pacienteAntigo[0]), JSON.stringify(req.body), req);
        console.log('Redirecionando para /pacientes...');
        res.redirect('/pacientes');
    } catch (error) {
        console.error('❌ Erro ao atualizar paciente:', error);
        console.error('Stack:', error.stack);

        if (error && error.code === 'ER_DUP_ENTRY') {
            return res.render('pacientes/form', {
                paciente: { ...req.body, id: req.params.id },
                usuario: req.session.usuario,
                error: 'Já existe um paciente cadastrado com este CPF.'
            });
        }

        res.render('pacientes/form', { 
            paciente: { ...req.body, id: req.params.id }, 
            usuario: req.session.usuario, 
            error: `Erro ao atualizar paciente: ${error.message}` 
        });
    }
});

app.post('/pacientes/:id/excluir', requireAuth, requireAdmin, async (req, res) => {
    try {
        const db = getDB();
        const [pacienteAntigo] = await db.execute('SELECT * FROM pacientes WHERE id = ?', [req.params.id]);
        
        await db.execute('UPDATE pacientes SET ativo = FALSE WHERE id = ?', [req.params.id]);
        
        await logLGPD(req.session.usuario.id, 'DELETE', 'pacientes', req.params.id, JSON.stringify(pacienteAntigo[0]), null, req);
        res.redirect('/pacientes');
    } catch (error) {
        console.error('Erro ao excluir paciente:', error);
        res.redirect('/pacientes');
    }
});

// AGENDAMENTOS
app.get('/agendamentos', requireAuth, requireRoles(['admin', 'medico', 'secretaria']), async (req, res) => {
    try {
        const db = getDB();
        let agendamentos = [];
        const filtros = {
            status: (req.query?.status == null ? '' : String(req.query.status)).trim(),
            profissional_id: (req.query?.profissional_id == null ? '' : String(req.query.profissional_id)).trim(),
            periodo: (req.query?.periodo == null ? '' : String(req.query.periodo)).trim()
        };

        const where = [];
        const params = [];
        if (filtros.status) {
            where.push('LOWER(status) = ?');
            params.push(String(filtros.status).toLowerCase());
        }
        if (filtros.profissional_id) {
            where.push('profissional_id = ?');
            params.push(Number(filtros.profissional_id));
        }
        if (filtros.periodo) {
            const p = String(filtros.periodo).toLowerCase();
            if (p === 'hoje') {
                where.push('DATE(data_hora) = CURDATE()');
            } else if (p === 'semana') {
                where.push('YEARWEEK(data_hora, 1) = YEARWEEK(CURDATE(), 1)');
            } else if (p === 'mes') {
                where.push('MONTH(data_hora) = MONTH(CURDATE()) AND YEAR(data_hora) = YEAR(CURDATE())');
            }
        }

        const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

        let profissionais = [];
        try {
            const [rowsProf] = await db.execute(
                'SELECT id, nome FROM profissionais WHERE ativo = 1 ORDER BY nome ASC LIMIT 500'
            );
            profissionais = rowsProf || [];
        } catch (e) {
            profissionais = [];
        }

        try {
            const [rows] = await db.execute(
                `SELECT id, paciente_id, paciente_nome, paciente_cpf, profissional_id, profissional_nome, data_hora, duracao_minutos, tipo_consulta, status, observacoes, valor, forma_pagamento, status_pagamento, convenio, enviar_lembrete, confirmar_whatsapp
                 FROM agendamentos
                 ${whereSql}
                 ORDER BY data_hora DESC, id DESC
                 LIMIT 200`,
                params
            );
            agendamentos = rows;
        } catch (e) {
            // Se a tabela existe mas está com schema antigo
            if (e && e.code === 'ER_BAD_FIELD_ERROR') {
                const ensureColumn = async (sql) => {
                    try {
                        await db.execute(sql);
                    } catch (err) {
                        if (err && (err.code === 'ER_DUP_FIELDNAME' || err.code === 'ER_DUP_KEYNAME')) return;
                        console.error('Erro ao aplicar migração em /agendamentos:', err);
                    }
                };

                await ensureColumn("ALTER TABLE agendamentos ADD COLUMN paciente_nome VARCHAR(255) NULL");
                await ensureColumn("ALTER TABLE agendamentos ADD COLUMN paciente_cpf VARCHAR(32) NULL");
                await ensureColumn("ALTER TABLE agendamentos ADD COLUMN profissional_nome VARCHAR(255) NULL");
                await ensureColumn("ALTER TABLE agendamentos ADD COLUMN data_hora DATETIME NULL");
                await ensureColumn("ALTER TABLE agendamentos ADD COLUMN duracao_minutos INT NOT NULL DEFAULT 30");
                await ensureColumn("ALTER TABLE agendamentos ADD COLUMN tipo_consulta VARCHAR(64) NULL");
                await ensureColumn("ALTER TABLE agendamentos ADD COLUMN status VARCHAR(32) NOT NULL DEFAULT 'agendado'");
                await ensureColumn("ALTER TABLE agendamentos ADD COLUMN observacoes TEXT NULL");
                await ensureColumn("ALTER TABLE agendamentos ADD COLUMN valor DECIMAL(10,2) NULL");
                await ensureColumn("ALTER TABLE agendamentos ADD COLUMN forma_pagamento VARCHAR(32) NULL");
                await ensureColumn("ALTER TABLE agendamentos ADD COLUMN status_pagamento VARCHAR(32) NULL");
                await ensureColumn("ALTER TABLE agendamentos ADD COLUMN convenio VARCHAR(64) NULL");
                await ensureColumn("ALTER TABLE agendamentos ADD COLUMN enviar_lembrete TINYINT(1) NOT NULL DEFAULT 1");
                await ensureColumn("ALTER TABLE agendamentos ADD COLUMN confirmar_whatsapp TINYINT(1) NOT NULL DEFAULT 1");

                // Garantir tipos (caso existam como ENUM/VARCHAR curto)
                await ensureColumn("ALTER TABLE agendamentos MODIFY COLUMN tipo_consulta VARCHAR(64) NULL");
                await ensureColumn("ALTER TABLE agendamentos MODIFY COLUMN status VARCHAR(32) NOT NULL DEFAULT 'agendado'");
                await ensureColumn("ALTER TABLE agendamentos MODIFY COLUMN forma_pagamento VARCHAR(32) NULL");
                await ensureColumn("ALTER TABLE agendamentos MODIFY COLUMN status_pagamento VARCHAR(32) NULL");
                await ensureColumn("ALTER TABLE agendamentos MODIFY COLUMN convenio VARCHAR(64) NULL");

                const [rows2] = await db.execute(
                    `SELECT id, paciente_id, paciente_nome, paciente_cpf, profissional_id, profissional_nome, data_hora, duracao_minutos, tipo_consulta, status, observacoes
                     FROM agendamentos
                     ${whereSql}
                     ORDER BY id DESC
                     LIMIT 200`,
                    params
                );
                agendamentos = rows2;
            } else {
                throw e;
            }
        }

        res.render('agendamentos/lista', {
            title: 'Agendamentos',
            currentPage: 'agendamentos',
            usuario: req.session.usuario,
            success: req.query.success || null,
            error: req.query.error || null,
            filtros,
            profissionais,
            agendamentos
        });
    } catch (error) {
        console.error('Erro ao listar agendamentos:', error);
        res.render('agendamentos/lista', {
            title: 'Agendamentos',
            currentPage: 'agendamentos',
            usuario: req.session.usuario,
            filtros: {
                status: '',
                profissional_id: '',
                periodo: ''
            },
            profissionais: [],
            agendamentos: [],
            error: 'Erro ao listar agendamentos'
        });
    }
});

app.get('/agendamentos/export', requireAuth, requireRoles(['admin', 'medico', 'secretaria']), async (req, res) => {
    try {
        const db = getDB();
        const filtros = {
            status: (req.query?.status == null ? '' : String(req.query.status)).trim(),
            profissional_id: (req.query?.profissional_id == null ? '' : String(req.query.profissional_id)).trim(),
            periodo: (req.query?.periodo == null ? '' : String(req.query.periodo)).trim()
        };

        const where = [];
        const params = [];
        if (filtros.status) {
            where.push('LOWER(status) = ?');
            params.push(String(filtros.status).toLowerCase());
        }
        if (filtros.profissional_id) {
            where.push('profissional_id = ?');
            params.push(Number(filtros.profissional_id));
        }
        if (filtros.periodo) {
            const p = String(filtros.periodo).toLowerCase();
            if (p === 'hoje') {
                where.push('DATE(data_hora) = CURDATE()');
            } else if (p === 'semana') {
                where.push('YEARWEEK(data_hora, 1) = YEARWEEK(CURDATE(), 1)');
            } else if (p === 'mes') {
                where.push('MONTH(data_hora) = MONTH(CURDATE()) AND YEAR(data_hora) = YEAR(CURDATE())');
            }
        }

        const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';
        const [rows] = await db.execute(
            `SELECT id, paciente_nome, paciente_cpf, profissional_nome, data_hora, duracao_minutos, tipo_consulta, status
             FROM agendamentos
             ${whereSql}
             ORDER BY data_hora DESC, id DESC
             LIMIT 1000`,
            params
        );

        const format = String(req.query?.format || 'csv').toLowerCase();
        if (format === 'json') {
            res.setHeader('Content-Type', 'application/json; charset=utf-8');
            res.setHeader('Content-Disposition', 'attachment; filename="agendamentos.json"');
            return res.send(JSON.stringify({ exported_at: nowIsoLocal(), filtros, agendamentos: rows || [] }, null, 2));
        }

        const escapeCsv = (v) => {
            if (v == null) return '';
            const s = String(v);
            if (/[",\n]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
            return s;
        };

        const header = ['id', 'paciente', 'cpf', 'profissional', 'data_hora', 'duracao_minutos', 'tipo_consulta', 'status'];
        const lines = [header.join(',')];
        for (const a of (rows || [])) {
            lines.push([
                escapeCsv(a.id),
                escapeCsv(a.paciente_nome),
                escapeCsv(a.paciente_cpf),
                escapeCsv(a.profissional_nome),
                escapeCsv(a.data_hora),
                escapeCsv(a.duracao_minutos),
                escapeCsv(a.tipo_consulta),
                escapeCsv(a.status)
            ].join(','));
        }

        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', 'attachment; filename="agendamentos.csv"');
        return res.send(lines.join('\n'));
    } catch (error) {
        console.error('Erro ao exportar agendamentos:', error);
        return res.status(500).send('Erro ao exportar agendamentos');
    }
});

app.get('/api/pacientes/:id/agendamentos', requireAuth, requireRoles(['admin', 'medico', 'secretaria']), async (req, res) => {
    try {
        const pacienteId = Number(req.params.id);
        if (!pacienteId) return res.status(400).json({ success: false, message: 'ID inválido' });

        const db = getDB();
        const [rows] = await db.execute(
            `SELECT id, data_hora, duracao_minutos, tipo_consulta, status, profissional_nome, observacoes
               FROM agendamentos
              WHERE paciente_id = ?
              ORDER BY data_hora DESC, id DESC
              LIMIT 200`,
            [pacienteId]
        );

        return res.json({ success: true, agendamentos: rows || [] });
    } catch (error) {
        console.error('Erro ao listar agendamentos do paciente:', error);
        return res.status(500).json({ success: false, message: 'Erro ao listar agendamentos do paciente' });
    }
});

app.get('/agendamentos/novo', requireAuth, requireRoles(['admin', 'medico', 'secretaria']), async (req, res) => {
    try {
        const db = getDB();
        const [pacientes] = await db.execute(
            'SELECT id, nome, cpf FROM pacientes WHERE ativo = 1 ORDER BY nome ASC LIMIT 500'
        );
        const [profissionais] = await db.execute(
            'SELECT id, nome FROM profissionais WHERE ativo = 1 ORDER BY nome ASC LIMIT 200'
        );

        res.render('agendamentos/form-novo', {
            title: 'Novo Agendamento',
            currentPage: 'agendamentos',
            usuario: req.session.usuario,
            pacientes,
            profissionais,
            error: null
        });
    } catch (error) {
        console.error('Erro ao abrir novo agendamento:', error);
        res.redirect('/agendamentos');
    }
});

app.post('/agendamentos', requireAuth, requireRoles(['admin', 'medico', 'secretaria']), async (req, res) => {
    try {
        const {
            paciente_id,
            profissional_id,
            data_hora,
            duracao_minutos,
            tipo_consulta,
            observacoes,
            valor,
            forma_pagamento,
            status_pagamento,
            convenio,
            enviar_lembrete,
            confirmar_whatsapp
        } = req.body;

        if (!paciente_id || !profissional_id || !data_hora || !duracao_minutos || !tipo_consulta) {
            const db = getDB();
            const [pacientes] = await db.execute(
                'SELECT id, nome, cpf FROM pacientes WHERE ativo = 1 ORDER BY nome ASC LIMIT 500'
            );
            const [profissionais] = await db.execute(
                'SELECT id, nome FROM profissionais WHERE ativo = 1 ORDER BY nome ASC LIMIT 200'
            );
            return res.render('agendamentos/form-novo', {
                title: 'Novo Agendamento',
                currentPage: 'agendamentos',
                usuario: req.session.usuario,
                pacientes,
                profissionais,
                error: 'Preencha os campos obrigatórios.'
            });
        }

        const db = getDB();
        const [pacienteRows] = await db.execute(
            'SELECT id, nome, cpf FROM pacientes WHERE id = ? AND ativo = 1 LIMIT 1',
            [paciente_id]
        );
        const [profRows] = await db.execute(
            'SELECT id, nome FROM profissionais WHERE id = ? AND ativo = 1 LIMIT 1',
            [profissional_id]
        );

        if (pacienteRows.length === 0 || profRows.length === 0) {
            const [pacientes] = await db.execute(
                'SELECT id, nome, cpf FROM pacientes WHERE ativo = 1 ORDER BY nome ASC LIMIT 500'
            );
            const [profissionais] = await db.execute(
                'SELECT id, nome FROM profissionais WHERE ativo = 1 ORDER BY nome ASC LIMIT 200'
            );
            return res.render('agendamentos/form-novo', {
                title: 'Novo Agendamento',
                currentPage: 'agendamentos',
                usuario: req.session.usuario,
                pacientes,
                profissionais,
                error: 'Paciente ou profissional inválido (não encontrado/sem vínculo ativo).'
            });
        }

        const paciente = pacienteRows[0];
        const profissional = profRows[0];

        const [insertResult] = await db.execute(
            `INSERT INTO agendamentos (
                paciente_id, paciente_nome, paciente_cpf,
                profissional_id, profissional_nome,
                data_hora, duracao_minutos, tipo_consulta,
                status, observacoes,
                valor, forma_pagamento, status_pagamento,
                convenio, enviar_lembrete, confirmar_whatsapp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
            ,[
                paciente_id,
                paciente.nome,
                paciente.cpf,
                profissional_id,
                profissional.nome,
                data_hora,
                Number(duracao_minutos),
                tipo_consulta,
                'agendado',
                observacoes || null,
                valor ? Number(valor) : null,
                forma_pagamento || null,
                status_pagamento || null,
                convenio || null,
                enviar_lembrete ? 1 : 0,
                confirmar_whatsapp ? 1 : 0
            ]
        );

        try {
            const agendamentoId = insertResult && insertResult.insertId ? insertResult.insertId : null;
            if (agendamentoId) {
                await syncFinanceiroFromAgendamento(db, {
                    id: agendamentoId,
                    paciente_id,
                    paciente_nome: paciente.nome,
                    data_hora,
                    tipo_consulta,
                    valor: valor ? Number(valor) : null,
                    forma_pagamento: forma_pagamento || null,
                    status_pagamento: status_pagamento || null
                });
            }
        } catch (finErr) {
            console.error('Erro ao gerar lançamento financeiro automático:', finErr);
        }

        // Criar lembretes automáticos (1 dia antes e 1 hora antes)
        try {
            const agendamentoId = insertResult && insertResult.insertId ? insertResult.insertId : null;
            const [pacienteContatoRows] = await db.execute(
                'SELECT telefone FROM pacientes WHERE id = ? LIMIT 1',
                [paciente_id]
            );
            const pacienteTelefone = pacienteContatoRows.length ? pacienteContatoRows[0].telefone : null;

            const envio1Dia = moment(data_hora).subtract(1, 'day').toDate();
            const envio1Hora = moment(data_hora).subtract(1, 'hour').toDate();

            const viaWhats = enviar_lembrete ? 1 : 0;
            const mensagemBase = `🏥 *Clínica Andreia Ballejo - Lembrete de Consulta*\n\n` +
                `Olá *${paciente.nome}*! 😊\n\n` +
                `📅 *Data:* ${moment(data_hora).format('DD/MM/YYYY')}\n` +
                `🕒 *Horário:* ${moment(data_hora).format('HH:mm')}\n` +
                `👨‍⚕️ *Profissional:* ${profissional.nome}\n` +
                `🏷️ *Tipo:* ${tipo_consulta}\n\n` +
                `⏰ *Recomendação:* chegue *15 minutos antes* para recepção e preparo.\n` +
                `🪪 *Traga:* documento com foto e, se tiver, cartão do convênio/guia.\n\n` +
                `✅ Por favor, *confirme sua presença* respondendo esta mensagem.\n` +
                `🔁 Se precisar remarcar/cancelar, avise com antecedência.\n\n` +
                `Até lá!`;

            // 1 dia antes
            await db.execute(
                `INSERT INTO lembretes (paciente_id, profissional_id, tipo, titulo, mensagem, data_envio, status, via_whatsapp, via_email, agenda_id)
                 VALUES (?, ?, 'consulta', ?, ?, ?, 'pendente', ?, 0, NULL)`
                ,[
                    paciente_id,
                    profissional_id,
                    'Lembrete de consulta (1 dia antes)',
                    mensagemBase,
                    envio1Dia,
                    viaWhats
                ]
            );

            // 1 hora antes
            await db.execute(
                `INSERT INTO lembretes (paciente_id, profissional_id, tipo, titulo, mensagem, data_envio, status, via_whatsapp, via_email, agenda_id)
                 VALUES (?, ?, 'consulta', ?, ?, ?, 'pendente', ?, 0, NULL)`
                ,[
                    paciente_id,
                    profissional_id,
                    'Lembrete de consulta (1 hora antes)',
                    mensagemBase,
                    envio1Hora,
                    viaWhats
                ]
            );

            // Guardar telefone no agendamento para uso futuro (se existir coluna)
            void pacienteTelefone;
            void agendamentoId;
        } catch (remErr) {
            console.error('Erro ao criar lembretes automáticos:', remErr);
        }

        res.redirect('/agendamentos?success=Agendamento%20criado%20com%20sucesso');
    } catch (error) {
        console.error('Erro ao criar agendamento:', error);
        try {
            const db = getDB();
            const [pacientes] = await db.execute(
                'SELECT id, nome, cpf FROM pacientes WHERE ativo = 1 ORDER BY nome ASC LIMIT 500'
            );
            const [profissionais] = await db.execute(
                'SELECT id, nome FROM profissionais WHERE ativo = 1 ORDER BY nome ASC LIMIT 200'
            );
            res.render('agendamentos/form-novo', {
                title: 'Novo Agendamento',
                currentPage: 'agendamentos',
                usuario: req.session.usuario,
                pacientes,
                profissionais,
                error: `Erro ao criar agendamento: ${error.message}`
            });
        } catch {
            res.render('agendamentos/form-novo', {
                title: 'Novo Agendamento',
                currentPage: 'agendamentos',
                usuario: req.session.usuario,
                error: 'Erro ao criar agendamento'
            });
        }
    }
});

// AGENDA
app.get('/agenda', requireAuth, requireRoles(['admin', 'medico', 'secretaria']), async (req, res) => {
    try {
        const db = getDB();

        const data = req.query.data || moment().format('YYYY-MM-DD');
        const periodo = req.query.periodo ? String(req.query.periodo) : '';
        const status = req.query.status ? String(req.query.status).toLowerCase() : '';
        const profissionalId = req.query.profissional_id ? Number(req.query.profissional_id) : null;

        let startDate = moment(data, 'YYYY-MM-DD').startOf('day');
        let endDate = moment(data, 'YYYY-MM-DD').endOf('day');

        if (periodo === 'hoje') {
            startDate = moment().startOf('day');
            endDate = moment().endOf('day');
        } else if (periodo === 'semana') {
            startDate = moment().startOf('isoWeek');
            endDate = moment().endOf('isoWeek');
        } else if (periodo === 'mes') {
            startDate = moment().startOf('month');
            endDate = moment().endOf('month');
        }

        const where = ['data_hora >= ? AND data_hora <= ?'];
        const params = [startDate.format('YYYY-MM-DD HH:mm:ss'), endDate.format('YYYY-MM-DD HH:mm:ss')];

        if (status) {
            where.push('LOWER(status) = ?');
            params.push(status);
        }
        if (profissionalId) {
            where.push('profissional_id = ?');
            params.push(profissionalId);
        }

        const [agenda] = await db.execute(
            `SELECT id, paciente_id, paciente_nome, paciente_cpf, profissional_id, profissional_nome,
                    data_hora, duracao_minutos, tipo_consulta, status, observacoes,
                    valor, forma_pagamento, status_pagamento, convenio
             FROM agendamentos
             WHERE ${where.join(' AND ')}
             ORDER BY data_hora ASC, id ASC
             LIMIT 500`,
            params
        );

        const [profissionais] = await db.execute(
            'SELECT id, nome FROM profissionais WHERE ativo = 1 ORDER BY nome ASC LIMIT 200'
        );

        res.render('agenda/lista', {
            title: 'Agenda',
            currentPage: 'agenda',
            usuario: req.session.usuario,
            agenda,
            profissionais,
            filtros: {
                data,
                periodo,
                status,
                profissional_id: profissionalId ? String(profissionalId) : ''
            },
            dataSelecionada: data
        });
    } catch (error) {
        console.error('❌ Erro ao carregar agenda:', error);
        console.error('❌ Stack trace:', error.stack);
        res.render('agenda/lista', { 
            title: 'Agenda',
            currentPage: 'agenda',
            agenda: [],
            profissionais: [],
            filtros: {
                data: moment().format('YYYY-MM-DD'),
                periodo: '',
                status: '',
                profissional_id: ''
            },
            dataSelecionada: moment().format('YYYY-MM-DD'),
            usuario: req.session.usuario,
            error: 'Erro ao carregar agenda: ' + error.message
        });
    }
});

app.get('/agenda/export', requireAuth, requireRoles(['admin', 'medico', 'secretaria']), async (req, res) => {
    try {
        const db = getDB();

        const data = req.query.data || moment().format('YYYY-MM-DD');
        const periodo = req.query.periodo ? String(req.query.periodo) : '';
        const status = req.query.status ? String(req.query.status).toLowerCase() : '';
        const profissionalId = req.query.profissional_id ? Number(req.query.profissional_id) : null;

        let startDate = moment(data, 'YYYY-MM-DD').startOf('day');
        let endDate = moment(data, 'YYYY-MM-DD').endOf('day');
        if (periodo === 'hoje') {
            startDate = moment().startOf('day');
            endDate = moment().endOf('day');
        } else if (periodo === 'semana') {
            startDate = moment().startOf('isoWeek');
            endDate = moment().endOf('isoWeek');
        } else if (periodo === 'mes') {
            startDate = moment().startOf('month');
            endDate = moment().endOf('month');
        }

        const where = ['data_hora >= ? AND data_hora <= ?'];
        const params = [startDate.format('YYYY-MM-DD HH:mm:ss'), endDate.format('YYYY-MM-DD HH:mm:ss')];
        if (status) {
            where.push('LOWER(status) = ?');
            params.push(status);
        }
        if (profissionalId) {
            where.push('profissional_id = ?');
            params.push(profissionalId);
        }

        const filtros = {
            data,
            periodo,
            status,
            profissional_id: profissionalId ? String(profissionalId) : ''
        };

        const [rows] = await db.execute(
            `SELECT id, paciente_nome, paciente_cpf, profissional_nome, data_hora, duracao_minutos, tipo_consulta, status
             FROM agendamentos
             WHERE ${where.join(' AND ')}
             ORDER BY data_hora ASC, id ASC
             LIMIT 2000`,
            params
        );

        const format = String(req.query?.format || 'csv').toLowerCase();
        if (format === 'json') {
            res.setHeader('Content-Type', 'application/json; charset=utf-8');
            res.setHeader('Content-Disposition', 'attachment; filename="agenda.json"');
            return res.send(JSON.stringify({ exported_at: nowIsoLocal(), filtros, agenda: rows || [] }, null, 2));
        }

        const escapeCsv = (v) => {
            if (v == null) return '';
            const s = String(v);
            if (/[\",\n]/.test(s)) return '"' + s.replace(/\"/g, '""') + '"';
            return s;
        };

        const header = ['id', 'paciente', 'cpf', 'profissional', 'data_hora', 'duracao_minutos', 'tipo_consulta', 'status'];
        const lines = [header.join(',')];
        for (const a of (rows || [])) {
            lines.push([
                escapeCsv(a.id),
                escapeCsv(a.paciente_nome),
                escapeCsv(a.paciente_cpf),
                escapeCsv(a.profissional_nome),
                escapeCsv(a.data_hora),
                escapeCsv(a.duracao_minutos),
                escapeCsv(a.tipo_consulta),
                escapeCsv(a.status)
            ].join(','));
        }

        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', 'attachment; filename="agenda.csv"');
        return res.send(lines.join('\n'));
    } catch (error) {
        console.error('Erro ao exportar agenda:', error);
        return res.status(500).send('Erro ao exportar agenda');
    }
});

function formatDateTimeForInput(dt) {
    try {
        if (!dt) return '';
        const d = dt instanceof Date ? dt : new Date(dt);
        if (isNaN(d.getTime())) return '';
        const pad = (n) => String(n).padStart(2, '0');
        return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
    } catch {
        return '';
    }
}

app.get('/agendamentos/:id/editar', requireAuth, requireRoles(['admin', 'medico', 'secretaria']), async (req, res) => {
    try {
        const id = Number(req.params.id);
        if (!id) return res.redirect('/agenda?error=ID%20inv%C3%A1lido');

        const db = getDB();
        const [rows] = await db.execute(
            `SELECT id, paciente_id, paciente_nome, paciente_cpf, profissional_id, profissional_nome,
                    data_hora, duracao_minutos, tipo_consulta, status, observacoes,
                    valor, forma_pagamento, status_pagamento, convenio, enviar_lembrete, confirmar_whatsapp
               FROM agendamentos
              WHERE id = ?
              LIMIT 1`,
            [id]
        );
        if (!rows.length) return res.redirect('/agenda?error=Agendamento%20n%C3%A3o%20encontrado');

        const agendamento = rows[0];
        agendamento.data_hora_form = formatDateTimeForInput(agendamento.data_hora);

        const [pacientes] = await db.execute(
            'SELECT id, nome, cpf FROM pacientes WHERE ativo = 1 ORDER BY nome ASC LIMIT 500'
        );
        const [profissionais] = await db.execute(
            'SELECT id, nome FROM profissionais WHERE ativo = 1 ORDER BY nome ASC LIMIT 200'
        );

        const redirectTo = req.query && req.query.redirect_to ? String(req.query.redirect_to) : '/agenda';

        return res.render('agendamentos/form-editar', {
            title: 'Editar Agendamento',
            currentPage: 'agenda',
            usuario: req.session.usuario,
            agendamento,
            pacientes,
            profissionais,
            redirectTo,
            error: null
        });
    } catch (error) {
        console.error('Erro ao abrir edição de agendamento:', error);
        return res.redirect('/agenda?error=Erro%20ao%20abrir%20edi%C3%A7%C3%A3o');
    }
});

app.get('/agendamentos/:id/remarcar', requireAuth, requireRoles(['admin', 'medico', 'secretaria']), async (req, res) => {
    const id = Number(req.params.id);
    if (!id) return res.redirect('/agenda?error=ID%20inv%C3%A1lido');
    return res.redirect(`/agendamentos/${id}/editar?redirect_to=${encodeURIComponent('/agenda')}`);
});

app.post('/agendamentos/:id/status', requireAuth, requireRoles(['admin', 'medico', 'secretaria']), async (req, res) => {
    try {
        const id = Number(req.params.id);
        if (!id) return res.status(400).json({ success: false, message: 'ID inválido' });

        const status = (req.body?.status || '').toString().trim().toLowerCase();
        const allowed = new Set(['agendado', 'confirmado', 'realizado', 'cancelado']);
        if (!allowed.has(status)) {
            return res.status(400).json({ success: false, message: 'Status inválido' });
        }

        const db = getDB();
        const [rows] = await db.execute('SELECT id FROM agendamentos WHERE id = ? LIMIT 1', [id]);
        if (!rows.length) return res.status(404).json({ success: false, message: 'Agendamento não encontrado' });

        await db.execute('UPDATE agendamentos SET status = ? WHERE id = ?', [status, id]);
        return res.json({ success: true });
    } catch (error) {
        console.error('Erro ao atualizar status do agendamento:', error);
        return res.status(500).json({ success: false, message: 'Erro ao atualizar status' });
    }
});

app.post('/agendamentos/:id/cancelar', requireAuth, requireRoles(['admin', 'medico', 'secretaria']), async (req, res) => {
    try {
        const id = Number(req.params.id);
        if (!id) return res.status(400).json({ success: false, message: 'ID inválido' });

        const db = getDB();
        const [rows] = await db.execute('SELECT id FROM agendamentos WHERE id = ? LIMIT 1', [id]);
        if (!rows.length) return res.status(404).json({ success: false, message: 'Agendamento não encontrado' });

        await db.execute('UPDATE agendamentos SET status = ? WHERE id = ?', ['cancelado', id]);
        return res.json({ success: true });
    } catch (error) {
        console.error('Erro ao cancelar agendamento:', error);
        return res.status(500).json({ success: false, message: 'Erro ao cancelar agendamento' });
    }
});

app.post('/agendamentos/:id/editar', requireAuth, requireRoles(['admin', 'medico', 'secretaria']), async (req, res) => {
    try {
        const id = Number(req.params.id);
        if (!id) return res.redirect('/agenda?error=ID%20inv%C3%A1lido');

        const redirectTo = (req.body && req.body.redirect_to) ? String(req.body.redirect_to) : '/agenda';

        const paciente_id = req.body?.paciente_id ? Number(req.body.paciente_id) : null;
        const profissional_id = req.body?.profissional_id ? Number(req.body.profissional_id) : null;
        const data_hora = (req.body?.data_hora || '').toString().trim();
        const duracao_minutos = req.body?.duracao_minutos ? Number(req.body.duracao_minutos) : NaN;
        const tipo_consulta = (req.body?.tipo_consulta || '').toString().trim();
        const observacoes = (req.body?.observacoes || '').toString();
        const valor = req.body?.valor !== '' && req.body?.valor != null ? Number(req.body.valor) : null;
        const forma_pagamento = (req.body?.forma_pagamento || '').toString().trim() || null;
        const status_pagamento = (req.body?.status_pagamento || '').toString().trim().toLowerCase() || null;
        const convenio = (req.body?.convenio || '').toString().trim() || null;
        const status = (req.body?.status || '').toString().trim().toLowerCase() || 'agendado';
        const enviar_lembrete = req.body?.enviar_lembrete ? 1 : 0;
        const confirmar_whatsapp = req.body?.confirmar_whatsapp ? 1 : 0;

        if (!paciente_id || !profissional_id || !data_hora || !Number.isFinite(duracao_minutos) || duracao_minutos <= 0 || !tipo_consulta) {
            const db = getDB();
            const [pacientes] = await db.execute(
                'SELECT id, nome, cpf FROM pacientes WHERE ativo = 1 ORDER BY nome ASC LIMIT 500'
            );
            const [profissionais] = await db.execute(
                'SELECT id, nome FROM profissionais WHERE ativo = 1 ORDER BY nome ASC LIMIT 200'
            );
            const [rows] = await db.execute(
                `SELECT id, paciente_id, profissional_id, data_hora, duracao_minutos, tipo_consulta, status, observacoes,
                        valor, forma_pagamento, status_pagamento, convenio, enviar_lembrete, confirmar_whatsapp
                   FROM agendamentos WHERE id = ? LIMIT 1`,
                [id]
            );
            const agendamento = rows && rows[0] ? rows[0] : { id };
            agendamento.paciente_id = paciente_id;
            agendamento.profissional_id = profissional_id;
            agendamento.data_hora_form = data_hora;
            agendamento.duracao_minutos = duracao_minutos;
            agendamento.tipo_consulta = tipo_consulta;
            agendamento.observacoes = observacoes;
            agendamento.valor = valor;
            agendamento.forma_pagamento = forma_pagamento;
            agendamento.status_pagamento = status_pagamento;
            agendamento.convenio = convenio;
            agendamento.status = status;
            agendamento.enviar_lembrete = enviar_lembrete;
            agendamento.confirmar_whatsapp = confirmar_whatsapp;

            return res.render('agendamentos/form-editar', {
                title: 'Editar Agendamento',
                currentPage: 'agenda',
                usuario: req.session.usuario,
                agendamento,
                pacientes,
                profissionais,
                redirectTo,
                error: 'Preencha os campos obrigatórios.'
            });
        }

        const dt = new Date(data_hora);
        if (isNaN(dt.getTime())) {
            return res.redirect(`${redirectTo}?error=Data%20inv%C3%A1lida`);
        }

        const allowedStatus = new Set(['agendado', 'confirmado', 'realizado', 'cancelado']);
        const statusFinal = allowedStatus.has(status) ? status : 'agendado';
        const allowedStatusPag = new Set(['pendente', 'pago', 'cancelado']);
        const statusPagFinal = status_pagamento && allowedStatusPag.has(status_pagamento) ? status_pagamento : null;

        const db = getDB();

        const [pacRows] = await db.execute('SELECT nome, cpf FROM pacientes WHERE id = ? AND ativo = 1 LIMIT 1', [paciente_id]);
        if (!pacRows.length) return res.redirect(`${redirectTo}?error=Paciente%20inv%C3%A1lido`);
        const pacienteNome = String(pacRows[0].nome || '');
        const pacienteCpf = String(pacRows[0].cpf || '');

        const [prRows] = await db.execute('SELECT nome FROM profissionais WHERE id = ? AND ativo = 1 LIMIT 1', [profissional_id]);
        if (!prRows.length) return res.redirect(`${redirectTo}?error=Profissional%20inv%C3%A1lido`);
        const profissionalNome = String(prRows[0].nome || '');

        const [beforeRows] = await db.execute(
            `SELECT id, paciente_id, paciente_nome, profissional_id, profissional_nome, data_hora, duracao_minutos,
                    tipo_consulta, status, observacoes, valor, forma_pagamento, status_pagamento, convenio,
                    enviar_lembrete, confirmar_whatsapp
               FROM agendamentos
              WHERE id = ?
              LIMIT 1`,
            [id]
        );
        if (!beforeRows.length) return res.redirect(`${redirectTo}?error=Agendamento%20n%C3%A3o%20encontrado`);

        await db.execute(
            `UPDATE agendamentos
                SET paciente_id = ?, paciente_nome = ?, paciente_cpf = ?,
                    profissional_id = ?, profissional_nome = ?,
                    data_hora = ?, duracao_minutos = ?, tipo_consulta = ?,
                    status = ?, observacoes = ?,
                    valor = ?, forma_pagamento = ?, status_pagamento = ?, convenio = ?,
                    enviar_lembrete = ?, confirmar_whatsapp = ?
              WHERE id = ?`,
            [
                paciente_id, pacienteNome, pacienteCpf,
                profissional_id, profissionalNome,
                dt, duracao_minutos, tipo_consulta,
                statusFinal, observacoes,
                (valor != null && Number.isFinite(valor)) ? valor : null,
                forma_pagamento,
                statusPagFinal,
                convenio,
                enviar_lembrete,
                confirmar_whatsapp,
                id
            ]
        );

        if (statusPagFinal === 'pago') {
            await syncFinanceiroFromAgendamento(db, {
                id,
                paciente_id,
                paciente_nome: pacienteNome,
                data_hora: dt,
                tipo_consulta,
                valor,
                status_pagamento: statusPagFinal,
                forma_pagamento
            });
        }

        return res.redirect(`${redirectTo}?success=Agendamento%20atualizado`);
    } catch (error) {
        console.error('Erro ao editar agendamento:', error);
        return res.redirect('/agenda?error=Erro%20ao%20editar%20agendamento');
    }
});

// LEMBRETES
app.get('/lembretes', requireAuth, requireRoles(['admin', 'medico', 'secretaria']), async (req, res) => {
    try {
        const db = getDB();
        const [lembretes] = await db.execute(
            `SELECT l.id, l.tipo, l.titulo, l.mensagem, l.data_envio, l.status, l.via_whatsapp, l.via_email,
                    p.nome AS paciente_nome, p.telefone AS paciente_telefone,
                    pr.nome AS profissional_nome
             FROM lembretes l
             LEFT JOIN pacientes p ON p.id = l.paciente_id
             LEFT JOIN profissionais pr ON pr.id = l.profissional_id
             ORDER BY l.data_envio DESC, l.id DESC
             LIMIT 500`
        );

        const estatisticas = {
            pendentes: lembretes.filter(l => (l.status || '').toLowerCase() === 'pendente').length,
            enviados: lembretes.filter(l => (l.status || '').toLowerCase() === 'enviado').length,
            falharam: lembretes.filter(l => (l.status || '').toLowerCase() === 'erro').length,
            total: lembretes.length
        };

        res.render('lembretes/lista', {
            title: 'Lembretes',
            currentPage: 'lembretes',
            usuario: req.session.usuario,
            lembretes,
            estatisticas
        });
    } catch (error) {
        console.error('Erro ao listar lembretes:', error);
        res.render('lembretes/lista', {
            title: 'Lembretes',
            currentPage: 'lembretes',
            usuario: req.session.usuario,
            lembretes: [],
            estatisticas: { pendentes: 0, enviados: 0, falharam: 0, total: 0 },
            error: 'Erro ao listar lembretes'
        });
    }
});

app.get('/lembretes/novo', requireAuth, requireRoles(['admin', 'medico', 'secretaria']), async (req, res) => {
    try {
        const db = getDB();
        const [pacientes] = await db.execute(
            'SELECT id, nome, cpf FROM pacientes WHERE ativo = 1 ORDER BY nome ASC LIMIT 500'
        );
        const [profissionais] = await db.execute(
            'SELECT id, nome FROM profissionais WHERE ativo = 1 ORDER BY nome ASC LIMIT 200'
        );

        return res.render('lembretes/form', {
            title: 'Novo Lembrete',
            currentPage: 'lembretes',
            usuario: req.session.usuario,
            lembrete: null,
            pacientes,
            profissionais,
            error: null
        });
    } catch (error) {
        console.error('Erro ao abrir novo lembrete:', error);
        return res.redirect('/lembretes');
    }
});

app.post('/lembretes', requireAuth, requireRoles(['admin', 'medico', 'secretaria']), async (req, res) => {
    try {
        const {
            paciente_id,
            profissional_id,
            tipo,
            titulo,
            mensagem,
            data_envio,
            status,
            via_whatsapp,
            via_email
        } = req.body || {};

        if (!paciente_id || !tipo || !titulo || !mensagem || !data_envio) {
            const db = getDB();
            const [pacientes] = await db.execute(
                'SELECT id, nome, cpf FROM pacientes WHERE ativo = 1 ORDER BY nome ASC LIMIT 500'
            );
            const [profissionais] = await db.execute(
                'SELECT id, nome FROM profissionais WHERE ativo = 1 ORDER BY nome ASC LIMIT 200'
            );

            return res.render('lembretes/form', {
                title: 'Novo Lembrete',
                currentPage: 'lembretes',
                usuario: req.session.usuario,
                lembrete: null,
                pacientes,
                profissionais,
                error: 'Preencha os campos obrigatórios.'
            });
        }

        const db = getDB();
        const pid = Number(paciente_id);
        const profId = profissional_id ? Number(profissional_id) : null;
        const [pacienteRows] = await db.execute(
            'SELECT id FROM pacientes WHERE id = ? AND ativo = 1 LIMIT 1',
            [pid]
        );
        if (!pacienteRows.length) {
            const [pacientes] = await db.execute(
                'SELECT id, nome, cpf FROM pacientes WHERE ativo = 1 ORDER BY nome ASC LIMIT 500'
            );
            const [profissionais] = await db.execute(
                'SELECT id, nome FROM profissionais WHERE ativo = 1 ORDER BY nome ASC LIMIT 200'
            );
            return res.render('lembretes/form', {
                title: 'Novo Lembrete',
                currentPage: 'lembretes',
                usuario: req.session.usuario,
                lembrete: null,
                pacientes,
                profissionais,
                error: 'Paciente inválido.'
            });
        }

        const viaWhats = via_whatsapp ? 1 : 0;
        const viaEmail = via_email ? 1 : 0;
        const st = status ? String(status).toLowerCase() : 'pendente';

        await db.execute(
            `INSERT INTO lembretes (paciente_id, profissional_id, tipo, titulo, mensagem, data_envio, status, via_whatsapp, via_email)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                pid,
                profId,
                String(tipo).toLowerCase(),
                String(titulo).trim(),
                String(mensagem).trim(),
                moment(data_envio).format('YYYY-MM-DD HH:mm:ss'),
                st,
                viaWhats,
                viaEmail
            ]
        );

        return res.redirect('/lembretes');
    } catch (error) {
        console.error('Erro ao criar lembrete:', error);
        return res.redirect('/lembretes');
    }
});

app.get('/lembretes/:id/editar', requireAuth, requireRoles(['admin', 'medico', 'secretaria']), async (req, res) => {
    try {
        const db = getDB();
        const id = Number(req.params.id);
        if (!id) return res.redirect('/lembretes');

        const [rows] = await db.execute(
            'SELECT * FROM lembretes WHERE id = ? LIMIT 1',
            [id]
        );
        if (!rows.length) return res.redirect('/lembretes');

        const [pacientes] = await db.execute(
            'SELECT id, nome, cpf FROM pacientes WHERE ativo = 1 ORDER BY nome ASC LIMIT 500'
        );
        const [profissionais] = await db.execute(
            'SELECT id, nome FROM profissionais WHERE ativo = 1 ORDER BY nome ASC LIMIT 200'
        );

        return res.render('lembretes/form', {
            title: 'Editar Lembrete',
            currentPage: 'lembretes',
            usuario: req.session.usuario,
            lembrete: rows[0],
            pacientes,
            profissionais,
            error: null
        });
    } catch (error) {
        console.error('Erro ao abrir edição de lembrete:', error);
        return res.redirect('/lembretes');
    }
});

app.post('/lembretes/:id/editar', requireAuth, requireRoles(['admin', 'medico', 'secretaria']), async (req, res) => {
    try {
        const db = getDB();
        const id = Number(req.params.id);
        if (!id) return res.redirect('/lembretes');

        const {
            paciente_id,
            profissional_id,
            tipo,
            titulo,
            mensagem,
            data_envio,
            status,
            via_whatsapp,
            via_email
        } = req.body || {};

        if (!paciente_id || !tipo || !titulo || !mensagem || !data_envio) {
            const [rows] = await db.execute('SELECT * FROM lembretes WHERE id = ? LIMIT 1', [id]);
            const [pacientes] = await db.execute(
                'SELECT id, nome, cpf FROM pacientes WHERE ativo = 1 ORDER BY nome ASC LIMIT 500'
            );
            const [profissionais] = await db.execute(
                'SELECT id, nome FROM profissionais WHERE ativo = 1 ORDER BY nome ASC LIMIT 200'
            );

            return res.render('lembretes/form', {
                title: 'Editar Lembrete',
                currentPage: 'lembretes',
                usuario: req.session.usuario,
                lembrete: rows.length ? rows[0] : null,
                pacientes,
                profissionais,
                error: 'Preencha os campos obrigatórios.'
            });
        }

        const pid = Number(paciente_id);
        const profId = profissional_id ? Number(profissional_id) : null;
        const viaWhats = via_whatsapp ? 1 : 0;
        const viaEmail = via_email ? 1 : 0;
        const st = status ? String(status).toLowerCase() : 'pendente';

        await db.execute(
            `UPDATE lembretes
             SET paciente_id = ?, profissional_id = ?, tipo = ?, titulo = ?, mensagem = ?, data_envio = ?, status = ?, via_whatsapp = ?, via_email = ?
             WHERE id = ?
             LIMIT 1`,
            [
                pid,
                profId,
                String(tipo).toLowerCase(),
                String(titulo).trim(),
                String(mensagem).trim(),
                moment(data_envio).format('YYYY-MM-DD HH:mm:ss'),
                st,
                viaWhats,
                viaEmail,
                id
            ]
        );

        return res.redirect('/lembretes');
    } catch (error) {
        console.error('Erro ao editar lembrete:', error);
        return res.redirect('/lembretes');
    }
});

app.get('/api/lembretes/:id', requireAuth, requireRoles(['admin', 'medico', 'secretaria']), async (req, res) => {
    try {
        const db = getDB();
        const id = Number(req.params.id);
        if (!id) return res.status(400).json({ success: false, message: 'ID inválido' });

        const [rows] = await db.execute(
            `SELECT l.id, l.tipo, l.titulo, l.mensagem, l.data_envio, l.status, l.via_whatsapp, l.via_email,
                    l.tentativas, l.ultimo_erro,
                    p.nome AS paciente_nome, p.telefone AS paciente_telefone,
                    pr.nome AS profissional_nome
             FROM lembretes l
             LEFT JOIN pacientes p ON p.id = l.paciente_id
             LEFT JOIN profissionais pr ON pr.id = l.profissional_id
             WHERE l.id = ?
             LIMIT 1`,
            [id]
        );

        if (!rows.length) return res.status(404).json({ success: false, message: 'Lembrete não encontrado' });
        return res.json({ success: true, lembrete: rows[0] });
    } catch (error) {
        console.error('Erro ao obter lembrete:', error);
        return res.status(500).json({ success: false, message: 'Erro ao obter lembrete' });
    }
});

app.post('/lembretes/:id/enviar', requireAuth, requireRoles(['admin', 'medico', 'secretaria']), async (req, res) => {
    try {
        const db = getDB();
        const retryMinutes = Number(process.env.REMINDER_RETRY_INTERVAL_MINUTES || 5);
        const maxAttempts = Number(process.env.REMINDER_MAX_ATTEMPTS || 20);
        const id = Number(req.params.id);
        if (!id) {
            return res.status(400).json({ success: false, message: 'ID inválido' });
        }

        const [rows] = await db.execute(
            `SELECT l.id, l.mensagem, l.via_whatsapp, l.status, l.tentativas,
                    p.telefone AS paciente_telefone
             FROM lembretes l
             LEFT JOIN pacientes p ON p.id = l.paciente_id
             WHERE l.id = ?
             LIMIT 1`,
            [id]
        );

        if (!rows.length) {
            return res.status(404).json({ success: false, message: 'Lembrete não encontrado' });
        }

        const lembrete = rows[0];
        if (!lembrete.via_whatsapp) {
            return res.status(400).json({ success: false, message: 'Este lembrete não está configurado para WhatsApp' });
        }

        const status = whatsappService.getStatus();
        if (!status || !status.isConnected) {
            return res.status(409).json({ success: false, message: 'WhatsApp não está conectado' });
        }

        if (!lembrete.paciente_telefone) {
            await db.execute(
                "UPDATE lembretes SET status = 'erro', data_envio_real = NOW() WHERE id = ?",
                [id]
            );
            return res.status(400).json({ success: false, message: 'Paciente sem telefone cadastrado' });
        }

        try {
            await whatsappService.sendMessage(lembrete.paciente_telefone, lembrete.mensagem || 'Lembrete');
            await db.execute(
                "UPDATE lembretes SET status = 'enviado', data_envio_real = NOW() WHERE id = ?",
                [id]
            );
        } catch (sendErr) {
            const attempts = Number(lembrete.tentativas || 0) + 1;
            const errMsg = sendErr && sendErr.message ? String(sendErr.message).slice(0, 250) : 'Erro ao enviar';
            console.error('Falha ao enviar lembrete manualmente (WhatsApp):', id, errMsg, `tentativa ${attempts}/${maxAttempts}`);

            if (attempts >= maxAttempts) {
                await db.execute(
                    "UPDATE lembretes SET status = 'erro', data_envio_real = NOW(), tentativas = ?, ultimo_erro = ? WHERE id = ?",
                    [attempts, errMsg, id]
                );
            } else {
                await db.execute(
                    "UPDATE lembretes SET status = 'pendente', tentativas = ?, ultimo_erro = ?, data_envio = DATE_ADD(NOW(), INTERVAL ? MINUTE) WHERE id = ?",
                    [attempts, errMsg, retryMinutes, id]
                );
            }

            return res.status(500).json({ success: false, message: 'Erro ao enviar; reagendado para nova tentativa' });
        }

        return res.json({ success: true });
    } catch (error) {
        console.error('Erro ao enviar lembrete manualmente:', error);
        return res.status(500).json({ success: false, message: 'Erro ao enviar lembrete' });
    }
});

app.post('/lembretes/:id/excluir', requireAuth, requireRoles(['admin', 'medico', 'secretaria']), async (req, res) => {
    try {
        const db = getDB();
        const id = Number(req.params.id);
        if (!id) {
            return res.status(400).json({ success: false, message: 'ID inválido' });
        }

        await db.execute('DELETE FROM lembretes WHERE id = ? LIMIT 1', [id]);
        return res.json({ success: true });
    } catch (error) {
        console.error('Erro ao excluir lembrete:', error);
        return res.status(500).json({ success: false, message: 'Erro ao excluir lembrete' });
    }
});

// Middleware de validação e tratamento de erros
app.use((err, req, res, next) => {
    console.error('Erro global:', err);
    
    // Erros de validação
    if (err && err.name === 'ValidationError') {
        return res.status(400).json({
            success: false,
            message: 'Dados inválidos',
            errors: err.details
        });
    }
    
    // Erros de banco de dados
    if (err && err.code === 'ER_DUP_ENTRY') {
        return res.status(409).json({
            success: false,
            message: 'Registro já existe'
        });
    }
    
    // Erro padrão
    res.status((err && err.status) || 500).json({
        success: false,
        message: (err && err.message) ? err.message : 'Erro interno do servidor'
    });
});

// Inicialização do servidor
async function startServer() {
    try {
        // Inicializar banco de dados
        await initDB();

        // Tabela para recuperação de senha
        try {
            const db = getDB();
            await ensureAccessControlTables(db);
            await db.execute(`
                CREATE TABLE IF NOT EXISTS password_resets (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    email VARCHAR(191) NOT NULL,
                    token_hash CHAR(64) NOT NULL,
                    code_hash VARCHAR(255) NOT NULL,
                    expires_at DATETIME NOT NULL,
                    used_at DATETIME NULL,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    ip_address VARCHAR(64) NULL,
                    user_agent VARCHAR(255) NULL,
                    INDEX idx_pr_user (user_id),
                    INDEX idx_pr_email (email),
                    INDEX idx_pr_token (token_hash),
                    INDEX idx_pr_expires (expires_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            `);
        } catch (e) {
            console.error('Erro ao garantir tabela password_resets:', e);
        }

        // Garantir tabela de agendamentos (MVP)
        try {
            const db = getDB();
            await db.execute(`
                CREATE TABLE IF NOT EXISTS agendamentos (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    paciente_id INT NOT NULL,
                    paciente_nome VARCHAR(255) NOT NULL,
                    paciente_cpf VARCHAR(32) NULL,
                    profissional_id INT NOT NULL,
                    profissional_nome VARCHAR(255) NOT NULL,
                    data_hora DATETIME NOT NULL,
                    duracao_minutos INT NOT NULL DEFAULT 30,
                    tipo_consulta VARCHAR(64) NOT NULL,
                    status VARCHAR(32) NOT NULL DEFAULT 'agendado',
                    observacoes TEXT NULL,
                    valor DECIMAL(10,2) NULL,
                    forma_pagamento VARCHAR(32) NULL,
                    status_pagamento VARCHAR(32) NULL,
                    convenio VARCHAR(64) NULL,
                    enviar_lembrete TINYINT(1) NOT NULL DEFAULT 1,
                    confirmar_whatsapp TINYINT(1) NOT NULL DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX idx_data_hora (data_hora),
                    INDEX idx_paciente_id (paciente_id),
                    INDEX idx_profissional_id (profissional_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            `);

            // Se a tabela já existia com outro schema, garantir colunas mínimas via ALTER TABLE
            const ensureColumn = async (sql) => {
                try {
                    await db.execute(sql);
                } catch (e) {
                    // ER_DUP_FIELDNAME / ER_DUP_KEYNAME
                    if (e && (e.code === 'ER_DUP_FIELDNAME' || e.code === 'ER_DUP_KEYNAME')) return;
                    // Em alguns casos, MySQL pode retornar parse errors dependendo da versão
                    console.error('Erro ao aplicar migração de agendamentos:', e);
                }
            };

            await ensureColumn("ALTER TABLE agendamentos ADD COLUMN paciente_nome VARCHAR(255) NULL");
            await ensureColumn("ALTER TABLE agendamentos ADD COLUMN paciente_cpf VARCHAR(32) NULL");
            await ensureColumn("ALTER TABLE agendamentos ADD COLUMN profissional_nome VARCHAR(255) NULL");
            await ensureColumn("ALTER TABLE agendamentos ADD COLUMN duracao_minutos INT NOT NULL DEFAULT 30");
            await ensureColumn("ALTER TABLE agendamentos ADD COLUMN tipo_consulta VARCHAR(64) NULL");
            await ensureColumn("ALTER TABLE agendamentos ADD COLUMN status VARCHAR(32) NOT NULL DEFAULT 'agendado'");
            await ensureColumn("ALTER TABLE agendamentos ADD COLUMN observacoes TEXT NULL");
            await ensureColumn("ALTER TABLE agendamentos ADD COLUMN valor DECIMAL(10,2) NULL");
            await ensureColumn("ALTER TABLE agendamentos ADD COLUMN forma_pagamento VARCHAR(32) NULL");
            await ensureColumn("ALTER TABLE agendamentos ADD COLUMN status_pagamento VARCHAR(32) NULL");
            await ensureColumn("ALTER TABLE agendamentos ADD COLUMN convenio VARCHAR(64) NULL");
            await ensureColumn("ALTER TABLE agendamentos ADD COLUMN enviar_lembrete TINYINT(1) NOT NULL DEFAULT 1");
            await ensureColumn("ALTER TABLE agendamentos ADD COLUMN confirmar_whatsapp TINYINT(1) NOT NULL DEFAULT 1");
            await ensureColumn("ALTER TABLE agendamentos ADD COLUMN data_hora DATETIME NULL");

            // Garantir tipos (caso existam como ENUM/VARCHAR curto)
            await ensureColumn("ALTER TABLE agendamentos MODIFY COLUMN tipo_consulta VARCHAR(64) NULL");
            await ensureColumn("ALTER TABLE agendamentos MODIFY COLUMN status VARCHAR(32) NOT NULL DEFAULT 'agendado'");
            await ensureColumn("ALTER TABLE agendamentos MODIFY COLUMN forma_pagamento VARCHAR(32) NULL");
            await ensureColumn("ALTER TABLE agendamentos MODIFY COLUMN status_pagamento VARCHAR(32) NULL");
            await ensureColumn("ALTER TABLE agendamentos MODIFY COLUMN convenio VARCHAR(64) NULL");

            await ensureColumn("ALTER TABLE agendamentos ADD INDEX idx_data_hora (data_hora)");
            await ensureColumn("ALTER TABLE agendamentos ADD INDEX idx_paciente_id (paciente_id)");
            await ensureColumn("ALTER TABLE agendamentos ADD INDEX idx_profissional_id (profissional_id)");

            await ensureColumn("ALTER TABLE lembretes ADD COLUMN tentativas INT NOT NULL DEFAULT 0");
            await ensureColumn("ALTER TABLE lembretes ADD COLUMN ultimo_erro VARCHAR(255) NULL");

            try {
                const [tipoRows] = await db.execute(
                    `SELECT DATA_TYPE, COLUMN_TYPE
                     FROM information_schema.columns
                     WHERE table_schema = DATABASE()
                       AND table_name = 'lembretes'
                       AND column_name = 'tipo'
                     LIMIT 1`
                );

                const tipoRow = (tipoRows && tipoRows[0]) ? tipoRows[0] : null;
                const columnType = tipoRow && tipoRow.COLUMN_TYPE ? String(tipoRow.COLUMN_TYPE) : '';

                if (!columnType.toLowerCase().includes('aniversario')) {
                    await ensureColumn("ALTER TABLE lembretes MODIFY COLUMN tipo ENUM('consulta','medicamento','exame','pagamento','outro','aniversario') DEFAULT NULL");
                }
            } catch (e) {
                console.error('Erro ao garantir tipo de lembretes (aniversario):', e);
            }

            try {
                const db = getDB();
                await db.execute(`
                    CREATE TABLE IF NOT EXISTS app_config (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        chave VARCHAR(191) NOT NULL,
                        valor TEXT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                        UNIQUE KEY uq_app_config_chave (chave)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                `);

                try {
                    await scheduleAutoBackup();
                } catch (e) {
                    console.error('Erro ao iniciar agendamento de backup automático:', e);
                }

                await db.execute(`
                    CREATE TABLE IF NOT EXISTS financeiro (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        tipo VARCHAR(16) NOT NULL,
                        descricao VARCHAR(255) NOT NULL,
                        paciente_id INT NULL,
                        paciente_nome VARCHAR(255) NULL,
                        agendamento_id INT NULL,
                        valor DECIMAL(10,2) NOT NULL DEFAULT 0,
                        status VARCHAR(32) NOT NULL DEFAULT 'pendente',
                        data_cadastro DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        forma_pagamento VARCHAR(32) NULL,
                        categoria VARCHAR(64) NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                        UNIQUE KEY uq_financeiro_agendamento (agendamento_id),
                        INDEX idx_financeiro_data (data_cadastro),
                        INDEX idx_financeiro_tipo (tipo)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                `);

                try {
                    await db.execute(`
                        CREATE TABLE IF NOT EXISTS prontuarios (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            paciente_id INT NOT NULL,
                            profissional_id INT NOT NULL,
                            data_atendimento DATE NOT NULL,
                            tipo_atendimento VARCHAR(64) NOT NULL,
                            queixa_principal VARCHAR(255) NOT NULL,
                            historia_doenca TEXT NOT NULL,
                            historia_patologica TEXT NULL,
                            historia_fisiologica TEXT NULL,
                            exame_fisico TEXT NULL,
                            diagnostico TEXT NOT NULL,
                            plano_tratamento TEXT NOT NULL,
                            prognostico TEXT NULL,
                            observacoes TEXT NULL,
                            status VARCHAR(32) NOT NULL DEFAULT 'em_andamento',
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                            INDEX idx_prontuarios_paciente (paciente_id),
                            INDEX idx_prontuarios_profissional (profissional_id),
                            INDEX idx_prontuarios_data (data_atendimento)
                        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                    `);

                    await db.execute(`
                        CREATE TABLE IF NOT EXISTS prontuario_evolucoes (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            prontuario_id INT NOT NULL,
                            texto TEXT NOT NULL,
                            data_evolucao DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                            INDEX idx_pe_prontuario (prontuario_id),
                            INDEX idx_pe_data (data_evolucao)
                        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                    `);

                    const ensureProntuarios = async (sql) => {
                        try {
                            await db.execute(sql);
                        } catch (e) {
                            if (e && (e.code === 'ER_DUP_FIELDNAME' || e.code === 'ER_DUP_KEYNAME')) return;
                            console.error('Erro ao aplicar migração prontuarios:', e);
                        }
                    };

                    await ensureProntuarios("ALTER TABLE prontuarios ADD COLUMN paciente_id INT NOT NULL");
                    await ensureProntuarios("ALTER TABLE prontuarios ADD COLUMN profissional_id INT NOT NULL");
                    await ensureProntuarios("ALTER TABLE prontuarios ADD COLUMN data_atendimento DATE NOT NULL");
                    await ensureProntuarios("ALTER TABLE prontuarios ADD COLUMN tipo_atendimento VARCHAR(64) NOT NULL");
                    await ensureProntuarios("ALTER TABLE prontuarios ADD COLUMN queixa_principal VARCHAR(255) NOT NULL");
                    await ensureProntuarios("ALTER TABLE prontuarios ADD COLUMN historia_doenca TEXT NOT NULL");
                    await ensureProntuarios("ALTER TABLE prontuarios ADD COLUMN historia_patologica TEXT NULL");
                    await ensureProntuarios("ALTER TABLE prontuarios ADD COLUMN historia_fisiologica TEXT NULL");
                    await ensureProntuarios("ALTER TABLE prontuarios ADD COLUMN exame_fisico TEXT NULL");
                    await ensureProntuarios("ALTER TABLE prontuarios ADD COLUMN diagnostico TEXT NOT NULL");
                    await ensureProntuarios("ALTER TABLE prontuarios ADD COLUMN plano_tratamento TEXT NOT NULL");
                    await ensureProntuarios("ALTER TABLE prontuarios ADD COLUMN prognostico TEXT NULL");
                    await ensureProntuarios("ALTER TABLE prontuarios ADD COLUMN observacoes TEXT NULL");
                    await ensureProntuarios("ALTER TABLE prontuarios ADD COLUMN status VARCHAR(32) NOT NULL DEFAULT 'em_andamento'");
                    await ensureProntuarios("ALTER TABLE prontuarios ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP");
                    await ensureProntuarios("ALTER TABLE prontuarios ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP");
                    await ensureProntuarios("ALTER TABLE prontuarios ADD INDEX idx_prontuarios_paciente (paciente_id)");
                    await ensureProntuarios("ALTER TABLE prontuarios ADD INDEX idx_prontuarios_profissional (profissional_id)");
                    await ensureProntuarios("ALTER TABLE prontuarios ADD INDEX idx_prontuarios_data (data_atendimento)");

                    const ensureEvolucoes = async (sql) => {
                        try {
                            await db.execute(sql);
                        } catch (e) {
                            if (e && (e.code === 'ER_DUP_FIELDNAME' || e.code === 'ER_DUP_KEYNAME')) return;
                            console.error('Erro ao aplicar migração prontuario_evolucoes:', e);
                        }
                    };

                    await ensureEvolucoes("ALTER TABLE prontuario_evolucoes ADD COLUMN prontuario_id INT NOT NULL");
                    await ensureEvolucoes("ALTER TABLE prontuario_evolucoes ADD COLUMN texto TEXT NOT NULL");
                    await ensureEvolucoes("ALTER TABLE prontuario_evolucoes ADD COLUMN data_evolucao DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP");
                    await ensureEvolucoes("ALTER TABLE prontuario_evolucoes ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP");
                    await ensureEvolucoes("ALTER TABLE prontuario_evolucoes ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP");
                    await ensureEvolucoes("ALTER TABLE prontuario_evolucoes ADD INDEX idx_pe_prontuario (prontuario_id)");
                    await ensureEvolucoes("ALTER TABLE prontuario_evolucoes ADD INDEX idx_pe_data (data_evolucao)");
                } catch (e) {
                    console.error('Erro ao garantir tabelas de prontuários:', e);
                }

                const ensureFinanceiro = async (sql) => {
                    try {
                        await db.execute(sql);
                    } catch (e) {
                        if (e && (e.code === 'ER_DUP_FIELDNAME' || e.code === 'ER_DUP_KEYNAME')) return;
                        console.error('Erro ao aplicar migração financeiro:', e);
                    }
                };

                await ensureFinanceiro("ALTER TABLE financeiro ADD COLUMN descricao VARCHAR(255) NOT NULL");
                await ensureFinanceiro("ALTER TABLE financeiro ADD COLUMN tipo VARCHAR(16) NOT NULL");
                await ensureFinanceiro("ALTER TABLE financeiro ADD COLUMN paciente_id INT NULL");
                await ensureFinanceiro("ALTER TABLE financeiro ADD COLUMN paciente_nome VARCHAR(255) NULL");
                await ensureFinanceiro("ALTER TABLE financeiro ADD COLUMN agendamento_id INT NULL");
                await ensureFinanceiro("ALTER TABLE financeiro ADD COLUMN valor DECIMAL(10,2) NOT NULL DEFAULT 0");
                await ensureFinanceiro("ALTER TABLE financeiro ADD COLUMN status VARCHAR(32) NOT NULL DEFAULT 'pendente'");
                await ensureFinanceiro("ALTER TABLE financeiro ADD COLUMN data_cadastro DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP");
                await ensureFinanceiro("ALTER TABLE financeiro ADD COLUMN forma_pagamento VARCHAR(32) NULL");
                await ensureFinanceiro("ALTER TABLE financeiro ADD COLUMN categoria VARCHAR(64) NULL");
                await ensureFinanceiro("ALTER TABLE financeiro ADD UNIQUE KEY uq_financeiro_agendamento (agendamento_id)");
                await ensureFinanceiro("ALTER TABLE financeiro ADD INDEX idx_financeiro_data (data_cadastro)");
                await ensureFinanceiro("ALTER TABLE financeiro ADD INDEX idx_financeiro_tipo (tipo)");
            } catch (tableError) {
                console.error('Erro ao garantir tabela financeiro:', tableError);
            }

        } catch (tableError) {
            console.error('Erro ao garantir tabela agendamentos:', tableError);
        }

        // ===============================
// CONFIGURAÇÃO DE HOST E PORTA
// ===============================
const HOST = '0.0.0.0';
const PORT = process.env.PORT || 3000;

// ===============================
// INICIAR SERVIDOR
// ===============================
app.listen(PORT, HOST, () => {
    console.log('======================================');
    console.log(`🚀 Servidor rodando`);
    console.log(`🌐 Local:   http://localhost:${PORT}`);
    console.log(`🌐 Externo: http://SEU_IP_PUBLICO:${PORT}`);
    console.log('WhatsApp: inicialização manual pelo painel (/whatsapp)');
    console.log('======================================');

    // ===============================
    // CRON DE LEMBRETES
    // ===============================
    if (!reminderCronStarted) {
        reminderCronStarted = true;

        cron.schedule('* * * * *', async () => {
            try {
                await processarLembretesPendentes();
            } catch (err) {
                console.error('Erro ao processar lembretes:', err);
            }
        });

        cron.schedule('5 7 * * *', async () => {
            try {
                await criarLembretesAniversarioInternos();
            } catch (err) {
                console.error('Erro ao criar lembretes de aniversário:', err);
            }
        });
    }

    // ===============================
    // SERVIÇOS APÓS START
    // ===============================
    setTimeout(() => {
        console.log('🚀 Iniciando sistema de envio de lembretes...');
        // const agendaService = require('./agendaService');
        // agendaService.iniciarEnvioLembretes();
    }, 5000);

    setTimeout(() => {
        void criarLembretesAniversarioInternos();
    }, 7000);
});

    } catch (error) {
        console.error('Erro ao iniciar servidor:', error);
    }
}

module.exports = app;

startServer();
