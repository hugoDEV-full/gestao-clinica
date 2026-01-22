require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const moment = require('moment');
const fs = require('fs');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const cron = require('node-cron');
const expressLayouts = require('express-ejs-layouts');

const archiver = require('archiver');
const unzipper = require('unzipper');

const os = require('os');

// Importar serviços
const { initDB, getDB } = require('./database');

// WhatsApp Service
const whatsappService = require('./whatsappService.js');

const app = express();

// Middleware de validação e tratamento de erros
app.use((err, req, res, next) => {
    console.error('Erro global:', err);
    
    // Erros de validação
    if (err.name === 'ValidationError') {
        return res.status(400).json({
            success: false,
            message: 'Dados inválidos',
            errors: err.details
        });
    }
    
    // Erros de banco de dados
    if (err.code === 'ER_DUP_ENTRY') {
        return res.status(409).json({
            success: false,
            message: 'Registro já existe'
        });
    }
    
    // Erro padrão
    res.status(err.status || 500).json({
        success: false,
        message: err.message || 'Erro interno do servidor'
    });
});

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
const sessionSecret = process.env.SESSION_SECRET || 'segredo_padrao_muito_secreto';
if (isProd && sessionSecret === 'segredo_padrao_muito_secreto') {
    console.warn('SESSION_SECRET não configurado em produção. Configure SESSION_SECRET no .env');
}
app.use(session({
    secret: sessionSecret,
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
    if (!t) return { tipo: 'secretaria', error: null };
    if (!allowed.has(t)) {
        return { tipo: null, error: 'Tipo inválido. Use: admin, medico, secretaria, paciente' };
    }
    return { tipo: t, error: null };
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

app.get('/whatsapp', requireAuth, (req, res) => {
    res.render('whatsapp-teste', {
        title: 'WhatsApp',
        currentPage: 'whatsapp',
        usuario: req.session.usuario
    });
});

app.get('/api/whatsapp/status-teste', requireAuth, (req, res) => {
    try {
        res.json({ success: true, status: whatsappService.getStatus() });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Erro ao obter status do WhatsApp' });
    }
});

app.get('/api/whatsapp/qrcode-teste', requireAuth, (req, res) => {
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
        return res.status(500).json({ success: false, message: 'Erro ao iniciar WhatsApp' });
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
            dateString = dateValue.toISOString().split('T')[0];
        } else if (typeof dateValue === 'string') {
            console.log('formatDateForInput - É string');
            dateString = dateValue;
        } else {
            console.log('formatDateForInput - Tipo não reconhecido');
            return '';
        }
        
        console.log('formatDateForInput - String processada:', dateString);
        
        // Se já estiver no formato YYYY-MM-DD, retorna direto
        if (dateString && dateString.match(/^\d{4}-\d{2}-\d{2}$/)) {
            console.log('formatDateForInput - Já está no formato correto:', dateString);
            return dateString;
        }
        
        // Tenta converter para objeto Date
        const date = new Date(dateString);
        console.log('formatDateForInput - Date object:', date);
        
        if (isNaN(date.getTime())) {
            console.log('formatDateForInput - Data inválida!');
            return '';
        }
        
        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const day = String(date.getDate()).padStart(2, '0');
        
        const formatted = `${year}-${month}-${day}`;
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
    res.redirect('/login');
});

app.get('/login', (req, res) => {
    const registrar = String(req.query.registrar || '').trim();
    const info = registrar ? 'O cadastro de novos usuários é feito pelo administrador. Após entrar como admin, acesse o menu Usuários.' : null;
    res.render('login', { error: null, info });
});

app.post('/login', authLimiter, async (req, res) => {
    const { email, senha } = req.body;
    try {
        const db = getDB();
        const [usuarios] = await db.execute('SELECT * FROM usuarios WHERE email = ? AND ativo = TRUE', [email]);
        if (usuarios.length === 0) {
            return res.render('login', { error: 'Usuário ou senha inválidos', info: null });
        }
        
        const usuario = usuarios[0];
        const senhaValida = await bcrypt.compare(senha, usuario.senha);
        
        if (!senhaValida) {
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
        console.log(`Usuário ${usuario.nome} (${usuario.email}) fez login em ${new Date().toISOString()}`);
        
        // Registrar no log LGPD
        try {
            await logLGPD(
                usuario.id, 
                'LOGIN', 
                'sessao', 
                null, 
                null, 
                JSON.stringify({ 
                    login_time: new Date().toISOString(),
                    ip: req.ip,
                    user_agent: req.get('User-Agent')
                }),
                req
            );
        } catch (logError) {
            console.error('Erro ao registrar login no LGPD:', logError);
        }
        
        res.redirect('/dashboard');
    } catch (error) {
        console.error('Erro no login:', error);
        res.render('login', { error: 'Erro ao fazer login', info: null });
    }
});

// Rota de logout melhorada
app.get('/logout', async (req, res) => {
    try {
        // Registrar logout no log de auditoria se houver usuário
        if (req.session.usuario) {
            console.log(`Usuário ${req.session.usuario.nome} (${req.session.usuario.email}) fez logout`);
            
            // Registrar no log LGPD se disponível
            try {
                await logLGPD(
                    req.session.usuario.id, 
                    'LOGOUT', 
                    'sessao', 
                    null, 
                    JSON.stringify({ login_time: req.session.loginTime }), 
                    null,
                    req
                );
            } catch (logError) {
                console.error('Erro ao registrar logout no LGPD:', logError);
            }
        }
        
        // Destruir sessão
        req.session.destroy((err) => {
            if (err) {
                console.error('Erro ao destruir sessão:', err);
            }
            res.redirect('/login');
        });
    } catch (error) {
        console.error('Erro no logout:', error);
        res.redirect('/login');
    }
});

// DASHBOARD
app.get('/dashboard', requireAuth, async (req, res) => {
    try {
        const db = getDB();
        
        // Estatísticas
        const [pacientesCount] = await db.execute('SELECT COUNT(*) as count FROM pacientes WHERE ativo = TRUE');
        const [consultasHoje] = await db.execute('SELECT COUNT(*) as count FROM agenda WHERE DATE(data_hora) = CURDATE()');
        const [consultasMes] = await db.execute('SELECT COUNT(*) as count FROM agenda WHERE MONTH(data_hora) = MONTH(CURDATE()) AND YEAR(data_hora) = YEAR(CURDATE())');
        const [lembretesPendentes] = await db.execute('SELECT COUNT(*) as count FROM lembretes WHERE status = "pendente"');
        
        // Receitas do mês
        const [receitasMes] = await db.execute(`
            SELECT COALESCE(SUM(valor), 0) as total 
            FROM financeiro 
            WHERE tipo = 'receita' 
            AND MONTH(data_cadastro) = MONTH(CURDATE()) 
            AND YEAR(data_cadastro) = YEAR(CURDATE())
        `);
        
        // Consultas recentes
        const [consultasRecentes] = await db.execute(`
            SELECT a.*, p.nome as paciente_nome 
            FROM agenda a 
            JOIN pacientes p ON a.paciente_id = p.id 
            WHERE a.data_hora >= NOW() - INTERVAL 7 DAY
            ORDER BY a.data_hora DESC 
            LIMIT 5
        `);
        
        // Próximas consultas (24 horas)
        const [proximasConsultas] = await db.execute(`
            SELECT a.*, p.nome as paciente_nome, pr.nome as profissional_nome
            FROM agenda a 
            JOIN pacientes p ON a.paciente_id = p.id 
            LEFT JOIN profissionais pr ON a.profissional_id = pr.id 
            WHERE a.data_hora BETWEEN NOW() AND NOW() + INTERVAL 24 HOUR
            ORDER BY a.data_hora ASC 
            LIMIT 10
        `);
        
        // Lembretes recentes
        const [lembretesRecentes] = await db.execute(`
            SELECT l.*, p.nome as paciente_nome 
            FROM lembretes l 
            JOIN pacientes p ON l.paciente_id = p.id 
            WHERE l.data_envio >= NOW() - INTERVAL 7 DAY
            ORDER BY l.data_envio DESC 
            LIMIT 5
        `);
        
        res.render('dashboard/index', { 
            usuario: req.session.usuario,
            currentPage: 'dashboard',
            estatisticas: {
                totalPacientes: pacientesCount[0].count,
                consultasHoje: consultasHoje[0].count,
                proximasConsultas: proximasConsultas.length,
                faturamentoMes: parseFloat(receitasMes[0].total) || 0,
                consultasSemana: [12, 19, 15, 25, 22, 18, 14] // Dados mock para gráfico
            },
            proximasConsultas,
            lembretesPendentes: lembretesPendentes[0].count,
            consultasRecentes,
            lembretesRecentes
        });
    } catch (error) {
        console.error('Erro no dashboard:', error);
        res.render('dashboard/index', { 
            usuario: req.session.usuario,
            currentPage: 'dashboard',
            error: 'Erro ao carregar dashboard'
        });
    }
});

app.get('/perfil', requireAuth, (req, res) => {
    res.render('perfil', {
        title: 'Meu Perfil',
        currentPage: 'perfil',
        usuario: req.session.usuario
    });
});

app.get('/ajuda', requireAuth, (req, res) => {
    res.render('ajuda', {
        title: 'Ajuda',
        currentPage: 'ajuda',
        usuario: req.session.usuario
    });
});

app.get('/prontuarios', requireAuth, (req, res) => {
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
                prontuarios,
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

app.get('/api/prontuarios/:id', requireAuth, async (req, res) => {
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

        const [evolucoes] = await db.execute(
            'SELECT * FROM prontuario_evolucoes WHERE prontuario_id = ? ORDER BY data_evolucao DESC, id DESC LIMIT 200',
            [id]
        );

        return res.json({ success: true, prontuario: rows[0], evolucoes });
    } catch (error) {
        console.error('Erro ao carregar prontuário:', error);
        return res.status(500).json({ success: false, message: 'Erro ao carregar prontuário' });
    }
});

app.post('/prontuarios', requireAuth, async (req, res) => {
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

app.post('/prontuarios/:id/evolucoes', requireAuth, async (req, res) => {
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

app.get('/prontuarios/:id/imprimir', requireAuth, async (req, res) => {
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
    const dbName = process.env.DB_NAME || 'gestao_fisio';
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
        const dbName = process.env.DB_NAME || 'gestao_fisio';
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
            const db = getDB();

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
                resumo: {
                    receitasMes: receitas,
                    despesasMes: despesas,
                    saldoMes: receitas - despesas,
                    saldoAcumulado: Number(saldoAcumulado?.[0]?.total || 0)
                },
                lancamentos
            });
        } catch (error) {
            console.error('Erro ao carregar financeiro:', error);
            res.render('financeiro/index', {
                title: 'Financeiro',
                currentPage: 'financeiro',
                usuario: req.session.usuario,
                resumo: { receitasMes: 0, despesasMes: 0, saldoMes: 0, saldoAcumulado: 0 },
                lancamentos: [],
                error: 'Erro ao carregar financeiro'
            });
        }
    })();
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

app.get('/profissionais', requireAuth, (req, res) => {
    res.render('profissionais/index', {
        title: 'Profissionais',
        currentPage: 'profissionais',
        usuario: req.session.usuario
    });
});

app.get('/convenios', requireAuth, (req, res) => {
    res.render('convenios/index', {
        currentPage: 'convenios',
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
        const telefone = req.body?.telefone != null ? (req.body.telefone || '').toString().trim() : null;

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

        res.render('auditoria/index', {
            title: 'Auditoria',
            currentPage: 'auditoria',
            usuario: req.session.usuario,
            logs,
            filtros: { q, acao, tabela, limit }
        });
    } catch (error) {
        console.error('Erro ao carregar auditoria:', error);
        res.render('auditoria/index', {
            title: 'Auditoria',
            currentPage: 'auditoria',
            usuario: req.session.usuario,
            logs: [],
            filtros: { q: '', acao: '', tabela: '', limit: 200 },
            error: 'Erro ao carregar auditoria: ' + error.message
        });
    }
});

// PACIENTES
app.get('/pacientes', requireAuth, async (req, res) => {
    try {
        const db = getDB();
        const [pacientes] = await db.execute('SELECT * FROM pacientes WHERE ativo = TRUE ORDER BY nome');
        res.render('pacientes/lista', { pacientes, usuario: req.session.usuario });
    } catch (error) {
        console.error('Erro ao listar pacientes:', error);
        res.render('pacientes/lista', { pacientes: [], usuario: req.session.usuario });
    }
});

app.get('/pacientes/novo', requireAuth, (req, res) => {
    res.render('pacientes/form', { paciente: null, usuario: req.session.usuario, error: null });
});

app.post('/pacientes', requireAuth, async (req, res) => {
    try {
        console.log('POST /pacientes - Criando novo paciente');
        console.log('Dados recebidos:', req.body);
        
        const { nome, cpf, rg, data_nascimento, sexo, telefone, email, endereco, cidade, estado, cep, convenio, numero_convenio, validade_convenio, alergias, medicamentos, historico_familiar, observacoes } = req.body;
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

app.get('/pacientes/:id/editar', requireAuth, async (req, res) => {
    try {
        console.log('=== GET /pacientes/:id/editar ===');
        console.log('ID do paciente:', req.params.id);
        
        const db = getDB();
        const [pacientes] = await db.execute('SELECT * FROM pacientes WHERE id = ?', [req.params.id]);
        
        console.log('Paciente encontrado no banco:', pacientes.length > 0 ? 'SIM' : 'NÃO');
        if (pacientes.length > 0) {
            const paciente = pacientes[0];
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

app.post('/pacientes/:id/editar', requireAuth, async (req, res) => {
    try {
        console.log('=== POST /pacientes/:id/editar ===');
        console.log('ID do paciente:', req.params.id);
        console.log('Todos os dados recebidos:', Object.keys(req.body));
        console.log('Dados recebidos:', req.body);
        
        const { nome, cpf, rg, data_nascimento, sexo, telefone, email, endereco, cidade, estado, cep, convenio, numero_convenio, validade_convenio, alergias, medicamentos, historico_familiar, observacoes } = req.body;
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
        
        await db.execute(
            'UPDATE pacientes SET nome = ?, cpf = ?, rg = ?, data_nascimento = ?, sexo = ?, telefone = ?, email = ?, endereco = ?, cidade = ?, estado = ?, cep = ?, convenio = ?, numero_convenio = ?, validade_convenio = ?, alergias = ?, medicamentos = ?, historico_familiar = ?, observacoes = ? WHERE id = ?',
            [nome, cpf, rg, data_nascimento, sexoDb, telefone, email, endereco, cidade, estado, cep, convenio, numero_convenio, validade_convenio, alergias, medicamentos, historico_familiar, observacoes, req.params.id]
        );
        
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

app.post('/pacientes/:id/excluir', requireAuth, async (req, res) => {
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
app.get('/agendamentos', requireAuth, async (req, res) => {
    try {
        const db = getDB();
        let agendamentos = [];
        try {
            const [rows] = await db.execute(
                `SELECT id, paciente_id, paciente_nome, paciente_cpf, profissional_id, profissional_nome, data_hora, duracao_minutos, tipo_consulta, status, observacoes, valor, forma_pagamento, status_pagamento, convenio, enviar_lembrete, confirmar_whatsapp
                 FROM agendamentos
                 ORDER BY data_hora DESC, id DESC
                 LIMIT 200`
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
                     ORDER BY id DESC
                     LIMIT 200`
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
            agendamentos
        });
    } catch (error) {
        console.error('Erro ao listar agendamentos:', error);
        res.render('agendamentos/lista', {
            title: 'Agendamentos',
            currentPage: 'agendamentos',
            usuario: req.session.usuario,
            agendamentos: [],
            error: 'Erro ao listar agendamentos'
        });
    }
});

app.get('/agendamentos/novo', requireAuth, async (req, res) => {
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

app.post('/agendamentos', requireAuth, async (req, res) => {
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
app.get('/agenda', requireAuth, async (req, res) => {
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

// LEMBRETES
app.get('/lembretes', requireAuth, async (req, res) => {
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

app.get('/lembretes/novo', requireAuth, async (req, res) => {
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

app.post('/lembretes', requireAuth, async (req, res) => {
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

app.get('/lembretes/:id/editar', requireAuth, async (req, res) => {
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

app.post('/lembretes/:id/editar', requireAuth, async (req, res) => {
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

app.get('/api/lembretes/:id', requireAuth, async (req, res) => {
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

app.post('/lembretes/:id/enviar', requireAuth, async (req, res) => {
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

app.post('/lembretes/:id/excluir', requireAuth, async (req, res) => {
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

// Inicialização do servidor
async function startServer() {
    try {
        // Inicializar banco de dados
        await initDB();

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

        // Iniciar servidor após inicializar o banco
        app.listen(PORT, () => {
            console.log(`Servidor rodando na porta ${PORT}`);
            console.log(`Acesse: http://localhost:${PORT}`);
            console.log('Serviço de WhatsApp Web iniciando...');

            if (!reminderCronStarted) {
                reminderCronStarted = true;
                cron.schedule('* * * * *', () => {
                    processarLembretesPendentes();
                });
            }

            if (process.env.WHATSAPP_AUTO_START === '1') {
                setTimeout(() => {
                    whatsappService.start().catch((e) => {
                        console.error('Erro ao iniciar WhatsApp automaticamente:', e);
                    });
                }, 2000);
            }
            
            // Iniciar sistema de envio de lembretes após o servidor estar pronto
            setTimeout(() => {
                console.log('🚀 Iniciando sistema de envio de lembretes...');
                // const agendaService = require('./agendaService');
                // agendaService.iniciarEnvioLembretes();
            }, 5000);
        });
    } catch (error) {
        console.error('Erro ao iniciar servidor:', error);
    }
}

module.exports = app;

startServer();
