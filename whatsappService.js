const qrcode = require('qrcode-terminal');
const { Client, LocalAuth } = require('whatsapp-web.js');
const moment = require('moment');
const fs = require('fs');

class WhatsAppService {
    constructor() {
        this.client = null;
        this.isConnected = false;
        this.phoneNumber = process.env.WHATSAPP_NUMBER || '5561982976481';
        this.qrCode = null;
        this.isStarting = false;
        this._startAttempts = 0;
        this.initializeClient();
    }

    isConnectedState(state) {
        const s = (state == null) ? '' : String(state).toLowerCase();
        return s === 'connected' || s === 'open' || s === 'ready';
    }

    resolveBrowserExecutablePath() {
        const envPath = process.env.WHATSAPP_CHROME_PATH;
        if (envPath && fs.existsSync(envPath)) return envPath;

        const candidates = [
            // Chrome
            'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
            'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
            // Edge
            'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
            'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe'
        ];

        for (const p of candidates) {
            if (fs.existsSync(p)) return p;
        }
        return undefined;
    }

    initializeClient() {
        const executablePath = this.resolveBrowserExecutablePath();
        const headlessEnv = process.env.WHATSAPP_HEADLESS;
        const headless = headlessEnv === '0' ? false : (headlessEnv === 'new' ? 'new' : true);

        this.client = new Client({
            authStrategy: new LocalAuth({
                clientId: 'clinica-andreia-ballejo'
            }),
            puppeteer: {
                headless,
                executablePath,
                args: [
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--no-first-run',
                    '--no-default-browser-check',
                    '--disable-dev-shm-usage',
                    '--disable-features=TranslateUI',
                    '--disable-background-networking',
                    '--disable-background-timer-throttling',
                    '--disable-renderer-backgrounding',
                    '--disable-infobars',
                    '--disable-gpu',
                    '--window-size=1365,768',
                    '--lang=pt-BR'
                ]
            }
        });

        this.setupEventListeners();
    }

    setupEventListeners() {
        // QR Code
        this.client.on('qr', (qr) => {
            console.log('QR Code recebido, escaneie com seu WhatsApp!');
            qrcode.generate(qr, { small: true });
            this.qrCode = qr;
        });

        // Autenticado
        this.client.on('authenticated', () => {
            console.log('WhatsApp autenticado com sucesso!');
        });

        // Pronto
        this.client.on('ready', () => {
            console.log('WhatsApp Client está pronto!');
            this.isConnected = true;
            this.qrCode = null;
        });

        // Mudança de estado
        this.client.on('change_state', (state) => {
            try {
                console.log('WhatsApp Client mudou de estado:', state);
                this.isConnected = this.isConnectedState(state);
                if (this.isConnected) this.qrCode = null;
            } catch (e) {
                // ignore
            }
        });

        // Desconectado
        this.client.on('disconnected', (reason) => {
            console.log('WhatsApp Client desconectado:', reason);
            this.isConnected = false;
        });

        // Falha na autenticação
        this.client.on('auth_failure', (msg) => {
            console.error('Falha na autenticação do WhatsApp:', msg);
            this.isConnected = false;
        });

        // Erro
        this.client.on('remote_session_saved', () => {
            console.log('Sessão remota salva com sucesso!');
        });
    }

    // Iniciar o cliente
    async start() {
        try {
            if (this.isStarting) return;
            this.isStarting = true;
            console.log('Iniciando WhatsApp Client...');
            this._startAttempts += 1;
            await this.client.initialize();
        } catch (error) {
            console.error('Erro ao iniciar WhatsApp Client:', error);

            const msg = (error && error.message) ? String(error.message) : '';
            const isExecutionContextDestroyed =
                msg.includes('Execution context was destroyed') ||
                msg.includes('Runtime.callFunctionOn');

            if (isExecutionContextDestroyed && this._startAttempts < 2) {
                try {
                    console.log('Falha de contexto do Puppeteer detectada. Reiniciando cliente do WhatsApp e tentando novamente...');
                    if (this.client) {
                        try { await this.client.destroy(); } catch (e) {}
                    }
                    this.isConnected = false;
                    this.qrCode = null;
                    this.initializeClient();
                    await new Promise((r) => setTimeout(r, 2000));
                    return await this.start();
                } catch (retryError) {
                    console.error('Erro ao reiniciar WhatsApp Client:', retryError);
                    throw retryError;
                }
            }

            throw error;
        } finally {
            this.isStarting = false;
        }
    }

    // Obter status
    getStatus() {
        // Inferir conexão de forma mais robusta do que apenas o flag interno,
        // porque em alguns cenários o wwebjs pode trocar estados sem disparar `ready` novamente.
        try {
            if (this.client) {
                const st = this.client.state;
                const inferredConnected = this.isConnectedState(st) || !!(this.client.info && this.client.info.wid);
                if (inferredConnected && !this.isConnected) {
                    this.isConnected = true;
                    this.qrCode = null;
                }
                if (!inferredConnected && this.isConnected) {
                    // Mantém coerência quando o cliente cai mas não disparou evento ainda
                    this.isConnected = false;
                }
            }
        } catch (e) {
            // ignore
        }
        return {
            isConnected: this.isConnected,
            isStarting: this.isStarting,
            phoneNumber: this.phoneNumber,
            qrCode: this.qrCode,
            clientInfo: this.client ? {
                info: this.client.info,
                state: this.client.state
            } : null
        };
    }

    getPhoneNumber() {
        return this.phoneNumber;
    }

    setPhoneNumber(phoneNumber) {
        this.phoneNumber = phoneNumber;
    }

    // Obter QR Code
    getQRCode() {
        return this.qrCode;
    }

    // Enviar mensagem
    async sendMessage(phoneNumber, message) {
        if (!this.isConnected || !this.client) {
            throw new Error('WhatsApp não está conectado');
        }

        try {
            console.log(`Enviando mensagem para ${phoneNumber}...`);

            const digits = String(phoneNumber || '').replace(/\D/g, '');
            if (!digits) {
                throw new Error('Número de telefone inválido');
            }

            const candidates = [];
            const pushUnique = (v) => {
                if (v && !candidates.includes(v)) candidates.push(v);
            };

            pushUnique(digits);

            if (digits.length === 11) {
                pushUnique(`55${digits}`);
            }

            if (digits.startsWith('55')) {
                pushUnique(digits.slice(2));
            }

            let lastError = null;
            for (const candidate of candidates) {
                try {
                    console.log(`Resolvendo número no WhatsApp: ${candidate}`);
                    const numberId = await this.client.getNumberId(candidate);
                    if (!numberId || !numberId._serialized) {
                        console.log(`Número não encontrado no WhatsApp: ${candidate}`);
                        continue;
                    }

                    console.log(`Enviando para: ${numberId._serialized}`);
                    const sendOptions = { sendSeen: false };
                    let result;
                    try {
                        result = await this.client.sendMessage(numberId._serialized, message, sendOptions);
                    } catch (sendErr) {
                        const sendMsg = (sendErr && sendErr.message) ? String(sendErr.message) : '';
                        const isMarkedUnreadError = sendMsg.includes('markedUnread') || sendMsg.includes('sendSeen');
                        if (isMarkedUnreadError) {
                            console.log('Falha ao enviar causada por sendSeen/markedUnread. Tentando novamente sem marcar como visto...');
                            await new Promise((r) => setTimeout(r, 1500));
                            result = await this.client.sendMessage(numberId._serialized, message, sendOptions);
                        } else {
                            throw sendErr;
                        }
                    }
                    if (result && result.id) {
                        console.log(`Mensagem enviada com sucesso! ID: ${result.id._serialized}`);
                        return true;
                    }
                } catch (error) {
                    console.log(`Falha ao enviar usando ${candidate}: ${error.message}`);
                    lastError = error;
                }
            }

            throw lastError || new Error('Não foi possível resolver o número no WhatsApp');

        } catch (error) {
            console.error('Erro ao enviar mensagem:', error);
            throw error;
        }
    }

    // Verificar se número existe no WhatsApp
    async verifyNumberExists(phoneNumber) {
        if (!this.isConnected || !this.client) {
            throw new Error('WhatsApp não está conectado');
        }

        try {
            const digits = String(phoneNumber || '').replace(/\D/g, '');
            if (!digits) return false;

            const candidates = [];
            const pushUnique = (v) => {
                if (v && !candidates.includes(v)) candidates.push(v);
            };

            pushUnique(digits);
            if (digits.length === 11) pushUnique(`55${digits}`);
            if (digits.startsWith('55')) pushUnique(digits.slice(2));

            for (const candidate of candidates) {
                const numberId = await this.client.getNumberId(candidate);
                if (numberId && numberId._serialized) return true;
            }

            return false;
        } catch (error) {
            console.error('Erro ao verificar número:', error);
            return false;
        }
    }

    // Reativar serviço
    async reactivate() {
        try {
            console.log('Reativando WhatsApp...');
            
            if (this.client) {
                await this.client.logout();
                await this.client.destroy();
            }
            
            this.isConnected = false;
            this.qrCode = null;
            
            this.initializeClient();
            await this.start();
            
            console.log('WhatsApp reativado com sucesso!');
        } catch (error) {
            console.error('Erro ao reativar WhatsApp:', error);
            throw error;
        }
    }

    // Enviar lembrete de consulta
    async sendAppointmentReminder(appointment) {
        const message = `🏥 *Clínica Andreia Ballejo - Lembrete de Consulta* 🏥

Olá *${appointment.paciente_nome}*! 😊

📋 *Detalhes do agendamento*
📅 *Data:* ${moment(appointment.data_hora).format('DD/MM/YYYY')}
🕒 *Horário:* ${moment(appointment.data_hora).format('HH:mm')}
👨‍⚕️ *Profissional:* ${appointment.profissional_nome || 'Não informado'}
🏷️ *Tipo:* ${appointment.tipo_consulta || 'Consulta'}

⏰ *Recomendação:* chegue *15 minutos antes* para recepção e preparo.
🪪 *Traga:* documento com foto e, se tiver, cartão do convênio/guia.

✅ Por favor, *confirme sua presença* respondendo esta mensagem.
🔁 Se precisar remarcar/cancelar, avise com antecedência.

---
📍 *Clínica Andreia Ballejo Fisioterapia*
📞 *Contato:* (61) 9829-7648
⏰ *Enviado em:* ${moment().format('DD/MM/YYYY HH:mm')}`;

        try {
            const success = await this.sendMessage(appointment.paciente_telefone, message);
            return success;
        } catch (error) {
            console.error('Erro ao enviar lembrete de consulta:', error);
            return false;
        }
    }

    // Enviar lembrete de pagamento
    async sendPaymentReminder(payment) {
        const message = `💰 *LEMBRETE - CLÍNICA ANDREIA BALLEJO* 💰

📋 *PAGAMENTO PENDENTE*

👤 *Paciente:* ${payment.paciente_nome}
💵 *Valor:* R$ ${parseFloat(payment.valor).toFixed(2)}
📅 *Vencimento:* ${moment(payment.data_vencimento).format('DD/MM/YYYY')}
📝 *Descrição:* ${payment.descricao || 'Mensalidade'}

---
📍 *Clínica Andreia Ballejo Fisioterapia*
📞 *Contato:* (61) 9829-7648
🏦 *Pix:* (61) 9829-7648
⏰ *Enviado em:* ${moment().format('DD/MM/YYYY HH:mm')}

Por favor, regularize seu pagamento o quanto antes.`;

        try {
            const success = await this.sendMessage(payment.paciente_telefone, message);
            return success;
        } catch (error) {
            console.error('Erro ao enviar lembrete de pagamento:', error);
            return false;
        }
    }

    // Testar conexão
    async testConnection() {
        try {
            if (!this.isConnected) {
                return { success: false, message: 'WhatsApp não está conectado' };
            }

            const info = this.client.info;
            return {
                success: true,
                message: 'Conexão ativa',
                info: {
                    wid: info.wid._serialized,
                    me: info.me,
                    pushname: info.pushname,
                    connected: this.isConnected
                }
            };
        } catch (error) {
            return { success: false, message: error.message };
        }
    }
}

// Criar instância única
const whatsappService = new WhatsAppService();

// Iniciar automaticamente (comentado para evitar erro de Puppeteer)
// setTimeout(() => {
//     whatsappService.start().catch(console.error);
// }, 2000);

module.exports = whatsappService;
