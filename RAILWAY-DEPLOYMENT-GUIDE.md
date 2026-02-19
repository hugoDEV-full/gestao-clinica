# Guia de Deploy no Railway - Sistema Clínica Andreia Ballejo

## 📋 Resumo do Projeto
- **Sistema:** Gestão Clínica com WhatsApp
- **Backend:** Node.js + Express + MySQL
- **WhatsApp:** whatsapp-web.js com Chromium
- **Deploy:** Railway (Dockerfile + Volume + MySQL Plugin)

---

## 🚀 Configuração no Railway

### 1️⃣ Serviço MySQL (Plugin)
```bash
# Variáveis criadas automaticamente:
DB_HOST=mysql.railway.internal
DB_PORT=3306
DB_USER=root
DB_PASSWORD=<senha_gerada>
DB_NAME=railway
```

### 2️⃣ Serviço Node.js (Aplicação)
```bash
# Builder: Dockerfile (instala Chromium)
# Porta: 8080
# Start Command: npm start (roda setup + server)
```

### 3️⃣ Volume para WhatsApp
- **Mount Path:** `/data`
- **Propósito:** Persistir sessão do WhatsApp
- **Uso:** WHATSAPP_AUTH_PATH=/data/wwebjs_auth

---

## 🔧 Variáveis de Ambiente (Node.js Service)

### Banco de Dados
```
DB_HOST=mysql.railway.internal
DB_PORT=3306
DB_USER=root
DB_PASSWORD=<senha_do_mysql>
DB_NAME=railway
DB_TIMEZONE=+00:00
```

### Sessão e Segurança
```
SESSION_SECRET=uma-chave-secreta-para-sessoes-32-caracteres
ACCESS_HMAC_SECRET=outra-chave-secreta-para-hmac-64-caracteres
```

### WhatsApp
```
WHATSAPP_NUMBER=5561982976481
WHATSAPP_CHROME_PATH=/usr/bin/chromium
WHATSAPP_HEADLESS=1
WHATSAPP_AUTH_PATH=/data/wwebjs_auth
WHATSAPP_AUTO_INIT=1
```

---

## 📁 Arquivos Chave

### Dockerfile
```dockerfile
FROM node:18-alpine

# Instalar dependências do Chromium
RUN apk add --no-cache \
    chromium \
    nss \
    freetype \
    freetype-dev \
    harfbuzz \
    ca-certificates \
    ttf-freefont

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .

EXPOSE 8080
CMD ["npm", "start"]
```

### .dockerignore
```
node_modules
npm-debug.log
.git
.gitignore
README.md
.env
.nyc_output
coverage
.nyc_output
.coverage
.cache
dist
build
*.log
.env.*
```

### Scripts no package.json
```json
{
  "scripts": {
    "start": "npm run setup && node server.js",
    "setup": "node scripts/setup-railway.js",
    "create-admin": "node scripts/create-admin.js"
  }
}
```

---

## 🗄️ Schema do Banco (schema-full.sql)

### Estrutura Correta
1. **SET FOREIGN_KEY_CHECKS=0** no início
2. **DROP TABLE** em ordem reversa (dependências primeiro)
3. **CREATE TABLE** sem foreign keys
4. **ALTER TABLE** para adicionar foreign keys depois
5. **SET FOREIGN_KEY_CHECKS=1** no fim

### Ordem das Tabelas
```sql
-- Base tables (sem FK)
app_config, configuracoes, usuarios, pacientes, profissionais
colaboradores, password_resets, colaborador_devices
access_tokens, access_logs, ponto_logs

-- Tables com FK
agenda, agendamentos, financeiro, lembretes
prontuarios, prontuario_evolucoes, logs_lgpd
```

---

## 🔧 Scripts de Setup

### setup-railway.js
- Conecta no MySQL Railway
- Executa schema statement por statement
- Ignora erros de tabela já existente
- Recria foreign keys separadamente

### create-admin.js
- Cria usuário admin via console
- Hash de senha com bcrypt
- Verifica duplicatas

---

## 🐛 Problemas Comuns e Soluções

### 1. Erro: "Table already exists"
**Solução:** Script setup agora ignora tabelas existentes

### 2. Erro: "Foreign key constraint fails"
**Solução:** Schema reordenado (DROP em ordem reversa, FK depois)

### 3. WhatsApp não inicia
**Verificar:**
- WHATSAPP_CHROME_PATH=/usr/bin/chromium
- WHATSAPP_AUTH_PATH=/data/wwebjs_auth
- Volume montado em /data

### 4. MemoryStore Warning
**Aviso normal em desenvolvimento.** Opcional: Redis para produção.

---

## 📱 WhatsApp - Configuração Completa

### Variáveis Essenciais
```
WHATSAPP_CHROME_PATH=/usr/bin/chromium
WHATSAPP_HEADLESS=1
WHATSAPP_AUTH_PATH=/data/wwebjs_auth
WHATSAPP_AUTO_INIT=1
```

### Puppeteer Args (whatsappService.js)
```javascript
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
```

### Fluxo de Login
1. `GET /api/whatsapp/start` - Inicia cliente
2. `GET /api/whatsapp/qrcode-teste` - Retorna QR
3. Escanear QR no celular
4. Sessão salva em `/data/wwebjs_auth`

---

## 👥 Registro de Usuários

### Rotas Públicas
- `GET /register` - Formulário de registro
- `POST /register` - Processa cadastro

### Validações
- Email único
- CPF único (se informado)
- Senha mínimo 6 caracteres
- bcrypt para hash

### Tipo Padrão
- Novos usuários: `secretaria`
- Admins: criados via script ou manualmente

---

## 🔄 Deploy Automático

### GitHub Integration
- Branch: `master`
- Deploy automático em cada push
- Zero-downtime (com volume persistente)

### Processo de Deploy
1. GitHub → Railway (trigger)
2. Build Dockerfile
3. Start: `npm run setup && node server.js`
4. Setup cria/atualiza schema
5. Server sobe na porta 8080

---

## 🌐 Acesso Público

### URL Pública
Formato: `https://<projeto>.up.railway.app`

### Portas
- Interna: 8080
- Externa: 80/443 (Railway proxy)

---

## 📊 Monitoramento

### Logs Importantes
```
✅ Schema importado com sucesso!
🎉 Banco de dados pronto para uso.
🚀 Servidor rodando
WhatsApp: inicializando cliente
```

### Debug Variables
```javascript
console.log('DB_HOST:', dbHost);
console.log('DB_USER:', dbUser);
console.log('DB_NAME:', dbName);
console.log('SESSION_SECRET:', sessionSecret);
```

---

## 🛠️ Manutenção

### Criar Admin (se necessário)
```bash
# Via New Command no Railway
npm run create-admin

# Resultado:
# Email: hugo.leonardo.jobs@gmail.com
# Senha: Bento1617@*
# Tipo: admin
```

### Resetar Banco
```sql
-- No MySQL Console
DROP TABLE IF EXISTS prontuario_evolucoes, prontuarios, logs_lgpd, 
lembretes, financeiro, agendamentos, agenda, access_logs, 
access_tokens, ponto_logs, colaborador_devices, password_resets, 
colaboradores, profissionais, pacientes, usuarios, 
configuracoes, app_config;
```

---

## 📝 Checklist de Deploy

### ✅ Antes do Deploy
- [ ] Dockerfile presente e funcional
- [ ] schema-full.sql ordenado corretamente
- [ ] Variáveis de ambiente configuradas
- [ ] Volume criado para /data
- [ ] Scripts de setup prontos

### ✅ Pós-Deploy
- [ ] Schema importado sem erros
- [ ] Sistema online (URL pública)
- [ ] WhatsApp QR gerado
- [ ] Registro de usuários funcionando
- [ ] Login admin funcionando

---

## 🚀 Comandos Úteis

### Railway Console
```bash
# Criar admin
npm run create-admin

# Ver logs
tail -f /var/log/app.log

# Testar conexão MySQL
node -e "const db=require('./database');db.initDB().then(()=>console.log('OK')).catch(console.error)"
```

### Debug WhatsApp
```bash
# Verificar Chromium
which chromium
chromium --version

# Testar WhatsApp
curl http://localhost:8080/api/whatsapp/status
```

---

## 🎯 Próximos Passos (Opcionais)

### Produção
- [ ] Redis para sessões
- [ ] Domínio customizado
- [ ] SSL (já vem com Railway)
- [ ] Monitoramento (Uptime/Healthcheck)

### WhatsApp
- [ ] Multiple devices
- [ ] Webhook para eventos
- [ ] Dashboard de status

---

## 📞 Suporte

### Logs de Erros Comuns
1. **ETIMEDOUT** - Verificar DB_HOST
2. **Table doesn't exist** - Rodar setup
3. **Foreign key fails** - Reordenar schema
4. **WhatsApp fails** - Verificar Chromium + Volume

### Contato
- GitHub: issues no repositório
- Railway: logs no dashboard
- WhatsApp: testar com QR code

---

**Criado em:** 2026-02-19  
**Versão:** 1.0.0  
**Plataforma:** Railway  
**Status:** ✅ Produção
