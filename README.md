# Clínica Andreia Ballejo - Sistema de Gestão

Sistema completo de gestão para clínicas de fisioterapia desenvolvido com Node.js, Express e Bootstrap.

## 🚀 Funcionalidades

### 🏥 Gestão Clínica
- **Pacientes**: Cadastro completo com histórico médico
- **Agenda**: Agendamentos e gerenciamento de consultas
- **Prontuários**: Registros clínicos digitais
- **Profissionais**: Gestão da equipe clínica
- **Convênios**: Cadastro de planos de saúde

### 💊 Gestão de Medicamentos
- **Estoque**: Controle de medicamentos e materiais
- **Prescrições**: Receitas digitais
- **Atestados**: Documentos médicos

### 📱 WhatsApp Integration
- **Lembretes Automáticos**: Envio de lembretes via WhatsApp
- **Confirmações**: Confirmação automática de consultas
- **Notificações**: Avisos de pagamentos e exames

### 📊 Relatórios
- **Financeiro**: Controle de receitas e despesas
- **Estatísticas**: Análise de atendimentos
- **LGPD**: Logs completos de auditoria

### 🔐 Segurança
- **Autenticação**: Login seguro com sessões
- **Roles**: Níveis de acesso (admin, profissional, secretária)
- **LGPD**: Conformidade com Lei de Proteção de Dados

## 🛠️ Tecnologias

- **Backend**: Node.js, Express.js
- **Frontend**: EJS, Bootstrap 5
- **Banco**: MySQL
- **WhatsApp**: WhatsApp Web.js
- **Segurança**: bcrypt, express-session
- **Uploads**: Multer
- **Agendamento**: node-cron

## 📦 Instalação

### Pré-requisitos
- Node.js 16+
- MySQL 8.0+
- npm ou yarn

### Passos

1. **Clonar o repositório**
```bash
git clone <repositório>
cd gestao-fisio
```

2. **Instalar dependências**
```bash
npm install
```

3. **Configurar ambiente**
```bash
cp .env.example .env
# Editar o arquivo .env com suas configurações
```

4. **Configurar banco de dados**
```sql
CREATE DATABASE gestao_fisio;
-- Importar o arquivo SQL (se disponível)
```

5. **Iniciar o servidor**
```bash
# Desenvolvimento
npm run dev

# Produção
npm start
```

6. **Acessar o sistema**
```
http://localhost:3000
```

## 🔧 Configuração

### Variáveis de Ambiente

```env
# Servidor
PORT=3000
NODE_ENV=development

# Banco de Dados
DB_HOST=localhost
DB_PORT=3306
DB_NAME=gestao_fisio
DB_USER=root
DB_PASSWORD=sua_senha

# Sessão
SESSION_SECRET=segredo_muito_secreto

# WhatsApp
WHATSAPP_NUMBER=5561982976481

# Clínica
CLINICA_NAME=Clínica Andreia Ballejo
CLINICA_PHONE=(61) 9829-7648
CLINICA_EMAIL=contato@clinica.com
```

### Estrutura de Pastas

```
gestao-fisio/
├── views/                 # Templates EJS
│   ├── dashboard/        # Dashboard
│   ├── pacientes/       # Gestão de pacientes
│   ├── agenda/          # Agenda e consultas
│   ├── lembretes/       # Lembretes e notificações
│   └── login.ejs        # Tela de login
├── public/              # Arquivos estáticos
│   ├── css/            # Estilos CSS
│   ├── js/             # JavaScript
│   └── img/            # Imagens
├── uploads/             # Arquivos upload
├── layouts/             # Layouts EJS
├── server.js           # Servidor principal
├── package.json         # Dependências
├── .env                # Variáveis de ambiente
└── README.md           # Documentação
```

## 👥 Usuários Padrão

### Administrador
- **Email**: admin@clinica.com
- **Senha**: admin123
- **Acesso**: Total ao sistema

### Profissional
- **Email**: profissional@clinica.com
- **Senha**: prof123
- **Acesso**: Pacientes, agenda, prontuários

### Secretária
- **Email**: secretaria@clinica.com
- **Senha**: sec123
- **Acesso**: Agenda, pacientes, lembretes

## 📱 WhatsApp Integration

O sistema integra com WhatsApp para:

1. **Lembretes Automáticos**
   - Consultas do dia seguinte
   - Pagamentos pendentes
   - Exames agendados

2. **Confirmações**
   - Confirmação de presença
   - Reagendamentos

3. **Configuração**
   - Escanear QR Code no terminal
   - Status em tempo real
   - Teste de envio

### Configurando WhatsApp

1. Acesse `/whatsapp-teste`
2. Escaneie o QR Code no terminal
3. Aguarde a conexão
4. Teste o envio

## 📊 Relatórios

O sistema gera relatórios de:

- **Atendimentos**: Por período, profissional, tipo
- **Financeiro**: Receitas, despesas, fluxo de caixa
- **Pacientes**: Novos, ativos, inativos
- **WhatsApp**: Mensagens enviadas, taxas de sucesso

## 🔒 LGPD

Sistema em conformidade com LGPD:

- **Logs**: Todas as operações são logadas
- **Consentimento**: Registro de consentimentos
- **Anonimização**: Dados sensíveis protegidos
- **Exportação**: Dados do paciente disponíveis

## 🚀 Deploy

### Produção

1. **Configurar ambiente**
```bash
NODE_ENV=production
```

2. **Usar PM2**
```bash
npm install -g pm2
pm2 start server.js --name gestao-fisio
```

3. **Configurar Nginx**
```nginx
server {
    listen 80;
    server_name sua-clinica.com;
    
    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## 🐛 Troubleshooting

### Problemas Comuns

1. **WhatsApp não conecta**
   - Verifique o número no .env
   - Escaneie o QR Code novamente
   - Reinicie o serviço

2. **Banco de dados não conecta**
   - Verifique credenciais no .env
   - Confirme se o MySQL está rodando
   - Teste a conexão manualmente

3. **Sessão expira**
   - Verifique SESSION_SECRET
   - Configure cookie secure em produção
   - Ajuste tempo de sessão

## 📝 Licença

MIT License - Copyright (c) 2024 Clínica Andreia Ballejo

## 🤝 Suporte

Para suporte técnico:
- **Email**: suporte@clinica.com
- **Telefone**: (61) 9829-7648
- **WhatsApp**: (61) 9829-7648

---

**Desenvolvido com ❤️ para a Clínica Andreia Ballejo**
