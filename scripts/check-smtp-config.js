require('dotenv').config();

console.log('=== Verificando configurações SMTP ===');
console.log('EMAIL_HOST:', process.env.EMAIL_HOST || '❌ Não configurado');
console.log('EMAIL_PORT:', process.env.EMAIL_PORT || '❌ Não configurado');
console.log('EMAIL_USER:', process.env.EMAIL_USER || '❌ Não configurado');
console.log('EMAIL_PASS:', process.env.EMAIL_PASS ? '✅ Configurado' : '❌ Não configurado');
console.log('EMAIL_FROM:', process.env.EMAIL_FROM || '❌ Não configurado');
console.log('APP_BASE_URL:', process.env.APP_BASE_URL || '❌ Não configurado');
console.log('=====================================');

if (process.env.EMAIL_HOST && process.env.EMAIL_USER && process.env.EMAIL_PASS) {
    console.log('✅ SMTP parece configurado!');
    console.log('Para testar no Railway, adicione estas variáveis de ambiente:');
    console.log('');
    console.log(`EMAIL_HOST=${process.env.EMAIL_HOST}`);
    console.log(`EMAIL_PORT=${process.env.EMAIL_PORT || 587}`);
    console.log(`EMAIL_USER=${process.env.EMAIL_USER}`);
    console.log(`EMAIL_PASS=${process.env.EMAIL_PASS}`);
    console.log(`EMAIL_FROM=${process.env.EMAIL_FROM || process.env.EMAIL_USER}`);
    console.log(`APP_BASE_URL=${process.env.APP_BASE_URL}`);
} else {
    console.log('❌ SMTP não está configurado no .env');
    console.log('Configure as variáveis EMAIL no seu .env ou Railway');
}
