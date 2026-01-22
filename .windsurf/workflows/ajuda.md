
---
description: Ajuda (página) - funcionalidades e rotas
---

# Ajuda

## Auditoria (LGPD)

### O que é
O sistema possui um **log de auditoria** para registrar ações relevantes (principalmente alterações de dados) para fins de rastreabilidade e conformidade.

### O que é registrado
Os registros são armazenados na tabela `logs_lgpd` e podem conter:
- **Usuário** (`usuario_id`): quem executou a ação (quando disponível)
- **Ação** (`acao`): `INSERT`, `UPDATE`, `DELETE` (e outras que o sistema venha a registrar)
- **Tabela afetada** (`tabela_afetada`): nome lógico/real da tabela (ex.: `pacientes`)
- **ID do registro** (`registro_id`): identificador do registro afetado (quando aplicável)
- **Dados anteriores** (`dados_anteriores`): estado “antes” (quando aplicável)
- **Dados novos** (`dados_novos`): estado “depois” (quando aplicável)
- **IP** (`ip_address`): IP do cliente
- **Data/Hora** (`created_at`): quando o log foi gravado

Observação: os payloads de “antes/depois” podem ser **sanitizados** (removendo/mascarando campos sensíveis) conforme a implementação.

### Quando é registrado
Em geral, quando o backend executa operações de escrita (criação/edição/remoção) e chama a rotina de log LGPD.

### Onde visualizar
- **Página/rota**: `GET /auditoria`
- **Permissão**: requer login e perfil **admin**

### Como filtrar (querystring)
Na URL da auditoria, você pode usar:
- **Busca geral**: `q` (procura em ação/tabela/dados e também nome/e-mail do usuário)
- **Ação**: `acao` (ex.: `UPDATE`)
- **Tabela**: `tabela` (ex.: `pacientes`)
- **Limite**: `limit` (padrão 200; mínimo 50; máximo 1000)

Exemplos:
- `GET /auditoria?q=joao&limit=200`
- `GET /auditoria?acao=DELETE&tabela=pacientes`

### Troubleshooting
- **Erro: `Unknown column 'l.created_at'`**
  - **Causa**: a tabela `logs_lgpd` foi criada anteriormente sem a coluna `created_at`. `CREATE TABLE IF NOT EXISTS` não altera tabelas já existentes.
  - **Correção**: adicionar a coluna `created_at` na tabela (via ajuste automático do sistema ao abrir `/auditoria` ou via `ALTER TABLE`).
