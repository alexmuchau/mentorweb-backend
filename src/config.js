// Configuração lida das variáveis de ambiente do Worker (vars + secrets).
// Segredos NÃO têm valor padrão: se faltar, a requisição falha com erro claro em vez de usar senha embutida.
import { env } from 'cloudflare:workers';

function required(name) {
  const value = env[name];
  if (value === undefined || value === null || value === '') {
    throw new Error(`Variável de ambiente obrigatória ausente: ${name}`);
  }
  return value;
}

export const config = {
  get dbHost() { return required('DB_HOST'); },
  get dbPort() { return parseInt(env.DB_PORT || '3306', 10); },
  get dbUser() { return required('DB_USER'); },
  get dbPassword() { return required('DB_PASSWORD'); },
  // O servidor antigo rodava em America/Sao_Paulo (UTC-3, sem horário de verão desde 2019); o mysql2 usava o fuso local
  // para ler DATETIME/DATE. Manter -03:00 preserva as datas que o Base44 recebe.
  get dbTimezone() { return env.DB_TIMEZONE || '-03:00'; },
  get dbSsl() { return env.DB_SSL === 'true'; },

  get supplierSyncUser() { return required('SUPPLIER_SYNC_USER'); },
  get supplierSyncPass() { return required('SUPPLIER_SYNC_PASS'); },
  get systemAdminUser() { return required('SYSTEM_ADMIN_USER'); },
  get systemAdminPass() { return required('SYSTEM_ADMIN_PASS'); },

  get allowedOrigins() {
    return env.ALLOWED_ORIGINS ? env.ALLOWED_ORIGINS.split(',').map((o) => o.trim()) : '*';
  },
};
