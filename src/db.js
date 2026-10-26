// Acesso ao MySQL a partir do Worker.
//
// Workers não mantêm pool entre requisições (cada requisição pode rodar em um isolate diferente e
// sockets não podem ser compartilhados). Por isso o "pool" aqui vive só durante UMA requisição:
// getConnection() reaproveita conexões já abertas nela e release() devolve à lista ociosa.
// Ao fim da requisição, closeRequestPools() destrói todos os sockets.
//
// A API (getConnection/execute/query/beginTransaction/commit/rollback/release) imita a do
// mysql2 Pool para que as rotas portadas do Express funcionem sem alteração.
import { AsyncLocalStorage } from 'node:async_hooks';
import { createConnection } from 'mysql2/promise';
import { config } from './config.js';

const requestStore = new AsyncLocalStorage();

/** Executa fn com um escopo de pools próprio da requisição e fecha tudo no final. */
export async function withRequestPools(fn) {
  const store = { pools: new Map() };
  try {
    return await requestStore.run(store, fn);
  } finally {
    for (const pool of store.pools.values()) pool.close();
  }
}

async function openConnection(database) {
  return createConnection({
    host: config.dbHost,
    port: config.dbPort,
    user: config.dbUser,
    password: config.dbPassword,
    database,
    timezone: config.dbTimezone,
    connectTimeout: 10000,
    // Obrigatório no runtime do Workers (não há eval/new Function).
    disableEval: true,
    ...(config.dbSsl ? { ssl: { rejectUnauthorized: false } } : {}),
  });
}

class Lease {
  constructor(raw, pool) {
    this.raw = raw;
    this.pool = pool;
    this.released = false;
  }
  execute(...args) { return this.raw.execute(...args); }
  query(...args) { return this.raw.query(...args); }
  beginTransaction() { return this.raw.beginTransaction(); }
  commit() { return this.raw.commit(); }
  rollback() { return this.raw.rollback(); }
  release() {
    if (this.released) return;
    this.released = true;
    this.pool.idle.push(this.raw);
  }
}

class RequestPool {
  constructor(database) {
    this.database = database;
    this.idle = [];
    this.all = new Set();
  }

  async open() {
    const raw = await openConnection(this.database);
    this.all.add(raw);
    return raw;
  }

  async getConnection() {
    const raw = this.idle.pop() || (await this.open());
    return new Lease(raw, this);
  }

  async execute(...args) {
    const conn = await this.getConnection();
    try {
      return await conn.execute(...args);
    } finally {
      conn.release();
    }
  }

  async query(...args) {
    const conn = await this.getConnection();
    try {
      return await conn.query(...args);
    } finally {
      conn.release();
    }
  }

  close() {
    for (const raw of this.all) {
      try { raw.destroy(); } catch { /* socket já fechado */ }
    }
    this.all.clear();
    this.idle = [];
  }
}

/**
 * Retorna o "pool" do banco informado para a requisição atual, validando que a conexão funciona
 * (mesmo comportamento do server.js antigo, que testava o pool ao criá-lo).
 */
export async function getDatabasePool(databaseName) {
  if (!databaseName) {
    throw new Error('Nome do banco de dados não fornecido.');
  }

  const store = requestStore.getStore();
  if (!store) {
    throw new Error('getDatabasePool chamado fora de uma requisição.');
  }

  const existing = store.pools.get(databaseName);
  if (existing) return existing;

  const pool = new RequestPool(databaseName);
  try {
    // A conexão de teste fica ociosa e será reaproveitada pela primeira getConnection().
    pool.idle.push(await pool.open());
  } catch (error) {
    console.error(`[${new Date().toISOString()}]`, `Erro ao criar ou testar pool para o banco de dados ${databaseName}:`, error);
    pool.close();
    throw new Error(`Não foi possível conectar ao banco de dados ${databaseName}.`);
  }

  store.pools.set(databaseName, pool);
  return pool;
}
