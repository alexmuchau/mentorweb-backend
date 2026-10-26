// Middleware de autenticação de ambiente (portado de server.js, sem mudança de regra).
// Define req.pool, req.isClientAppAuth, req.isSupplierAuth e req.environment.
import { getDatabasePool } from './db.js';
import { config } from './config.js';

// Retorna true se autenticou (e preencheu req); caso contrário já respondeu o erro e retorna false.
async function authenticate(req, res) {
  const { cnpj, usuario, senha, banco_dados } = req.headers;

  req.pool = null;
  req.isClientAppAuth = false;
  req.isSupplierAuth = false;
  req.environment = null;

  if (!cnpj || !usuario || !senha || !banco_dados) {
    res.status(400).json({ error: 'Credenciais de ambiente incompletas', details: 'Headers CNPJ, Usuário, Senha e Banco de Dados são obrigatórios.' });
    return false;
  }

  let connection;
  try {
    req.pool = await getDatabasePool(banco_dados);

    // CASO 1: Autenticação para Fornecedor (credenciais de sistema)
    if (usuario === config.supplierSyncUser && senha === config.supplierSyncPass) {
      req.isSupplierAuth = true;
      req.environment = { cnpj, usuario, tipo: 'fornecedor_sync' };
      console.log('Ambiente autenticado como Fornecedor Sync.');
      return true;
    }

    // CASO 2: Autenticação para ClienteApp (credenciais do ambiente do cliente)
    connection = await req.pool.getConnection();
    const [rows] = await connection.execute(
      'SELECT * FROM tb_ambientes WHERE cnpj = ? AND usuario = ? AND senha = ? AND ativo = "S"',
      [cnpj, usuario, senha]
    );
    connection.release();
    connection = null;

    if (rows.length > 0) {
      req.isClientAppAuth = true;
      req.environment = { ...rows[0], tipo: 'cliente' };
      console.log(`Ambiente autenticado como ClienteApp: ${rows[0].nome_empresa}`);
      return true;
    }

    console.warn(`Falha na autenticação do ambiente para CNPJ: ${cnpj} e Usuário: ${usuario}`);
    res.status(401).json({ error: 'Credenciais de ambiente inválidas ou inativas.' });
    return false;

  } catch (error) {
    console.error(`[${new Date().toISOString()}]`, `Erro no middleware authenticateEnvironment para banco ${banco_dados}:`, error);
    if (error.message && error.message.includes('Não foi possível conectar ao banco de dados')) {
      res.status(401).json({ error: 'Falha na conexão com o banco de dados do ambiente.', details: error.message });
      return false;
    }
    if (error.sqlMessage) {
      res.status(500).json({ error: 'Erro no banco de dados', details: error.sqlMessage });
      return false;
    }
    res.status(500).json({ error: 'Erro interno do servidor', details: error.message });
    return false;
  } finally {
    if (connection) connection.release();
  }
}

export const authenticateEnvironment = async (req, res, next) => {
  if (await authenticate(req, res)) return next();
};
