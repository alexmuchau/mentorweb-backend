const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
require('dotenv').config(); // Carrega variáveis de ambiente do arquivo .env

const app = express();
const PORT = process.env.PORT || 3333; // Porta padrão 3333 ou a definida no .env

// Middlewares de segurança e performance
app.use(helmet());
app.use(compression());
app.use(morgan('combined'));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Muitas requisições desta IP, tente novamente após 15 minutos.'
});
app.use('/api/', limiter);

// Configuração CORS
const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000', 'http://localhost:5173'];
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error(`A política CORS para este site não permite acesso da Origem ${origin}.`), false);
    }
  },
  credentials: true
}));

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Mapa de pools de conexão MySQL
const connections = new Map();

// Função para criar um pool de conexão
const createConnectionPool = (database) => {
  return mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: database,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    acquireTimeout: 60000,
    timeout: 60000,
  });
};

// Middleware de autenticação
const authenticateEnvironment = async (req, res, next) => {
  try {
    const { cnpj, usuario, senha, banco_dados } = req.headers;

    if (!cnpj || !usuario || !senha || !banco_dados) {
      return res.status(401).json({ error: 'Credenciais obrigatórias ausentes nos headers: cnpj, usuario, senha, banco_dados' });
    }

    if (!connections.has(banco_dados)) {
      connections.set(banco_dados, createConnectionPool(banco_dados));
    }
    const pool = connections.get(banco_dados);

    // --- Lógica para FornecedorApp (banco: muchaucom_pisciNew, tabelas: PascalCase) ---
    if (usuario === 'mentorweb_fornecedor' && senha === 'mentorweb_sync_forn_2024') {
      try {
        await pool.query('SELECT 1');
        req.pool = pool;
        req.isFornecedorSync = true;
        req.ambiente = { cnpj, usuario, banco_dados, tipo: 'fornecedor' };
        return next();
      } catch (error) {
        console.error(`Falha ao conectar ao banco de dados do fornecedor ${banco_dados}:`, error);
        return res.status(401).json({ error: `Credenciais de FornecedorApp inválidas ou banco de dados '${banco_dados}' inacessível.` });
      }
    }

    // --- Lógica para ClienteApp (banco: muchaucom_mentor, tabelas: lowercase) ---
    // CORREÇÃO: A query agora usa 'tb_ambientes' e a coluna 'cnpj', tudo em minúsculas.
    const [rows] = await pool.execute(
      'SELECT * FROM tb_ambientes WHERE cnpj = ? AND usuario = ? AND senha = ? AND ativo = "S"',
      [cnpj, usuario, senha]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: 'Credenciais de ClienteApp inválidas para este ambiente.' });
    }

    req.pool = pool;
    req.isClienteSync = true;
    req.ambiente = rows[0];
    next();
  } catch (error) {
    console.error('Erro no middleware de autenticação:', error);
    res.status(500).json({ error: 'Erro interno do servidor durante a autenticação.', details: error.message });
  }
};

// =========================================================
// ROTA DE SERVIÇO GERAL
// =========================================================
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString(), version: '3.1.0' });
});

// =========================================================
// ROTAS PARA SINCRONIZAÇÃO DE CLIENTEAPP (banco muchaucom_mentor)
// =========================================================

// Rota para obter produtos do ERP (ClienteApp busca)
app.get('/api/sync/send-produtos', authenticateEnvironment, async (req, res) => {
  if (!req.isClienteSync) return res.status(403).json({ error: 'Acesso negado.' });
  const connection = await req.pool.getConnection();
  try {
    const [rows] = await connection.execute('SELECT codigo, produto, preco_venda, estoque, ativo FROM tb_produtos WHERE ativo = "S"');
    res.json({ success: true, data: rows, total: rows.length });
  } catch (error) {
    console.error('Erro ao buscar produtos (cliente):', error);
    res.status(500).json({ success: false, error: 'Erro ao buscar produtos.', details: error.message });
  } finally {
    connection.release();
  }
});

// Rota para obter clientes do ERP (ClienteApp busca)
app.get('/api/sync/send-clientes', authenticateEnvironment, async (req, res) => {
  if (!req.isClienteSync) return res.status(403).json({ error: 'Acesso negado.' });
  const connection = await req.pool.getConnection();
  try {
    const [rows] = await connection.execute('SELECT codigo, nome, cnpj, ativo FROM tb_clientes WHERE ativo = "S"');
    res.json({ success: true, data: rows, total: rows.length });
  } catch (error) {
    console.error('Erro ao buscar clientes:', error);
    res.status(500).json({ success: false, error: 'Erro ao buscar clientes.', details: error.message });
  } finally {
    connection.release();
  }
});

// Rota para obter formas de pagamento do ERP (ClienteApp busca)
app.get('/api/sync/send-formas-pagamento', authenticateEnvironment, async (req, res) => {
  if (!req.isClienteSync) return res.status(403).json({ error: 'Acesso negado.' });
  const connection = await req.pool.getConnection();
  try {
    const [rows] = await connection.execute('SELECT codigo, forma_pagamento, ativo FROM tb_formas_pagamento WHERE ativo = "S"');
    res.json({ success: true, data: rows, total: rows.length });
  } catch (error) {
    console.error('Erro ao buscar formas de pagamento:', error);
    res.status(500).json({ success: false, error: 'Erro ao buscar formas de pagamento.', details: error.message });
  } finally {
    connection.release();
  }
});

// Rota para obter comandas do ERP (ClienteApp busca)
app.get('/api/sync/send-comandas', authenticateEnvironment, async (req, res) => {
  if (!req.isClienteSync) return res.status(403).json({ error: 'Acesso negado.' });
  const connection = await req.pool.getConnection();
  try {
    const [rows] = await connection.execute('SELECT codigo, comanda, ativo FROM tb_comandas WHERE ativo = "S"');
    res.json({ success: true, data: rows, total: rows.length });
  } catch (error) {
    console.error('Erro ao buscar comandas:', error);
    res.status(500).json({ success: false, error: 'Erro ao buscar comandas.', details: error.message });
  } finally {
    connection.release();
  }
});

// Rota para receber pedidos do MentorWeb (ClienteApp envia para seu ERP)
app.post('/api/sync/receive-pedidos', authenticateEnvironment, async (req, res) => {
  if (!req.isClienteSync) return res.status(403).json({ error: 'Acesso negado.' });
  const connection = await req.pool.getConnection();
  try {
    await connection.beginTransaction();
    const { pedidos } = req.body;
    const processedOrders = [];
    for (const pedido of pedidos) {
      const [pedidoResult] = await connection.execute(
        'INSERT INTO tb_pedidos (data_hora_lancamento, id_cliente, id_forma_pagamento, id_local_retirada, total_produtos) VALUES (?, ?, ?, ?, ?)',
        [new Date(pedido.data), pedido.id_cliente, pedido.id_forma_pagamento, pedido.id_local_retirada, pedido.total_produtos]
      );
      const pedidoId = pedidoResult.insertId;
      for (const item of pedido.itens) {
        await connection.execute(
          'INSERT INTO tb_pedidos_produtos (id_pedido, id_produto, quantidade, valor_unitario, valor_total) VALUES (?, ?, ?, ?, ?)',
          [pedidoId, item.id_produto, item.quantidade, item.unitario, item.total_produto]
        );
      }
      processedOrders.push({ id_original: pedido.id, id_lcto_erp: pedidoId, status: 'sucesso' });
    }
    await connection.commit();
    res.json({ success: true, message: `${processedOrders.length} pedidos processados.`, data: processedOrders });
  } catch (error) {
    await connection.rollback();
    console.error('Erro ao receber pedidos (cliente):', error);
    res.status(500).json({ success: false, error: 'Erro ao processar pedidos.', details: error.message });
  } finally {
    connection.release();
  }
});

// =========================================================
// ROTAS PARA SINCRONIZAÇÃO DE FORNECEDORAPP (banco muchaucom_pisciNew)
// =========================================================

// Rota para obter produtos (FornecedorApp busca em seu ERP)
app.get('/api/sync/send-produtos-fornecedor', authenticateEnvironment, async (req, res) => {
  if (!req.isFornecedorSync) return res.status(403).json({ error: 'Acesso negado.' });
  const connection = await req.pool.getConnection();
  try {
    const [rows] = await connection.execute('SELECT id, nome, preco_unitario FROM tb_Produtos WHERE Ativo = "S" ORDER BY nome');
    res.json({ success: true, data: rows, total: rows.length });
  } catch (error) {
    console.error('Erro ao buscar produtos do fornecedor:', error);
    res.status(500).json({ success: false, error: 'Erro ao buscar produtos do fornecedor.', details: error.message });
  } finally {
    connection.release();
  }
});

// Rota para receber pedido para fornecedor (ClienteApp envia para ERP do Fornecedor)
app.post('/api/sync/receive-pedido-fornecedor', authenticateEnvironment, async (req, res) => {
  if (!req.isFornecedorSync) return res.status(403).json({ error: 'Acesso negado.' });
  const connection = await req.pool.getConnection();
  try {
    await connection.beginTransaction();
    const { pedido } = req.body;
    const [pedidoResult] = await connection.execute(
      'INSERT INTO tb_Pedidos (data_hora_lancamento, nome_cliente, total_produtos) VALUES (?, ?, ?)',
      [new Date(), pedido.cliente || 'Cliente MentorWeb', pedido.total_pedido]
    );
    const pedidoId = pedidoResult.insertId;
    for (const item of pedido.itens) {
      await connection.execute(
        'INSERT INTO tb_Pedidos_Produtos (id_pedido, id_produto, nome_produto, quantidade, valor_unitario, valor_total) VALUES (?, ?, ?, ?, ?, ?)',
        [pedidoId, item.id_produto_fornecedor, item.nome_produto, item.quantidade, item.valor_unitario, item.total_produto]
      );
    }
    await connection.commit();
    res.json({ success: true, message: 'Pedido recebido com sucesso.', data: { id_lcto_erp: pedidoId } });
  } catch (error) {
    await connection.rollback();
    console.error('Erro ao receber pedido do fornecedor:', error);
    res.status(500).json({ success: false, error: 'Erro ao processar pedido do fornecedor.', details: error.message });
  } finally {
    connection.release();
  }
});

// Tratamento de erros global
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Algo deu errado no servidor!');
});

// Iniciar o servidor
app.listen(PORT, () => {
  console.log(`Servidor Node.js rodando na porta ${PORT}`);
});
