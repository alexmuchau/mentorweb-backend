const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3333;

// Credenciais para sincronização de fornecedor
const SUPPLIER_SYNC_USER = process.env.SUPPLIER_SYNC_USER || 'mentorweb_fornecedor';
const SUPPLIER_SYNC_PASS = process.env.SUPPLIER_SYNC_PASS || 'mentorweb_sync_forn_2024';

// Middlewares de segurança e performance
app.use(helmet());
app.use(compression());
app.use(morgan('combined'));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000
});
app.use(limiter);

// CORS
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'cnpj', 'usuario', 'senha', 'banco_dados'],
  credentials: true
}));

// Middleware para parsing JSON
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Objeto para armazenar pools de conexão específicos por banco de dados
const dbPools = {};

// Função para obter ou criar um pool de conexão para um banco de dados específico
async function getDatabasePool(databaseName) {
  if (!databaseName) {
    throw new Error('Nome do banco de dados não fornecido.');
  }

  // Se o pool para este banco de dados já existe, retorne-o
  if (dbPools[databaseName]) {
    return dbPools[databaseName];
  }

  // Crie um novo pool de conexão para o banco de dados específico
  const newPool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: databaseName, // O banco de dados padrão para este pool
    port: process.env.DB_PORT || 3306, // Adicionado porta, se aplicável
    waitForConnections: true,
    connectionLimit: 10, // Ajuste conforme necessário
    queueLimit: 0
  });

  // Testar a conexão
  try {
    const connection = await newPool.getConnection();
    await connection.query('SELECT 1'); // Testa a conexão com uma query simples
    connection.release();
    console.log(`Pool de conexão criado e testado para o banco de dados: ${databaseName}`);
  } catch (error) {
    console.error(`Erro ao criar ou testar pool para o banco de dados ${databaseName}:`, error);
    // Em caso de erro na conexão inicial, remova o pool para que uma nova tentativa possa ser feita
    delete dbPools[databaseName];
    throw new Error(`Não foi possível conectar ao banco de dados ${databaseName}.`);
  }

  // Armazene e retorne o novo pool
  dbPools[databaseName] = newPool;
  return newPool;
}

// Middleware de autenticação de ambiente
const authenticateEnvironment = async (req, res, next) => {
  console.log('--- HEADERS RECEBIDOS EM authenticateEnvironment ---');
  console.log('cnpj:', req.headers.cnpj);
  console.log('usuario:', req.headers.usuario);
  console.log('senha:', req.headers.senha ? '******' : 'N/A');
  console.log('banco_dados:', req.headers.banco_dados);
  console.log('-------------------------------------------------');

  const { cnpj, usuario, senha, banco_dados } = req.headers;

  // Inicializa req.pool e flags
  req.pool = null; 
  req.isClientAppAuth = false;
  req.isSupplierAuth = false;
  req.environment = null;

  if (!cnpj || !usuario || !senha || !banco_dados) {
    return res.status(400).json({ error: 'Credenciais de ambiente incompletas', details: 'Headers CNPJ, Usuário, Senha e Banco de Dados são obrigatórios.' });
  }

  try {
    // Tenta obter o pool para o banco_dados.
    req.pool = await getDatabasePool(banco_dados); 

    // CASO 1: Autenticação para Fornecedor (credenciais de sistema)
    if (usuario === SUPPLIER_SYNC_USER && senha === SUPPLIER_SYNC_PASS) {
      req.isSupplierAuth = true;
      req.environment = { cnpj, usuario, tipo: 'fornecedor_sync' };
      console.log('Ambiente autenticado como Fornecedor Sync.');
      return next();
    }
    
    // CASO 2: Autenticação para ClienteApp (credenciais do ambiente do cliente)
    const [rows] = await req.pool.execute(
      'SELECT * FROM tb_ambientes WHERE cnpj = ? AND usuario = ? AND senha = ? AND ativo = "S"',
      [cnpj, usuario, senha]
    );

    if (rows.length > 0) {
      req.isClientAppAuth = true;
      req.environment = { ...rows[0], tipo: 'cliente' };
      console.log(`Ambiente autenticado como ClienteApp: ${rows[0].nome_empresa}`);
      return next();
    }

    // Se nenhuma autenticação for bem-sucedida
    console.warn(`Falha na autenticação do ambiente para CNPJ: ${cnpj} e Usuário: ${usuario}`);
    return res.status(401).json({ error: 'Credenciais de ambiente inválidas ou inativas.' });

  } catch (error) {
    console.error(`Erro no middleware authenticateEnvironment para banco ${banco_dados}:`, error);
    if (error.message && error.message.includes('Não foi possível conectar ao banco de dados')) {
        return res.status(401).json({ error: 'Falha na conexão com o banco de dados do ambiente.', details: error.message });
    }
    if (error.sqlMessage) { 
        return res.status(500).json({ error: 'Erro no banco de dados', details: error.sqlMessage });
    }
    return res.status(500).json({ error: 'Erro interno do servidor', details: error.message });
  }
};

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// ROTA ESPECIAL: Autenticação de usuário fornecedor (não usa authenticateEnvironment)
app.post('/api/sync/authenticate-fornecedor-user', async (req, res) => {
  const { cnpj_cpf, usuario, senha } = req.body;
  const { 'banco_dados': banco_dados, 'usuario': headerUser, 'senha': headerPass } = req.headers;

  // Validação dos headers de sistema
  if (headerUser !== SUPPLIER_SYNC_USER || headerPass !== SUPPLIER_SYNC_PASS) {
      console.warn(`Tentativa de autenticação de fornecedor com headers de sistema inválidos.`);
      return res.status(401).json({ error: "Credenciais de sincronização de fornecedor inválidas nos headers." });
  }

  if (!cnpj_cpf || !usuario || !senha || !banco_dados) {
    return res.status(400).json({ error: 'Dados de autenticação incompletos.' });
  }

  let connection;
  try {
    const pool = await getDatabasePool(banco_dados);
    connection = await pool.getConnection();

    console.log(`Autenticando usuário fornecedor: ${usuario} para o documento: ${cnpj_cpf}`);

    const [rows] = await connection.execute(
      `SELECT Codigo, ID_Pessoa, Documento, Nome, usuario, Ativo FROM tb_Ambientes_Fornecedor WHERE Documento = ? AND usuario = ? AND Senha = ? AND Ativo = 'S'`,
      [cnpj_cpf, usuario, senha]
    );

    if (rows.length > 0) {
      const user = rows[0];
      // Agora, busca o ID e Nome do ambiente do usuário logado na tabela tb_Ambientes
      const [ambienteRows] = await connection.execute(
        `SELECT Codigo, Nome FROM tb_Ambientes WHERE Codigo = ?`,
        [user.Codigo] // Assumindo que Codigo em tb_Ambientes_Fornecedor corresponde a Codigo em tb_Ambientes
      );

      let id_ambiente_erp = null;
      let nome_ambiente = null;
      if (ambienteRows.length > 0) {
        id_ambiente_erp = ambienteRows[0].Codigo;
        nome_ambiente = ambienteRows[0].Nome;
      }
      
      return res.status(200).json({
        success: true,
        user: {
          ...user,
          id_ambiente_erp: id_ambiente_erp,
          nome_ambiente: nome_ambiente
        }
      });
    } else {
      return res.status(401).json({ success: false, error: 'Credenciais de usuário fornecedor inválidas ou inativas.' });
    }

  } catch (error) {
    console.error('Erro ao autenticar usuário fornecedor com ERP:', error);
    res.status(500).json({ error: 'Erro interno do servidor durante a autenticação.', details: error.message });
  } finally {
    if (connection) connection.release();
  }
});


// Rotas de sincronização de dados (requerem autenticação de ambiente)

// Rota para produtos de cliente
app.get('/api/sync/send-produtos', authenticateEnvironment, async (req, res) => {
  if (!req.isClientAppAuth) {
    return res.status(403).json({ error: 'Acesso negado', details: 'Esta rota é exclusiva para ClienteApp.' });
  }
  let connection;
  try {
    connection = await req.pool.getConnection();
    const [rows] = await connection.execute(
      'SELECT Codigo, Produto, Codigo_Barras, Preco_Venda, Estoque, Ativo FROM tb_Produtos WHERE Ativo = "S" ORDER BY Produto'
    );
    res.json({ success: true, produtos: rows, total: rows.length });
  } catch (error) {
    console.error('Erro ao buscar produtos:', error);
    res.status(500).json({ error: 'Erro interno do servidor', details: error.message });
  } finally {
    if (connection) connection.release();
  }
});

// Rota para clientes de cliente
app.get('/api/sync/send-clientes', authenticateEnvironment, async (req, res) => {
  if (!req.isClientAppAuth) {
    return res.status(403).json({ error: 'Acesso negado', details: 'Esta rota é exclusiva para ClienteApp.' });
  }
  let connection;
  try {
    connection = await req.pool.getConnection();
    const [rows] = await connection.execute(
      'SELECT Codigo, Nome, CNPJ, CPF, Ativo FROM tb_Clientes WHERE Ativo = "S" ORDER BY Nome'
    );
    res.json({ success: true, clientes: rows, total: rows.length });
  } catch (error) {
    console.error('Erro ao buscar clientes:', error);
    res.status(500).json({ error: 'Erro interno do servidor', details: error.message });
  } finally {
    if (connection) connection.release();
  }
});

// Rota para formas de pagamento de cliente
app.get('/api/sync/send-formas-pagamento', authenticateEnvironment, async (req, res) => {
  if (!req.isClientAppAuth) {
    return res.status(403).json({ error: 'Acesso negado', details: 'Esta rota é exclusiva para ClienteApp.' });
  }
  let connection;
  try {
    connection = await req.pool.getConnection();
    const [rows] = await connection.execute(
      'SELECT Codigo, Forma_Pagamento, Ativo FROM tb_Formas_Pagamento WHERE Ativo = "S" ORDER BY Forma_Pagamento'
    );
    res.json({ success: true, formas: rows, total: rows.length });
  } catch (error) {
    console.error('Erro ao buscar formas de pagamento:', error);
    res.status(500).json({ error: 'Erro interno do servidor', details: error.message });
  } finally {
    if (connection) connection.release();
  }
});

// Rota para comandas de cliente
app.get('/api/sync/send-comandas', authenticateEnvironment, async (req, res) => {
  if (!req.isClientAppAuth) {
    return res.status(403).json({ error: 'Acesso negado', details: 'Esta rota é exclusiva para ClienteApp.' });
  }
  let connection;
  try {
    connection = await req.pool.getConnection();
    const [rows] = await connection.execute(
      'SELECT Codigo, Comanda, Ativo FROM tb_Comandas WHERE Ativo = "S" ORDER BY Comanda'
    );
    res.json({ success: true, comandas: rows, total: rows.length });
  } catch (error) {
    console.error('Erro ao buscar comandas:', error);
    res.status(500).json({ error: 'Erro interno do servidor', details: error.message });
  } finally {
    if (connection) connection.release();
  }
});

// Rota para receber pedidos de cliente
app.post('/api/sync/receive-pedidos', authenticateEnvironment, async (req, res) => {
  if (!req.isClientAppAuth) {
    return res.status(403).json({ error: 'Acesso negado', details: 'Esta rota é exclusiva para ClienteApp.' });
  }

  const { pedidos } = req.body;
  if (!Array.isArray(pedidos) || pedidos.length === 0) {
    return res.status(400).json({ error: 'Dados do pedido inválidos ou incompletos.' });
  }

  let connection;
  try {
    connection = await req.pool.getConnection();
    await connection.beginTransaction();

    const pedidosInseridos = [];

    for (const pedido of pedidos) {
      const [pedidoResult] = await connection.execute(
        `INSERT INTO tb_Pedidos (Data, Hora, ID_Cliente, ID_Forma_Pagamento, ID_Local_Retirada, Total_Produtos, ID_Lcto_ERP) VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [pedido.data, pedido.hora, pedido.id_cliente, pedido.id_forma_pagamento, pedido.id_local_retirada, pedido.total_produtos, pedido.id_lcto_erp]
      );
      const newPedidoId = pedidoResult.insertId;

      for (const item of pedido.itens) {
        await connection.execute(
          `INSERT INTO tb_Pedidos_Produtos (ID_Pedido, ID_Produto, Quantidade, Unitario, Total_Produto, ID_Lcto_ERP) VALUES (?, ?, ?, ?, ?, ?)`,
          [newPedidoId, item.id_produto, item.quantidade, item.unitario, item.total_produto, item.id_lcto_erp]
        );
      }
      pedidosInseridos.push({ id_pedido_mentorweb: pedido.id_pedido_mentorweb, codigo: newPedidoId });
    }

    await connection.commit();
    res.json({ success: true, message: 'Pedidos recebidos e salvos com sucesso.', pedidos_inseridos: pedidosInseridos });

  } catch (error) {
    console.error('Erro ao receber pedidos:', error);
    if (connection) await connection.rollback();
    res.status(500).json({ error: 'Erro interno do servidor ao processar pedidos.', details: error.message });
  } finally {
    if (connection) connection.release();
  }
});

// Rotas para Fornecedor

// Rota para produtos de fornecedor
app.get('/api/sync/send-produtos-fornecedor', authenticateEnvironment, async (req, res) => {
  if (!req.isSupplierAuth) {
    return res.status(403).json({ error: 'Acesso negado', details: 'Esta rota é exclusiva para sincronização de fornecedor.' });
  }
  let connection;
  try {
    connection = await req.pool.getConnection();
    const [rows] = await connection.execute(
      'SELECT Codigo as id, Produto as nome, Preco_Venda as preco_unitario, Estoque as estoque, Ativo as ativo FROM tb_Produtos_Fornecedor WHERE Ativo = "S" ORDER BY Produto'
    );
    res.json({ success: true, produtos: rows, total: rows.length });
  } catch (error) {
    console.error('Erro ao buscar produtos do fornecedor:', error);
    res.status(500).json({ error: 'Erro interno do servidor', details: error.message });
  } finally {
    if (connection) connection.release();
  }
});

// Rota para receber um pedido para o fornecedor
app.post('/api/sync/receive-pedido-fornecedor', authenticateEnvironment, async (req, res) => {
  console.log('--- INICIANDO receive-pedido-fornecedor ---');
  
  if (!req.isSupplierAuth) {
    return res.status(403).json({ 
      error: 'Acesso negado', 
      details: 'Esta rota requer autenticação de sincronização de fornecedor.' 
    });
  }

  const { id_ambiente, total_pedido, produtos, data_pedido, cliente } = req.body;

  if (!id_ambiente || total_pedido === undefined || !Array.isArray(produtos) || produtos.length === 0) {
    return res.status(400).json({ error: 'Dados do pedido inválidos ou incompletos.' });
  }

  let connection;
  try {
    connection = await req.pool.getConnection();
    await connection.beginTransaction();
    console.log('Transação iniciada.');

    // 1. Inserir na tabela de pedidos
    const pedidoQuery = `
      INSERT INTO tb_Pedidos_Fornecedor 
      (id_ambiente, valor_total, data_hora_lancamento, status) 
      VALUES (?, ?, ?, 'pendente')
    `;
    const [pedidoResult] = await connection.execute(pedidoQuery, [
      id_ambiente, 
      total_pedido,
      data_pedido // Usando data_pedido do payload
    ]);
    const newPedidoId = pedidoResult.insertId;
    console.log(`Pedido mestre inserido com ID: ${newPedidoId}`);

    // 2. Inserir os produtos do pedido
    const produtoQuery = `
      INSERT INTO tb_Pedidos_Produtos_Fornecedor
      (id_pedido, id_produto, quantidade, preco_unitario, valor_total, identificador_cliente_item)
      VALUES ?
    `;
    
    const produtosValues = produtos.map(p => [
      newPedidoId,
      p.id_produto,
      p.quantidade,
      p.valor_unitario,
      p.total_produto,
      p.identificador_cliente_item // Novo campo
    ]);

    await connection.query(produtoQuery, [produtosValues]);
    console.log(`${produtos.length} produtos do pedido inseridos.`);

    await connection.commit();
    console.log('Transação concluída com sucesso (commit).');

    res.status(200).json({
      success: true,
      message: 'Pedido recebido e salvo com sucesso',
      codigo_pedido: newPedidoId
    });

  } catch (error) {
    console.error('Erro ao salvar pedido do fornecedor:', error);
    if (connection) {
      await connection.rollback();
      console.log('Rollback da transação executado.');
    }
    res.status(500).json({
      error: 'Erro interno do servidor ao processar o pedido',
      details: error.message
    });
  } finally {
    if (connection) {
      connection.release();
      console.log('Conexão liberada.');
    }
  }
});


app.listen(PORT, () => {
  console.log(`Servidor ERP Sync rodando na porta ${PORT}`);
});
