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
    console.log(`Pool existente para banco: ${databaseName}`);
    return dbPools[databaseName];
  }

  // Crie um novo pool de conexão para o banco de dados específico
  const newPool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: databaseName, // O banco de dados padrão para este pool
    port: parseInt(process.env.DB_PORT || 3306), // Adicionado parseInt
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

// Função auxiliar para remover máscara de CNPJ/CPF
function removeDocumentMask(document) {
  if (!document) return '';
  return String(document).replace(/\D/g, ''); // Remove todos os caracteres não numéricos
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

// ROTA ESPECIAL: Autenticação de usuário fornecedor (NÃO USA authenticateEnvironment)
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
    
    const documentoSemMascara = removeDocumentMask(cnpj_cpf);
    console.log(`Documento CNPJ/CPF sem máscara para consulta: ${documentoSemMascara}`);

    const [rows] = await connection.execute(
      `SELECT Codigo, ID_Pessoa, Documento, Nome, usuario, Ativo FROM tb_Ambientes_Fornecedor WHERE Documento = ? AND usuario = ? AND Senha = ? AND Ativo = 'S'`,
      [documentoSemMascara, usuario, senha]
    );

    if (rows.length === 0) {
      console.log(`Falha na autenticação do usuário fornecedor para CNPJ/CPF: ${cnpj_cpf} e Usuário: ${usuario}`);
      return res.status(401).json({ 
        success: false, 
        error: "Credenciais inválidas ou usuário inativo." 
      });
    }

    const usuarioERP = rows[0];
    console.log(`Usuário autenticado: ${usuarioERP.Nome} (ID_Pessoa: ${usuarioERP.ID_Pessoa})`);

    res.status(200).json({
      success: true,
      user: {
        ID_Pessoa: usuarioERP.ID_Pessoa,
        Documento: usuarioERP.Documento,
        Nome: usuarioERP.Nome,
        usuario: usuarioERP.usuario,
        Ativo: usuarioERP.Ativo,
        id_ambiente_erp: usuarioERP.Codigo,
        nome_ambiente: `Ambiente ${usuarioERP.Codigo}`
      }
    });

  } catch (error) {
    console.error('Erro ao autenticar usuário fornecedor:', error);
    res.status(500).json({
      success: false,
      error: 'Erro interno do servidor ao autenticar usuário.',
      details: error.message
    });
  } finally {
    if (connection) {
      connection.release();
      console.log('Conexão liberada após autenticação de usuário fornecedor.');
    }
  }
});

// Rotas de Sincronização de Dados (protegidas por middleware)
app.use('/api/sync', authenticateEnvironment);

// ROTA: Sincronizar produtos do fornecedor para o cliente
app.post('/api/sync/send-produtos-fornecedor', async (req, res) => {
  if (!req.isSupplierAuth) {
    return res.status(403).json({ error: 'Acesso negado. Apenas Fornecedor Sync pode acessar esta rota.' });
  }

  let connection;
  try {
    const { id_ambiente } = req.body;
    if (!id_ambiente) {
      return res.status(400).json({ error: 'ID do ambiente é obrigatório no corpo da requisição.' });
    }
    
    connection = await req.pool.getConnection();

    // Consultar produtos do banco de dados do fornecedor
    const query = 'SELECT Codigo, Descricao, Codigo_Barra, Unidade, Ativo FROM tb_Produtos_Fornecedor WHERE ID_Ambiente = ? AND Ativo = "S"';
    const [produtos] = await connection.execute(query, [id_ambiente]);
    
    res.status(200).json({
      success: true,
      message: `${produtos.length} produtos encontrados.`,
      produtos: produtos
    });

  } catch (error) {
    console.error('Erro ao buscar produtos do fornecedor:', error);
    res.status(500).json({
      success: false,
      error: 'Erro interno do servidor ao buscar produtos do fornecedor.',
      details: error.message
    });
  } finally {
    if (connection) {
      connection.release();
    }
  }
});

// ROTA: Sincronizar clientes do fornecedor para o cliente
app.post('/api/sync/send-clientes-fornecedor', async (req, res) => {
  if (!req.isSupplierAuth) {
    return res.status(403).json({ error: 'Acesso negado. Apenas Fornecedor Sync pode acessar esta rota.' });
  }

  let connection;
  try {
    const { id_ambiente } = req.body;
    if (!id_ambiente) {
      return res.status(400).json({ error: 'ID do ambiente é obrigatório no corpo da requisição.' });
    }
    
    connection = await req.pool.getConnection();

    const query = 'SELECT Codigo, Nome_Razao_Social, Nome_Fantasia, Cnpj_Cpf, Endereco, Bairro, Cidade, Estado, Cep, Ativo FROM tb_Clientes_Fornecedor WHERE ID_Ambiente = ? AND Ativo = "S"';
    const [clientes] = await connection.execute(query, [id_ambiente]);

    res.status(200).json({
      success: true,
      message: `${clientes.length} clientes encontrados.`,
      clientes: clientes
    });

  } catch (error) {
    console.error('Erro ao buscar clientes do fornecedor:', error);
    res.status(500).json({
      success: false,
      error: 'Erro interno do servidor ao buscar clientes do fornecedor.',
      details: error.message
    });
  } finally {
    if (connection) {
      connection.release();
    }
  }
});

// ROTA: Sincronizar forma de pagamento do fornecedor para o cliente
app.post('/api/sync/send-formas-pagamento-fornecedor', async (req, res) => {
  if (!req.isSupplierAuth) {
    return res.status(403).json({ error: 'Acesso negado. Apenas Fornecedor Sync pode acessar esta rota.' });
  }

  let connection;
  try {
    const { id_ambiente } = req.body;
    if (!id_ambiente) {
      return res.status(400).json({ error: 'ID do ambiente é obrigatório no corpo da requisição.' });
    }

    connection = await req.pool.getConnection();

    const query = 'SELECT Codigo, Descricao FROM tb_Formas_Pagamento_Fornecedor WHERE ID_Ambiente = ? AND Ativo = "S"';
    const [formasPagamento] = await connection.execute(query, [id_ambiente]);

    res.status(200).json({
      success: true,
      message: `${formasPagamento.length} formas de pagamento encontradas.`,
      formas_pagamento: formasPagamento
    });
  } catch (error) {
    console.error('Erro ao buscar formas de pagamento do fornecedor:', error);
    res.status(500).json({
      success: false,
      error: 'Erro interno do servidor ao buscar formas de pagamento do fornecedor.',
      details: error.message
    });
  } finally {
    if (connection) {
      connection.release();
    }
  }
});

// ROTA: Sincronizar comandas do fornecedor para o cliente
app.post('/api/sync/send-comandas-fornecedor', async (req, res) => {
  if (!req.isSupplierAuth) {
    return res.status(403).json({ error: 'Acesso negado. Apenas Fornecedor Sync pode acessar esta rota.' });
  }

  let connection;
  try {
    const { id_ambiente } = req.body;
    if (!id_ambiente) {
      return res.status(400).json({ error: 'ID do ambiente é obrigatório no corpo da requisição.' });
    }

    connection = await req.pool.getConnection();

    const query = 'SELECT Codigo, Descricao FROM tb_Comandas_Fornecedor WHERE ID_Ambiente = ? AND Ativo = "S"';
    const [comandas] = await connection.execute(query, [id_ambiente]);

    res.status(200).json({
      success: true,
      message: `${comandas.length} comandas encontradas.`,
      comandas: comandas
    });

  } catch (error) {
    console.error('Erro ao buscar comandas do fornecedor:', error);
    res.status(500).json({
      success: false,
      error: 'Erro interno do servidor ao buscar comandas do fornecedor.',
      details: error.message
    });
  } finally {
    if (connection) {
      connection.release();
    }
  }
});

// ROTA: Receber pedido do fornecedor (com transação)
app.post('/api/sync/receive-pedido-fornecedor', async (req, res) => {
  if (!req.isSupplierAuth) {
    return res.status(403).json({ error: 'Acesso negado. Apenas Fornecedor Sync pode acessar esta rota.' });
  }

  const { id_ambiente, total_pedido, produtos, data_pedido, id_pedido_app } = req.body;

  if (!id_ambiente || total_pedido === undefined || !Array.isArray(produtos) || produtos.length === 0) {
    return res.status(400).json({ error: 'Dados do pedido inválidos ou incompletos.' });
  }

  let connection;
  try {
    const pool = await getDatabasePool(req.headers.banco_dados);
    connection = await pool.getConnection();
    await connection.beginTransaction();

    console.log('--- INICIANDO receive-pedido-fornecedor ---');
    console.log('Dados recebidos:', { id_ambiente, total_pedido, produtos_count: produtos.length, data_pedido, id_pedido_app });

    // 1. Inserir o pedido mestre
    const pedidoQuery = `
      INSERT INTO tb_Pedidos_Fornecedor
      (ID_Ambiente, Valor_Total, Data_Pedido, Identificador_App)
      VALUES (?, ?, ?, ?)
    `;

    const [pedidoResult] = await connection.query(pedidoQuery, [
      id_ambiente,
      total_pedido,
      data_pedido,
      id_pedido_app
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
      success: false,
      error: 'Erro interno do servidor ao processar o pedido',
      details: error.message
    });
  } finally {
    if (connection) {
      connection.release();
      console.log('Conexão liberada após processamento do pedido.');
    }
  }
});


// Iniciar o servidor
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
