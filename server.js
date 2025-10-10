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
  allowedHeaders: ['Content-Type', 'Authorization', 'x-cnpj', 'x-usuario', 'x-senha', 'x-database-name'],
  credentials: true
}));

// Middleware para parsing JSON
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Objeto para armazenar pools de conexão específicos por banco de dados
const dbPools = {};

// Função para remover máscara de CNPJ/CPF
const removeDocumentMask = (documento) => {
  if (typeof documento !== 'string') return '';
  return documento.replace(/\D/g, '');
};

/**
 * Função para obter ou criar um pool de conexão para um banco de dados específico.
 */
async function getDatabasePool(databaseName) {
  if (!databaseName) {
    throw new Error('Nome do banco de dados não fornecido.');
  }

  if (dbPools[databaseName]) {
    return dbPools[databaseName];
  }

  const newPool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: databaseName,
    port: parseInt(process.env.DB_PORT || 3333), // Alterado para 3333 como padrão
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
  });

  try {
    const connection = await newPool.getConnection();
    await connection.query('SELECT 1');
    connection.release();
    console.log(`Pool de conexão criado e testado para o banco de dados: ${databaseName}`);
  } catch (error) {
    console.error(`Erro ao criar ou testar pool para o banco de dados ${databaseName}:`, error);
    delete dbPools[databaseName];
    throw new Error(`Não foi possível conectar ao banco de dados ${databaseName}.`);
  }

  dbPools[databaseName] = newPool;
  return newPool;
}

// Middleware de autenticação de ambiente
const authenticateEnvironment = async (req, res, next) => {
  const banco_dados = req.headers['x-database-name'];
  const cnpj = req.headers['x-cnpj'];
  const usuario = req.headers['x-usuario'];
  const senha = req.headers['x-senha'];

  req.pool = null;  
  req.isClientAppAuth = false;
  req.isSupplierAuth = false;
  req.environment = null;

  if (!cnpj || !usuario || !senha || !banco_dados) {
    return res.status(400).json({ 
      error: 'Credenciais de ambiente incompletas', 
      details: 'Headers X-CNPJ, X-USUARIO, X-SENHA e X-DATABASE-NAME são obrigatórios.' 
    });
  }

  let connection;
  try {
    req.pool = await getDatabasePool(banco_dados);  

    // CASO 1: Autenticação para Fornecedor (credenciais de sistema)
    if (usuario === SUPPLIER_SYNC_USER && senha === SUPPLIER_SYNC_PASS) {
      req.isSupplierAuth = true;
      req.environment = { cnpj, usuario, tipo: 'fornecedor_sync' };
      console.log('Ambiente autenticado como Fornecedor Sync.');
      return next();
    }
    
    // CASO 2: Autenticação para ClienteApp (credenciais do ambiente do cliente)
    connection = await req.pool.getConnection();
    const [rows] = await connection.execute(
      'SELECT * FROM tb_ambientes WHERE cnpj = ? AND usuario = ? AND senha = ? AND ativo = "S"',
      [cnpj, usuario, senha]
    );

    if (rows.length > 0) {
      req.isClientAppAuth = true;
      req.environment = { ...rows[0], tipo: 'cliente' };
      console.log(`Ambiente autenticado como ClienteApp: ${rows[0].nome_empresa}`);
      return next();
    }

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
  } finally {
    if (connection) connection.release();
  }
};

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// ==========================================
// ROTAS PARA FORNECEDOR
// ==========================================

// ROTA: Autenticação de usuário fornecedor
app.post('/api/sync/authenticate-fornecedor-user', async (req, res) => {
  const { cnpj_cpf, usuario, senha } = req.body;
  const { 'x-database-name': banco_dados, 'x-cnpj': headerCnpj, 'x-usuario': headerUser, 'x-senha': headerPass } = req.headers;

  // Validação das credenciais de sincronização - Apenas SUPPLIER_SYNC_USER/PASS pode chamar esta rota
  if (headerUser !== SUPPLIER_SYNC_USER || headerPass !== SUPPLIER_SYNC_PASS) {
    console.warn('❌ FALHA NA VALIDAÇÃO DOS HEADERS DE SISTEMA');
    return res.status(401).json({ error: "Credenciais de sincronização de fornecedor inválidas nos headers." });
  }

  if (!cnpj_cpf || !usuario || !senha || !banco_dados) {
    return res.status(400).json({ error: 'Dados de autenticação incompletos.' });
  }

  let connection;
  try {
    const pool = await getDatabasePool(banco_dados);
    connection = await pool.getConnection();

    const documentoSemMascara = removeDocumentMask(cnpj_cpf);

    const [rows] = await connection.execute(
      `SELECT Codigo, ID_Pessoa, Documento, Nome, usuario, Ativo, d_entrega, dias_bloqueio_pedidos 
       FROM tb_Ambientes_Fornecedor 
       WHERE Documento = ? AND usuario = ? AND Senha = ? AND Ativo = 'S'`,
      [documentoSemMascara, usuario, senha]
    );

    if (rows.length === 0) {
      return res.status(401).json({  
        success: false,  
        error: "Credenciais inválidas ou usuário inativo."  
      });
    }

    const usuarioERP = rows[0];

    res.status(200).json({
      success: true,
      user: {
        ID_Pessoa: usuarioERP.ID_Pessoa,
        Documento: usuarioERP.Documento,
        Nome: usuarioERP.Nome,
        usuario: usuarioERP.usuario,
        Ativo: usuarioERP.Ativo,
        id_ambiente_erp: usuarioERP.Codigo, // Código do ambiente na tb_Ambientes_Fornecedor
        nome_ambiente: usuarioERP.Nome, // Usar o nome do ambiente
        d_entrega: usuarioERP.d_entrega || null,
        dias_bloqueio_pedidos: usuarioERP.dias_bloqueio_pedidos || 0
      }
    });

  } catch (error) {
    console.error('❌ ERRO ao autenticar usuário fornecedor:', error);
    res.status(500).json({
      success: false,
      error: 'Erro interno do servidor ao autenticar usuário fornecedor.',
      details: error.message
    });
  } finally {
    if (connection) connection.release();
  }
});

// ROTA: Buscar produtos do fornecedor (para o próprio fornecedor)
app.post('/api/sync/send-produtos-fornecedor', authenticateEnvironment, async (req, res) => {
  if (!req.isSupplierAuth && !req.isClientAppAuth) { // Permite Fornecedor Sync ou ClienteApp (se estiver acessando produtos de um fornecedor)
    return res.status(403).json({ error: 'Acesso negado. Requer autenticação de fornecedor ou cliente.' });
  }

  const { id_ambiente_fornecedor } = req.body; // Adicionado para permitir filtrar por ambiente específico
  const banco_dados = req.headers['x-database-name'];

  if (!banco_dados) {
    return res.status(400).json({ error: 'Banco de dados não especificado no header.' });
  }
  
  let connection;
  try {
    const pool = await getDatabasePool(banco_dados);
    connection = await pool.getConnection();

    let query = `
      SELECT 
        tp.codigo as id, 
        tp.produto as nome, 
        tp.codigo_barras as codigo_barras, 
        tp.preco_venda as preco_unitario, 
        tp.q_minimo, 
        tp.q_multiplo,
        ta.Nome as nome_fornecedor,
        ta.Codigo as id_prod_fornecedor -- ID do ambiente na tb_Ambientes_Fornecedor
      FROM tb_Produtos_Fornecedor tp
      LEFT JOIN tb_Ambientes_Fornecedor ta ON tp.id_ambiente_fornecedor = ta.Codigo
      WHERE tp.ativo = 'S'
    `;
    const params = [];

    if (id_ambiente_fornecedor) { // Filtra produtos de um ambiente específico do fornecedor
        query += ` AND tp.id_ambiente_fornecedor = ?`;
        params.push(id_ambiente_fornecedor);
    }
    
    query += ` ORDER BY tp.produto`;

    const [rows] = await connection.execute(query, params);
    
    res.json({
        success: true,
        produtos: rows
    });
  } catch (error) {
    console.error('❌ ERRO AO BUSCAR PRODUTOS DO FORNECEDOR:', error);
    res.status(500).json({ success: false, error: 'Erro ao buscar produtos no ERP do fornecedor.', details: error.message });
  } finally {
    if (connection) connection.release();
  }
});

// ROTA: Buscar ambientes do fornecedor
app.post('/api/sync/get-ambientes-fornecedor', authenticateEnvironment, async (req, res) => {
  console.log('🌳 REQUISIÇÃO PARA BUSCAR AMBIENTES DO FORNECEDOR');

  if (!req.isSupplierAuth) {
    console.warn('❌ Acesso negado: Requer autenticação de Fornecedor Sync.');
    return res.status(403).json({ error: 'Acesso negado. Esta rota requer autenticação de Fornecedor Sync.' });
  }

  let connection;
  try {
    connection = await req.pool.getConnection();

    const [rows] = await connection.execute(
       `SELECT Codigo as id, Nome as nome, ID_Pessoa, Documento, d_entrega, dias_bloqueio_pedidos FROM tb_Ambientes_Fornecedor WHERE Ativo = 'S' ORDER BY Nome`
    );
    
    res.json({
      success: true,
      ambientes: rows
    });

  } catch (error) {
    console.error('❌ ERRO AO BUSCAR AMBIENTES:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Erro ao buscar ambientes no ERP do fornecedor.', 
      details: error.message 
    });
  } finally {
    if (connection) connection.release();
  }
});

// ROTA: Receber pedido de CLIENTE para FORNECEDOR (Pedidos Fornecedor Integrado)
app.post('/api/sync/receive-pedido-cliente-fornecedor', authenticateEnvironment, async (req, res) => {
  console.log('--- INICIANDO receive-pedido-cliente-fornecedor ---');
  
  if (!req.isSupplierAuth) {
    console.warn('❌ Acesso negado: Requer autenticação de Fornecedor Sync.');
    return res.status(403).json({ error: 'Acesso negado. Esta rota requer autenticação de Fornecedor Sync.' });
  }

  const {
      id_ambiente,
      valor_total,
      produtos,
      data_pedido,
      nome_cliente,
      contato,
      identificador_cliente_item,
      id_pedido_base44 // ID do PedidoFornecedor do Base44 para vincular
  } = req.body;

  if (!id_ambiente || valor_total === undefined || !Array.isArray(produtos) || produtos.length === 0 || !data_pedido) {
      console.warn('❌ DADOS DO PEDIDO INVÁLIDOS OU INCOMPLETOS para /receive-pedido-cliente-fornecedor.');
      return res.status(400).json({ 
          success: false, 
          error: 'Dados do pedido inválidos ou incompletos.' 
      });
  }

  let connection;
  try {
      connection = await req.pool.getConnection();
      await connection.beginTransaction();

      // Formatar data_pedido para o formato DATETIME do MySQL (YYYY-MM-DD HH:MM:SS)
      const dataPedidoFormatada = new Date(data_pedido).toISOString().slice(0, 19).replace('T', ' ');

      // 1. Inserir na tb_Pedidos_Fornecedor
      const pedidoQuery = `
        INSERT INTO tb_Pedidos_Fornecedor
        (data_hora_lancamento, id_ambiente, valor_total, status, identificador_cliente_item, nome_cliente, contato, id_pedido_base44)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `;
      const [pedidoResult] = await connection.execute(pedidoQuery, [
        dataPedidoFormatada,
        id_ambiente,
        valor_total,
        'pendente',
        identificador_cliente_item || null,
        nome_cliente || null,
        removeDocumentMask(contato) || null,
        id_pedido_base44 || null // Salva o ID do PedidoFornecedor do Base44
      ]);

      const newPedidoId = pedidoResult.insertId;
      console.log(`✅ Pedido inserido com ID: ${newPedidoId}`);

      // 2. Inserir na tb_Pedidos_Produtos_Fornecedor
      const produtoQuery = `
        INSERT INTO tb_Pedidos_Produtos_Fornecedor
        (id_pedido, id_produto, quantidade, preco_unitario, valor_total)
        VALUES ?
      `;

      const productsValues = produtos.map(p => [
        newPedidoId,
        p.id_produto,
        p.quantidade,
        p.valor_unitario,
        p.total_produto
      ]);

      await connection.query(produtoQuery, [productsValues]);
      console.log(`✅ ${productsValues.length} produtos inseridos para o pedido ${newPedidoId}.`);

      await connection.commit();
      console.log(`🎉 Pedido ${newPedidoId} processado e commitado com sucesso.`);

      res.json({
        success: true,
        message: 'Pedido recebido e salvo com sucesso',
        codigo_pedido: newPedidoId, // Retorna o ID do pedido no ERP do fornecedor
        id_pedido_base44: id_pedido_base44 // Retorna o ID do Base44 para que ele possa ser atualizado
      });

  } catch (error) {
      console.error('❌ ERRO ao salvar pedido de cliente para fornecedor:', error);
      if (connection) await connection.rollback();
      res.status(500).json({
        success: false,
        error: 'Erro interno do servidor ao processar o pedido',
        details: error.message
      });
  } finally {
      if (connection) connection.release();
  }
});

// ROTA: Cancelar pedido do fornecedor
app.post('/api/sync/cancel-pedido-fornecedor', authenticateEnvironment, async (req, res) => {
  console.log('🚫 ROTA: Cancelar pedido do fornecedor');
  
  if (!req.isSupplierAuth) {
    return res.status(403).json({ error: 'Acesso negado. Requer autenticação de Fornecedor Sync.' });
  }

  const { id_pedido_sistema_externo, motivo_cancelamento, data_cancelamento } = req.body;

  if (!id_pedido_sistema_externo) {
    return res.status(400).json({ success: false, error: 'ID do pedido é obrigatório.' });
  }

  let connection;
  try {
    connection = await req.pool.getConnection();

    const [result] = await connection.execute(
      `UPDATE tb_Pedidos_Fornecedor 
       SET status = 'cancelado', 
           data_cancelamento = ?, 
           motivo_cancelamento = ?
       WHERE codigo = ?`, // id_pedido_sistema_externo corresponde ao 'codigo' na tb_Pedidos_Fornecedor
      [data_cancelamento || new Date().toISOString().slice(0, 19).replace('T', ' '), motivo_cancelamento || 'Cancelado pelo sistema', id_pedido_sistema_externo]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, error: 'Pedido não encontrado no ERP do fornecedor' });
    }

    res.json({ success: true, message: 'Pedido cancelado com sucesso no ERP do fornecedor' });

  } catch (error) {
    console.error('❌ ERRO ao cancelar pedido no MySQL:', error);
    res.status(500).json({ success: false, error: 'Erro interno ao cancelar pedido', details: error.message });
  } finally {
    if (connection) connection.release();
  }
});

// ==========================================
// ROTAS PARA CLIENTES
// ==========================================

// Rota para buscar clientes
app.post('/api/sync/get-clientes', authenticateEnvironment, async (req, res) => {
  try {
    if (!req.isClientAppAuth) {
      return res.status(403).json({ 
        error: 'Acesso negado', 
        details: 'Esta rota requer autenticação de ClienteApp.' 
      });
    }

    const query = `
      SELECT 
        codigo, 
        nome, 
        cnpj,
        cpf,
        ativo
      FROM tb_clientes 
      WHERE ativo = 'S'
      ORDER BY nome
    `;

    const [rows] = await req.pool.execute(query);
    
    res.json({
      success: true,
      clientes: rows,
      total: rows.length
    });

  } catch (error) {
    console.error('Erro ao buscar clientes:', error);
    res.status(500).json({
      error: 'Erro interno do servidor',
      details: error.message
    });
  }
});

// Rota para buscar produtos do cliente
app.post('/api/sync/get-produtos', authenticateEnvironment, async (req, res) => {
  try {
    if (!req.isClientAppAuth) {
      return res.status(403).json({ 
        error: 'Acesso negado', 
        details: 'Esta rota requer autenticação de ClienteApp.' 
      });
    }

    const query = `
      SELECT 
        codigo, 
        produto, 
        codigo_barras, 
        preco_venda, 
        estoque, 
        ativo
      FROM tb_produtos 
      WHERE ativo = 'S'
      ORDER BY produto
    `;

    const [rows] = await req.pool.execute(query);
    
    res.json({
      success: true,
      produtos: rows,
      total: rows.length
    });

  } catch (error) {
    console.error('Erro ao buscar produtos do cliente:', error);
    res.status(500).json({
      error: 'Erro interno do servidor',
      details: error.message
    });
  }
});

// Rota para buscar formas de pagamento do cliente
app.post('/api/sync/get-formas-pagamento', authenticateEnvironment, async (req, res) => {
  try {
    if (!req.isClientAppAuth) {
      return res.status(403).json({  
        error: 'Acesso negado',  
        details: 'Esta rota requer autenticação de ClienteApp.'  
      });
    }

    let connection;
    try {
      connection = await req.pool.getConnection();
      const query = `
        SELECT codigo, forma_pagamento, ativo  
        FROM tb_formas_pagamento  
        WHERE ativo = 'S'
        ORDER BY forma_pagamento
      `;

      const [rows] = await connection.execute(query);
      
      res.json({
        success: true,
        formas: rows,
        total: rows.length
      });
    } finally {
      if (connection) connection.release();
    }
  } catch (error) {
    console.error('Erro ao buscar formas de pagamento do cliente:', error);
    res.status(500).json({
      error: 'Erro interno do servidor',
      details: error.message
    });
  }
});

// Rota para buscar comandas do cliente
app.post('/api/sync/get-comandas', authenticateEnvironment, async (req, res) => {
  try {
    if (!req.isClientAppAuth) {
      return res.status(403).json({  
        error: 'Acesso negado',  
        details: 'Esta rota requer autenticação de ClienteApp.'  
      });
    }
    const { filtro_status } = req.body; // Adicionado para permitir filtro de status

    let connection;
    try {
      connection = await req.pool.getConnection();
      let query = `
        SELECT codigo, comanda, ativo  
        FROM tb_comandas  
      `;
      const params = [];

      if (filtro_status && ['S', 'N', 'U'].includes(filtro_status)) {
          query += ' WHERE ativo = ?';
          params.push(filtro_status);
      }
      query += ' ORDER BY comanda';


      const [rows] = await connection.execute(query, params);
      
      res.json({
        success: true,
        comandas: rows,
        total: rows.length
      });
    } finally {
      if (connection) connection.release();
    }
  } catch (error) {
    console.error('Erro ao buscar comandas do cliente:', error);
    res.status(500).json({
      error: 'Erro interno do servidor',
      details: error.message
    });
  }
});

// ROTA para receber pedidos do cliente (pré-venda)
app.post('/api/sync/send-pedidos', authenticateEnvironment, async (req, res) => {
  console.log('📦 ROTA: /api/sync/send-pedidos - Recebendo pedido do cliente');
  
  if (!req.isClientAppAuth) {
    console.warn('❌ Acesso negado: requer autenticação de ClienteApp');
    return res.status(403).json({
      error: 'Acesso negado',
      details: 'Esta rota requer autenticação de ClienteApp.'
    });
  }

  const { data, hora, id_cliente, id_forma_pagamento, id_local_retirada, total_produtos, produtos } = req.body;

  const pedido = {
      data, hora, id_cliente, id_forma_pagamento, id_local_retirada, total_produtos, produtos,
      status: req.body.status || 'pendente',
  };

  if (!pedido.data || !pedido.hora || pedido.total_produtos === undefined || !Array.isArray(pedido.produtos) || pedido.produtos.length === 0) {
    console.warn('❌ Dados do pedido incompletos');
    return res.status(400).json({
      error: 'Dados do pedido inválidos ou incompletos',
      details: 'data, hora, total_produtos e produtos são obrigatórios'
    });
  }

  let connection;
  try {
    connection = await req.pool.getConnection();
    await connection.beginTransaction();

    const pedidoQuery = `
      INSERT INTO tb_pedidos
      (data, hora, id_cliente, id_forma_pagamento, id_local_retirada, total_produtos, status)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `;
    const [pedidoResult] = await connection.execute(pedidoQuery, [
      pedido.data,
      pedido.hora,
      pedido.id_cliente || null,
      pedido.id_forma_pagamento || null,
      pedido.id_local_retirada || null,
      pedido.total_produtos,
      pedido.status
    ]);

    const newPedidoId = pedidoResult.insertId;

    const produtoQuery = `
      INSERT INTO tb_pedidos_produtos
      (id_pedido, id_produto, quantidade, unitario, total_produto, observacao)
      VALUES ?
    `;
    
    const produtosValues = pedido.produtos.map(item => [
      newPedidoId,
      item.id_produto,
      item.quantidade,
      item.unitario,
      item.total_produto,
      item.observacao || ''
    ]);

    await connection.query(produtoQuery, [produtosValues]);

    await connection.commit();

    res.status(200).json({
      success: true,
      id_pedido: newPedidoId,
      message: 'Pedido enviado com sucesso'
    });

  } catch (error) {
    console.error('❌ ERRO ao processar pedido do cliente:', error);
    if (connection) {
      await connection.rollback();
    }
    res.status(500).json({
      success: false,
      error: 'Erro interno do servidor ao processar o pedido do cliente.',
      details: error.message
    });
  } finally {
    if (connection) connection.release();
  }
});

// ROTA: Buscar lista de pedidos do cliente
app.post('/api/sync/get-pedidos-list', authenticateEnvironment, async (req, res) => {
  console.log('📋 ROTA: /api/sync/get-pedidos-list - Buscando pedidos do cliente');

  if (!req.isClientAppAuth) {
    return res.status(403).json({ error: 'Acesso negado. Requer autenticação de ClienteApp.' });
  }

  let connection;
  try {
    connection = await req.pool.getConnection();
    const [rows] = await connection.execute(`
      SELECT 
        codigo, 
        data, 
        hora, 
        id_cliente, 
        id_forma_pagamento, 
        id_local_retirada, 
        total_produtos, 
        id_lcto_erp, 
        status
      FROM tb_pedidos 
      ORDER BY data DESC, hora DESC
    `);
    
    res.json({
      success: true,
      pedidos: rows
    });

  } catch (error) {
    console.error('❌ ERRO AO BUSCAR PEDIDOS:', error);
    res.status(500).json({
      success: false,
      error: 'Erro interno do servidor ao buscar pedidos.',
      details: error.message
    });
  } finally {
    if (connection) connection.release();
  }
});

// ROTA: Buscar itens de um pedido específico
app.post('/api/sync/send-itens-pedido', authenticateEnvironment, async (req, res) => {
  console.log('📋 ROTA: /api/sync/send-itens-pedido - Buscando itens do pedido');

  if (!req.isClientAppAuth) {
    return res.status(403).json({ error: 'Acesso negado. Requer autenticação de ClienteApp.' });
  }

  const { codigo_pedido } = req.body;

  if (!codigo_pedido) {
    return res.status(400).json({ error: 'Código do pedido é obrigatório.' });
  }

  let connection;
  try {
    connection = await req.pool.getConnection();
    const [rows] = await connection.execute(`
      SELECT 
        pp.codigo,
        pp.id_pedido,
        pp.id_produto,
        pp.quantidade,
        pp.unitario,
        pp.total_produto,
        pp.observacao,
        p.produto as nome_produto
      FROM tb_pedidos_produtos pp
      LEFT JOIN tb_produtos p ON pp.id_produto = p.codigo
      WHERE pp.id_pedido = ?
      ORDER BY pp.codigo
    `, [codigo_pedido]);
    
    res.json({
      success: true,
      itens: rows
    });

  } catch (error) {
    console.error('❌ ERRO AO BUSCAR ITENS DO PEDIDO:', error);
    res.status(500).json({
      success: false,
      error: 'Erro interno do servidor ao buscar itens do pedido.',
      details: error.message
    });
  } finally {
    if (connection) connection.release();
  }
});

// ROTA: Enviar dados de Analytics
app.post('/api/sync/send-analytics', authenticateEnvironment, async (req, res) => {
  console.log('📋 ROTA: /api/sync/send-analytics - Buscando dados de analytics');

  if (!req.isClientAppAuth) {
    return res.status(403).json({ error: 'Acesso negado. Requer autenticação de ClienteApp.' });
  }

  let connection;
  try {
    connection = await req.pool.getConnection();
    
    const hoje = new Date();
    const primeiroDiaMesAtual = new Date(hoje.getFullYear(), hoje.getMonth(), 1);
    const ultimoDiaMesAtual = new Date(hoje.getFullYear(), hoje.getMonth() + 1, 0);

    const primeiroDiaMesAnterior = new Date(hoje.getFullYear(), hoje.getMonth() - 1, 1);
    const ultimoDiaMesAnterior = new Date(hoje.getFullYear(), hoje.getMonth(), 0);

    // Vendas do Mês Atual
    const [vendasMesAtual] = await connection.execute(`
      SELECT SUM(total_produtos) as total, COUNT(codigo) as pedidos
      FROM tb_pedidos
      WHERE data BETWEEN ? AND ?
    `, [primeiroDiaMesAtual, ultimoDiaMesAtual]);

    // Vendas do Mês Anterior
    const [vendasMesAnterior] = await connection.execute(`
      SELECT SUM(total_produtos) as total, COUNT(codigo) as pedidos
      FROM tb_pedidos
      WHERE data BETWEEN ? AND ?
    `, [primeiroDiaMesAnterior, ultimoDiaMesAnterior]);

    // Total de Clientes
    const [totalClientes] = await connection.execute(`
      SELECT COUNT(codigo) as total FROM tb_clientes WHERE ativo = 'S'
    `);
    
    // Novos Clientes do Mês
    const [novosClientesMes] = await connection.execute(`
      SELECT COUNT(codigo) as total
      FROM tb_clientes
      WHERE created_date BETWEEN ? AND ?
    `, [primeiroDiaMesAtual, ultimoDiaMesAtual]);

    // Total de Produtos
    const [totalProdutos] = await connection.execute(`
      SELECT COUNT(codigo) as total FROM tb_produtos WHERE ativo = 'S'
    `);

    // Produtos Mais Vendidos (top 5)
    const [maisVendidos] = await connection.execute(`
      SELECT 
        tpp.id_produto, 
        tp.produto as nome,
        SUM(tpp.quantidade) as vendas,
        SUM(tpp.total_produto) as valor_total
      FROM tb_pedidos_produtos tpp
      JOIN tb_produtos tp ON tpp.id_produto = tp.codigo
      GROUP BY tpp.id_produto, tp.produto
      ORDER BY vendas DESC
      LIMIT 5
    `);

    const vendasAtuais = vendasMesAtual[0].total || 0;
    const pedidosAtuais = vendasMesAtual[0].pedidos || 0;
    const vendasAnteriores = vendasMesAnterior[0].total || 0;
    const pedidosAnteriores = vendasMesAnterior[0].pedidos || 0;

    const crescimentoVendas = vendasAnteriores > 0 ? ((vendasAtuais - vendasAnteriores) / vendasAnteriores) * 100 : (vendasAtuais > 0 ? 100 : 0);
    const crescimentoPedidos = pedidosAnteriores > 0 ? ((pedidosAtuais - pedidosAnteriores) / pedidosAnteriores) * 100 : (pedidosAtuais > 0 ? 100 : 0);

    res.json({
      success: true,
      analytics: {
        vendas: {
          totalMes: vendasAtuais,
          totalMesAnterior: vendasAnteriores,
          crescimento: crescimentoVendas
        },
        pedidos: {
          totalMes: pedidosAtuais,
          totalMesAnterior: pedidosAnteriores,
          crescimento: crescimentoPedidos
        },
        clientes: {
          total: totalClientes[0].total || 0,
          novosClientes: novosClientesMes[0].total || 0
        },
        produtos: {
          total: totalProdutos[0].total || 0,
          maisVendidos: maisVendidos
        }
      }
    });

  } catch (error) {
    console.error('❌ ERRO AO BUSCAR DADOS DE ANALYTICS:', error);
    res.status(500).json({
      success: false,
      error: 'Erro interno do servidor ao buscar dados de analytics.',
      details: error.message
    });
  } finally {
    if (connection) connection.release();
  }
});


// ROTA: Atualizar status da comanda
app.post('/api/sync/update-comanda-status', authenticateEnvironment, async (req, res) => {
    const { id_comanda, status } = req.body;

    if (!req.isClientAppAuth) {
        return res.status(403).json({
            error: 'Acesso negado',
            details: 'Esta rota requer autenticação de ClienteApp.'
        });
    }

    if (!id_comanda || !status) {
        return res.status(400).json({
            success: false,
            error: 'id_comanda e status são obrigatórios'
        });
    }

    const statusValidos = ['S', 'N', 'U'];
    if (!statusValidos.includes(status)) {
        return res.status(400).json({
            success: false,
            error: 'Status inválido. Use S (disponível), N (inativo) ou U (em uso)'
        });
    }

    let connection;
    try {
        connection = await req.pool.getConnection();

        const updateQuery = `
            UPDATE tb_comandas 
            SET ativo = ? 
            WHERE codigo = ?
        `;

        const [result] = await connection.execute(updateQuery, [status, id_comanda]);

        if (result.affectedRows === 0) {
            return res.json({
                success: false,
                error: 'Comanda não encontrada'
            });
        }

        res.json({
            success: true,
            message: `Status da comanda atualizado para ${status}`,
            id_comanda: id_comanda,
            novo_status: status
        });

    } catch (error) {
        console.error('❌ ERRO ao atualizar status da comanda:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    } finally {
        if (connection) connection.release();
    }
});


// ROTA: Cancelar pré-venda do cliente (se existir)
app.post('/api/sync/cancel-pre-venda-cliente', authenticateEnvironment, async (req, res) => {
  console.log('🚫 ROTA: Cancelar pré-venda do cliente');
  
  if (!req.isClientAppAuth) {
    return res.status(403).json({ error: 'Acesso negado. Requer autenticação de ClienteApp.' });
  }

  const { id_pre_venda_erp, motivo, data_cancelamento } = req.body;

  if (!id_pre_venda_erp) {
    return res.status(400).json({ success: false, error: 'ID da pré-venda no ERP é obrigatório.' });
  }

  let connection;
  try {
    connection = await req.pool.getConnection();

    // Exemplo de como você poderia "cancelar" uma pré-venda
    // Isso é um placeholder, pois o que significa "cancelar" no seu ERP depende da sua lógica.
    // Pode ser atualizar o status para "cancelado", ou remover o registro, etc.
    const [result] = await connection.execute(
      `UPDATE tb_pedidos 
       SET status = 'cancelado', 
           motivo_cancelamento = ?, 
           data_cancelamento = ?
       WHERE codigo = ?`, // Assumindo que id_pre_venda_erp é o 'codigo' na tb_pedidos
      [motivo || 'Cancelado pelo sistema', data_cancelamento || new Date().toISOString().slice(0, 19).replace('T', ' '), id_pre_venda_erp]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, error: 'Pré-venda não encontrada no ERP do cliente.' });
    }

    res.json({ success: true, message: 'Pré-venda cancelada/atualizada com sucesso no ERP do cliente.' });

  } catch (error) {
    console.error('❌ ERRO ao cancelar pré-venda do cliente:', error);
    res.status(500).json({ success: false, error: 'Erro interno ao cancelar pré-venda.', details: error.message });
  } finally {
    if (connection) connection.release();
  }
});


// ==========================================
// OUTRAS ROTAS (Ex: Admin ERP para Fornecedores)
// ==========================================

// Rota para buscar clientes de um fornecedor específico (Chamada pelo FornecedorApp para o seu ERP)
app.post('/api/sync/get-clientes-fornecedor', authenticateEnvironment, async (req, res) => {
    if (!req.isSupplierAuth) {
        return res.status(403).json({ error: 'Acesso negado. Requer autenticação de Fornecedor Sync.' });
    }

    const { id_fornecedor_na_tabela_clientes } = req.body; // ID do fornecedor na tabela de clientes do fornecedor

    if (!id_fornecedor_na_tabela_clientes) {
        return res.status(400).json({ error: 'ID do fornecedor é obrigatório.' });
    }

    let connection;
    try {
        connection = await req.pool.getConnection();
        const [rows] = await connection.execute(
            `SELECT 
                codigo as id, 
                nome as nome_cliente, 
                cnpj_cpf, 
                endereco, 
                telefone 
            FROM tb_clientes_do_fornecedor 
            WHERE id_fornecedor = ? AND ativo = 'S' ORDER BY nome_cliente`,
            [id_fornecedor_na_tabela_clientes]
        );
        res.json({ success: true, clientes: rows });
    } catch (error) {
        console.error('❌ ERRO ao buscar clientes do fornecedor:', error);
        res.status(500).json({ success: false, error: 'Erro ao buscar clientes do fornecedor.', details: error.message });
    } finally {
        if (connection) connection.release();
    }
});

// Rota para buscar datas de bloqueio de pedidos para um fornecedor
app.post('/api/sync/get-datas-bloqueio-fornecedor', authenticateEnvironment, async (req, res) => {
    if (!req.isSupplierAuth) {
        return res.status(403).json({ error: 'Acesso negado. Requer autenticação de Fornecedor Sync.' });
    }

    const { id_ambiente_fornecedor } = req.body; // ID do ambiente na tb_Ambientes_Fornecedor

    if (!id_ambiente_fornecedor) {
        return res.status(400).json({ error: 'ID do ambiente do fornecedor é obrigatório.' });
    }

    let connection;
    try {
        connection = await req.pool.getConnection();
        const [rows] = await connection.execute(
            `SELECT d_entrega, dias_bloqueio_pedidos
             FROM tb_Ambientes_Fornecedor
             WHERE Codigo = ?`,
            [id_ambiente_fornecedor]
        );

        if (rows.length === 0) {
            return res.status(404).json({ success: false, error: 'Ambiente do fornecedor não encontrado.' });
        }

        const data = rows[0];
        res.json({
            success: true,
            d_entrega: data.d_entrega,
            dias_bloqueio_pedidos: data.dias_bloqueio_pedidos
        });
    } catch (error) {
        console.error('❌ ERRO ao buscar datas de bloqueio do fornecedor:', error);
        res.status(500).json({ success: false, error: 'Erro ao buscar datas de bloqueio.', details: error.message });
    } finally {
        if (connection) connection.release();
    }
});

// Iniciar o servidor
app.listen(PORT, () => {
  console.log(`🚀 Servidor ERP rodando na porta ${PORT}`);
});
