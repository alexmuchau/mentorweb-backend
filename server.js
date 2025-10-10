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
    port: parseInt(process.env.DB_PORT || 3306),
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
  const { 'x-database-name': banco_dados, 'x-usuario': headerUser, 'x-senha': headerPass } = req.headers;

  if (headerUser !== SUPPLIER_SYNC_USER || headerPass !== SUPPLIER_SYNC_PASS) {
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
        id_ambiente_erp: usuarioERP.Codigo,
        nome_ambiente: `Ambiente ${usuarioERP.Codigo}`,
        d_entrega: usuarioERP.d_entrega,
        dias_bloqueio_pedidos: usuarioERP.dias_bloqueio_pedidos || 0
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
    if (connection) connection.release();
  }
});

// ROTA: Enviar pedido para fornecedor
app.post('/api/sync/send-pedido-fornecedor', authenticateEnvironment, async (req, res) => {
  if (!req.isClientAppAuth) {
    return res.status(403).json({ error: 'Acesso negado. Apenas clientes podem enviar pedidos para o fornecedor.' });
  }

  const { produtos, id_ambiente, total_pedido, data_pedido, id_pedido_app, nome_cliente, contato, identificador_cliente_item } = req.body;

  console.log('Dados recebidos para pedido:', { 
    produtos: produtos?.length, 
    id_ambiente, 
    total_pedido, 
    data_pedido, 
    nome_cliente, 
    contato, 
    identificador_cliente_item 
  });

  if (!produtos || produtos.length === 0) {
    return res.status(400).json({
      success: false,
      message: 'O pedido deve conter pelo menos um produto.'
    });
  }

  let connection;
  try {
    connection = await req.pool.getConnection();
    await connection.beginTransaction();

    const dataPedidoFormatada = new Date(data_pedido).toLocaleString('sv-SE', { timeZone: 'America/Sao_Paulo' }).slice(0, 19);

    const pedidoQuery = `
      INSERT INTO tb_Pedidos_Fornecedor
      (id_ambiente, valor_total, data_hora_lancamento, id_pedido_sistema_externo, nome_cliente, contato, identificador_cliente_item, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `;
    const [pedidoResult] = await connection.query(pedidoQuery, [
      id_ambiente,
      total_pedido,
      dataPedidoFormatada,
      id_pedido_app || null,
      nome_cliente || null,
      contato || null,
      identificador_cliente_item || null,
      'pendente'
    ]);
    const newPedidoId = pedidoResult.insertId;

    const produtoQuery = `
      INSERT INTO tb_Pedidos_Produtos_Fornecedor
      (id_pedido, id_produto, quantidade, preco_unitario, valor_total)
      VALUES ?
    `;

    const produtosValues = produtos.map(p => [
      newPedidoId,
      p.id_produto,
      p.quantidade,
      p.valor_unitario,
      p.total_produto
    ]);

    await connection.query(produtoQuery, [produtosValues]);
    await connection.commit();

    console.log(`Pedido ${newPedidoId} salvo com sucesso no MySQL`);

    res.status(200).json({
      success: true,
      message: 'Pedido recebido e salvo com sucesso',
      codigo_pedido: newPedidoId
    });

  } catch (error) {
    console.error('Erro ao salvar pedido do fornecedor:', error);
    if (connection) await connection.rollback();
    res.status(500).json({
      error: 'Erro interno do servidor ao processar o pedido',
      details: error.message
    });
  } finally {
    if (connection) connection.release();
  }
});

// ROTA: Receber pedido do fornecedor
app.post('/api/sync/receive-pedido-fornecedor', authenticateEnvironment, async (req, res) => {
  if (!req.isSupplierAuth) {
    return res.status(403).json({
      error: 'Acesso negado. Apenas sincronização de fornecedor pode receber pedidos.'
    });
  }

  const pedidoData = req.body;

  console.log('Processando pedido de fornecedor:', JSON.stringify(pedidoData, null, 2));

  let connection;
  try {
    connection = await req.pool.getConnection();
    await connection.beginTransaction();

    const dataPedidoCliente = new Date(pedidoData.data_pedido);
    const dataFormatada = dataPedidoCliente.toLocaleString('sv-SE', { timeZone: 'America/Sao_Paulo' }).slice(0, 19);

    const [pedidoResult] = await connection.execute(`
      INSERT INTO tb_Pedidos_Fornecedor (
        data_hora_lancamento,
        id_ambiente,
        valor_total,
        status,
        nome_cliente,
        contato,
        identificador_cliente_item
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `, [
      dataFormatada,
      pedidoData.id_ambiente,
      pedidoData.total_pedido,
      'pendente',
      pedidoData.nome_cliente || null,
      pedidoData.contato || null,
      pedidoData.identificador_cliente_item || null
    ]);

    const pedidoId = pedidoResult.insertId;
    console.log(`Pedido inserido com ID: ${pedidoId}`);

    for (const produto of pedidoData.produtos) {
      await connection.execute(`
        INSERT INTO tb_Pedidos_Produtos_Fornecedor (
          id_pedido,
          id_produto,
          quantidade,
          preco_unitario,
          valor_total
        ) VALUES (?, ?, ?, ?, ?)
      `, [
        pedidoId,
        produto.id_produto,
        produto.quantidade,
        produto.preco_unitario,
        produto.valor_total
      ]);
    }

    await connection.commit();
    console.log(`Pedido ${pedidoId} processado com sucesso`);

    res.json({
      success: true,
      codigo_pedido: pedidoId,
      message: 'Pedido recebido e processado com sucesso'
    });

  } catch (error) {
    if (connection) await connection.rollback();
    console.error('Erro ao processar pedido:', error);
    res.status(500).json({
      success: false,
      error: 'Erro interno do servidor',
      details: error.message
    });
  } finally {
    if (connection) connection.release();
  }
});

// ROTA: Receber pedido de CLIENTE para FORNECEDOR (Pedidos Fornecedor Integrado)
app.post('/api/sync/receive-pedido-cliente-fornecedor', authenticateEnvironment, async (req, res) => {
  console.log('--- INICIANDO receive-pedido-cliente-fornecedor ---');
  
  const pedidoData = req.body;

  const {
    id_ambiente,
    total_pedido,
    produtos,
    data_pedido,
    nome_cliente,
    contato,
    identificador_cliente_item
  } = pedidoData;

  console.log(`📋 Dados do pedido recebidos de cliente para fornecedor:`);
  console.log(JSON.stringify(pedidoData, null, 2));

  if (
    !id_ambiente ||
    total_pedido === undefined ||
    !Array.isArray(produtos) ||
    produtos.length === 0 ||
    !data_pedido
  ) {
    console.warn('❌ DADOS DO PEDIDO INVÁLIDOS OU INCOMPLETOS.');
    return res.status(400).json({
      success: false,
      error: 'Dados do pedido inválidos ou incompletos.',
      details: 'id_ambiente, total_pedido, produtos (array não vazio) e data_pedido são obrigatórios.'
    });
  }

  let connection;
  try {
    connection = await req.pool.getConnection();
    await connection.beginTransaction();

    const dataPedidoProcessada = new Date(data_pedido).toLocaleString('sv-SE', { timeZone: 'America/Sao_Paulo' }).slice(0, 19);

    const pedidoQuery = `
      INSERT INTO tb_Pedidos_Fornecedor (
        data_hora_lancamento,
        id_ambiente,
        valor_total,
        status,
        id_pedido_sistema_externo,
        nome_cliente,
        contato,
        identificador_cliente_item
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `;
    const [pedidoResult] = await connection.query(pedidoQuery, [
      dataPedidoProcessada,
      id_ambiente,
      total_pedido,
      'pendente',
      null,
      nome_cliente || null,
      contato || null,
      identificador_cliente_item || null
    ]);

    const newPedidoId = pedidoResult.insertId;
    console.log(`✅ Pedido inserido na tb_Pedidos_Fornecedor com ID: ${newPedidoId}`);

    const produtoQuery = `
      INSERT INTO tb_Pedidos_Produtos_Fornecedor (
        id_pedido,
        id_produto,
        quantidade,
        preco_unitario,
        valor_total
      ) VALUES ?
    `;

    const produtosValues = produtos.map(p => [
      newPedidoId,
      p.id_produto,
      p.quantidade,
      p.valor_unitario || p.preco_unitario,
      p.total_produto || p.valor_total
    ]);

    await connection.query(produtoQuery, [produtosValues]);
    console.log(`✅ ${produtosValues.length} produtos inseridos para o pedido ${newPedidoId}.`);

    await connection.commit();
    console.log(`🎉 Pedido ${newPedidoId} processado e commitado com sucesso.`);

    return res.status(200).json({
      success: true,
      message: 'Pedido recebido e salvo com sucesso',
      codigo_pedido: newPedidoId
    });

  } catch (error) {
    console.error('❌ Erro ao salvar pedido de cliente para fornecedor:', error);
    if (connection) await connection.rollback();
    return res.status(500).json({
      success: false,
      error: 'Erro interno do servidor ao processar o pedido',
      details: error.message
    });
  } finally {
    if (connection) connection.release();
  }
});

// ROTA CORRIGIDA: Buscar produtos do fornecedor (para o próprio fornecedor)
app.post('/api/sync/send-produtos-fornecedor', authenticateEnvironment, async (req, res) => {
  if (!req.isSupplierAuth) {
    return res.status(403).json({ error: 'Acesso negado. Apenas sincronização de fornecedor pode buscar produtos.' });
  }

  let connection;
  try {
    connection = await req.pool.getConnection();

    const [rows] = await connection.execute(
      `SELECT id, nome, preco_unitario, Ativo, q_minimo, q_multiplo 
       FROM tb_Produtos_Fornecedor 
       WHERE Ativo = 'S' 
       ORDER BY nome`
    );

    const produtos = rows.map(p => ({
      ...p,
      preco_unitario: parseFloat(p.preco_unitario),
      q_minimo: parseInt(p.q_minimo) || 1,
      q_multiplo: parseInt(p.q_multiplo) || 1
    }));

    console.log(`Produtos do fornecedor encontrados: ${produtos.length}`);

    res.json({
      success: true,
      produtos: produtos
    });

  } catch (error) {
    console.error(`Erro ao buscar produtos do fornecedor:`, error);
    res.status(500).json({
      success: false,
      error: 'Erro interno do servidor ao buscar produtos do fornecedor.',
      details: error.message
    });
  } finally {
    if (connection) connection.release();
  }
});

// ROTA: Inativar usuário fornecedor (administrativa)
app.post('/api/erp/inativar-usuario-fornecedor', async (req, res) => {
  console.log('🔒 INICIANDO PROCESSO DE INATIVAÇÃO DE USUÁRIO FORNECEDOR');

  const SYSTEM_ADMIN_USER = 'admin_sistema';
  const SYSTEM_ADMIN_PASS = 'admin_inativar_2024';

  const { cnpj_cpf, usuario, motivo } = req.body;
  const banco_dados = req.headers['banco_dados'];
  const headerUser = req.headers['usuario'];
  const headerPass = req.headers['senha'];

  console.log('📋 DADOS RECEBIDOS PARA INATIVAÇÃO:');
  console.log(`   - Usuário a inativar: ${usuario}`);
  console.log(`   - CNPJ/CPF do usuário: ${cnpj_cpf}`);
  console.log(`   - Banco de dados: ${banco_dados}`);
  console.log(`   - Motivo da inativação: ${motivo || 'Não especificado'}`);

  if (headerUser !== SYSTEM_ADMIN_USER || headerPass !== SYSTEM_ADMIN_PASS) {
    console.warn('❌ FALHA NA VALIDAÇÃO DOS HEADERS DE SISTEMA PARA INATIVAÇÃO');
    return res.status(401).json({ error: "Credenciais de sistema inválidas para inativação." });
  }

  if (!cnpj_cpf || !usuario || !banco_dados) {
    console.warn('❌ DADOS DE INATIVAÇÃO INCOMPLETOS');
    return res.status(400).json({ error: 'Dados de inativação incompletos (cnpj_cpf, usuario, banco_dados são obrigatórios).' });
  }

  let connection;
  try {
    console.log(`🔌 CONECTANDO AO BANCO PARA INATIVAR USUÁRIO: ${banco_dados}`);
    const pool = await getDatabasePool(banco_dados);
    connection = await pool.getConnection();
    console.log('✅ Conexão obtida com sucesso para inativação');

    const documentoLimpo = removeDocumentMask(cnpj_cpf);
    console.log(`📝 Documento limpo: ${documentoLimpo}`);

    console.log('🔍 EXECUTANDO QUERY DE INATIVAÇÃO:');
    const [result] = await connection.execute(
      `UPDATE tb_Ambientes_Fornecedor SET Ativo = 'N' WHERE Documento = ? AND usuario = ?`,
      [documentoLimpo, usuario]
    );

    console.log(`📊 RESULTADO DA INATIVAÇÃO: ${result.affectedRows} usuário(s) inativado(s)`);

    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        error: "Nenhum usuário encontrado com os dados fornecidos para inativação."
      });
    }

    res.json({
      success: true,
      message: `Usuário ${usuario} (documento: ${cnpj_cpf}) inativado com sucesso.`,
      usuarios_afetados: result.affectedRows
    });

  } catch (error) {
    console.error('❌ ERRO CRÍTICO DURANTE INATIVAÇÃO:', error);
    res.status(500).json({
      success: false,
      error: 'Erro interno do servidor ao inativar usuário.',
      details: error.message
    });
  } finally {
    if (connection) {
      connection.release();
      console.log('🔌 Conexão liberada de volta ao pool para inativação');
    }
  }
});

// ROTA CORRIGIDA: Buscar ambientes do fornecedor
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
       `SELECT Codigo as id, Nome as nome, ID_Pessoa, Documento, d_entrega, dias_bloqueio_pedidos 
        FROM tb_Ambientes_Fornecedor 
        WHERE Ativo = 'S' 
        ORDER BY Nome`
    );
    
    console.log(`🌳 Ambientes encontrados: ${rows.length}`);
    
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
    if (connection) {
      connection.release();
      console.log('🔌 Conexão liberada para busca de ambientes');
    }
  }
});

// ROTA RENOMEADA: Buscar produtos do fornecedor PARA UM CLIENTE ESPECÍFICO
app.post('/api/sync/get-produtos-fornecedor', authenticateEnvironment, async (req, res) => {
  console.log('📦 REQUISIÇÃO PARA BUSCAR PRODUTOS DO FORNECEDOR');
  
  const { id_ambiente_fornecedor } = req.body;

  console.log('📋 DADOS RECEBIDOS:');
  console.log(`   - ID do Ambiente do Cliente: ${id_ambiente_fornecedor}`);

  if (!id_ambiente_fornecedor) {
    console.warn('❌ DADOS INCOMPLETOS: id_ambiente_fornecedor é obrigatório.');
    return res.status(400).json({ error: 'id_ambiente_fornecedor é obrigatório.' });
  }

  let connection;
  try {
    connection = await req.pool.getConnection();
    
    const [rows] = await connection.execute(
      `SELECT 
        id, 
        nome, 
        preco_unitario,
        q_minimo,
        q_multiplo,
        Ativo 
      FROM tb_Produtos_Fornecedor 
      WHERE Ativo = 'S' 
      ORDER BY nome`
    );

    const produtos = rows.map(p => ({
      id: p.id,
      codigo: p.id,
      nome: p.nome,
      produto: p.nome,
      preco_unitario: parseFloat(p.preco_unitario || 0),
      q_minimo: parseInt(p.q_minimo) || 1,
      q_multiplo: parseInt(p.q_multiplo) || 1,
      ativo: p.Ativo
    }));
    
    console.log(`📦 Produtos encontrados: ${produtos.length} itens.`);
    
    res.json({
      success: true,
      produtos: produtos,
      total: produtos.length
    });

  } catch (error) {
    console.error(`❌ ERRO AO BUSCAR PRODUTOS:`, error);
    res.status(500).json({ 
      success: false, 
      error: 'Erro ao buscar produtos no ERP.', 
      details: error.message 
    });
  } finally {
    if (connection) connection.release();
  }
});

// ROTA CORRIGIDA: Cancelar pedido do fornecedor
app.post('/api/sync/cancel-pedido-fornecedor', authenticateEnvironment, async (req, res) => {
  console.log('🔒 INICIANDO CANCELAMENTO DE PEDIDO FORNECEDOR');
  
  const { id_pedido, motivo_cancelamento } = req.body;

  if (!req.isSupplierAuth) {
    console.warn('❌ Acesso negado: Requer autenticação de Fornecedor Sync.');
    return res.status(403).json({ error: 'Acesso negado. Esta rota requer autenticação de Fornecedor Sync.' });
  }

  if (!id_pedido) {
    return res.status(400).json({ error: 'ID do pedido é obrigatório.' });
  }

  let connection;
  try {
    connection = await req.pool.getConnection();

    const offsetHours = 3;
    const offsetMs = offsetHours * 60 * 60 * 1000;
    const dataBrasilia = new Date(new Date().getTime() - offsetMs);
    const dataCancelamento = dataBrasilia.toISOString().slice(0, 19).replace('T', ' ');
    const motivoFinal = motivo_cancelamento || 'Cancelado pelo usuário';
    
    const [result] = await connection.execute(
      `UPDATE tb_Pedidos_Fornecedor 
       SET status = 'cancelado', 
           data_cancelamento = ?, 
           motivo_cancelamento = ?
       WHERE id = ?`,
      [dataCancelamento, motivoFinal, id_pedido]
    );
    
    if (result.affectedRows === 0) {
      console.warn(`⚠️ Pedido ${id_pedido} não encontrado`);
      return res.status(404).json({ 
        success: false, 
        error: 'Pedido não encontrado.' 
      });
    }

    console.log(`✅ Pedido ${id_pedido} cancelado com sucesso`);
    
    res.json({
      success: true,
      message: 'Pedido cancelado com sucesso'
    });

  } catch (error) {
    console.error('❌ ERRO AO CANCELAR PEDIDO:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Erro interno do servidor ao cancelar pedido.', 
      details: error.message 
    });
  } finally {
    if (connection) connection.release();
  }
});

// ROTA: Buscar status de pedidos fornecedor
app.post('/api/sync/get-status-pedidos-fornecedor', authenticateEnvironment, async (req, res) => {
  if (!req.isSupplierAuth) {
    return res.status(403).json({ error: 'Acesso negado.' });
  }

  const { ids_pedidos } = req.body;

  if (!Array.isArray(ids_pedidos) || ids_pedidos.length === 0) {
    return res.status(400).json({ error: 'IDs de pedidos são obrigatórios.' });
  }

  let connection;
  try {
    connection = await req.pool.getConnection();

    const placeholders = ids_pedidos.map(() => '?').join(',');
    const [rows] = await connection.execute(
      `SELECT id, status FROM tb_Pedidos_Fornecedor WHERE id IN (${placeholders})`,
      ids_pedidos
    );

    res.json({ success: true, pedidos: rows });
  } catch (error) {
    console.error('Erro ao buscar status dos pedidos:', error);
    res.status(500).json({ success: false, error: error.message });
  } finally {
    if (connection) connection.release();
  }
});

// ==========================================
// ROTAS PARA CLIENTES
// ==========================================

// ROTA: Buscar clientes
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

// ROTA: Buscar produtos do cliente
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
        ativo,
        id_prod_fornecedor
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

// ROTA: Buscar formas de pagamento do cliente
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

// ROTA: Buscar comandas do cliente
app.post('/api/sync/get-comandas', authenticateEnvironment, async (req, res) => {
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
        SELECT codigo, comanda, ativo  
        FROM tb_comandas  
        WHERE ativo = 'S'
        ORDER BY comanda
      `;

      const [rows] = await connection.execute(query);
      
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

// ROTA CORRIGIDA: Atualizar status da comanda
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

    console.log(`📋 Atualizando status da comanda ${id_comanda} para "${status}"`);

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
            console.log(`⚠️ Nenhuma comanda encontrada com código ${id_comanda}`);
            return res.json({
                success: false,
                error: 'Comanda não encontrada'
            });
        }

        console.log(`✅ Status da comanda ${id_comanda} atualizado para "${status}"`);

        res.json({
            success: true,
            message: `Status da comanda atualizado para ${status}`,
            id_comanda: id_comanda,
            novo_status: status
        });

    } catch (error) {
        console.error('❌ Erro ao atualizar status da comanda:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    } finally {
        if (connection) connection.release();
    }
});

// ROTA: Receber pedidos do cliente
app.post('/api/sync/send-pedidos', authenticateEnvironment, async (req, res) => {
  console.log('📦 ROTA: /api/sync/send-pedidos - Recebendo pedido do cliente');

  let connection;
  try {
    if (!req.isClientAppAuth) {
      console.warn('❌ Acesso negado: requer autenticação de ClienteApp');
      return res.status(403).json({
        error: 'Acesso negado',
        details: 'Esta rota requer autenticação de ClienteApp.'
      });
    }

    const { data, hora, id_cliente, id_forma_pagamento, id_local_retirada, total_produtos, produtos, id_pedido_base44 } = req.body;

    const pedido = {
        data, hora, id_cliente, id_forma_pagamento, id_local_retirada, total_produtos, produtos,
        status: req.body.status || 'pendente',
        id_pedido_base44: id_pedido_base44
    };

    if (!pedido.data || !pedido.hora || pedido.total_produtos === undefined || !Array.isArray(pedido.produtos) || pedido.produtos.length === 0) {
      console.warn('❌ Dados do pedido incompletos');
      return res.status(400).json({
        error: 'Dados do pedido inválidos ou incompletos',
        details: 'data, hora, total_produtos e produtos são obrigatórios'
      });
    }

    console.log(`📋 Pedido recebido: ${pedido.produtos.length} produtos, total: R$ ${pedido.total_produtos}`);

    connection = await req.pool.getConnection();
    await connection.beginTransaction();
    console.log('✅ Conexão obtida e transação iniciada');

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
    console.log(`✅ Pedido inserido com ID: ${newPedidoId}`);

    if (Array.isArray(pedido.produtos) && pedido.produtos.length > 0) {
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
      console.log(`✅ ${produtosValues.length} produtos inseridos para o pedido ${newPedidoId}`);
    }

    await connection.commit();
    console.log(`🎉 Pedido ${newPedidoId} processado e commitado com sucesso`);

    res.status(200).json({
      success: true,
      id_pedido: newPedidoId,
      message: 'Pedido recebido e salvo com sucesso no ERP.'
    });

  } catch (error) {
    console.error('❌ Erro ao salvar pedido do cliente:', error);
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

// ROTA: Buscar lista de pedidos
app.post('/api/sync/get-pedidos', authenticateEnvironment, async (req, res) => {
  if (!req.isClientAppAuth) {
    return res.status(403).json({ error: 'Acesso negado. Apenas sincronização de cliente pode buscar pedidos.' });
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
    console.error(`Erro ao buscar pedidos:`, error);
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
app.post('/api/sync/get-itens-pedido', authenticateEnvironment, async (req, res) => {
  if (!req.isClientAppAuth) {
    return res.status(403).json({ error: 'Acesso negado. Apenas sincronização de cliente pode buscar itens do pedido.' });
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
    console.error(`Erro ao buscar itens do pedido ${codigo_pedido}:`, error);
    res.status(500).json({
      success: false,
      error: 'Erro interno do servidor ao buscar itens do pedido.',
      details: error.message
    });
  } finally {
    if (connection) connection.release();
  }
});

// ROTA CORRIGIDA: Buscar dados para analytics
app.post('/api/sync/get-analytics', authenticateEnvironment, async (req, res) => {
  if (!req.isClientAppAuth) {
    return res.status(403).json({ error: 'Acesso negado. Apenas sincronização de cliente pode buscar analytics.' });
  }

  let connection;
  try {
    connection = await req.pool.getConnection();

    const agora = new Date();
    const mesAtual = agora.getMonth() + 1;
    const anoAtual = agora.getFullYear();
    const mesAnterior = mesAtual === 1 ? 12 : mesAtual - 1;
    const anoAnterior = mesAtual === 1 ? anoAtual - 1 : anoAtual;

    const [vendasMesAtual] = await connection.execute(`
      SELECT COALESCE(SUM(total_produtos), 0) as total
      FROM tb_pedidos
      WHERE MONTH(data) = ? AND YEAR(data) = ?
    `, [mesAtual, anoAtual]);

    const [vendasMesAnterior] = await connection.execute(`
      SELECT COALESCE(SUM(total_produtos), 0) as total
      FROM tb_pedidos
      WHERE MONTH(data) = ? AND YEAR(data) = ?
    `, [mesAnterior, anoAnterior]);

    const [pedidosMesAtual] = await connection.execute(`
      SELECT COUNT(*) as total
      FROM tb_pedidos
      WHERE MONTH(data) = ? AND YEAR(data) = ?
    `, [mesAtual, anoAtual]);

    const [pedidosMesAnterior] = await connection.execute(`
      SELECT COUNT(*) as total
      FROM tb_pedidos
      WHERE MONTH(data) = ? AND YEAR(data) = ?
    `, [mesAnterior, anoAnterior]);

    const [totalClientes] = await connection.execute(`
      SELECT COUNT(*) as total
      FROM tb_clientes
      WHERE ativo = 'S'
    `);

    const [totalProdutos] = await connection.execute(`
      SELECT COUNT(*) as total
      FROM tb_produtos
      WHERE ativo = 'S'
    `);

    const [produtosMaisVendidos] = await connection.execute(`
      SELECT
        p.codigo,
        p.produto as nome,
        COALESCE(SUM(pp.quantidade), 0) as vendas,
        COALESCE(SUM(pp.total_produto), 0) as valor_total
      FROM tb_produtos p
      LEFT JOIN tb_pedidos_produtos pp ON p.codigo = pp.id_produto
      LEFT JOIN tb_pedidos ped ON pp.id_pedido = ped.codigo
      WHERE p.ativo = 'S'
        AND (ped.data IS NULL OR (MONTH(ped.data) = ? AND YEAR(ped.data) = ?))
      GROUP BY p.codigo, p.produto
      ORDER BY vendas DESC, valor_total DESC
      LIMIT 5
    `, [mesAtual, anoAtual]);

    const totalVendasAtual = parseFloat(vendasMesAtual[0].total);
    const totalVendasAnterior = parseFloat(vendasMesAnterior[0].total);
    const crescimentoVendas = totalVendasAnterior > 0 ?
      ((totalVendasAtual - totalVendasAnterior) / totalVendasAnterior * 100) : 0;

    const totalPedidosAtual = parseInt(pedidosMesAtual[0].total);
    const totalPedidosAnterior = parseInt(pedidosMesAnterior[0].total);
    const crescimentoPedidos = totalPedidosAnterior > 0 ?
      ((totalPedidosAtual - totalPedidosAnterior) / totalPedidosAnterior * 100) : 0;

    const analytics = {
      vendas: {
        totalMes: totalVendasAtual,
        totalMesAnterior: totalVendasAnterior,
        crescimento: crescimentoVendas
      },
      pedidos: {
        totalMes: totalPedidosAtual,
        totalMesAnterior: totalPedidosAnterior,
        crescimento: crescimentoPedidos
      },
      clientes: {
        total: parseInt(totalClientes[0].total),
        novosClientes: 0
      },
      produtos: {
        total: parseInt(totalProdutos[0].total),
        maisVendidos: produtosMaisVendidos.map(p => ({
          codigo: p.codigo,
          nome: p.nome,
          vendas: parseInt(p.vendas),
          valor_total: parseFloat(p.valor_total)
        }))
      }
    };

    res.json({
      success: true,
      analytics: analytics
    });

  } catch (error) {
    console.error(`Erro ao buscar analytics:`, error);
    res.status(500).json({
      success: false,
      error: 'Erro interno do servidor ao buscar analytics.',
      details: error.message
    });
  } finally {
    if (connection) connection.release();
  }
});

app.listen(PORT, () => {
  console.log(`Servidor ERP Sync rodando na porta ${PORT}`);
});
