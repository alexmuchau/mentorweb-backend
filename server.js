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

// Função para remover máscara de CNPJ/CPF
const removeDocumentMask = (documento) => {
  if (typeof documento !== 'string') return '';
  return documento.replace(/\D/g, '');
};

/**
 * Função para obter ou criar um pool de conexão para um banco de dados específico.
 * A utilização de pools de conexão é crucial para a performance e escalabilidade,
 * pois evita a sobrecarga de criar e fechar conexões para cada requisição.
 * @param {string} databaseName - O nome do banco de dados.
 * @returns {Promise<mysql.Pool>} O pool de conexão.
 */
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
    port: parseInt(process.env.DB_PORT || 3306), // Adicionado parseInt para garantir que a porta seja um número inteiro
    waitForConnections: true,
    connectionLimit: 10, // Ajuste conforme a carga do servidor. Um valor de 10 é um bom ponto de partida.
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
  const { cnpj, usuario, senha, banco_dados } = req.headers;

  // Inicializa req.pool e flags
  req.pool = null;  
  req.isClientAppAuth = false;
  req.isSupplierAuth = false;
  req.environment = null;

  if (!cnpj || !usuario || !senha || !banco_dados) {
    return res.status(400).json({ error: 'Credenciais de ambiente incompletas', details: 'Headers CNPJ, Usuário, Senha e Banco de Dados são obrigatórios.' });
  }

  let connection;
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
  } finally {
    if (connection) connection.release();
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
      return res.status(401).json({ error: "Credenciais de sincronização de fornecedor inválidas nos headers." });
  }

  if (!cnpj_cpf || !usuario || !senha || !banco_dados) {
    return res.status(400).json({ error: 'Dados de autenticação incompletos.' });
  }

  let connection;
  try {
    const pool = await getDatabasePool(banco_dados);
    connection = await pool.getConnection();

    // REMOVEMOS A MÁSCARA ANTES DE CONSULTAR O BANCO DE DADOS
    const documentoSemMascara = removeDocumentMask(cnpj_cpf);

    const [rows] = await connection.execute(
      `SELECT Codigo, ID_Pessoa, Documento, Nome, usuario, Ativo FROM tb_Ambientes_Fornecedor WHERE Documento = ? AND usuario = ? AND Senha = ? AND Ativo = 'S'`,
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
    }
  }
});

// ROTA: Enviar pedido para fornecedor
app.post('/api/sync/send-pedido-fornecedor', authenticateEnvironment, async (req, res) => {
  if (!req.isClientAppAuth) {
    return res.status(403).json({ error: 'Acesso negado. Apenas clientes podem enviar pedidos para o fornecedor.' });
  }

  const { banco_dados } = req.headers;
  const { produtos, id_ambiente, total_pedido, data_pedido, id_pedido_app } = req.body;

  if (!produtos || produtos.length === 0) {
    return res.status(400).json({
      success: false,
      message: 'O pedido deve conter pelo menos um produto.'
    });
  }

  let connection;
  try {
    const pool = await getDatabasePool(banco_dados);
    connection = await pool.getConnection();
    await connection.beginTransaction();

    const pedidoQuery = `
      INSERT INTO tb_Pedidos_Fornecedor
      (id_ambiente, total_pedido, data_pedido, id_pedido_app)
      VALUES (?, ?, ?, ?)
    `;
    const [pedidoResult] = await connection.query(pedidoQuery, [
      id_ambiente,
      total_pedido,
      data_pedido,
      id_pedido_app || null
    ]);
    const newPedidoId = pedidoResult.insertId;

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
      p.identificador_cliente_item
    ]);

    await connection.query(produtoQuery, [produtosValues]);

    await connection.commit();

    res.status(200).json({
      success: true,
      message: 'Pedido recebido e salvo com sucesso',
      codigo_pedido: newPedidoId
    });

  } catch (error) {
    console.error('Erro ao salvar pedido do fornecedor:', error);
    if (connection) {
      await connection.rollback();
    }
    res.status(500).json({
      error: 'Erro interno do servidor ao processar o pedido',
      details: error.message
    });
  } finally {
    if (connection) connection.release();
  }
});

// ROTA: Receber pedido do fornecedor - VERSÃO COM FUSO HORÁRIO E CAMPOS CORRIGIDOS
app.post('/api/sync/receive-pedido-fornecedor', authenticateEnvironment, async (req, res) => {
  if (!req.isSupplierAuth) {
    return res.status(403).json({ 
      error: 'Acesso negado. Apenas sincronização de fornecedor pode receber pedidos.'
    });
  }

  const { banco_dados } = req.headers;
  const pedidoData = req.body;

  console.log('Processando pedido de fornecedor:', JSON.stringify(pedidoData, null, 2));

  let connection;
  try {
    const pool = await getDatabasePool(banco_dados);
    connection = await pool.getConnection();
    await connection.beginTransaction();

    // Converte a data do pedido para o fuso de São Paulo no formato do MySQL
    const dataPedidoCliente = new Date(pedidoData.data_pedido);
    const dataFormatada = dataPedidoCliente.toLocaleString('sv-SE', { timeZone: 'America/Sao_Paulo' }).slice(0, 19);

    // 1. Inserir pedido principal SEM id_pedido_sistema_externo
    const [pedidoResult] = await connection.execute(`
      INSERT INTO tb_Pedidos_Fornecedor (
        data_hora_lancamento,
        id_ambiente,
        valor_total,
        status
      ) VALUES (?, ?, ?, ?)
    `, [
      dataFormatada,
      pedidoData.id_ambiente,
      pedidoData.total_pedido,
      'pendente'  // Status padrão = 'pendente'
    ]);

    const pedidoId = pedidoResult.insertId;
    console.log(`Pedido inserido com ID: ${pedidoId}`);

    // 2. Inserir produtos do pedido
    for (const produto of pedidoData.produtos) {
																	 
      let identificadorInt = null;
      if (produto.identificador_cliente_item) {
        const numeroExtraido = String(produto.identificador_cliente_item).replace(/\D/g, '');
        identificadorInt = numeroExtraido ? parseInt(numeroExtraido, 10) : null;
      }
      
      await connection.execute(`
        INSERT INTO tb_Pedidos_Produtos_Fornecedor (
          id_pedido,
          id_produto,
          quantidade,
          preco_unitario,
          valor_total,
          identificador_cliente_item
        ) VALUES (?, ?, ?, ?, ?, ?)
      `, [
        pedidoId,
        produto.id_produto,
        produto.quantidade,
        produto.valor_unitario,
        produto.total_produto,
        identificadorInt
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
// ROTA: Buscar produtos do fornecedor (chamada pelo erpSync action 'get_produtos_fornecedor')
app.get('/api/sync/send-produtos-fornecedor', authenticateEnvironment, async (req, res) => {
  // Apenas credenciais de sincronização de fornecedor podem usar esta rota
  if (!req.isSupplierAuth) {
    return res.status(403).json({ error: 'Acesso negado. Apenas sincronização de fornecedor pode buscar produtos.' });
  }

  const { banco_dados } = req.headers; // O banco de dados do fornecedor está nos headers

  let connection;
  try {
    const pool = await getDatabasePool(banco_dados); // Usa o banco de dados do fornecedor
    connection = await pool.getConnection();

    // Consulta à tabela tb_Produtos_Fornecedor
    const [rows] = await connection.execute(
      `SELECT id, nome, preco_unitario, Ativo FROM tb_Produtos_Fornecedor WHERE Ativo = 'S'`
    );

    // Formatar preco_unitario para float se necessário
    const produtos = rows.map(p => ({
      ...p,
      preco_unitario: parseFloat(p.preco_unitario) // Garante que seja um número
    }));

    res.json({
      success: true,
      produtos: produtos
    });

  } catch (error) {
    console.error(`Erro ao buscar produtos do fornecedor (${banco_dados}):`, error);
    res.status(500).json({
      success: false,
      error: 'Erro interno do servidor ao buscar produtos do fornecedor.',
      details: error.message
    });
  } finally {
    if (connection) connection.release();
  }
});

// --- ROTA DE ADMINISTRAÇÃO PARA INATIVAR USUÁRIO FORNECEDOR ---
// Este endpoint é destinado a ser chamado por um processo administrativo da MentorWeb
// (como o Painel DEV ou o módulo de Configurações da Empresa ERP) para gerenciar
// o status de usuários no ERP de um fornecedor.
app.post('/api/erp/inativar-usuario-fornecedor', async (req, res) => {
  console.log('🔒 INICIANDO PROCESSO DE INATIVAÇÃO DE USUÁRIO FORNECEDOR');

  // Credenciais de sistema para esta rota, se necessário.
  // IMPORTANTE: Ajuste estas credenciais para algo seguro e específico do seu ambiente.
  const SYSTEM_ADMIN_USER = 'admin_sistema';
  const SYSTEM_ADMIN_PASS = 'admin_inativar_2024';

  const body = req.body;
  const { cnpj_cpf, usuario, motivo } = body;
  const banco_dados = req.headers['banco_dados'];
  const headerUser = req.headers['usuario'];
  const headerPass = req.headers['senha'];

  console.log('📋 DADOS RECEBIDOS PARA INATIVAÇÃO:');
  console.log(`   - Usuário a inativar: ${usuario}`);
  console.log(`   - CNPJ/CPF do usuário: ${cnpj_cpf}`);
  console.log(`   - Banco de dados: ${banco_dados}`);
  console.log(`   - Motivo da inativação: ${motivo || 'Não especificado'}`);
  console.log(`   - Header Usuario (Sistema): ${headerUser}`);
  console.log(`   - Header tem senha (Sistema): ${!!headerPass}`);

  // Validação das credenciais de sistema
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
    const pool = await getDatabasePool(banco_dados); // Supondo que getDatabasePool esteja definido
    connection = await pool.getConnection();
    console.log('✅ Conexão obtida com sucesso para inativação');

    // Remover máscara do documento
    const documentoLimpo = removeDocumentMask(cnpj_cpf); // Supondo que removeDocumentMask esteja definido
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

// === ROTA: Buscar ambientes do fornecedor ===
app.get('/api/sync/send-ambientes-fornecedor', async (req, res) => {
  console.log('🌳 REQUISIÇÃO PARA BUSCAR AMBIENTES DO FORNECEDOR');
  
  const banco_dados = req.headers['banco_dados'];
  const cnpj = req.headers['cnpj'];
  const headerUser = req.headers['usuario'];
  const headerPass = req.headers['senha'];

  console.log('📋 DADOS RECEBIDOS:');
  console.log(`   - Banco de dados: ${banco_dados}`);
  console.log(`   - CNPJ: ${cnpj}`);
  console.log(`   - Header Usuario: ${headerUser}`);

  // Validação das credenciais
  if (headerUser !== 'mentorweb_fornecedor' || headerPass !== 'mentorweb_sync_forn_2024') {
    console.warn('❌ CREDENCIAIS DE SISTEMA INVÁLIDAS');
    return res.status(401).json({ error: "Credenciais de sincronização inválidas." });
  }

  if (!banco_dados) {
    return res.status(400).json({ error: 'Banco de dados não especificado no header.' });
  }

  let connection;
  try {
    console.log(`🔌 CONECTANDO AO BANCO: ${banco_dados}`);
    const pool = await getDatabasePool(banco_dados);
    connection = await pool.getConnection();
    
    const [rows] = await connection.execute(
      `SELECT Codigo as id, Nome as nome, ID_Pessoa, Documento FROM tb_Ambientes_Fornecedor WHERE Ativo = 'S' ORDER BY Nome`
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

// ROTA: Buscar produtos do fornecedor PARA UM CLIENTE ESPECÍFICO (Pedidos Fornecedor Integrado)
// (POST porque espera id_ambiente_fornecedor no corpo da requisição)
app.post('/api/sync/send-produtos-fornecedor-para-cliente', /* SEU MIDDLEWARE DE AUTENTICAÇÃO AQUI, por exemplo, authenticateMentorWebSync, */ async (req, res) => {
  console.log('📦 REQUISIÇÃO PARA BUSCAR PRODUTOS DO FORNECEDOR PARA UM CLIENTE ESPECÍFICO');
  
  const { id_ambiente_fornecedor } = req.body; // ID do ambiente do cliente no ERP do fornecedor
  const banco_dados = req.headers['banco_dados'];
  // Os headers de usuário/senha já devem ter sido autenticados pelo seu middleware.

  console.log('📋 DADOS RECEBIDOS:');
  console.log(`   - Banco de dados: ${banco_dados}`);
  console.log(`   - ID do Ambiente do Cliente: ${id_ambiente_fornecedor}`);

  if (!banco_dados || !id_ambiente_fornecedor) {
    console.warn('❌ DADOS INCOMPLETOS: Banco de dados e id_ambiente_fornecedor são obrigatórios.');
    return res.status(400).json({ error: 'Banco de dados e id_ambiente_fornecedor são obrigatórios.' });
  }

  let connection;
  try {
    const pool = await getDatabasePool(banco_dados); // Supondo que getDatabasePool esteja definido
    connection = await pool.getConnection();
    
    // Consulta à tabela tb_Produtos_Fornecedor com as colunas da imagem
    // AQUI você pode ADICIONAR LOGICA para filtrar produtos ou preços
    // com base no id_ambiente_fornecedor, se houver tabelas de preço por cliente.
    const [rows] = await connection.execute(
      `SELECT 
        id, 
        nome, 
        preco_unitario, 
        Ativo 
      FROM tb_Produtos_Fornecedor 
      WHERE Ativo = 'S' 
      ORDER BY nome`
    );

    const produtos = rows.map(p => ({
      id: p.id,
      nome: p.nome,
      preco: parseFloat(p.preco_unitario), // Garante que seja um número (campo 'preco' para o frontend)
      // 'Ativo' pode ser incluído se o frontend precisar, mas a query já filtra por 'S'
    }));
    
    console.log(`📦 Produtos encontrados para o cliente (ambiente ${id_ambiente_fornecedor}) no banco ${banco_dados}: ${produtos.length} itens.`);
    
    res.json({
      success: true,
      produtos: produtos
    });

  } catch (error) {
    console.error(`❌ ERRO AO BUSCAR PRODUTOS PARA O CLIENTE (ambiente ${id_ambiente_fornecedor}, banco ${banco_dados}):`, error);
    res.status(500).json({ 
      success: false, 
      error: 'Erro ao buscar produtos para o cliente no ERP.', 
      details: error.message 
    });
  } finally {
    if (connection) {
      connection.release();
      console.log('🔌 Conexão liberada para busca de produtos do cliente.');
    }
  }
});

// Rota para enviar formas de pagamento do cliente
app.get('/api/sync/send-formas-pagamento', authenticateEnvironment, async (req, res) => {
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

// Rota para enviar comandas do cliente
app.get('/api/sync/send-comandas', authenticateEnvironment, async (req, res) => {
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

// Rota para receber pedidos do cliente
app.post('/api/sync/receive-pedidos', authenticateEnvironment, async (req, res) => {
  try {
    if (!req.isClientAppAuth) {
      return res.status(403).json({  
        error: 'Acesso negado',  
        details: 'Esta rota requer autenticação de ClienteApp.'  
      });
    }

    const { pedidos } = req.body;

    if (!Array.isArray(pedidos) || pedidos.length === 0) {
      return res.status(400).json({ error: 'Array de pedidos inválido ou vazio.' });
    }

    let insertedPedidos = [];
    let connection;

    try {
      connection = await req.pool.getConnection();
      for (const pedido of pedidos) {
        await connection.beginTransaction();

        // 1. Inserir na tabela de pedidos
        const pedidoQuery = `
          INSERT INTO tb_pedidos  
          (data, hora, id_cliente, id_forma_pagamento, total_produtos, id_lcto_erp, status)  
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `;
        const [pedidoResult] = await connection.execute(pedidoQuery, [
          pedido.data,
          pedido.hora,
          pedido.id_cliente,
          pedido.id_forma_pagamento,
          pedido.total_produtos,
          pedido.id_lcto_erp || null,
          pedido.status || 'pendente'
        ]);
        const newPedidoId = pedidoResult.insertId;

        // 2. Inserir os produtos do pedido
        if (Array.isArray(pedido.itens) && pedido.itens.length > 0) {
          const produtoQuery = `
            INSERT INTO tb_pedidos_produtos
            (id_pedido, id_produto, quantidade, unitario, total_produto, id_lcto_erp)
            VALUES ?
          `;
          
          const produtosValues = pedido.itens.map(item => [
            newPedidoId,
            item.id_produto,
            item.quantidade,
            item.unitario,
            item.total_produto,
            item.id_lcto_erp || null
          ]);

          await connection.query(produtoQuery, [produtosValues]);
        }

        await connection.commit();
        insertedPedidos.push({ id_pedido: newPedidoId, success: true });
      }
      res.status(200).json({
        success: true,
        message: 'Pedidos recebidos e salvos com sucesso',
        pedidos_inseridos: insertedPedidos
      });

    } catch (error) {
      console.error('Erro ao salvar pedidos do cliente:', error);
      if (connection) {
        await connection.rollback();
      }
      res.status(500).json({
        error: 'Erro interno do servidor ao processar os pedidos',
        details: error.message
      });
    } finally {
      if (connection) {
        connection.release();
      }
    }
  } catch (error) {
    console.error('Erro fora do bloco transacional ao processar receive-pedidos:', error);
    res.status(500).json({
      error: 'Erro fatal ao processar pedidos',
      details: error.message
    });
  }
});

// ROTA: Buscar lista de pedidos (chamada pelo erpSync action 'get_pedidos')
app.get('/api/sync/send-pedidos-list', authenticateEnvironment, async (req, res) => {
  if (!req.isClientAppAuth) {
    return res.status(403).json({ error: 'Acesso negado. Apenas sincronização de cliente pode buscar pedidos.' });
  }

  const { banco_dados } = req.headers;

  let connection;
  try {
    const pool = await getDatabasePool(banco_dados);
    connection = await pool.getConnection();

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
    console.error(`Erro ao buscar pedidos do banco ${banco_dados}:`, error);
    res.status(500).json({
      success: false,
      error: 'Erro interno do servidor ao buscar pedidos.',
      details: error.message
    });
  } finally {
    if (connection) connection.release();
  }
});

// ROTA: Buscar itens de um pedido específico (chamada pelo erpSync action 'get_itens_pedido')
app.post('/api/sync/send-itens-pedido', authenticateEnvironment, async (req, res) => {
  if (!req.isClientAppAuth) {
    return res.status(403).json({ error: 'Acesso negado. Apenas sincronização de cliente pode buscar itens do pedido.' });
  }

  const { codigo_pedido } = req.body;
  const { banco_dados } = req.headers;

  if (!codigo_pedido) {
    return res.status(400).json({ error: 'Código do pedido é obrigatório.' });
  }

  let connection;
  try {
    const pool = await getDatabasePool(banco_dados);
    connection = await pool.getConnection();

    const [rows] = await connection.execute(`
      SELECT
        pp.codigo,
        pp.id_pedido,
        pp.id_produto,
        pp.quantidade,
        pp.unitario,
        pp.total_produto,
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
    console.error(`Erro ao buscar itens do pedido ${codigo_pedido} no banco ${banco_dados}:`, error);
    res.status(500).json({
      success: false,
      error: 'Erro interno do servidor ao buscar itens do pedido.',
      details: error.message
    });
  } finally {
    if (connection) connection.release();
  }
});

// ROTA: Buscar dados para analytics (chamada pelo erpSync action 'get_analytics')
app.get('/api/sync/send-analytics', authenticateEnvironment, async (req, res) => {
  if (!req.isClientAppAuth) {
    return res.status(403).json({ error: 'Acesso negado. Apenas sincronização de cliente pode buscar analytics.' });
  }

  const { banco_dados } = req.headers;

  let connection;
  try {
    const pool = await getDatabasePool(banco_dados);
    connection = await pool.getConnection();

    // Obter data atual e data do mês anterior
    const agora = new Date();
    const mesAtual = agora.getMonth() + 1;
    const anoAtual = agora.getFullYear();
    const mesAnterior = mesAtual === 1 ? 12 : mesAtual - 1;
    const anoAnterior = mesAtual === 1 ? anoAtual - 1 : anoAtual;

    // Vendas do mês atual
    const [vendasMesAtual] = await connection.execute(`
      SELECT COALESCE(SUM(total_produtos), 0) as total
      FROM tb_pedidos
      WHERE MONTH(data) = ? AND YEAR(data) = ?
    `, [mesAtual, anoAtual]);

    // Vendas do mês anterior
    const [vendasMesAnterior] = await connection.execute(`
      SELECT COALESCE(SUM(total_produtos), 0) as total
      FROM tb_pedidos
      WHERE MONTH(data) = ? AND YEAR(data) = ?
    `, [mesAnterior, anoAnterior]);

    // Pedidos do mês atual
    const [pedidosMesAtual] = await connection.execute(`
      SELECT COUNT(*) as total
      FROM tb_pedidos
      WHERE MONTH(data) = ? AND YEAR(data) = ?
    `, [mesAtual, anoAtual]);

    // Pedidos do mês anterior
    const [pedidosMesAnterior] = await connection.execute(`
      SELECT COUNT(*) as total
      FROM tb_pedidos
      WHERE MONTH(data) = ? AND YEAR(data) = ?
    `, [mesAnterior, anoAnterior]);

    // Total de clientes ativos
    const [totalClientes] = await connection.execute(`
      SELECT COUNT(*) as total
      FROM tb_clientes
      WHERE ativo = 'S'
    `);

    // Total de produtos ativos
    const [totalProdutos] = await connection.execute(`
      SELECT COUNT(*) as total
      FROM tb_produtos
      WHERE ativo = 'S'
    `);

    // Produtos mais vendidos (aproximação)
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

    // Calcular crescimento
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
        novosClientes: 0 // Você pode implementar lógica para novos clientes se necessário
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
    console.error(`Erro ao buscar analytics do banco ${banco_dados}:`, error);
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
