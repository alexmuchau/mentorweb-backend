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


// Rotas para ClienteApp (usando authenticateEnvironment)
// Rota para enviar produtos do cliente
app.get('/api/sync/send-produtos', authenticateEnvironment, async (req, res) => {
  try {
    if (!req.isClientAppAuth) {
      return res.status(403).json({ 
        error: 'Acesso negado', 
        details: 'Esta rota requer autenticação de ClienteApp.' 
      });
    }

    const query = `
      SELECT codigo, produto, codigo_barras, preco_venda, estoque, ativo 
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

// Rota para enviar clientes do cliente
app.get('/api/sync/send-clientes', authenticateEnvironment, async (req, res) => {
  try {
    if (!req.isClientAppAuth) {
      return res.status(403).json({ 
        error: 'Acesso negado', 
        details: 'Esta rota requer autenticação de ClienteApp.' 
      });
    }

    const query = `
      SELECT codigo, nome, cnpj, cpf, ativo 
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
    console.error('Erro ao buscar clientes do cliente:', error);
    res.status(500).json({
      error: 'Erro interno do servidor',
      details: error.message
    });
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

    const query = `
      SELECT codigo, forma_pagamento, ativo 
      FROM tb_formas_pagamento 
      WHERE ativo = 'S'
      ORDER BY forma_pagamento
    `;

    const [rows] = await req.pool.execute(query);
    
    res.json({
      success: true,
      formas: rows,
      total: rows.length
    });

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

    const query = `
      SELECT codigo, comanda, ativo 
      FROM tb_comandas 
      WHERE ativo = 'S'
      ORDER BY comanda
    `;

    const [rows] = await req.pool.execute(query);
    
    res.json({
      success: true,
      comandas: rows,
      total: rows.length
    });

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
            (id_pedido_erp, id_produto, quantidade, unitario, total_produto, id_lcto_erp)
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
        insertedPedidos.push({ id_pedido_erp: newPedidoId, success: true });
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


// Rotas para Fornecedor (usando authenticateEnvironment)
// Rota para enviar produtos do fornecedor
app.get('/api/sync/send-produtos-fornecedor', authenticateEnvironment, async (req, res) => {
  try {
    if (!req.isSupplierAuth) {
      return res.status(403).json({ 
        error: 'Acesso negado', 
        details: 'Esta rota requer autenticação de fornecedor.' 
      });
    }

    const query = `
      SELECT id, nome, preco_unitario, Ativo as ativo 
      FROM tb_Produtos_Fornecedor 
      WHERE Ativo = 'S'
      ORDER BY nome
    `;

    const [rows] = await req.pool.execute(query);
    
    res.json({
      success: true,
      produtos: rows,
      total: rows.length
    });

  } catch (error) {
    console.error('Erro ao buscar produtos do fornecedor:', error);
    res.status(500).json({
      error: 'Erro interno do servidor',
      details: error.message
    });
  }
});


// Rota para receber um pedido para o fornecedor
app.post('/api/sync/receive-pedido-fornecedor', authenticateEnvironment, async (req, res) => {
  if (!req.isSupplierAuth) {
    return res.status(403).json({ 
      error: 'Acesso negado', 
      details: 'Esta rota requer autenticação de sincronização de fornecedor.' 
    });
  }

  const { id_ambiente, total_pedido, produtos, id_pedido_app, cliente } = req.body;

  if (!id_ambiente || total_pedido === undefined || !Array.isArray(produtos) || produtos.length === 0) {
    return res.status(400).json({ error: 'Dados do pedido inválidos ou incompletos.' });
  }

  // A data e hora são geradas com base no fuso horário do servidor.
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const day = String(now.getDate()).padStart(2, '0');
  const hours = String(now.getHours()).padStart(2, '0');
  const minutes = String(now.getMinutes()).padStart(2, '0');
  const seconds = String(now.getSeconds()).padStart(2, '0');
  const data_pedido = `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;


  let connection;
  try {
    // A conexão é obtida do pool. O bloco 'finally' garante que ela será liberada,
    // o que é essencial para evitar o esgotamento do pool.
    connection = await req.pool.getConnection();
    // Inicia uma transação para garantir que o pedido e seus produtos sejam salvos atomicamente.
    await connection.beginTransaction();

    // 1. Inserir na tabela de pedidos (tb_Pedidos_Fornecedor)
    const pedidoQuery = `
      INSERT INTO tb_Pedidos_Fornecedor 
      (id_ambiente, valor_total, data_hora_lancamento, status, id_pedido_sistema_externo) 
      VALUES (?, ?, ?, 'pendente', ?)
    `;
    const [pedidoResult] = await connection.execute(pedidoQuery, [
      id_ambiente, 
      total_pedido,
      data_pedido,
      id_pedido_app || null
    ]);
    const newPedidoId = pedidoResult.insertId;

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
      p.identificador_cliente_item
    ]);

    await connection.query(produtoQuery, [produtosValues]);

    // Confirma a transação. Se qualquer um dos passos acima falhar,
    // o bloco catch fará o rollback.
    await connection.commit();

    res.status(200).json({
      success: true,
      message: 'Pedido recebido e salvo com sucesso',
      codigo_pedido: newPedidoId
    });

  } catch (error) {
    console.error('Erro ao salvar pedido do fornecedor:', error);
    if (connection) {
      // Reverte todas as operações da transação em caso de erro.
      await connection.rollback();
    }
    res.status(500).json({
      error: 'Erro interno do servidor ao processar o pedido',
      details: error.message
    });
  } finally {
    if (connection) {
      connection.release();
    }
  }
});


app.listen(PORT, () => {
  console.log(`Servidor ERP Sync rodando na porta ${PORT}`);
});
