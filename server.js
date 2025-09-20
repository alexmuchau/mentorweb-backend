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
  // Console.log para debug do que o servidor está recebendo
  console.log('--- HEADERS RECEBIDOS ---');
  console.log('cnpj:', req.headers.cnpj);
  console.log('usuario:', req.headers.usuario);
  console.log('senha:', req.headers.senha);
  console.log('banco_dados:', req.headers.banco_dados);
  console.log('-------------------------');

  const cnpj = req.headers.cnpj;
  const usuario = req.headers.usuario;
  const senha = req.headers.senha;
  const banco_dados = req.headers.banco_dados;

  req.isClientAppAuth = false;
  req.isSupplierAuth = false;
  req.environment = null; // Informações do ambiente autenticado
  req.pool = null; // Garante que req.pool seja sempre inicializado

  if (!cnpj || !usuario || !senha || !banco_dados) {
    return res.status(400).json({ error: 'Credenciais de ambiente incompletas', details: 'Headers CNPJ, Usuário, Senha e Banco de Dados são obrigatórios.' });
  }

  try {
    // Tenta obter o pool para o banco_dados. Isso pode falhar se o banco não existir ou credenciais estiverem erradas.
    req.pool = await getDatabasePool(banco_dados); 

    // NOVO: Primeiro, tenta autenticar como usuário de sincronização de fornecedor (credenciais fixas)
    // Isso é para chamadas internas de serviço (ex: buscar produtos de fornecedor)
    if (usuario === SUPPLIER_SYNC_USER && senha === SUPPLIER_SYNC_PASS) {
        req.isSupplierAuth = true;
        req.environment = { cnpj, usuario, tipo: 'fornecedor_sync' };
        return next(); // Autenticado como sincronização de fornecedor
    }
    
    // NOVO/MODIFICADO: Lógica para login de fornecedor (autenticação de usuário individual na tb_Ambientes)
    // Isso é para a tela de login do usuário fornecedor
    if (cnpj === 'fornecedor_auth' && usuario === 'fornecedor_auth' && senha === 'fornecedor_auth') {
        req.isSupplierAuth = true; // Marca que é uma requisição de autenticação de fornecedor
        req.environment = { cnpj, usuario, tipo: 'fornecedor_login' };
        return next(); // Permite que a rota authenticate-fornecedor-user lide com a autenticação real
    }

    // MODIFICADO: Lógica para ClienteApp (autenticação de usuário individual na tb_ambientes)
    // Se não for uma requisição de fornecedor_sync nem de fornecedor_login, tenta autenticar como ClienteApp
    const [rows] = await req.pool.execute( // Usar req.pool aqui
      'SELECT * FROM tb_ambientes WHERE cnpj = ? AND usuario = ? AND senha = ? AND ativo = "S"',
      [cnpj, usuario, senha]
    );

    if (rows.length > 0) {
      req.isClientAppAuth = true;
      req.environment = { ...rows[0], tipo: 'cliente' };
      return next();
    }

    // Se nenhuma autenticação for bem-sucedida
    return res.status(401).json({ error: 'Credenciais de ambiente inválidas', details: `CNPJ: ${cnpj}, Usuário: ${usuario}` });

  } catch (error) {
    console.error(`Erro no middleware authenticateEnvironment para banco ${banco_dados}:`, error);
    // Se o erro for na obtenção do pool, ou seja, banco de dados não existe/credenciais inválidas
    if (error.message && error.message.includes('Não foi possível conectar ao banco de dados')) {
        return res.status(401).json({ error: 'Falha na conexão com o banco de dados do ambiente.', details: error.message });
    }
    if (error.sqlMessage) { // Erros de SQL específicos
        return res.status(500).json({ error: 'Erro no banco de dados', details: error.sqlMessage });
    }
    return res.status(500).json({ error: 'Erro interno do servidor', details: error.message });
  }
};

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// ROTA ESPECIAL: Autenticação de usuário fornecedor (não usa authenticateEnvironment para pegar pool)
app.post('/api/sync/authenticate-fornecedor-user', async (req, res) => {
  const { cnpj_cpf, usuario, senha } = req.body;
  const { banco_dados } = req.headers; // banco_dados vem do header

  console.log('=== ROTA DE AUTENTICAÇÃO DE FORNECEDOR ===');
  console.log('CNPJ/CPF:', cnpj_cpf);
  console.log('Usuário:', usuario);
  console.log('Banco de dados:', banco_dados);

  if (!cnpj_cpf || !usuario || !senha || !banco_dados) {
    return res.status(400).json({ 
      error: 'CNPJ/CPF, usuário, senha e banco_dados são obrigatórios' 
    });
  }

  try {
    const pool = await getDatabasePool(banco_dados); // Obtém o pool para o banco de dados do fornecedor
    console.log(`Conectado ao banco do fornecedor: ${banco_dados}`);

    // IMPORTANTE: Para fornecedor, usa tb_Ambientes (com A maiúsculo)
    const [rows] = await pool.execute(
      'SELECT * FROM tb_Ambientes WHERE documento = ? AND usuario = ? AND senha = ? AND ativo = "S"',
      [cnpj_cpf, usuario, senha]
    );

    if (rows.length > 0) {
      console.log('Usuário autenticado com sucesso:', rows[0]);
      res.json({ success: true, user: rows[0] });
    } else {
      res.status(401).json({ success: false, error: 'Credenciais inválidas' });
    }

  } catch (error) {
    console.error('Erro na autenticação de usuário fornecedor:', error);
    res.status(500).json({ success: false, error: 'Erro interno do servidor durante a autenticação.' });
  }
});


// Rotas de sincronização que requerem autenticação de ambiente
app.get('/api/sync/send-produtos-fornecedor', authenticateEnvironment, async (req, res) => {
  if (!req.isSupplierAuth) { // Verifica se é uma chamada autenticada como fornecedor (sync ou login)
    return res.status(401).json({ error: 'Acesso não autorizado para produtos de fornecedor' });
  }
  
  try {
    const pool = req.pool; // Pool de conexão já autenticado e anexado à requisição pelo middleware

    // IMPORTANTE: Para fornecedor, usa tb_Produtos (com P maiúsculo)
    const [rows] = await pool.execute('SELECT * FROM tb_Produtos WHERE Ativo = "S"');
    res.json({
      success: true,
      produtos: rows,
      total: rows.length
    });
  } catch (error) {
    console.error('Erro ao buscar produtos do fornecedor:', error);
    res.status(500).json({ error: 'Erro ao buscar produtos do fornecedor', details: error.message });
  }
});

app.post('/api/sync/receive-pedido-fornecedor', authenticateEnvironment, async (req, res) => {
  if (!req.isSupplierAuth) {
    return res.status(401).json({ error: 'Acesso não autorizado para receber pedido de fornecedor' });
  }

  const pedidoData = req.body;
  const pool = req.pool; // Pool de conexão já autenticado e anexado à requisição pelo middleware

  try {
    // Exemplo: Salvar o pedido no banco de dados do fornecedor
    // Adapte esta lógica conforme a estrutura do seu banco de dados
    const [result] = await pool.execute(
      'INSERT INTO tb_Pedidos_Fornecedor (id_cliente_app, total_pedido, data_pedido, status, cliente_nome_mw) VALUES (?, ?, ?, ?, ?)',
      [pedidoData.id_cliente_app || null, pedidoData.total_pedido, pedidoData.data_pedido, 'pendente', pedidoData.cliente || 'Desconhecido']
    );

    const pedidoId = result.insertId;

    for (const item of pedidoData.produtos) {
      await pool.execute(
        'INSERT INTO tb_Itens_Pedido_Fornecedor (id_pedido_fornecedor, id_produto, quantidade, valor_unitario, total_produto) VALUES (?, ?, ?, ?, ?)',
        [pedidoId, item.id_produto, item.quantidade, item.valor_unitario, item.total_produto]
      );
    }
    
    res.json({ success: true, message: 'Pedido recebido com sucesso!', codigo_pedido: pedidoId });
  } catch (error) {
    console.error('Erro ao receber pedido de fornecedor:', error);
    res.status(500).json({ error: 'Erro ao receber pedido de fornecedor', details: error.message });
  }
});


app.get('/api/sync/send-produtos', authenticateEnvironment, async (req, res) => {
  if (!req.isClientAppAuth) {
    return res.status(401).json({ error: 'Acesso não autorizado para produtos', details: 'Apenas ClientApp autorizado pode acessar.' });
  }
  try {
    const pool = req.pool; // Pool de conexão já autenticado e anexado à requisição pelo middleware
    const [rows] = await pool.execute('SELECT * FROM tb_produtos WHERE Ativo = "S"');
    res.json({ success: true, produtos: rows, total: rows.length });
  } catch (error) {
    console.error('Erro ao buscar produtos:', error);
    res.status(500).json({ error: 'Erro ao buscar produtos', details: error.message });
  }
});

app.get('/api/sync/send-clientes', authenticateEnvironment, async (req, res) => {
  if (!req.isClientAppAuth) {
    return res.status(401).json({ error: 'Acesso não autorizado para clientes', details: 'Apenas ClientApp autorizado pode acessar.' });
  }
  try {
    const pool = req.pool; // Pool de conexão já autenticado e anexado à requisição pelo middleware
    const [rows] = await pool.execute('SELECT * FROM tb_clientes');
    res.json({ success: true, clientes: rows, total: rows.length });
  } catch (error) {
    console.error('Erro ao buscar clientes:', error);
    res.status(500).json({ error: 'Erro ao buscar clientes', details: error.message });
  }
});

app.get('/api/sync/send-formas-pagamento', authenticateEnvironment, async (req, res) => {
  if (!req.isClientAppAuth) {
    return res.status(401).json({ error: 'Acesso não autorizado para formas de pagamento', details: 'Apenas ClientApp autorizado pode acessar.' });
  }
  try {
    const pool = req.pool; // Pool de conexão já autenticado e anexado à requisição pelo middleware
    const [rows] = await pool.execute('SELECT * FROM tb_formas_pagamento');
    res.json({ success: true, formas: rows, total: rows.length });
  } catch (error) {
    console.error('Erro ao buscar formas de pagamento:', error);
    res.status(500).json({ error: 'Erro ao buscar formas de pagamento', details: error.message });
  }
});

app.get('/api/sync/send-comandas', authenticateEnvironment, async (req, res) => {
  if (!req.isClientAppAuth) {
    return res.status(401).json({ error: 'Acesso não autorizado para comandas', details: 'Apenas ClientApp autorizado pode acessar.' });
  }
  try {
    const pool = req.pool; // Pool de conexão já autenticado e anexado à requisição pelo middleware
    const [rows] = await pool.execute('SELECT * FROM tb_comandas');
    res.json({ success: true, comandas: rows, total: rows.length });
  } catch (error) {
    console.error('Erro ao buscar comandas:', error);
    res.status(500).json({ error: 'Erro ao buscar comandas', details: error.message });
  }
});

app.post('/api/sync/receive-pedidos', authenticateEnvironment, async (req, res) => {
  if (!req.isClientAppAuth) {
    return res.status(401).json({ error: 'Acesso não autorizado para receber pedidos', details: 'Apenas ClientApp autorizado pode acessar.' });
  }
  const { pedidos } = req.body;
  const pool = req.pool; // Pool de conexão já autenticado e anexado à requisição pelo middleware

  try {
    const insertedPedidos = [];
    for (const pedido of pedidos) {
      // Exemplo: Inserir o pedido no banco de dados do cliente
      // Adapte esta lógica conforme a estrutura do seu banco de dados
      const [result] = await pool.execute(
        'INSERT INTO tb_pedidos (data, hora, id_cliente, id_forma_pagamento, id_local_retirada, total_produtos, status) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [pedido.data, pedido.hora, pedido.id_cliente, pedido.id_forma_pagamento, pedido.id_local_retirada, pedido.total_produtos, 'processando']
      );

      const pedidoId = result.insertId;
      insertedPedidos.push({ id_pedido_mentorweb: pedido.id_pedido_mentorweb, id_pedido_erp: pedidoId });

      for (const item of pedido.itens) {
        await pool.execute(
          'INSERT INTO tb_itens_pedido (id_pedido, id_produto, quantidade, unitario, total_produto) VALUES (?, ?, ?, ?, ?)',
          [pedidoId, item.id_produto, item.quantidade, item.unitario, item.total_produto]
        );
      }
    }
    res.json({ success: true, message: 'Pedidos recebidos e processados com sucesso!', pedidos_inseridos: insertedPedidos });
  } catch (error) {
    console.error('Erro ao receber pedidos:', error);
    res.status(500).json({ error: 'Erro ao receber pedidos', details: error.message });
  }
});


// Iniciar o servidor
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
