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
      console.log('Autenticação de fornecedor bem-sucedida para:', user.Nome);
      return res.status(200).json({
        success: true,
        user: {
          id_ambiente_erp: user.Codigo,
          nome_ambiente: user.Nome,
          ID_Pessoa: user.ID_Pessoa,
          Documento: user.Documento,
          Nome: user.Nome,
          usuario: user.usuario,
          Ativo: user.Ativo,
        }
      });
    } else {
      console.warn('Falha na autenticação de fornecedor. Credenciais inválidas ou usuário inativo.');
      return res.status(401).json({ success: false, error: 'Usuário, senha ou documento inválido, ou usuário inativo.' });
    }
  } catch (error) {
    console.error('Erro na rota /authenticate-fornecedor-user:', error);
    return res.status(500).json({ success: false, error: 'Erro interno do servidor.', details: error.message });
  } finally {
    if (connection) connection.release();
  }
});


// Middleware de autenticação de ambiente aplicado a todas as rotas de sincronização
app.use('/api/sync', authenticateEnvironment);


// --- ROTAS PARA CLIENTE APP (banco muchaucom_mentor) ---

app.get('/api/sync/send-produtos', async (req, res) => {
    if (!req.isClientAppAuth) {
        return res.status(403).json({ error: "Acesso não autorizado para esta rota." });
    }
    try {
        const [rows] = await req.pool.query("SELECT codigo, produto, codigo_barras, preco_venda, estoque, ativo FROM tb_produtos WHERE ativo = 'S'");
        res.json({ success: true, produtos: rows, total: rows.length });
    } catch (error) {
        console.error('Erro ao buscar produtos (cliente):', error);
        res.status(500).json({ success: false, error: 'Erro ao buscar produtos.', details: error.message });
    }
});

app.get('/api/sync/send-clientes', async (req, res) => {
    if (!req.isClientAppAuth) {
        return res.status(403).json({ error: "Acesso não autorizado para esta rota." });
    }
    try {
        const [rows] = await req.pool.query("SELECT codigo, nome, cnpj, cpf, ativo FROM tb_clientes WHERE ativo = 'S'");
        res.json({ success: true, clientes: rows, total: rows.length });
    } catch (error) {
        console.error('Erro ao buscar clientes:', error);
        res.status(500).json({ success: false, error: 'Erro ao buscar clientes.', details: error.message });
    }
});

app.get('/api/sync/send-formas-pagamento', async (req, res) => {
    if (!req.isClientAppAuth) {
        return res.status(403).json({ error: "Acesso não autorizado para esta rota." });
    }
    try {
        const [rows] = await req.pool.query("SELECT codigo, forma_pagamento, ativo FROM tb_formas_pagamento WHERE ativo = 'S'");
        res.json({ success: true, formas: rows, total: rows.length });
    } catch (error) {
        console.error('Erro ao buscar formas de pagamento:', error);
        res.status(500).json({ success: false, error: 'Erro ao buscar formas de pagamento.', details: error.message });
    }
});

app.get('/api/sync/send-comandas', async (req, res) => {
    if (!req.isClientAppAuth) {
        return res.status(403).json({ error: "Acesso não autorizado para esta rota." });
    }
    try {
        const [rows] = await req.pool.query("SELECT codigo, comanda, ativo FROM tb_comandas WHERE ativo = 'S'");
        res.json({ success: true, comandas: rows, total: rows.length });
    } catch (error) {
        console.error('Erro ao buscar comandas:', error);
        res.status(500).json({ success: false, error: 'Erro ao buscar comandas.', details: error.message });
    }
});

app.post('/api/sync/receive-pedidos', async (req, res) => {
    if (!req.isClientAppAuth) {
        return res.status(403).json({ error: "Acesso não autorizado para esta rota." });
    }

    // Log detalhado do corpo da requisição
    console.log('--- /api/sync/receive-pedidos ---');
    console.log('Request Body Recebido:', JSON.stringify(req.body, null, 2));
    console.log('---------------------------------');

    // CORREÇÃO: Espera um array `pedidos` no corpo da requisição
    const { pedidos } = req.body;

    if (!Array.isArray(pedidos) || pedidos.length === 0) {
        return res.status(400).json({ error: 'Dados do pedido incompletos ou em formato incorreto. Esperado um array `pedidos`.' });
    }

    let connection;
    try {
        connection = await req.pool.getConnection();
        await connection.beginTransaction();

        const pedidosInseridos = [];

        // Itera sobre cada pedido no array
        for (const pedido of pedidos) {
            const { data, hora, id_cliente, id_forma_pagamento, id_local_retirada, total_produtos, itens, id_pedido_mentorweb, observacoes } = pedido;

            // Valida cada pedido individualmente
            if (!data || !hora || !id_cliente || !id_forma_pagamento || total_produtos === undefined || !Array.isArray(itens) || itens.length === 0) {
                // Se um pedido for inválido, desfaz a transação inteira
                throw new Error(`Pedido com id_pedido_mentorweb ${id_pedido_mentorweb || '(desconhecido)'} está com dados incompletos.`);
            }

            console.log(`Processando pedido do app (ID MentorWeb: ${id_pedido_mentorweb}) para o cliente ${id_cliente}`);

            const [result] = await connection.execute(
                'INSERT INTO tb_pedidos (data, hora, id_cliente, id_forma_pagamento, id_local_retirada, total_produtos, status, id_lcto_erp, origem, observacoes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [data, hora, id_cliente, id_forma_pagamento, id_local_retirada || null, total_produtos, 'recebido', id_pedido_mentorweb, 'mentorweb', observacoes || null]
            );

            const idPedidoErp = result.insertId;
            console.log(`Pedido inserido em tb_pedidos com ID ERP: ${idPedidoErp}`);

            for (const item of itens) {
                await connection.execute(
                    'INSERT INTO tb_pedidos_produtos (id_pedido_erp, id_produto, quantidade, unitario, total_produto) VALUES (?, ?, ?, ?, ?)',
                    [idPedidoErp, item.id_produto, item.quantidade, item.unitario, item.total_produto]
                );
            }
            console.log(`${itens.length} itens inseridos em tb_pedidos_produtos para o pedido ERP ${idPedidoErp}.`);
            
            pedidosInseridos.push({
                id_pedido_mentorweb: id_pedido_mentorweb,
                id_pedido_erp: idPedidoErp,
                status: 'recebido'
            });
        }

        await connection.commit();
        res.status(201).json({ success: true, pedidos_inseridos: pedidosInseridos, message: 'Pedidos recebidos com sucesso.' });

    } catch (error) {
        if (connection) await connection.rollback();
        console.error('Erro ao receber pedido (cliente):', error);
        // Retorna uma mensagem de erro mais específica
        res.status(500).json({ success: false, error: 'Erro ao salvar pedido no ERP.', details: error.message });
    } finally {
        if (connection) connection.release();
    }
});


// --- ROTAS PARA FORNECEDOR (banco muchaucom_pisciNew) ---

app.get('/api/sync/send-produtos-fornecedor', async (req, res) => {
    if (!req.isSupplierAuth) {
        return res.status(403).json({ error: "Acesso não autorizado para esta rota." });
    }
    try {
        console.log("Buscando produtos do fornecedor...");
        // Adicionado ALIAS para consistência da resposta
        const [rows] = await req.pool.query("SELECT id, nome, preco_unitario, Ativo as ativo FROM tb_Produtos_Fornecedor WHERE Ativo = 'S'");
        console.log(`${rows.length} produtos de fornecedor encontrados.`);
        res.json({ success: true, produtos: rows, total: rows.length });
    } catch (error) {
        console.error('Erro ao buscar produtos (fornecedor):', error);
        res.status(500).json({ success: false, error: 'Erro ao buscar produtos do fornecedor.', details: error.message });
    }
});

app.post('/api/sync/receive-pedido-fornecedor', async (req, res) => {
  if (!req.isSupplierAuth) {
    return res.status(403).json({ error: "Acesso não autorizado para esta rota." });
  }

  const { produtos, total_pedido, cliente } = req.body;

  if (!Array.isArray(produtos) || produtos.length === 0 || total_pedido === undefined) {
    return res.status(400).json({ error: 'Dados do pedido para fornecedor incompletos.' });
  }

  let connection;
  try {
    connection = await req.pool.getConnection();
    await connection.beginTransaction();

    console.log(`Recebendo pedido para fornecedor do cliente: ${cliente}`);

    // Tenta encontrar o ID do ambiente do cliente que está fazendo o pedido
    const [clienteRows] = await connection.execute('SELECT Codigo FROM tb_Ambientes_Fornecedor WHERE Nome = ?', [cliente]);
    const idAmbienteCliente = clienteRows.length > 0 ? clienteRows[0].Codigo : null;
    
    if (!idAmbienteCliente) {
      throw new Error(`Cliente/Ambiente '${cliente}' não encontrado no banco de dados do fornecedor.`);
    }
    
    console.log(`ID do ambiente do cliente encontrado: ${idAmbienteCliente}`);

    const [result] = await connection.execute(
      'INSERT INTO tb_Pedidos_Fornecedor (data_hora_lancamento, id_ambiente, valor_total, status) VALUES (NOW(), ?, ?, ?)',
      [idAmbienteCliente, total_pedido, 'recebido']
    );

    const idPedidoFornecedor = result.insertId;
    console.log(`Pedido inserido em tb_Pedidos_Fornecedor com ID: ${idPedidoFornecedor}`);

    for (const item of produtos) {
      await connection.execute(
        'INSERT INTO tb_Pedidos_Produtos_Fornecedor (id_pedido, id_produto, quantidade, preco_unitario, valor_total, identificador_cliente_item) VALUES (?, ?, ?, ?, ?, ?)',
        [idPedidoFornecedor, item.id_produto, item.quantidade, item.valor_unitario, item.total_produto, item.id_produto]
      );
    }
    console.log(`${produtos.length} itens inseridos em tb_Pedidos_Produtos_Fornecedor.`);

    await connection.commit();
    res.status(201).json({ success: true, codigo_pedido: idPedidoFornecedor, message: 'Pedido para fornecedor recebido com sucesso.' });

  } catch (error) {
    if (connection) await connection.rollback();
    console.error('Erro ao receber pedido (fornecedor):', error);
    res.status(500).json({ success: false, error: 'Erro ao salvar pedido no ERP do fornecedor.', details: error.message });
  } finally {
    if (connection) connection.release();
  }
});


// Tratamento de erro 404
app.use((req, res) => {
  res.status(404).json({ error: 'Rota não encontrada' });
});

// Tratamento de erros geral
app.use((err, req, res, next) => {
  console.error('Erro não tratado:', err.stack);
  res.status(500).json({ error: 'Ocorreu um erro inesperado no servidor.' });
});

// Iniciar o servidor
app.listen(PORT, () => {
  console.log(`Servidor de sincronização MentorWeb rodando na porta ${PORT}`);
});
