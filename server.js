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

const createConnectionPool = (database) => {
  return mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: database,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    // Remover ou comentar as linhas abaixo para evitar os warnings
    // acquireTimeout: 60000, 
    // timeout: 60000,
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
  res.json({ status: 'OK', timestamp: new Date().toISOString(), version: '3.3.0' });
});

// =========================================================
// ROTAS PARA SINCRONIZAÇÃO DE CLIENTEAPP (banco muchaucom_mentor)
// =========================================================

// Rota para obter produtos do ERP (ClienteApp busca)
app.get('/api/sync/send-produtos', authenticateEnvironment, async (req, res) => {
  if (!req.isClienteSync) {
    return res.status(403).json({ error: 'Acesso negado.' });
  }
  const connection = await req.pool.getConnection();
  try {
    // CORREÇÃO: Mapeando as colunas reais da sua tb_produtos (muchaucom_mentor)
    const [rows] = await connection.execute(
      'SELECT codigo AS id, produto, codigo_barras, preco_venda, estoque, ativo FROM tb_produtos WHERE ativo = "S" ORDER BY produto'
    );
    res.json({ success: true, produtos: rows, total: rows.length });
  } catch (error) {
    console.error('Erro ao buscar produtos (cliente):', error);
    res.status(500).json({ success: false, error: 'Erro ao buscar produtos.', details: error.message });
  } finally {
    connection.release();
  }
});

// Rota para obter clientes do ERP (ClienteApp busca)
app.get('/api/sync/send-clientes', authenticateEnvironment, async (req, res) => {
  if (!req.isClienteSync) {
    return res.status(403).json({ error: 'Acesso negado.' });
  }
  const connection = await req.pool.getConnection();
  try {
    const [rows] = await connection.execute(
      'SELECT codigo, nome, cnpj, cpf, ativo FROM tb_clientes WHERE ativo = "S" ORDER BY nome'
    );
    
    // --- ADICIONE ESTAS DUAS LINHAS PARA DEBUG ---
    console.log("DEBUG - Conteúdo de 'rows' antes de enviar JSON:", rows);
    console.log("DEBUG - Tamanho de 'rows' antes de enviar JSON:", rows.length);
    // ---------------------------------------------

    res.json({ success: true, clientes: rows, total: rows.length });
  } catch (error) {
    console.error('Erro ao buscar clientes (cliente):', error);
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
    res.json({ success: true, formas: rows, total: rows.length });
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
    res.json({ success: true, comandas: rows, total: rows.length });
  } catch (error) {
    console.error('Erro ao buscar comandas:', error);
    res.status(500).json({ success: false, error: 'Erro ao buscar comandas.', details: error.message });
  } finally {
    connection.release();
  }
});


// Rota para receber pedidos do MentorWeb (ClienteApp envia para seu ERP)
app.post('/api/sync/receive-pedidos', authenticateEnvironment, async (req, res) => {
  if (!req.isClienteSync) {
    return res.status(403).json({ error: 'Acesso negado.' });
  }
  const connection = await req.pool.getConnection();
  try {
    const { pedidos } = req.body; // Espera um array de pedidos

    if (!pedidos || !Array.isArray(pedidos) || pedidos.length === 0) {
      return res.status(400).json({ success: false, error: 'Dados de pedidos inválidos.' });
    }

    const insertedPedidos = [];

    for (const pedido of pedidos) {
      // Inserir o pedido principal na tb_pedidos
      const [resultPedido] = await connection.execute(
        'INSERT INTO tb_pedidos (data, hora, id_cliente, id_forma_pagamento, id_local_retirada, total_produtos, status) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [
          pedido.data,
          pedido.hora,
          pedido.id_cliente,
          pedido.id_forma_pagamento,
          pedido.id_local_retirada || null, // ESTA É A LINHA CRÍTICA QUE FOI ALTERADA
          pedido.total_produtos,
          'recebido' // Status inicial
        ]
      );
      const idPedido = resultPedido.insertId;

      // Inserir os itens do pedido na tb_pedidos_produtos
      for (const item of pedido.itens) {
        await connection.execute(
          'INSERT INTO tb_pedidos_produtos (id_pedido_erp, id_produto, quantidade, unitario, total_produto, id_lcto_erp) VALUES (?, ?, ?, ?, ?, ?)',
          [
            idPedido,
            item.id_produto,
            item.quantidade,
            item.unitario,
            item.total_produto,
            null // id_lcto_erp é NULL por padrão, conforme seu schema
          ]
        );
      }
      insertedPedidos.push({ id_pedido_mentorweb: pedido.id_pedido_mentorweb, id_pedido_erp: idPedido });
    }

    res.json({ success: true, pedidos_inseridos: insertedPedidos });
  } catch (error) {
    console.error('Erro ao receber pedidos (cliente):', error);
    res.status(500).json({ success: false, error: 'Erro ao receber pedidos.', details: error.message });
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
    // CORREÇÃO: Adicionando a cláusula WHERE Ativo = "S"
    // Usando os nomes das colunas conforme o schema mais recente (PascalCase)
    const [rows] = await connection.execute('SELECT id, nome, preco_unitario FROM tb_Produtos WHERE Ativo = "S" ORDER BY nome');
    res.json({ success: true, produtos: rows, total: rows.length });
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
    const { data: pedidoFrontend } = req.body; // 'data' é o objeto completo enviado pelo frontend

    // Inserir na tb_Pedidos (PascalCase)
    // Assumindo que tb_Pedidos para o Fornecedor tem 'data_pedido', 'id_cliente_app', 'id_fornecedor_app', 'total_pedido', 'status' (do frontend PedidoFornecedor)
    // E que tb_Pedidos tem colunas 'codigo_pedido_fornecedor' para o ID retornado, e 'data_pedido' para o DATETIME
    const [pedidoResult] = await connection.execute(
      'INSERT INTO tb_Pedidos (data_pedido, id_cliente_app, id_fornecedor_app, total_pedido, status) VALUES (?, ?, ?, ?, ?)',
      [
        new Date(pedidoFrontend.data_pedido), // Converte a string para objeto Date
        pedidoFrontend.id_cliente_app,
        pedidoFrontend.id_fornecedor_app,
        pedidoFrontend.total_pedido,
        pedidoFrontend.status // Status vindo do frontend, ex: 'processado'
      ]
    );
    const pedidoId = pedidoResult.insertId;

    // Inserir na tb_Pedidos_Produtos (PascalCase)
    // Assumindo que tb_Pedidos_Produtos tem 'id_pedido_fornecedor', 'id_produto_fornecedor', 'nome_produto', 'quantidade', 'valor_unitario', 'total_produto'
    for (const item of pedidoFrontend.produtos) { // 'produtos' é a lista de itens dentro do 'pedido'
      await connection.execute(
        'INSERT INTO tb_Pedidos_Produtos (id_pedido_fornecedor, id_produto_fornecedor, nome_produto, quantidade, valor_unitario, total_produto) VALUES (?, ?, ?, ?, ?, ?)',
        [
          pedidoId, // id_pedido_fornecedor se refere ao ID do pedido recém-criado
          item.id_produto_fornecedor,
          item.nome_produto,
          item.quantidade,
          item.valor_unitario,
          item.total_produto
        ]
      );
    }
    await connection.commit();
    res.json({ success: true, codigo_pedido: pedidoId, message: 'Pedido recebido com sucesso.' });
  } catch (error) {
    await connection.rollback();
    console.error('Erro ao receber pedido do fornecedor:', error);
    res.status(500).json({ success: false, error: 'Erro ao processar pedido do fornecedor.', details: error.message });
  } finally {
    connection.release();
  }
});

// Nova Rota para autenticação de usuário fornecedor (Node.js)
app.post('/api/sync/authenticate-fornecedor-user', authenticateEnvironment, async (req, res) => {
  if (!req.isFornecedorSync) {
    return res.status(403).json({ error: 'Acesso negado.' });
  }
  const connection = await req.pool.getConnection();
  try {
    const { cnpj_cpf, usuario, senha } = req.body;

    if (!cnpj_cpf || !usuario || !senha) {
      return res.status(400).json({ success: false, error: 'Documento, usuário e senha são obrigatórios.' });
    }

    // Consulta na tb_Ambientes
    const [rows] = await connection.execute(
      // CORREÇÃO AQUI: Traduzir 1/0 para S/N
      'SELECT ID_Pessoa, Documento, Nome, usuario, Senha, CASE WHEN Ativo = \'1\' THEN \'S\' ELSE \'N\' END AS Ativo FROM tb_Ambientes WHERE Documento = ? AND usuario = ? AND Senha = ?',
      [cnpj_cpf, usuario, senha]
    );

    if (rows.length === 0) {
      return res.status(401).json({ success: false, error: 'Credenciais inválidas.' });
    }

    const userData = rows[0];

    // Verificar se o usuário está ativo - AGORA VERIFICA 'S' (que virá do banco)
    if (userData.Ativo !== 'S') {
        return res.status(401).json({ success: false, error: 'Usuário inativo.' });
    }

    res.json({ success: true, user: userData });

  } catch (error) {
    console.error('Erro ao autenticar usuário fornecedor:', error);
    res.status(500).json({ success: false, error: 'Erro interno ao autenticar usuário fornecedor.', details: error.message });
  } finally {
    connection.release();
  }
});

// Tratamento de erros
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Algo deu errado no servidor!');
});

// Inicia o servidor
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
