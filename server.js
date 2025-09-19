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

// Cria um pool de conexão para um banco de dados específico
const createConnectionPool = (database) => {
  return mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: database, // Usa o nome do banco de dados passado
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
  });
};

// Middleware de autenticação unificado
const authenticateEnvironment = async (req, res, next) => {
  try {
    const { cnpj, usuario, senha, banco_dados } = req.headers;

    // ----- A. Handler for Supplier Authentication (Auth.js calls erpSync with FORNECEDOR_AUTH headers) -----
    // Usamos os headers em minúsculas, pois o Express os converte.
    if (cnpj === 'fornecedor_auth' && usuario === 'fornecedor_auth' && senha === 'fornecedor_auth') {
        if (!banco_dados) {
            return res.status(400).json({ error: 'Banco de dados ausente nos headers para autenticação de fornecedor.' });
        }
        // Cria pool para o banco de dados do fornecedor (deve conter tb_Ambientes, PascalCase)
        if (!connections.has(banco_dados)) {
            connections.set(banco_dados, createConnectionPool(banco_dados));
        }
        req.pool = connections.get(banco_dados); 
        req.isFornecedorAuth = true; 
        return next(); // Este é o ÚNICO caminho para login FORNECEDOR_AUTH.
    }

    // ----- B. Validação comum para todas as outras requisições autenticadas (sincronizações) -----
    if (!cnpj || !usuario || !senha || !banco_dados) {
      return res.status(401).json({ error: 'Credenciais obrigatórias ausentes nos headers: cnpj, usuario, senha, banco_dados' });
    }

    // Obtém ou cria pool para o banco de dados especificado nos headers
    if (!connections.has(banco_dados)) {
      connections.set(banco_dados, createConnectionPool(banco_dados));
    }
    const pool = connections.get(banco_dados);

    // ----- C. Handler para Sincronização FornecedorApp (erpSync com credenciais mentorweb_fornecedor) -----
    if (usuario === 'mentorweb_fornecedor' && senha === 'mentorweb_sync_forn_2024') {
      try {
        await pool.query('SELECT 1'); // Apenas testa a conexão
        req.pool = pool; // Usa este pool para operações de sincronização
        req.isFornecedorSync = true;
        req.ambiente = { cnpj, usuario, banco_dados, tipo: 'fornecedor' };
        return next(); // Este é o ÚNICO caminho para sincronização de fornecedor.
      } catch (error) {
        console.error(`Falha ao conectar ao banco de dados do fornecedor ${banco_dados}:`, error);
        return res.status(401).json({ error: `Credenciais de FornecedorApp inválidas ou banco de dados '${banco_dados}' inacessível.` });
      }
    }

    // ----- D. Handler para Sincronização ClienteApp (requisições de sincronização de dados do ClienteApp) -----
    // Este ponto só deve ser alcançado por requisições do ClienteApp.
    // Usamos 'tb_ambientes' (minúsculas) conforme sua última clarificação para ClienteApp.
    const [rows] = await pool.execute(
      'SELECT * FROM tb_ambientes WHERE cnpj = ? AND usuario = ? AND senha = ? AND ativo = "S"', // CORRIGIDO para tb_ambientes (minúsculas)
      [cnpj, usuario, senha]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: 'Credenciais de ClienteApp inválidas para este ambiente.' });
    }

    req.pool = pool; // Usa este pool para operações de sincronização
    req.isClienteSync = true;
    req.ambiente = rows[0];
    next(); // Continua para o handler de rota específico (ex: /send-produtos)

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
// ROTAS PARA SINCRONIZAÇÃO DE CLIENTEAPP
// =========================================================

// Rota para obter produtos do ERP (ClienteApp busca)
app.get('/api/sync/send-produtos', authenticateEnvironment, async (req, res) => {
  if (!req.isClienteSync) {
    return res.status(403).json({ error: 'Acesso negado para ClienteApp. Credenciais inválidas ou ausentes.' });
  }
  const pool = req.pool;
  try {
    const [rows] = await pool.execute('SELECT codigo, produto, codigo_barras, preco_venda, estoque, ativo FROM tb_produtos');
    res.json({ success: true, produtos: rows });
  } catch (error) {
    console.error('Erro ao buscar produtos:', error);
    res.status(500).json({ error: 'Erro ao buscar produtos no ERP.', details: error.message });
  }
});

// Rota para obter clientes do ERP (ClienteApp busca)
app.get('/api/sync/send-clientes', authenticateEnvironment, async (req, res) => {
  if (!req.isClienteSync) {
    return res.status(403).json({ error: 'Acesso negado para ClienteApp. Credenciais inválidas ou ausentes.' });
  }
  const pool = req.pool;
  try {
    const [rows] = await pool.execute('SELECT codigo, nome, cnpj, cpf, ativo FROM tb_clientes');
    res.json({ success: true, clientes: rows });
  } catch (error) {
    console.error('Erro ao buscar clientes:', error);
    res.status(500).json({ error: 'Erro ao buscar clientes no ERP.', details: error.message });
  }
});

// Rota para obter formas de pagamento do ERP (ClienteApp busca)
app.get('/api/sync/send-formas-pagamento', authenticateEnvironment, async (req, res) => {
  if (!req.isClienteSync) {
    return res.status(403).json({ error: 'Acesso negado para ClienteApp. Credenciais inválidas ou ausentes.' });
  }
  const pool = req.pool;
  try {
    const [rows] = await pool.execute('SELECT codigo, forma_pagamento, ativo FROM tb_formas_pagamento');
    res.json({ success: true, formas: rows });
  } catch (error) {
    console.error('Erro ao buscar formas de pagamento:', error);
    res.status(500).json({ error: 'Erro ao buscar formas de pagamento no ERP.', details: error.message });
  }
});

// Rota para obter comandas/mesas do ERP (ClienteApp busca)
app.get('/api/sync/send-comandas', authenticateEnvironment, async (req, res) => {
  if (!req.isClienteSync) {
    return res.status(403).json({ error: 'Acesso negado para ClienteApp. Credenciais inválidas ou ausentes.' });
  }
  const pool = req.pool;
  try {
    const [rows] = await pool.execute('SELECT codigo, comanda, ativo FROM tb_comandas');
    res.json({ success: true, comandas: rows });
  } catch (error) {
    console.error('Erro ao buscar comandas:', error);
    res.status(500).json({ error: 'Erro ao buscar comandas no ERP.', details: error.message });
  }
});

// Rota para receber pedidos do MentorWeb e enviar para o ERP (ClienteApp envia)
app.post('/api/sync/receive-pedidos', authenticateEnvironment, async (req, res) => {
  if (!req.isClienteSync) {
    return res.status(403).json({ error: 'Acesso negado para ClienteApp. Credenciais inválidas ou ausentes.' });
  }
  const pool = req.pool;
  let connection; // Declare connection outside try to ensure it's accessible in finally

  try {
    connection = await pool.getConnection(); // Get connection from the pool
    await connection.beginTransaction(); // Start transaction

    const { pedidos } = req.body;
    const insertedPedidos = [];

    for (const pedido of pedidos) {
      // Inserir na tabela de pedidos principal
      const [resultPedido] = await connection.execute(
        'INSERT INTO tb_pedidos (data, hora, id_cliente, id_forma_pagamento, id_local_retirada, total_produtos, id_lcto_erp, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [
          pedido.data,
          pedido.hora,
          pedido.id_cliente,
          pedido.id_forma_pagamento,
          pedido.id_local_retirada || null, // Garante que é null se não houver
          pedido.total_produtos,
          null, // id_lcto_erp deve ser null na criação inicial, será atualizado pelo ERP
          'pendente' // Adicionando status inicial
        ]
      );
      const idPedidoERP = resultPedido.insertId;

      // Inserir itens do pedido
      if (pedido.itens && Array.isArray(pedido.itens)) {
        for (const item of pedido.itens) {
          await connection.execute(
            'INSERT INTO tb_pedido_produto (id_pedido, id_produto, quantidade, unitario, total_produto) VALUES (?, ?, ?, ?, ?)',
            [idPedidoERP, item.id_produto, item.quantidade, item.unitario, item.total_produto]
          );
        }
      }
      insertedPedidos.push({ id_pedido_mentorweb: pedido.id_pedido_mentorweb, id_pedido_erp: idPedidoERP });
    }

    await connection.commit(); // Commit transaction
    res.json({ success: true, pedidos_inseridos: insertedPedidos });

  } catch (error) {
    if (connection) await connection.rollback(); // Rollback on error
    console.error('Erro ao receber pedidos:', error);
    res.status(500).json({ error: 'Erro ao processar pedidos recebidos.', details: error.message });
  } finally {
    if (connection) connection.release(); // Release connection
  }
});


// =========================================================
// ROTAS PARA SINCRONIZAÇÃO DE FORNECEDORAPP
// =========================================================

// Rota de autenticação de usuário fornecedor (chamada pelo Auth.js)
app.post('/api/sync/authenticate-fornecedor-user', authenticateEnvironment, async (req, res) => {
  // req.isFornecedorAuth será true se o middleware identificou os headers especiais
  if (!req.isFornecedorAuth) {
    return res.status(403).json({ error: 'Acesso negado ou credenciais de autenticação de fornecedor ausentes.' });
  }

  const { cnpj_cpf, usuario, senha } = req.body; // Credenciais do corpo da requisição

  let connection;
  try {
    connection = await req.pool.getConnection(); // Obtém conexão do pool específico do fornecedor

    // Consulta na tb_Ambientes (com 'A' maiúsculo) para autenticação de fornecedor
    const [rows] = await connection.execute(
      'SELECT ID_Pessoa, Documento, Nome, usuario, Senha, CASE WHEN Ativo = \'1\' THEN \'S\' ELSE \'N\' END AS Ativo, id_fornecedor_app FROM tb_Ambientes WHERE Documento = ? AND usuario = ? AND Senha = ?',
      [cnpj_cpf, usuario, senha]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: 'Credenciais inválidas.' });
    }
    const user = rows[0];

    // O id_fornecedor_app é retornado pelo próprio ERP para vincular ao Base44
    res.json({ success: true, user: user, id_fornecedor_app: user.id_fornecedor_app });

  } catch (error) {
    console.error('Erro ao autenticar usuário fornecedor:', error);
    res.status(500).json({ error: 'Erro interno do servidor durante a autenticação de fornecedor.', details: error.message });
  } finally {
    if (connection) connection.release();
  }
});

// Rota para obter produtos de um fornecedor específico
app.get('/api/sync/send-produtos-fornecedor', authenticateEnvironment, async (req, res) => {
  if (!req.isFornecedorSync) {
    return res.status(403).json({ error: 'Acesso negado para FornecedorApp. Credenciais inválidas ou ausentes.' });
  }
  const pool = req.pool;
  try {
    const [rows] = await pool.execute('SELECT codigo as id, produto as nome, preco_venda as preco_unitario, estoque, codigo_barras FROM tb_produtos');
    res.json({ success: true, produtos: rows });
  } catch (error) {
    console.error('Erro ao buscar produtos do fornecedor:', error);
    res.status(500).json({ error: 'Erro ao buscar produtos do fornecedor no ERP.', details: error.message });
  }
});

// Rota para receber um pedido e enviar para o ERP do fornecedor
app.post('/api/sync/receive-pedido-fornecedor', authenticateEnvironment, async (req, res) => {
  if (!req.isFornecedorSync) {
    return res.status(403).json({ error: 'Acesso negado para FornecedorApp. Credenciais inválidas ou ausentes.' });
  }
  const pool = req.pool;
  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();

    const { produtos, total_pedido, data_pedido, cliente } = req.body;

    // Exemplo: Inserir pedido na tabela de pedidos do fornecedor (ajuste conforme sua estrutura)
    const [resultPedido] = await connection.execute(
      'INSERT INTO tb_pedidos_recebidos (data_pedido, total_pedido, cliente_origem) VALUES (?, ?, ?)',
      [data_pedido, total_pedido, cliente]
    );
    const idPedidoGerado = resultPedido.insertId;

    // Inserir itens do pedido na tabela de itens do pedido do fornecedor (ajuste conforme sua estrutura)
    for (const produto of produtos) {
      await connection.execute(
        'INSERT INTO tb_itens_pedidos_recebidos (id_pedido_recebido, id_produto_fornecedor, quantidade, valor_unitario, total_produto) VALUES (?, ?, ?, ?, ?)',
        [idPedidoGerado, produto.id_produto, produto.quantidade, produto.valor_unitario, produto.total_produto]
      );
    }

    await connection.commit();
    res.json({ success: true, codigo_pedido: idPedidoGerado, message: 'Pedido recebido e processado.' });

  } catch (error) {
    if (connection) await connection.rollback();
    console.error('Erro ao receber pedido para fornecedor:', error);
    res.status(500).json({ error: 'Erro ao processar pedido para fornecedor.', details: error.message });
  } finally {
    if (connection) connection.release();
  }
});


// Iniciar o servidor
app.listen(PORT, () => {
  console.log(`Servidor Node.js rodando na porta ${PORT}`);
});
