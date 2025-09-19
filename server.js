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
    // Caso especial: Requisição de autenticação de fornecedor pelo MentorWeb (Auth.js)
    // Esses headers especiais são definidos em erpSync.js para indicar que é uma autenticação
    if (req.headers.cnpj === 'FORNECEDOR_AUTH' && 
        req.headers.usuario === 'FORNECEDOR_AUTH' && 
        req.headers.senha === 'FORNECEDOR_AUTH') {
        
        const { banco_dados } = req.headers; // Obtém o banco_dados real da requisição
        if (!banco_dados) {
            return res.status(400).json({ error: 'Banco de dados ausente nos headers para autenticação de fornecedor.' });
        }

        // Cria ou usa um pool para o banco de dados específico do fornecedor que está sendo autenticado
        if (!connections.has(banco_dados)) {
            connections.set(banco_dados, createConnectionPool(banco_dados));
        }
        req.pool = connections.get(banco_dados); // Atribui o pool específico à requisição
        req.isFornecedorAuth = true; // Flag para a rota de autenticação de fornecedor
        return next();
    }

    // Lógica padrão de autenticação para ClienteApp e FornecedorApp (conexões de sincronização)
    const { cnpj, usuario, senha, banco_dados } = req.headers;

    if (!cnpj || !usuario || !senha || !banco_dados) {
      return res.status(401).json({ error: 'Credenciais obrigatórias ausentes nos headers: cnpj, usuario, senha, banco_dados' });
    }

    // Gerencia pools de conexão dinamicamente
    if (!connections.has(banco_dados)) {
      connections.set(banco_dados, createConnectionPool(banco_dados));
    }
    const pool = connections.get(banco_dados);

    // --- Lógica para FornecedorApp (sincronização de dados, não autenticação de usuário final) ---
    // Este `usuario` e `senha` são as credenciais internas do MentorWeb para acessar o ERP do fornecedor
    if (usuario === 'mentorweb_fornecedor' && senha === 'mentorweb_sync_forn_2024') {
      try {
        await pool.query('SELECT 1'); // Testa a conexão
        req.pool = pool;
        req.isFornecedorSync = true; // Marca como sincronização de fornecedor
        req.ambiente = { cnpj, usuario, banco_dados, tipo: 'fornecedor' };
        return next();
      } catch (error) {
        console.error(`Falha ao conectar ao banco de dados do fornecedor ${banco_dados}:`, error);
        return res.status(401).json({ error: `Credenciais de FornecedorApp inválidas ou banco de dados '${banco_dados}' inacessível.` });
      }
    }

    // --- Lógica para ClienteApp (sincronização de dados) ---
    // Aqui você pode ter uma tabela de usuários ClienteApp no seu ERP, por exemplo 'tb_clientes_app'
    // ou usar o cnpj/usuario/senha de um usuário admin do ERP
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
// ROTAS PARA SINCRONIZAÇÃO DE CLIENTEAPP (via credenciais tb_ambientes)
// =========================================================

// Rota para obter produtos do ERP (ClienteApp busca)
app.get('/api/sync/send-produtos', authenticateEnvironment, async (req, res) => {
  if (!req.isClienteSync) { // Verifica se a autenticação é para ClienteApp
    return res.status(403).json({ error: 'Acesso negado.' });
  }
  const connection = await req.pool.getConnection();
  try {
    const [rows] = await connection.execute('SELECT codigo, produto, codigo_barras, preco_venda, estoque, ativo FROM tb_produtos');
    res.json({ success: true, produtos: rows, total: rows.length });
  } catch (error) {
    console.error('Erro ao buscar produtos:', error);
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
    const [rows] = await connection.execute('SELECT codigo, nome, cnpj, cpf, ativo FROM tb_clientes');
    res.json({ success: true, clientes: rows, total: rows.length });
  } catch (error) {
    console.error('Erro ao buscar clientes:', error);
    res.status(500).json({ success: false, error: 'Erro ao buscar clientes.', details: error.message });
  } finally {
    connection.release();
  }
});

// Rota para obter formas de pagamento do ERP (ClienteApp busca)
app.get('/api/sync/send-formas-pagamento', authenticateEnvironment, async (req, res) => {
  if (!req.isClienteSync) {
    return res.status(403).json({ error: 'Acesso negado.' });
  }
  const connection = await req.pool.getConnection();
  try {
    const [rows] = await connection.execute('SELECT codigo, forma_pagamento, ativo FROM tb_formas_pagamento');
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
  if (!req.isClienteSync) {
    return res.status(403).json({ error: 'Acesso negado.' });
  }
  const connection = await req.pool.getConnection();
  try {
    const [rows] = await connection.execute('SELECT codigo, comanda, ativo FROM tb_comandas');
    res.json({ success: true, comandas: rows, total: rows.length });
  } catch (error) {
    console.error('Erro ao buscar comandas:', error);
    res.status(500).json({ success: false, error: 'Erro ao buscar comandas.', details: error.message });
  } finally {
    connection.release();
  }
});

// Rota para receber pedidos no ERP (ClienteApp envia)
app.post('/api/sync/receive-pedidos', authenticateEnvironment, async (req, res) => {
  if (!req.isClienteSync) {
    return res.status(403).json({ error: 'Acesso negado.' });
  }
  const connection = await req.pool.getConnection();
  try {
    const { pedidos } = req.body;
    if (!pedidos || !Array.isArray(pedidos) || pedidos.length === 0) {
      return res.status(400).json({ success: false, error: 'Dados de pedidos inválidos.' });
    }

    const insertedPedidos = [];

    for (const pedido of pedidos) {
      const [resultPedido] = await connection.execute(
        'INSERT INTO tb_pedidos (data, hora, id_cliente, id_forma_pagamento, id_local_retirada, total_produtos, id_lcto_erp) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [
          pedido.data,
          pedido.hora,
          pedido.id_cliente,
          pedido.id_forma_pagamento,
          pedido.id_local_retirada || null, // Garante que é null se não houver
          pedido.total_produtos,
          null, 
        ]
      );
      const idPedidoERP = resultPedido.insertId;

      if (pedido.itens && Array.isArray(pedido.itens)) {
        for (const item of pedido.itens) {
          await connection.execute(
            'INSERT INTO tb_pedidos_produtos (id_pedido, id_produto, quantidade, unitario, total_produto) VALUES (?, ?, ?, ?, ?)',
            [idPedidoERP, item.id_produto, item.quantidade, item.unitario, item.total_produto]
          );
        }
      }
      insertedPedidos.push({ id_pedido_mentorweb: pedido.id_pedido_mentorweb, id_pedido_erp: idPedidoERP });
    }

    res.json({ success: true, message: 'Pedidos recebidos e processados.', pedidos_inseridos: insertedPedidos });
  } catch (error) {
    console.error('Erro ao receber pedidos:', error);
    res.status(500).json({ success: false, error: 'Erro ao receber pedidos.', details: error.message });
  } finally {
    connection.release();
  }
});

// =========================================================
// ROTAS PARA AUTENTICAÇÃO DE USUÁRIO FORNECEDOR (tb_Ambientes)
// =========================================================
app.post('/api/sync/authenticate-fornecedor-user', authenticateEnvironment, async (req, res) => {
  // Verifica se é uma requisição de autenticação de fornecedor (e não uma sincronização)
  if (!req.isFornecedorAuth) {
    return res.status(403).json({ error: 'Acesso negado. Esta rota é apenas para autenticação.' });
  }
  const connection = await req.pool.getConnection(); // Usa o pool dinâmico configurado no middleware
  try {
    const { cnpj_cpf, usuario, senha } = req.body;

    if (!cnpj_cpf || !usuario || !senha) {
      return res.status(400).json({ success: false, error: 'Documento, usuário e senha são obrigatórios.' });
    }

    // Consulta na tb_Ambientes, incluindo o id_fornecedor_app
    const [rows] = await connection.execute(
      'SELECT ID_Pessoa, Documento, Nome, usuario, Senha, CASE WHEN Ativo = \'1\' THEN \'S\' ELSE \'N\' END AS Ativo, id_fornecedor_app FROM tb_Ambientes WHERE Documento = ? AND usuario = ? AND Senha = ?',
      [cnpj_cpf, usuario, senha]
    );

    if (rows.length === 0) {
      return res.status(401).json({ success: false, error: 'Credenciais inválidas.' });
    }

    const userData = rows[0];

    // Verificar se o usuário está ativo
    if (userData.Ativo !== 'S') {
        return res.status(401).json({ success: false, error: 'Usuário inativo.' });
    }
    
    // Verifica se o id_fornecedor_app veio e é válido
    if (!userData.id_fornecedor_app) {
        return res.status(500).json({ success: false, error: 'ID do FornecedorApp não configurado para este usuário no ERP.' });
    }

    res.json({ success: true, user: userData, id_fornecedor_app: userData.id_fornecedor_app });

  } catch (error) {
    console.error('Erro ao autenticar usuário fornecedor:', error);
    res.status(500).json({ success: false, error: 'Erro interno ao autenticar usuário fornecedor.', details: error.message });
  } finally {
    connection.release();
  }
});

// =========================================================
// ROTAS PARA SINCRONIZAÇÃO DE FORNECEDORAPP (via credenciais internas do MentorWeb)
// =========================================================

// Rota para obter produtos do Fornecedor (ERP do fornecedor busca)
app.get('/api/sync/send-produtos-fornecedor', authenticateEnvironment, async (req, res) => {
  if (!req.isFornecedorSync) { // Verifica se a autenticação é para sincronização de FornecedorApp
    return res.status(403).json({ error: 'Acesso negado.' });
  }
  const connection = await req.pool.getConnection();
  try {
    // Consulta produtos específicos do fornecedor (ex: com base no cnpj do header, ou no id do fornecedor)
    // Exemplo: SELECT id, nome, preco_unitario, estoque FROM tb_Produtos_Fornecedor WHERE id_fornecedor = ?
    const [rows] = await connection.execute('SELECT id, nome as produto, preco_unitario, estoque, codigo_barras FROM tb_produtos');
    res.json({ success: true, produtos: rows, total: rows.length });
  } catch (error) {
    console.error('Erro ao buscar produtos do fornecedor:', error);
    res.status(500).json({ success: false, error: 'Erro ao buscar produtos do fornecedor.', details: error.message });
  } finally {
    connection.release();
  }
});

// Rota para receber pedidos no ERP do Fornecedor (MentorWeb envia para o ERP do fornecedor)
app.post('/api/sync/receive-pedido-fornecedor', authenticateEnvironment, async (req, res) => {
  if (!req.isFornecedorSync) {
    return res.status(403).json({ error: 'Acesso negado.' });
  }
  const connection = await req.pool.getConnection();
  try {
    const { produtos, total_pedido, data_pedido, cliente } = req.body;
    if (!produtos || !Array.isArray(produtos) || produtos.length === 0) {
      return res.status(400).json({ success: false, error: 'Dados de produtos inválidos.' });
    }

    // Exemplo de inserção de pedido no ERP do fornecedor
    // A estrutura da tabela de pedidos do fornecedor pode variar (ex: tb_Pedidos_Entrada)
    const [resultPedido] = await connection.execute(
      'INSERT INTO tb_pedidos_fornecedor (data_pedido, total_pedido, nome_cliente_mentorweb) VALUES (?, ?, ?)',
      [data_pedido, total_pedido, cliente] // 'cliente' pode ser o nome do cliente que fez o pedido
    );
    const idPedidoFornecedorERP = resultPedido.insertId;

    if (produtos && Array.isArray(produtos)) {
      for (const item of produtos) {
        await connection.execute(
          'INSERT INTO tb_pedidos_fornecedor_itens (id_pedido_fornecedor, id_produto, quantidade, valor_unitario, total_produto) VALUES (?, ?, ?, ?, ?)',
          [idPedidoFornecedorERP, item.id_produto, item.quantidade, item.valor_unitario, item.total_produto]
        );
      }
    }

    res.json({ success: true, message: 'Pedido recebido e processado pelo ERP do fornecedor.', codigo_pedido: idPedidoFornecedorERP });
  } catch (error) {
    console.error('Erro ao receber pedido do fornecedor:', error);
    res.status(500).json({ success: false, error: 'Erro ao receber pedido do fornecedor.', details: error.message });
  } finally {
    connection.release();
  }
});

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
