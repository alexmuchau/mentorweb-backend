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
app.use(helmet());          // Proteções básicas de segurança HTTP
app.use(compression());     // Compacta as respostas HTTP para melhorar a performance
app.use(morgan('combined')); // Logger de requisições HTTP

// Rate limiting para proteger contra ataques de força bruta e DoS
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100, // Limita cada IP a 100 requisições por janelaMs
  message: 'Muitas requisições desta IP, tente novamente após 15 minutos.'
});
app.use('/api/', limiter); // Aplica o limitador a todas as rotas da API

// Configuração CORS (Cross-Origin Resource Sharing)
const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000', 'http://localhost:5173']; // Adapte os domínios permitidos
app.use(cors({
  origin: (origin, callback) => {
    // Permite requisições sem 'origin' (como de apps mobile ou ferramentas como Postman)
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = `A política CORS para este site não permite acesso da Origem ${origin}.`;
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
  credentials: true // Permite o envio de cookies de credenciais
}));

// Body parsing para lidar com diferentes tipos de payloads de requisição
app.use(express.json({ limit: '10mb' })); // Para JSON
app.use(express.urlencoded({ extended: true })); // Para URL-encoded

// Mapa de pools de conexão MySQL para diferentes bancos de dados
const connections = new Map();

// Função para criar um pool de conexão MySQL para um banco de dados específico
const createConnectionPool = (database) => {
  // Em produção, use um pool para gerenciar conexões de forma eficiente
  return mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '', // Use variável de ambiente para senhas!
    database: database, // O nome do banco de dados será dinâmico
    waitForConnections: true,
    connectionLimit: 10, // Número máximo de conexões no pool
    queueLimit: 0,       // Tamanho máximo da fila de requisições pendentes
    acquireTimeout: 60000, // Tempo máximo para adquirir uma conexão (60s)
    timeout: 60000,      // Tempo limite para uma consulta (60s)
  });
};

// Middleware de autenticação e identificação de ambiente (ClienteApp ou FornecedorApp)
const authenticateEnvironment = async (req, res, next) => {
  try {
    const { cnpj, usuario, senha, banco_dados } = req.headers;

    // Todas as requisições de sincronização devem conter estas credenciais nos headers
    if (!cnpj || !usuario || !senha || !banco_dados) {
      return res.status(401).json({ 
        error: 'Credenciais obrigatórias ausentes nos headers: cnpj, usuario, senha, banco_dados' 
      });
    }

    // Garante que haja um pool de conexão para o banco de dados especificado
    if (!connections.has(banco_dados)) {
      connections.set(banco_dados, createConnectionPool(banco_dados));
    }
    const pool = connections.get(banco_dados);

    // --- Lógica para FornecedorApp ---
    // Credenciais específicas para a sincronização com FornecedorApp
    // Assumimos que o CNPJ do fornecedor é o que define o ambiente
    if (usuario === 'mentorweb_fornecedor' && senha === 'mentorweb_sync_forn_2024') {
      try {
        await pool.query('SELECT 1 + 1'); // Testar a conexão para verificar se o banco do fornecedor é acessível
        req.pool = pool; // Anexa o pool de conexão à requisição
        req.isFornecedorSync = true; // Marca a requisição como sendo de um fornecedor
        req.ambiente = { // Informações do ambiente do fornecedor
          cnpj,
          usuario,
          banco_dados,
          tipo: 'fornecedor'
        };
        return next(); // Prossegue para a próxima middleware/rota
      } catch (error) {
        console.error(`Falha ao conectar ao banco de dados do fornecedor ${banco_dados}:`, error);
        return res.status(401).json({ 
          error: `Credenciais de FornecedorApp inválidas ou banco de dados '${banco_dados}' inacessível.` 
        });
      }
    }

    // --- Lógica para ClienteApp (verificação em tb_Ambientes) ---
    // Para ClienteApp, as credenciais são verificadas na tabela tb_Ambientes
    // Usamos 'Documento' do header 'cnpj' e 'usuario' do header 'usuario'
    const [rows] = await pool.execute(
      'SELECT * FROM tb_Ambientes WHERE Documento = ? AND usuario = ? AND Senha = ? AND Ativo = "S"',
      [cnpj, usuario, senha] // Note: 'banco_dados' não é usado na query SQL para tb_Ambientes
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: 'Credenciais de ClienteApp inválidas para este ambiente.' });
    }

    req.pool = pool; // Anexa o pool de conexão
    req.isClienteSync = true; // Marca a requisição como sendo de um cliente
    req.ambiente = rows[0]; // Informações do ambiente do cliente
    next(); // Prossegue
  } catch (error) {
    console.error('Erro no middleware de autenticação:', error);
    res.status(500).json({ error: 'Erro interno do servidor durante a autenticação.' });
  }
};

// =========================================================
// ROTAS DE SERVIÇO GERAL
// =========================================================

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    version: '2.1.0' // Versão atualizada do servidor
  });
});

// =========================================================
// ROTAS PARA SINCRONIZAÇÃO GERAL (ClienteApp e FornecedorApp)
// =========================================================

// Rota para buscar produtos (para ClienteApp ou FornecedorApp)
app.get('/api/sync/send-produtos', authenticateEnvironment, async (req, res) => {
  const connection = await req.pool.getConnection();
  try {
    const [produtos] = await connection.execute(
      // Usando os novos nomes de colunas: id, nome, preco_unitario
      'SELECT id, nome, preco_unitario FROM tb_Produtos ORDER BY nome'
    );
    res.json({ success: true, produtos: produtos });
  } catch (error) {
    console.error(`Erro ao buscar produtos no ERP (${req.ambiente.banco_dados}):`, error);
    res.status(500).json({ error: 'Erro ao buscar produtos.' });
  } finally {
    connection.release();
  }
});

// Rota para buscar clientes (apenas para ClienteApp)
app.get('/api/sync/send-clientes', authenticateEnvironment, async (req, res) => {
  if (!req.isClienteSync) {
    return res.status(403).json({ error: 'Acesso negado: Esta rota é exclusiva para ClienteApp.' });
  }
  const connection = await req.pool.getConnection();
  try {
    // Usando os novos nomes de colunas: Codigo, Documento, Nome, Ativo
    const [clientes] = await connection.execute(
      'SELECT Codigo, Documento, Nome, Ativo FROM tb_Ambientes WHERE Ativo = "S" ORDER BY Nome'
    );
    res.json({ success: true, clientes: clientes });
  } catch (error) {
    console.error(`Erro ao buscar clientes no ERP (${req.ambiente.banco_dados}):`, error);
    res.status(500).json({ error: 'Erro ao buscar clientes.' });
  } finally {
    connection.release();
  }
});

// Rota para buscar formas de pagamento (apenas para ClienteApp)
app.get('/api/sync/send-formas-pagamento', authenticateEnvironment, async (req, res) => {
  if (!req.isClienteSync) {
    return res.status(403).json({ error: 'Acesso negado: Esta rota é exclusiva para ClienteApp.' });
  }
  const connection = await req.pool.getConnection();
  try {
    // Assumindo uma tabela tb_FormasPagamento com colunas Codigo, forma_pagamento, Ativo
    const [formas] = await connection.execute(
      'SELECT Codigo, forma_pagamento, Ativo FROM tb_FormasPagamento WHERE Ativo = "S" ORDER BY forma_pagamento'
    );
    res.json({ success: true, formas: formas });
  } catch (error) {
    console.error(`Erro ao buscar formas de pagamento no ERP (${req.ambiente.banco_dados}):`, error);
    res.status(500).json({ error: 'Erro ao buscar formas de pagamento.' });
  } finally {
    connection.release();
  }
});

// Rota para buscar comandas (apenas para ClienteApp)
app.get('/api/sync/send-comandas', authenticateEnvironment, async (req, res) => {
  if (!req.isClienteSync) {
    return res.status(403).json({ error: 'Acesso negado: Esta rota é exclusiva para ClienteApp.' });
  }
  const connection = await req.pool.getConnection();
  try {
    // Assumindo uma tabela tb_Comandas com colunas Codigo, comanda, Ativo
    const [comandas] = await connection.execute(
      'SELECT Codigo, comanda, Ativo FROM tb_Comandas WHERE Ativo = "S" ORDER BY comanda'
    );
    res.json({ success: true, comandas: comandas });
  } catch (error) {
    console.error(`Erro ao buscar comandas no ERP (${req.ambiente.banco_dados}):`, error);
    res.status(500).json({ error: 'Erro ao buscar comandas.' });
  } finally {
    connection.release();
  }
});

// Rota para receber pedidos do MentorWeb (ClienteApp envia para seu ERP)
app.post('/api/sync/receive-pedidos', authenticateEnvironment, async (req, res) => {
  if (!req.isClienteSync) {
    return res.status(403).json({ error: 'Acesso negado: Esta rota é exclusiva para ClienteApp.' });
  }

  const connection = await req.pool.getConnection(); 
  
  try {
    await connection.beginTransaction();

    const { pedidos } = req.body; 
    const processedOrders = [];

    for (const pedido of pedidos) {
      // Inserir o pedido principal na tabela de pedidos (tb_Pedidos)
      const [resultPedido] = await connection.execute(
        'INSERT INTO tb_Pedidos (data_hora_lancamento, id_ambiente, valor_total, status, id_pedido_sistema_externo) VALUES (?, ?, ?, ?, ?)',
        [
          new Date(`${pedido.data}T${pedido.hora}`).toISOString().slice(0, 19).replace('T', ' '), // Formato DATETIME
          pedido.id_cliente, // Corresponde ao ID_Ambiente
          pedido.total_produtos,
          'pendente', // Status inicial
          pedido.id_pedido_mentorweb // ID do pedido vindo do MentorWeb
        ]
      );
      const pedidoId = resultPedido.insertId;

      // Inserir os itens do pedido na tabela tb_Pedidos_Produtos
      for (const item of pedido.itens) {
        await connection.execute(
          'INSERT INTO tb_Pedidos_Produtos (id_pedido, id_produto, quantidade, preco_unitario, valor_total, identificador_cliente_item) VALUES (?, ?, ?, ?, ?, ?)',
          [
            pedidoId,
            item.id_produto,
            item.quantidade,
            item.unitario,
            item.total_produto,
            item.identificador_cliente_item || 0 // Usar 0 ou outro valor padrão se não fornecido
          ]
        );
      }
      processedOrders.push({
        id_pedido_mentorweb: pedido.id_pedido_mentorweb,
        codigo_pedido_erp: pedidoId, // O ID gerado pelo seu ERP
        status: 'processado'
      });
    }

    await connection.commit();
    res.json({ success: true, pedidos_inseridos: processedOrders });

  } catch (error) {
    await connection.rollback();
    console.error(`Erro ao receber pedidos no ERP (${req.ambiente.banco_dados}):`, error);
    res.status(500).json({ 
      error: 'Erro ao receber pedidos.',
      details: error.message
    });
  } finally {
    connection.release();
  }
});

// =========================================================
// ROTAS PARA SINCRONIZAÇÃO ESPECÍFICA DO FORNECEDORAPP
// =========================================================

// Rota para buscar produtos do FornecedorApp (AGORA APONTA PARA SEND-PRODUTOS GERAL)
// Mantida por compatibilidade, mas o endpoint geral /api/sync/send-produtos é o preferencial
app.get('/api/sync/send-produtos-fornecedor', authenticateEnvironment, async (req, res) => {
  if (!req.isFornecedorSync) {
    return res.status(403).json({ error: 'Acesso negado: Esta rota é exclusiva para FornecedorApp.' });
  }

  const connection = await req.pool.getConnection();
  try {
    // Usando os novos nomes de colunas: id, nome, preco_unitario
    const [produtos] = await connection.execute(
      'SELECT id, nome, preco_unitario FROM tb_Produtos ORDER BY nome'
    );
    res.json({ success: true, produtos: produtos });
  } catch (error) {
    console.error(`Erro ao buscar produtos no ERP do Fornecedor (${req.ambiente.banco_dados}):`, error);
    res.status(500).json({ error: 'Erro ao buscar produtos do Fornecedor.' });
  } finally {
    connection.release();
  }
});


// Rota para receber pedidos do ClienteApp (FornecedorApp recebe do ClienteApp)
app.post('/api/sync/receive-pedido-fornecedor', authenticateEnvironment, async (req, res) => {
  if (!req.isFornecedorSync) {
    return res.status(403).json({ error: 'Acesso negado: Esta rota é exclusiva para FornecedorApp.' });
  }

  const connection = await req.pool.getConnection();
  try {
    await connection.beginTransaction();

    const { cliente, produtos, total_pedido, data_pedido } = req.body; // 'cliente' é o nome do cliente que fez o pedido

    // Inserir o pedido principal na tabela tb_Pedidos do Fornecedor
    const [resultPedido] = await connection.execute(
      'INSERT INTO tb_Pedidos (data_hora_lancamento, id_ambiente, valor_total, status) VALUES (?, ?, ?, ?)',
      [
        data_pedido, // data_pedido já deve vir no formato DATETIME
        null, // id_ambiente pode ser null ou mapear para um ID interno do fornecedor se houver necessidade
        total_pedido,
        'recebido' // Status inicial para pedidos de fornecedor
      ]
    );
    const pedidoId = resultPedido.insertId;

    // Inserir os itens do pedido na tabela tb_Pedidos_Produtos
    for (const item of produtos) {
      await connection.execute(
        'INSERT INTO tb_Pedidos_Produtos (id_pedido, id_produto, quantidade, preco_unitario, valor_total, identificador_cliente_item) VALUES (?, ?, ?, ?, ?, ?)',
        [
          pedidoId,
          item.id_produto,
          item.quantidade,
          item.valor_unitario,
          item.total_produto,
          cliente // O nome do cliente agora vai para identificador_cliente_item
        ]
      );
    }

    await connection.commit();
    res.json({ success: true, codigo_pedido: pedidoId, status: 'recebido' });

  } catch (error) {
    await connection.rollback();
    console.error(`Erro ao receber pedido de fornecedor no ERP (${req.ambiente.banco_dados}):`, error);
    res.status(500).json({ 
      error: 'Erro ao receber pedido de fornecedor.',
      details: error.message
    });
  } finally {
    connection.release();
  }
});



// Iniciar o servidor
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
  console.log(`Acesse o health check em http://localhost:${PORT}/health`);
});
