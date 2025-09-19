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
    if (usuario === 'mentorweb_fornecedor' && senha === 'mentorweb_sync_forn_2024') {
      try {
        // Testar a conexão para verificar se o banco do fornecedor é acessível
        await pool.query('SELECT 1'); // Executa uma query simples
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
        // Se a conexão falhar, o banco do fornecedor não é válido
        console.error(`Falha ao conectar ao banco de dados do fornecedor ${banco_dados}:`, error);
        return res.status(401).json({ 
          error: `Credenciais de FornecedorApp inválidas ou banco de dados '${banco_dados}' inacessível.` 
        });
      }
    }

    // --- Lógica para ClienteApp (verificação em tb_ambientes) ---
    // Para ClienteApp, as credenciais são verificadas na tabela tb_ambientes (minúscula)
    const [rows] = await pool.execute(
      'SELECT * FROM tb_ambientes WHERE Documento = ? AND usuario = ? AND Senha = ? AND Ativo = "S"',
      [cnpj, usuario, senha] 
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
// ROTAS PARA SINCRONIZAÇÃO DE CLIENTEAPP
// As rotas foram renomeadas para 'send-X' para corresponder ao erpSync do frontend
// =========================================================

// Rota para receber pedidos do MentorWeb (ClienteApp envia para seu ERP)
app.post('/api/sync/receive-pedidos', authenticateEnvironment, async (req, res) => {
  if (!req.isClienteSync) {
    return res.status(403).json({ error: 'Acesso negado: Esta rota é exclusiva para ClienteApp.' });
  }

  const connection = await req.pool.getConnection(); // Obtém uma conexão do pool
  
  try {
    await connection.beginTransaction(); // Inicia uma transação para garantir atomicidade

    const { pedidos } = req.body; // Pega os pedidos do corpo da requisição
    const processedOrders = []; // Para armazenar o status dos pedidos processados

    for (const pedido of pedidos) {
      // Insere o pedido principal na tabela de pedidos
      const [pedidoResult] = await connection.execute(
        `INSERT INTO tb_pedidos (data_hora_lancamento, id_ambiente, valor_total, status, id_pedido_sistema_externo)
         VALUES (?, ?, ?, ?, ?)`,
        [
          new Date(pedido.data + 'T' + pedido.hora).toISOString().slice(0, 19).replace('T', ' '), // Combina data e hora, formata para DATETIME MySQL
          pedido.id_cliente, // Supondo que id_cliente é o id_ambiente
          pedido.total_produtos,
          pedido.status,
          pedido.id_lcto_erp || null // Pode ser nulo se não houver ID do ERP ainda
        ]
      );

      const pedidoId = pedidoResult.insertId; // Obtém o ID do pedido inserido

      // Insere os itens do pedido
      for (const item of pedido.itens) {
        await connection.execute(
          `INSERT INTO tb_pedidos_produtos (id_pedido, id_produto, quantidade, preco_unitario, valor_total, identificador_cliente_item)
           VALUES (?, ?, ?, ?, ?, ?)`,
          [
            pedidoId,
            item.id_produto,
            item.quantidade,
            item.unitario,
            item.total_produto,
            item.identificador_cliente_item // Assumindo que este campo virá do frontend
          ]
        );
      }
      processedOrders.push({ id_pedido_mentorweb: pedido.id_pedido_mentorweb, codigo: pedidoId, success: true });
    }

    await connection.commit(); // Confirma a transação
    res.json({ success: true, message: 'Pedidos recebidos e processados com sucesso!', pedidos_inseridos: processedOrders });

  } catch (error) {
    await connection.rollback(); // Desfaz a transação em caso de erro
    console.error('Erro ao receber pedidos:', error);
    res.status(500).json({ success: false, error: 'Erro ao processar pedidos.', details: error.message });
  } finally {
    connection.release(); // Libera a conexão de volta para o pool
  }
});

// Rota para obter produtos do ERP (ClienteApp busca)
app.get('/api/sync/send-produtos', authenticateEnvironment, async (req, res) => {
  if (!req.isClienteSync) {
    return res.status(403).json({ error: 'Acesso negado: Esta rota é exclusiva para ClienteApp.' });
  }

  const connection = await req.pool.getConnection();
  try {
    const [rows] = await connection.execute('SELECT id, nome, preco_unitario FROM tb_produtos WHERE ativo = "S"'); // Supondo coluna 'ativo'
    res.json({ success: true, produtos: rows });
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
    return res.status(403).json({ error: 'Acesso negado: Esta rota é exclusiva para ClienteApp.' });
  }

  const connection = await req.pool.getConnection();
  try {
    const [rows] = await connection.execute('SELECT Codigo, Documento AS cnpj, Documento AS cpf, Nome AS nome, Ativo AS ativo FROM tb_ambientes WHERE Ativo = "S"');
    res.json({ success: true, clientes: rows });
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
    return res.status(403).json({ error: 'Acesso negado: Esta rota é exclusiva para ClienteApp.' });
  }

  const connection = await req.pool.getConnection();
  try {
    // Ajuste aqui para o nome real da sua tabela de formas de pagamento no muchaucom_mentor
    const [rows] = await connection.execute('SELECT id AS codigo, nome AS forma_pagamento, ativo FROM tb_formapagamento WHERE ativo = "S"'); // Supondo tb_formapagamento
    res.json({ success: true, formas: rows });
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
    return res.status(403).json({ error: 'Acesso negado: Esta rota é exclusiva para ClienteApp.' });
  }

  const connection = await req.pool.getConnection();
  try {
    // Ajuste aqui para o nome real da sua tabela de comandas no muchaucom_mentor
    const [rows] = await connection.execute('SELECT id AS codigo, nome AS comanda, ativo FROM tb_comandas WHERE ativo = "S"'); // Supondo tb_comandas
    res.json({ success: true, comandas: rows });
  } catch (error) {
    console.error('Erro ao buscar comandas:', error);
    res.status(500).json({ success: false, error: 'Erro ao buscar comandas.', details: error.message });
  } finally {
    connection.release();
  }
});

// =========================================================
// ROTAS PARA SINCRONIZAÇÃO DE FORNECEDORAPP
// =========================================================

// Rota para obter produtos do ERP do fornecedor
app.get('/api/sync/send-produtos-fornecedor', authenticateEnvironment, async (req, res) => {
  if (!req.isFornecedorSync) {
    return res.status(403).json({ error: 'Acesso negado: Esta rota é exclusiva para FornecedorApp.' });
  }

  const connection = await req.pool.getConnection();
  try {
    // Consulta para tb_Produtos (com 'P' maiúsculo) no banco do fornecedor
    // As colunas são id, nome, preco_unitario
    const [rows] = await connection.execute('SELECT id, nome AS produto, preco_unitario FROM tb_Produtos'); 
    res.json({ success: true, produtos: rows });
  } catch (error) {
    console.error('Erro ao buscar produtos do fornecedor:', error);
    res.status(500).json({ success: false, error: 'Erro ao buscar produtos do fornecedor.', details: error.message });
  } finally {
    connection.release();
  }
});

// Rota para receber pedidos do MentorWeb para o ERP do fornecedor
app.post('/api/sync/receive-pedido-fornecedor', authenticateEnvironment, async (req, res) => {
  if (!req.isFornecedorSync) {
    return res.status(403).json({ error: 'Acesso negado: Esta rota é exclusiva para FornecedorApp.' });
  }

  const connection = await req.pool.getConnection();
  
  try {
    await connection.beginTransaction(); // Inicia uma transação

    const { produtos, total_pedido, data_pedido, cliente } = req.body;

    // 1. Inserir na tb_Pedidos (cabeçalho)
    const [pedidoResult] = await connection.execute(
      `INSERT INTO tb_Pedidos (data_hora_lancamento, id_ambiente, valor_total, status)
       VALUES (?, ?, ?, ?)`,
      [
        new Date(data_pedido).toISOString().slice(0, 19).replace('T', ' '), // Formato DATETIME
        req.ambiente.Codigo || 0, // ID do ambiente do fornecedor (verificar se Codigo é o correto)
        total_pedido,
        'pendente' // Status inicial do pedido no ERP do fornecedor
      ]
    );
    const pedidoId = pedidoResult.insertId;

    // 2. Inserir na tb_Pedidos_Produtos (itens)
    for (const produto of produtos) {
      await connection.execute(
        `INSERT INTO tb_Pedidos_Produtos (id_pedido, id_produto, quantidade, preco_unitario, valor_total, identificador_cliente_item)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [
          pedidoId,
          produto.id_produto,
          produto.quantidade,
          produto.valor_unitario,
          produto.total_produto,
          cliente // O identificador_cliente_item aqui é o nome do cliente que vem do erpSync
        ]
      );
    }

    await connection.commit(); // Confirma a transação
    res.json({ success: true, message: 'Pedido recebido com sucesso!', codigo_pedido: pedidoId });

  } catch (error) {
    await connection.rollback(); // Desfaz a transação
    console.error('Erro ao receber pedido do fornecedor:', error);
    res.status(500).json({ success: false, error: 'Erro ao processar pedido do fornecedor.', details: error.message });
  } finally {
    connection.release();
  }
});

// =========================================================
// INICIA O SERVIDOR
// =========================================================
app.listen(PORT, () => {
  console.log(`Servidor Node.js rodando na porta ${PORT}`);
  console.log(`Health check disponível em http://localhost:${PORT}/health`);
});
