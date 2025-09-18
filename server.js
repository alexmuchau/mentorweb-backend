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
    // Para ClienteApp, as credenciais são verificadas na tabela tb_ambientes
    // Usamos 'Documento' do header 'cnpj' e 'usuario' do header 'usuario'
    const [rows] = await pool.execute(
      'SELECT * FROM tb_ambientes WHERE Documento = ? AND usuario = ? AND Senha = ? AND Ativo = "S"',
      [cnpj, usuario, senha] // Note: 'banco_dados' não é usado na query SQL para tb_ambientes
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

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    version: '2.1.0' 
  });
});

// =========================================================
// ROTAS PARA SINCRONIZAÇÃO DE CLIENTEAPP (banco muchaucom_mentor - tabelas minúsculas)
// =========================================================

// Rota para enviar produtos para o MentorWeb (ClienteApp)
app.get('/api/sync/send-produtos', authenticateEnvironment, async (req, res) => {
  if (!req.isClienteSync) {
    return res.status(403).json({ error: 'Acesso negado: Esta rota é exclusiva para ClienteApp.' });
  }

  try {
    const [rows] = await req.pool.execute(
      'SELECT id, nome, preco_unitario FROM tb_produtos ORDER BY nome'
    );

    res.json({
      success: true,
      data: rows.map(row => ({
        codigo: row.id,
        produto: row.nome,
        preco_venda: parseFloat(row.preco_unitario),
        estoque: 100, // Valor padrão, ajuste conforme necessário
        codigo_barras: `${row.id}` // Valor padrão, ajuste conforme necessário
      })),
      total: rows.length
    });
  } catch (error) {
    console.error('Erro ao buscar produtos (ClienteApp):', error);
    res.status(500).json({ error: 'Erro interno ao buscar produtos.' });
  }
});

// Rota para enviar clientes para o MentorWeb (ClienteApp)
app.get('/api/sync/send-clientes', authenticateEnvironment, async (req, res) => {
  if (!req.isClienteSync) {
    return res.status(403).json({ error: 'Acesso negado: Esta rota é exclusiva para ClienteApp.' });
  }

  try {
    const [rows] = await req.pool.execute(
      'SELECT Codigo, Nome, Documento FROM tb_ambientes WHERE Ativo = "S" ORDER BY Nome'
    );

    res.json({
      success: true,
      data: rows.map(row => ({
        codigo: row.Codigo,
        nome: row.Nome,
        cnpj: row.Documento,
        cpf: '', // Assumindo que Documento é CNPJ
        ativo: 'S'
      })),
      total: rows.length
    });
  } catch (error) {
    console.error('Erro ao buscar clientes (ClienteApp):', error);
    res.status(500).json({ error: 'Erro interno ao buscar clientes.' });
  }
});

// Rota para enviar formas de pagamento para o MentorWeb (ClienteApp)
app.get('/api/sync/send-formas-pagamento', authenticateEnvironment, async (req, res) => {
  if (!req.isClienteSync) {
    return res.status(403).json({ error: 'Acesso negado: Esta rota é exclusiva para ClienteApp.' });
  }

  try {
    // Como você não tem uma tabela específica de formas de pagamento ainda,
    // vou retornar algumas formas padrão. Ajuste conforme sua necessidade.
    const formasPagamento = [
      { codigo: 1, forma_pagamento: 'Dinheiro', ativo: 'S' },
      { codigo: 2, forma_pagamento: 'Cartão de Crédito', ativo: 'S' },
      { codigo: 3, forma_pagamento: 'Cartão de Débito', ativo: 'S' },
      { codigo: 4, forma_pagamento: 'PIX', ativo: 'S' },
      { codigo: 5, forma_pagamento: 'Transferência', ativo: 'S' }
    ];

    res.json({
      success: true,
      data: formasPagamento,
      total: formasPagamento.length
    });
  } catch (error) {
    console.error('Erro ao buscar formas de pagamento (ClienteApp):', error);
    res.status(500).json({ error: 'Erro interno ao buscar formas de pagamento.' });
  }
});

// Rota para enviar comandas para o MentorWeb (ClienteApp)
app.get('/api/sync/send-comandas', authenticateEnvironment, async (req, res) => {
  if (!req.isClienteSync) {
    return res.status(403).json({ error: 'Acesso negado: Esta rota é exclusiva para ClienteApp.' });
  }

  try {
    // Como você não tem uma tabela específica de comandas ainda,
    // vou retornar algumas comandas padrão. Ajuste conforme sua necessidade.
    const comandas = [
      { codigo: 1, comanda: 'Mesa 1', ativo: 'S' },
      { codigo: 2, comanda: 'Mesa 2', ativo: 'S' },
      { codigo: 3, comanda: 'Mesa 3', ativo: 'S' },
      { codigo: 4, comanda: 'Balcão', ativo: 'S' },
      { codigo: 5, comanda: 'Delivery', ativo: 'S' }
    ];

    res.json({
      success: true,
      data: comandas,
      total: comandas.length
    });
  } catch (error) {
    console.error('Erro ao buscar comandas (ClienteApp):', error);
    res.status(500).json({ error: 'Erro interno ao buscar comandas.' });
  }
});

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
      const [insertResult] = await connection.execute(
        'INSERT INTO tb_pedidos (data_hora_lancamento, id_ambiente, valor_total, status) VALUES (?, ?, ?, ?)',
        [
          new Date().toISOString().slice(0, 19).replace('T', ' '), // data_hora_lancamento formatada para MySQL
          pedido.id_cliente || req.ambiente.Codigo, // id_ambiente
          pedido.total_produtos, // valor_total
          'pendente' // status
        ]
      );

      const pedidoId = insertResult.insertId; // ID do pedido recém-inserido

      // Insere os produtos/itens do pedido
      for (const item of pedido.produtos) {
        await connection.execute(
          'INSERT INTO tb_pedidos_produtos (id_pedido, id_produto, quantidade, preco_unitario, valor_total, identificador_cliente_item) VALUES (?, ?, ?, ?, ?, ?)',
          [
            pedidoId, // id_pedido
            item.id_produto, // id_produto
            item.quantidade, // quantidade
            item.unitario, // preco_unitario
            item.total_produto, // valor_total
            item.cliente || 1 // identificador_cliente_item (padrão 1 se não especificado)
          ]
        );
      }

      // Marca o pedido como processado
      await connection.execute(
        'UPDATE tb_pedidos SET status = ?, id_pedido_sistema_externo = ? WHERE id = ?',
        ['processado', pedidoId, pedidoId]
      );

      processedOrders.push({
        id_pedido_original: pedido.id,
        id_pedido_erp: pedidoId,
        status: 'processado',
        data_processamento: new Date().toISOString()
      });
    }

    await connection.commit(); // Confirma a transação

    res.json({
      success: true,
      message: 'Pedidos processados com sucesso',
      pedidos_processados: processedOrders
    });

  } catch (error) {
    await connection.rollback(); // Reverte a transação em caso de erro
    console.error('Erro ao processar pedidos (ClienteApp):', error);
    res.status(500).json({ error: 'Erro interno ao processar pedidos.' });
  } finally {
    connection.release(); // Libera a conexão de volta para o pool
  }
});

// =========================================================
// ROTAS PARA SINCRONIZAÇÃO DE FORNECEDORAPP (banco muchaucom_pisciNew - tabelas maiúsculas)
// =========================================================

// Rota para enviar produtos do fornecedor para o MentorWeb (FornecedorApp)
app.get('/api/sync/send-produtos-fornecedor', authenticateEnvironment, async (req, res) => {
  if (!req.isFornecedorSync) {
    return res.status(403).json({ error: 'Acesso negado: Esta rota é exclusiva para FornecedorApp.' });
  }

  try {
    const [rows] = await req.pool.execute(
      'SELECT id, nome, preco_unitario FROM tb_Produtos ORDER BY nome'
    );

    res.json({
      success: true,
      data: rows.map(row => ({
        codigo: row.id,
        produto: row.nome,
        preco_venda: parseFloat(row.preco_unitario),
        estoque: 999, // Valor padrão para fornecedor, ajuste conforme necessário
        codigo_barras: `FORN_${row.id}` // Valor padrão, ajuste conforme necessário
      })),
      total: rows.length
    });
  } catch (error) {
    console.error('Erro ao buscar produtos do fornecedor (FornecedorApp):', error);
    res.status(500).json({ error: 'Erro interno ao buscar produtos do fornecedor.' });
  }
});

// Rota para receber pedidos do MentorWeb direcionados ao fornecedor (FornecedorApp)
app.post('/api/sync/receive-pedido-fornecedor', authenticateEnvironment, async (req, res) => {
  if (!req.isFornecedorSync) {
    return res.status(403).json({ error: 'Acesso negado: Esta rota é exclusiva para FornecedorApp.' });
  }

  const connection = await req.pool.getConnection(); // Obtém uma conexão do pool

  try {
    await connection.beginTransaction(); // Inicia uma transação para garantir atomicidade

    const { produtos, total_pedido, data_pedido, cliente } = req.body; // Pega os dados do pedido do corpo da requisição

    // Insere o pedido principal na tabela de pedidos do fornecedor
    const [insertResult] = await connection.execute(
      'INSERT INTO tb_Pedidos (data_hora_lancamento, id_ambiente, valor_total, status) VALUES (?, ?, ?, ?)',
      [
        data_pedido || new Date().toISOString().slice(0, 19).replace('T', ' '), // data_hora_lancamento
        1, // id_ambiente padrão para fornecedor, ajuste conforme necessário
        total_pedido, // valor_total
        'pendente' // status
      ]
    );

    const pedidoId = insertResult.insertId; // ID do pedido recém-inserido

    // Insere os produtos/itens do pedido do fornecedor
    for (const produto of produtos) {
      await connection.execute(
        'INSERT INTO tb_Pedidos_Produtos (id_pedido, id_produto, quantidade, preco_unitario, valor_total, identificador_cliente_item) VALUES (?, ?, ?, ?, ?, ?)',
        [
          pedidoId, // id_pedido
          produto.id_produto, // id_produto
          produto.quantidade, // quantidade
          produto.valor_unitario, // preco_unitario
          produto.total_produto, // valor_total
          1 // identificador_cliente_item padrão
        ]
      );
    }

    // Marca o pedido como processado
    await connection.execute(
      'UPDATE tb_Pedidos SET status = ?, id_pedido_sistema_externo = ? WHERE id = ?',
      ['processado', pedidoId, pedidoId]
    );

    await connection.commit(); // Confirma a transação

    res.json({
      success: true,
      message: 'Pedido do fornecedor processado com sucesso',
      codigo_pedido: pedidoId,
      data_processamento: new Date().toISOString()
    });

  } catch (error) {
    await connection.rollback(); // Reverte a transação em caso de erro
    console.error('Erro ao processar pedido do fornecedor (FornecedorApp):', error);
    res.status(500).json({ error: 'Erro interno ao processar pedido do fornecedor.' });
  } finally {
    connection.release(); // Libera a conexão de volta para o pool
  }
});

// =========================================================
// MIDDLEWARE DE TRATAMENTO DE ERROS GLOBAIS
// =========================================================

// Middleware global de tratamento de erros
app.use((err, req, res, next) => {
  console.error('Erro não tratado:', err);
  res.status(500).json({ 
    error: 'Erro interno do servidor', 
    message: err.message 
  });
});

// Middleware para rotas não encontradas (404)
app.use('*', (req, res) => {
  res.status(404).json({ 
    error: 'Rota não encontrada',
    path: req.originalUrl,
    method: req.method 
  });
});

// =========================================================
// INICIALIZAÇÃO DO SERVIDOR
// =========================================================

app.listen(PORT, () => {
  console.log(`🚀 Servidor ERP rodando na porta ${PORT}`);
  console.log(`📍 Health check disponível em: http://localhost:${PORT}/health`);
  console.log(`🔗 API base URL: http://localhost:${PORT}/api`);
});

// Tratamento de saída limpa do processo
process.on('SIGINT', () => {
  console.log('🛑 Servidor sendo encerrado...');
  // Fechar todas as conexões do pool
  connections.forEach((pool, database) => {
    pool.end();
    console.log(`📱 Pool de conexão fechado para banco: ${database}`);
  });
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('🛑 Servidor sendo encerrado (SIGTERM)...');
  // Fechar todas as conexões do pool
  connections.forEach((pool, database) => {
    pool.end();
    console.log(`📱 Pool de conexão fechado para banco: ${database}`);
  });
  process.exit(0);
});
