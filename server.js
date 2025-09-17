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
app.use(helmet());          // Proteções básicas de segurança HTTPssss
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
    // Para ClienteApp, as credenciais são verificadas em uma tabela de ambientes
    const [rows] = await pool.execute(
      'SELECT * FROM tb_ambientes WHERE cnpj = ? AND usuario = ? AND senha = ? AND banco_dados = ? AND ativo = "S"',
      [cnpj, usuario, senha, banco_dados]
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
// ROTAS PARA SINCRONIZAÇÃO DE CLIENTEAPP (EXISTENTES)
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
      // Insere o pedido principal na tabela de pedidos do ERP do cliente
      const [pedidoResult] = await connection.execute(`
        INSERT INTO tb_pedidos (
          data, hora, id_cliente, id_forma_pagamento, 
          id_local_retirada, total_produtos, status, 
          data_sync, origem
        ) VALUES (?, ?, ?, ?, ?, ?, 'recebido', NOW(), 'mentorweb')
      `, [
        pedido.data,
        pedido.hora,
        pedido.id_cliente,
        pedido.id_forma_pagamento,
        pedido.id_local_retirada || null, // Permite nulo
        pedido.total_produtos
      ]);

      const pedidoErpId = pedidoResult.insertId; // ID gerado pelo ERP

      // Insere os itens do pedido na tabela de produtos do pedido
      for (const item of pedido.itens) {
        await connection.execute(`
          INSERT INTO tb_pedidos_produtos (
            id_pedido_erp, id_produto, quantidade, 
            unitario, total_produto, data_sync
          ) VALUES (?, ?, ?, ?, ?, NOW())
        `, [
          pedidoErpId,
          item.id_produto,
          item.quantidade,
          item.unitario,
          item.total_produto
        ]);
      }

      processedOrders.push({
        mentorweb_id: pedido.id,    // ID do pedido no MentorWeb
        erp_id: pedidoErpId,        // ID do pedido gerado no ERP
        status: 'processado'
      });
    }

    await connection.commit(); // Confirma a transação se tudo deu certo

    res.json({
      success: true,
      message: `${processedOrders.length} pedidos processados com sucesso no ERP do Cliente.`,
      pedidos_processados: processedOrders,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    await connection.rollback(); // Desfaz a transação em caso de erro
    console.error('Erro ao processar pedidos do MentorWeb no ERP do Cliente:', error);
    res.status(500).json({ 
      error: 'Erro ao processar pedidos no ERP do Cliente.', 
      details: error.message 
    });
  } finally {
    connection.release(); // Libera a conexão de volta para o pool
  }
});

// Rota para enviar clientes do ERP para MentorWeb
app.get('/api/sync/send-clientes', authenticateEnvironment, async (req, res) => {
  if (!req.isClienteSync) {
    return res.status(403).json({ error: 'Acesso negado: Esta rota é exclusiva para ClienteApp.' });
  }
  try {
    const [clientes] = await req.pool.execute(`
      SELECT codigo, nome, cnpj, cpf, ativo 
      FROM tb_clientes 
      WHERE ativo = 'S'
      ORDER BY nome
    `);

    res.json({
      success: true,
      clientes: clientes, // Retorna como 'clientes' para consistência com o frontend
      total: clientes.length,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Erro ao buscar clientes no ERP do Cliente:', error);
    res.status(500).json({ error: 'Erro ao buscar clientes no ERP do Cliente.', details: error.message });
  }
});

// Rota para enviar produtos do ERP para MentorWeb
app.get('/api/sync/send-produtos', authenticateEnvironment, async (req, res) => {
  if (!req.isClienteSync) {
    return res.status(403).json({ error: 'Acesso negado: Esta rota é exclusiva para ClienteApp.' });
  }
  try {
    const [produtos] = await req.pool.execute(`
      SELECT codigo, produto, codigo_barras, preco_venda, estoque, ativo 
      FROM tb_produtos 
      WHERE ativo = 'S'
      ORDER BY produto
    `);

    res.json({
      success: true,
      produtos: produtos, // Retorna como 'produtos'
      total: produtos.length,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Erro ao buscar produtos no ERP do Cliente:', error);
    res.status(500).json({ error: 'Erro ao buscar produtos no ERP do Cliente.', details: error.message });
  }
});

// Rota para enviar formas de pagamento do ERP para MentorWeb
app.get('/api/sync/send-formas-pagamento', authenticateEnvironment, async (req, res) => {
  if (!req.isClienteSync) {
    return res.status(403).json({ error: 'Acesso negado: Esta rota é exclusiva para ClienteApp.' });
  }
  try {
    const [formas] = await req.pool.execute(`
      SELECT codigo, forma_pagamento, ativo 
      FROM tb_formas_pagamento 
      WHERE ativo = 'S'
      ORDER BY forma_pagamento
    `);

    res.json({
      success: true,
      formas: formas, // Retorna como 'formas'
      total: formas.length,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Erro ao buscar formas de pagamento no ERP do Cliente:', error);
    res.status(500).json({ error: 'Erro ao buscar formas de pagamento no ERP do Cliente.', details: error.message });
  }
});

// Rota para enviar comandas do ERP para MentorWeb
app.get('/api/sync/send-comandas', authenticateEnvironment, async (req, res) => {
  if (!req.isClienteSync) {
    return res.status(403).json({ error: 'Acesso negado: Esta rota é exclusiva para ClienteApp.' });
  }
  try {
    const [comandas] = await req.pool.execute(`
      SELECT codigo, comanda, ativo 
      FROM tb_comandas 
      WHERE ativo = 'S'
      ORDER BY comanda
    `);

    res.json({
      success: true,
      comandas: comandas, // Retorna como 'comandas'
      total: comandas.length,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Erro ao buscar comandas no ERP do Cliente:', error);
    res.status(500).json({ error: 'Erro ao buscar comandas no ERP do Cliente.', details: error.message });
  }
});


// =========================================================
// ROTAS PARA SINCRONIZAÇÃO DE FORNECEDORAPP (NOVAS)
// =========================================================

// Rota para enviar produtos do Fornecedor para o MentorWeb (ClienteApp busca produtos do Fornecedor)
app.get('/api/sync/send-produtos-fornecedor', authenticateEnvironment, async (req, res) => {
  if (!req.isFornecedorSync) {
    return res.status(403).json({ error: 'Acesso negado: Esta rota é exclusiva para FornecedorApp.' });
  }

  try {
    const [produtos] = await req.pool.execute(`
      SELECT Codigo, Produto, Unitario
      FROM tb_produtos 
      WHERE Ativo = 'S' -- Assumindo que a tabela tb_produtos do fornecedor tem um campo 'Ativo'
      ORDER BY Produto
    `);

    res.json({
      success: true,
      produtos: produtos, // Retorna como 'produtos'
      total: produtos.length,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error(`Erro ao buscar produtos no ERP do Fornecedor (${req.ambiente.banco_dados}):`, error);
    res.status(500).json({ error: 'Erro ao buscar produtos no ERP do Fornecedor.', details: error.message });
  }
});

// Rota para receber pedidos do MentorWeb para o FornecedorApp
app.post('/api/sync/receive-pedido-fornecedor', authenticateEnvironment, async (req, res) => {
  if (!req.isFornecedorSync) {
    return res.status(403).json({ error: 'Acesso negado: Esta rota é exclusiva para FornecedorApp.' });
  }

  const connection = await req.pool.getConnection();
  try {
    await connection.beginTransaction();

    const { data_lancamento, hora, total, itens, cliente } = req.body; // 'cliente' é o nome do ClienteApp que fez o pedido

    // 1. Inserir o pedido principal na tb_Pedidos do fornecedor
    const [pedidoResult] = await connection.execute(`
      INSERT INTO tb_pedidos (
        Data_Lancamento, Hora, Total, Processado, Id_Pedido_Sistema
      ) VALUES (?, ?, ?, ?, ?)
    `, [
      data_lancamento,
      hora,
      total,
      1, // Marca como processado = 1 (ou o valor que indicar processado no seu ERP)
      // Id_Pedido_Sistema: Será o ID do PedidoFornecedor da Base44, se o MentorWeb enviasse.
      // Por enquanto, vamos deixar NULL ou um valor default se não for recebido.
      // Ou, se o seu ERP gerar, pode ser o Codigo gerado aqui.
      null // O MentorWeb precisa do Código gerado aqui para marcar lá como Id_Pedido_Sistema
    ]);

    const pedidoFornecedorCodigo = pedidoResult.insertId; // Codigo do pedido gerado no ERP do fornecedor

    // 2. Inserir os itens do pedido na tb_Pedidos_Produtos do fornecedor
    for (const item of itens) {
      await connection.execute(`
        INSERT INTO tb_pedidos_produtos (
          Id_Pedido, Id_Produto, Quantidade, Unitario, Total, Cliente
        ) VALUES (?, ?, ?, ?, ?, ?)
      `, [
        pedidoFornecedorCodigo,
        item.id_produto,
        item.quantidade,
        item.unitario,
        item.total,
        cliente // Nome do cliente que fez o pedido
      ]);
    }

    await connection.commit(); // Confirma a transação

    res.json({
      success: true,
      message: `Pedido #${pedidoFornecedorCodigo} recebido e processado pelo Fornecedor.`,
      id_pedido_criado: pedidoFornecedorCodigo, // Retorna o ID gerado pelo fornecedor
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    await connection.rollback(); // Desfaz a transação
    console.error(`Erro ao processar pedido para Fornecedor (${req.ambiente.banco_dados}):`, error);
    res.status(500).json({ 
      error: 'Erro ao processar pedido no ERP do Fornecedor.', 
      details: error.message 
    });
  } finally {
    connection.release(); // Libera a conexão
  }
});


// Rotas para listar pedidos do fornecedor (opcional, se MentorWeb precisar consultar)
app.get('/api/sync/list-pedidos-fornecedor', authenticateEnvironment, async (req, res) => {
  if (!req.isFornecedorSync) {
    return res.status(403).json({ error: 'Acesso negado: Esta rota é exclusiva para FornecedorApp.' });
  }

  try {
    const [pedidos] = await req.pool.execute(`
      SELECT Codigo, Data_Lancamento, Hora, Total, Processado, Id_Pedido_Sistema
      FROM tb_pedidos
      ORDER BY Data_Lancamento DESC, Hora DESC
    `);

    res.json({
      success: true,
      pedidos: pedidos,
      total: pedidos.length,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error(`Erro ao listar pedidos no ERP do Fornecedor (${req.ambiente.banco_dados}):`, error);
    res.status(500).json({ error: 'Erro ao listar pedidos no ERP do Fornecedor.', details: error.message });
  }
});


// =========================================================
// INÍCIO DO SERVIDOR
// =========================================================

app.listen(PORT, () => {
  console.log(`Servidor Node.js rodando na porta ${PORT}`);
  console.log(`Origins permitidas: ${allowedOrigins.join(', ')}`);
});
