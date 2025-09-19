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

    // --- Lógica para ClienteApp (verificação em tb_ambientes - nomes de tabelas em minúsculas) ---
    // Para ClienteApp, as credenciais são verificadas em uma tabela de ambientes
    const [rows] = await pool.execute(
      // Usamos os nomes de colunas conforme o CREATE TABLE fornecido, e o nome da tabela em minúsculas
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
    version: '2.2.0' // Versão atualizada do servidor
  });
});

// =========================================================
// ROTAS PARA SINCRONIZAÇÃO DE CLIENTEAPP (muchaucom_mentor - tabelas em minúsculas)
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
      // Supondo que a tabela seja 'tb_pedidos' e os campos correspondam ao seu modelo
      const [pedidoResult] = await connection.execute(
        `INSERT INTO tb_pedidos (data_hora_lancamento, id_ambiente, valor_total, status, id_pedido_sistema_externo)
         VALUES (?, ?, ?, ?, ?)`,
        [
          `${pedido.data} ${pedido.hora}`, // Combina data e hora para DATETIME
          pedido.id_cliente, // Corresponde a id_ambiente
          pedido.total_produtos, // Corresponde a valor_total
          pedido.status,
          pedido.id_lcto_erp || null // Pode ser nulo se não houver ID externo ainda
        ]
      );

      const id_pedido_inserido = pedidoResult.insertId;

      for (const item of pedido.itens) {
        // Supondo que a tabela seja 'tb_pedidos_produtos'
        await connection.execute(
          `INSERT INTO tb_pedidos_produtos (id_pedido, id_produto, quantidade, preco_unitario, valor_total, identificador_cliente_item)
           VALUES (?, ?, ?, ?, ?, ?)`,
          [
            id_pedido_inserido,
            item.id_produto,
            item.quantidade,
            item.unitario, // Corresponde a preco_unitario
            item.total_produto, // Corresponde a valor_total
            item.identificador_cliente_item || null // Novo campo, pode ser nulo se não preenchido
          ]
        );
      }
      processedOrders.push({ id_pedido_mentorweb: pedido.id_pedido_mentorweb, codigo: id_pedido_inserido });
    }

    await connection.commit(); // Confirma a transação
    res.json({ success: true, pedidos_inseridos: processedOrders });
  } catch (error) {
    await connection.rollback(); // Desfaz a transação em caso de erro
    console.error('Erro ao receber pedidos do ClienteApp:', error);
    res.status(500).json({ error: 'Erro ao processar pedidos.' });
  } finally {
    if (connection) connection.release(); // Libera a conexão
  }
});

// Rota para buscar produtos do ClienteApp
app.get('/api/sync/get_produtos', authenticateEnvironment, async (req, res) => {
  if (!req.isClienteSync) {
    return res.status(403).json({ error: 'Acesso negado: Esta rota é exclusiva para ClienteApp.' });
  }
  const connection = await req.pool.getConnection();
  try {
    // Usando os nomes de colunas originais para compatibilidade com o frontend NovaVenda.js/Produtos.js
    const [rows] = await connection.execute(
      'SELECT Codigo, Produto, Unitario, Ativo FROM tb_produtos WHERE Ativo = "S" ORDER BY Produto'
    );
    // Mapeia os nomes das colunas do DB para o formato esperado pelo frontend
    const produtosFormatados = rows.map(row => ({
      codigo: row.Codigo,
      produto: row.Produto,
      preco_venda: row.Unitario, // Renomeado para preco_venda
      ativo: row.Ativo
    }));
    res.json({ success: true, produtos: produtosFormatados });
  } catch (error) {
    console.error('Erro ao buscar produtos para ClienteApp:', error);
    res.status(500).json({ error: 'Erro ao buscar produtos.' });
  } finally {
    if (connection) connection.release();
  }
});

// Rota para buscar clientes do ClienteApp
app.get('/api/sync/get_clientes', authenticateEnvironment, async (req, res) => {
  if (!req.isClienteSync) {
    return res.status(403).json({ error: 'Acesso negado: Esta rota é exclusiva para ClienteApp.' });
  }
  const connection = await req.pool.getConnection();
  try {
    // Supondo que a tabela tb_ambientes seja a fonte de clientes do ERP
    const [rows] = await connection.execute(
      'SELECT Codigo, Nome, Documento, Ativo FROM tb_ambientes WHERE Ativo = "S" ORDER BY Nome'
    );
    const clientesFormatados = rows.map(row => ({
      codigo: row.Codigo,
      nome: row.Nome,
      cnpj: row.Documento.length === 14 ? row.Documento : null, // Assume CNPJ se tiver 14 dígitos
      cpf: row.Documento.length === 11 ? row.Documento : null,   // Assume CPF se tiver 11 dígitos
      ativo: row.Ativo
    }));
    res.json({ success: true, clientes: clientesFormatados });
  } catch (error) {
    console.error('Erro ao buscar clientes para ClienteApp:', error);
    res.status(500).json({ error: 'Erro ao buscar clientes.' });
  } finally {
    if (connection) connection.release();
  }
});

// Rota para buscar formas de pagamento do ClienteApp
app.get('/api/sync/get_formas_pagamento', authenticateEnvironment, async (req, res) => {
  if (!req.isClienteSync) {
    return res.status(403).json({ error: 'Acesso negado: Esta rota é exclusiva para ClienteApp.' });
  }
  const connection = await req.pool.getConnection();
  try {
    // Assumindo que o nome da tabela é 'tb_FormaPagamento' com campos 'Codigo', 'Forma_Pagamento', 'Ativo'
    const [rows] = await connection.execute(
      'SELECT Codigo, Forma_Pagamento, Ativo FROM tb_formapagamento WHERE Ativo = "S" ORDER BY Forma_Pagamento'
    );
    const formasFormatadas = rows.map(row => ({
      codigo: row.Codigo,
      forma_pagamento: row.Forma_Pagamento,
      ativo: row.Ativo
    }));
    res.json({ success: true, formas: formasFormatadas });
  } catch (error) {
    console.error('Erro ao buscar formas de pagamento para ClienteApp:', error);
    res.status(500).json({ error: 'Erro ao buscar formas de pagamento.' });
  } finally {
    if (connection) connection.release();
  }
});

// Rota para buscar comandas do ClienteApp
app.get('/api/sync/get_comandas', authenticateEnvironment, async (req, res) => {
  if (!req.isClienteSync) {
    return res.status(403).json({ error: 'Acesso negado: Esta rota é exclusiva para ClienteApp.' });
  }
  const connection = await req.pool.getConnection();
  try {
    // Assumindo que o nome da tabela é 'tb_Comandas' com campos 'Codigo', 'Comanda', 'Ativo'
    const [rows] = await connection.execute(
      'SELECT Codigo, Comanda, Ativo FROM tb_comandas WHERE Ativo = "S" ORDER BY Comanda'
    );
    const comandasFormatadas = rows.map(row => ({
      codigo: row.Codigo,
      comanda: row.Comanda,
      ativo: row.Ativo
    }));
    res.json({ success: true, comandas: comandasFormatadas });
  } catch (error) {
    console.error('Erro ao buscar comandas para ClienteApp:', error);
    res.status(500).json({ error: 'Erro ao buscar comandas.' });
  } finally {
    if (connection) connection.release();
  }
});


// =========================================================
// ROTAS PARA SINCRONIZAÇÃO DE FORNECEDORAPP (muchaucom_pisciNew - tabelas em maiúsculas)
// =========================================================

// Rota para buscar produtos do FornecedorApp (usado na página PedidosFornecedor)
app.get('/api/sync/send-produtos-fornecedor', authenticateEnvironment, async (req, res) => {
  if (!req.isFornecedorSync) {
    return res.status(403).json({ error: 'Acesso negado: Esta rota é exclusiva para FornecedorApp.' });
  }
  const connection = await req.pool.getConnection();
  try {
    // Usando os novos nomes de colunas: id, nome, preco_unitario
    const [rows] = await connection.execute(
      'SELECT id, nome, preco_unitario FROM tb_Produtos' // Removido 'WHERE Ativo = "S"' pois não há 'Ativo' em tb_Produtos
    );
    const produtosFormatados = rows.map(row => ({
      codigo: row.id, // Mapeia id do DB para codigo esperado pelo frontend
      produto: row.nome,
      preco_venda: row.preco_unitario, // Mapeia preco_unitario do DB para preco_venda
      // Não há estoque nem codigo_barras nesta tabela, caso precise, adicione ao schema e query
    }));
    res.json({ success: true, produtos: produtosFormatados });
  } catch (error) {
    console.error('Erro ao buscar produtos para FornecedorApp:', error);
    res.status(500).json({ error: 'Erro ao buscar produtos para fornecedor.' });
  } finally {
    if (connection) connection.release();
  }
});

// Rota para receber pedidos de cliente para o ERP do FornecedorApp
app.post('/api/sync/receive-pedido-fornecedor', authenticateEnvironment, async (req, res) => {
  if (!req.isFornecedorSync) {
    return res.status(403).json({ error: 'Acesso negado: Esta rota é exclusiva para FornecedorApp.' });
  }

  const connection = await req.pool.getConnection();
  
  try {
    await connection.beginTransaction();

    const { produtos, total_pedido, data_pedido, cliente: clienteNome } = req.body;

    // Inserir na tabela de cabeçalho de pedidos do fornecedor
    // A tabela tb_Pedidos do fornecedor usa id_ambiente, valor_total, data_hora_lancamento, status, id_pedido_sistema_externo
    const [pedidoResult] = await connection.execute(
      `INSERT INTO tb_Pedidos (data_hora_lancamento, id_ambiente, valor_total, status)
       VALUES (?, ?, ?, ?)`,
      [
        data_pedido, // data_pedido já deve vir em formato DATETIME ou string compatível
        // id_ambiente: Aqui precisamos de um ID de ambiente válido.
        // Assumindo que 'clienteNome' pode ser o 'Nome' ou 'Documento' em tb_Ambientes
        // e que precisamos encontrar o 'Codigo' correspondente.
        // Para simplificar agora, vamos usar um ID fixo ou um placeholder,
        // mas em produção isso precisaria de uma busca ou um ID passado na requisição.
        1, // <<=== PLACEHOLDER: Usar um ID_Ambiente real ou buscar pelo clienteNome
        total_pedido,
        'processado' // Status inicial do pedido no ERP do fornecedor
      ]
    );

    const id_pedido_inserido = pedidoResult.insertId;

    for (const produtoItem of produtos) {
      // Inserir na tabela de itens de pedido do fornecedor
      // tb_Pedidos_Produtos: id_pedido, id_produto, quantidade, preco_unitario, valor_total, identificador_cliente_item
      await connection.execute(
        `INSERT INTO tb_Pedidos_Produtos (id_pedido, id_produto, quantidade, preco_unitario, valor_total, identificador_cliente_item)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [
          id_pedido_inserido,
          produtoItem.id_produto,
          produtoItem.quantidade,
          produtoItem.valor_unitario,
          produtoItem.total_produto,
          // identificador_cliente_item: Se 'clienteNome' for o identificador, usá-lo ou um ID numérico.
          // Para simplificar agora, vamos usar um placeholder.
          1 // <<=== PLACEHOLDER: Usar o identificador de cliente real para o item
        ]
      );
    }

    await connection.commit();
    res.json({ success: true, codigo_pedido: id_pedido_inserido });
  } catch (error) {
    await connection.rollback();
    console.error('Erro ao receber pedido para FornecedorApp:', error);
    res.status(500).json({ error: 'Erro ao processar pedido para fornecedor.' });
  } finally {
    if (connection) connection.release();
  }
});


// Inicia o servidor
app.listen(PORT, () => {
  console.log(`Servidor Node.js rodando na porta ${PORT}`);
  console.log(`Acesse http://localhost:${PORT}/health para verificar o status.`);
});
