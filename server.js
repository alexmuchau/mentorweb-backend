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

    // Limpa o CNPJ para autenticação de ClienteApp, pois o BD armazena sem formatação para eles
    // Apenas aplica se não for o usuário de sincronização do fornecedor, para evitar conflitos
    let cnpj_cleaned = cnpj; // Assume que o CNPJ pode já vir limpo ou será limpo mais tarde
    if (!(usuario === SUPPLIER_SYNC_USER && senha === SUPPLIER_SYNC_PASS)) {
        cnpj_cleaned = cnpj.replace(/\D/g, ''); // Limpa o CNPJ apenas para usuários normais
    }

    // CASO 1: Autenticação para ClienteApp (via headers cnpj, usuario, senha, banco_dados)
    // Para clientes, assumimos que o CNPJ no DB está limpo (sem formatação)
    const [clientRows] = await req.pool.execute(
      'SELECT Codigo as Codigo, Nome as Nome, Senha as Senha, Ativo as Ativo FROM tb_Ambientes_Fornecedor WHERE Documento = ? AND usuario = ? AND Senha = ? AND Ativo = "S"',
      [cnpj_cleaned, usuario, senha]
    );

    if (clientRows.length > 0) {
      req.isClientAppAuth = true;
      req.environment = clientRows[0]; // Stores the found environment data
      console.log('Ambiente autenticado como Cliente App. Ambiente:', req.environment.Nome);
    } 
    // CASO 2: Autenticação para Fornecedor (via headers cnpj, usuario, senha, banco_dados)
    // Verifica se é o usuário de sincronização específico do MentorWeb para fornecedores
    else if (usuario === SUPPLIER_SYNC_USER && senha === SUPPLIER_SYNC_PASS) {
      // Para o usuário de sincronização do fornecedor, usamos o CNPJ do HEADER DIRETAMENTE
      // porque o DB tb_Ambientes_Fornecedor.Documento armazena o CNPJ FORMATADO.
      const [supplierRows] = await req.pool.execute(
        'SELECT * FROM tb_Ambientes_Fornecedor WHERE Documento = ? AND Ativo = "S"', 
        [cnpj] // Usa o CNPJ do header sem limpar
      ); 
      
      if (supplierRows.length > 0) {
        req.isSupplierAuth = true;
        req.environment = supplierRows[0]; // Stores the found environment data
        console.log('Ambiente autenticado como Fornecedor Sync. Ambiente:', req.environment.Nome);
      } else {
        console.log('Credenciais de sincronização de fornecedor inválidas: CNPJ não encontrado ou inativo:', cnpj);
        return res.status(401).json({ success: false, error: 'Credenciais de sincronização de fornecedor inválidas (CNPJ não encontrado ou inativo).' });
      }
    }
    else {
      // Se não autenticou como cliente App nem como Fornecedor Sync
      console.log('Credenciais de ambiente inválidas: Usuário, senha ou CNPJ incorretos ou inativos.');
      return res.status(401).json({ error: 'Credenciais de ambiente inválidas (Usuário, senha ou CNPJ incorretos ou inativos).' });
    }

    next(); // Continua para a próxima middleware/rota se autenticado
  } catch (error) {
    console.error('Erro na autenticação do ambiente:', error);
    res.status(500).json({ error: 'Erro interno do servidor durante a autenticação', details: error.message });
  }
};

// Rotas de sincronização
app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'ok', message: 'Servidor ERP está online.' });
});

// Middleware de autenticação aplicado a todas as rotas de sincronização
app.use('/api/sync', authenticateEnvironment);

// Rota para autenticar usuário fornecedor (login)
app.post('/api/sync/authenticate-fornecedor-user', async (req, res) => {
  const { cnpj_cpf, usuario, senha } = req.body;
  const banco_dados_header = req.headers.banco_dados; // Obtém do header, já que o middleware já setou o pool

  if (!cnpj_cpf || !usuario || !senha || !banco_dados_header) {
      return res.status(400).json({ success: false, error: 'Documento, usuário, senha e banco de dados são obrigatórios para autenticação.' });
  }

  const connection = await req.pool.getConnection(); // Usa o pool já estabelecido pelo middleware
  try {
      // Limpa o CNPJ/CPF do corpo da requisição para comparação no DB
      const cnpj_cpf_cleaned = cnpj_cpf.replace(/\D/g, ''); 
      
      // Assumimos que tb_Ambientes_Fornecedor.Documento armazena CNPJ/CPF limpo para esta autenticação
      // Se tb_Ambientes_Fornecedor.Documento armazena formatado, remova o .replace(/\D/g, '') acima
      const [userRows] = await connection.execute(
          'SELECT Codigo as ID_Pessoa, Documento as Documento, Nome as Nome, usuario as usuario, Senha as Senha, Ativo as Ativo FROM tb_Ambientes_Fornecedor WHERE Documento = ? AND usuario = ? AND Senha = ? AND Ativo = "S"', 
          [cnpj_cpf_cleaned, usuario, senha]
      );

      if (userRows.length > 0) {
          const user = userRows[0];
          res.json({
              success: true,
              user: {
                  ID_Pessoa: user.ID_Pessoa,
                  Documento: user.Documento,
                  Nome: user.Nome,
                  usuario: user.usuario,
                  Ativo: user.Ativo,
                  // Adicionar id_ambiente_erp e nome_ambiente se aplicável para o usuário
                  id_ambiente_erp: user.Codigo, // Usar o Codigo da tabela tb_Ambientes_Fornecedor
                  nome_ambiente: user.Nome // Usar o Nome da tabela tb_Ambientes_Fornecedor
              }
          });
      } else {
          res.status(401).json({ success: false, error: 'Usuário, senha ou documento inválido, ou usuário inativo.' });
      }
  } catch (error) {
      console.error('Erro na autenticação do usuário fornecedor:', error);
      res.status(500).json({ success: false, error: 'Erro interno do servidor durante a autenticação.' });
  } finally {
      connection.release();
  }
});


// Rota para enviar produtos do cliente para o MentorWeb
app.get('/api/sync/send-produtos', authenticateEnvironment, async (req, res) => {
  if (!req.isClientAppAuth) {
    return res.status(403).json({ 
      error: 'Acesso negado', 
      details: 'Esta rota é exclusiva para aplicativos cliente.' 
    });
  }

  const connection = await req.pool.getConnection();
  try {
    const [rows] = await connection.execute(
      'SELECT codigo, produto, codigo_barras, preco_venda, estoque, ativo FROM tb_produtos WHERE ativo = "S" ORDER BY produto'
    );
    res.json({ success: true, produtos: rows, total: rows.length });
  } catch (error) {
    console.error('Erro ao buscar produtos:', error);
    res.status(500).json({ error: 'Erro interno do servidor ao buscar produtos.', details: error.message });
  } finally {
    connection.release();
  }
});

// Rota para enviar clientes do cliente para o MentorWeb
app.get('/api/sync/send-clientes', authenticateEnvironment, async (req, res) => {
  if (!req.isClientAppAuth) {
    return res.status(403).json({ 
      error: 'Acesso negado', 
      details: 'Esta rota é exclusiva para aplicativos cliente.' 
    });
  }

  const connection = await req.pool.getConnection();
  try {
    const [rows] = await connection.execute(
      'SELECT codigo, nome, cnpj, cpf, ativo FROM tb_clientes WHERE ativo = "S" ORDER BY nome'
    );
    res.json({ success: true, clientes: rows, total: rows.length });
  } catch (error) {
    console.error('Erro ao buscar clientes:', error);
    res.status(500).json({ error: 'Erro interno do servidor ao buscar clientes.', details: error.message });
  } finally {
    connection.release();
  }
});

// Rota para enviar formas de pagamento do cliente para o MentorWeb
app.get('/api/sync/send-formas-pagamento', authenticateEnvironment, async (req, res) => {
  if (!req.isClientAppAuth) {
    return res.status(403).json({ 
      error: 'Acesso negado', 
      details: 'Esta rota é exclusiva para aplicativos cliente.' 
    });
  }

  const connection = await req.pool.getConnection();
  try {
    const [rows] = await connection.execute(
      'SELECT codigo, forma_pagamento, ativo FROM tb_forma_pagamento WHERE ativo = "S" ORDER BY forma_pagamento'
    );
    res.json({ success: true, formas: rows, total: rows.length });
  } catch (error) {
    console.error('Erro ao buscar formas de pagamento:', error);
    res.status(500).json({ error: 'Erro interno do servidor ao buscar formas de pagamento.', details: error.message });
  } finally {
    connection.release();
  }
});

// Rota para enviar comandas do cliente para o MentorWeb
app.get('/api/sync/send-comandas', authenticateEnvironment, async (req, res) => {
  if (!req.isClientAppAuth) {
    return res.status(403).json({ 
      error: 'Acesso negado', 
      details: 'Esta rota é exclusiva para aplicativos cliente.' 
    });
  }

  const connection = await req.pool.getConnection();
  try {
    const [rows] = await connection.execute(
      'SELECT codigo, comanda, ativo FROM tb_comanda WHERE ativo = "S" ORDER BY comanda'
    );
    res.json({ success: true, comandas: rows, total: rows.length });
  } catch (error) {
    console.error('Erro ao buscar comandas:', error);
    res.status(500).json({ error: 'Erro interno do servidor ao buscar comandas.', details: error.message });
  } finally {
    connection.release();
  }
});

// Rota para receber pedidos do MentorWeb (cliente)
app.post('/api/sync/receive-pedidos', authenticateEnvironment, async (req, res) => {
  if (!req.isClientAppAuth) {
    return res.status(403).json({ 
      error: 'Acesso negado', 
      details: 'Esta rota é exclusiva para aplicativos cliente.' 
    });
  }

  const { pedidos } = req.body;

  if (!pedidos || !Array.isArray(pedidos) || pedidos.length === 0) {
    return res.status(400).json({ error: 'Dados de pedidos incompletos ou inválidos.' });
  }

  const connection = await req.pool.getConnection();
  try {
    await connection.beginTransaction();

    const pedidos_inseridos = [];

    for (const pedido of pedidos) {
      const { id_pedido_mentorweb, data, hora, id_cliente, id_forma_pagamento, id_local_retirada, total_produtos, itens } = pedido;

      // Inserir pedido principal
      const [resultPedido] = await connection.execute(
        'INSERT INTO tb_pedidos (data, hora, id_cliente, id_forma_pagamento, id_local_retirada, total_produtos, status) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [data, hora, id_cliente, id_forma_pagamento, id_local_retirada, total_produtos, 'processando']
      );
      const newPedidoId = resultPedido.insertId;

      // Inserir itens do pedido
      for (const item of itens) {
        await connection.execute(
          'INSERT INTO tb_pedidos_produtos (id_pedido, id_produto, quantidade, unitario, total_produto) VALUES (?, ?, ?, ?, ?)',
          [newPedidoId, item.id_produto, item.quantidade, item.unitario, item.total_produto]
        );
      }
      pedidos_inseridos.push({ id_pedido_mentorweb, id_pedido_erp: newPedidoId });
    }

    await connection.commit();
    res.json({ success: true, message: 'Pedidos recebidos e processados com sucesso!', pedidos_inseridos });

  } catch (error) {
    await connection.rollback();
    console.error('Erro ao processar pedidos:', error);
    res.status(500).json({ error: 'Erro interno do servidor ao processar pedidos.', details: error.message });
  } finally {
    connection.release();
  }
});

// Rota para enviar produtos do fornecedor para o MentorWeb (usado pelo usuário fornecedor)
app.get('/api/sync/send-produtos-fornecedor', authenticateEnvironment, async (req, res) => {
  if (!req.isSupplierAuth) {
    return res.status(403).json({ 
      error: 'Acesso negado', 
      details: 'Esta rota é exclusiva para autenticação de fornecedor.' 
    });
  }

  const connection = await req.pool.getConnection();
  try {
    console.log('Buscando produtos do fornecedor...');
    
    // CORREÇÃO: Ajuste a query para a sua tabela tb_Produtos_Fornecedor
    // e os aliases para corresponder ao que o frontend espera.
    const [rows] = await connection.execute(
      `SELECT 
        id as id,
        nome as produto,
        preco_unitario,
        Ativo as ativo
      FROM tb_Produtos_Fornecedor 
      WHERE Ativo = 'S'
      ORDER BY nome`
    );

    console.log(`Encontrados ${rows.length} produtos do fornecedor.`);

    const produtos = rows.map(row => ({
      id: row.id,
      produto: row.produto, // Aliased from 'nome'
      preco_venda: parseFloat(row.preco_unitario) || 0, // Frontend espera preco_venda
      // Se tiver estoque ou codigo_barras na tb_Produtos_Fornecedor, adicione aqui
      estoque: null, // Ou o campo correto do seu DB
      codigo_barras: null // Ou o campo correto do seu DB
    }));

    res.json({
      success: true,
      produtos: produtos,
      total: produtos.length
    });

  } catch (error) {
    console.error('Erro ao buscar produtos do fornecedor:', error);
    res.status(500).json({ 
      error: 'Erro interno do servidor', 
      details: error.message 
    });
  } finally {
    connection.release();
  }
});

// Rota para receber pedidos para fornecedor (usado por cliente ou usuário fornecedor)
app.post('/api/sync/receive-pedido-fornecedor', authenticateEnvironment, async (req, res) => {
  if (!req.isSupplierAuth) { // Esta rota deve ser autenticada como Fornecedor Sync
    return res.status(403).json({ 
      error: 'Acesso negado', 
      details: 'Esta rota é exclusiva para autenticação de fornecedor.' 
    });
  }

  const { produtos, total_pedido, data_pedido, cliente_nome, cliente_cnpj } = req.body;
  
  // CORREÇÃO: A variável 'cliente' agora aponta para o nome do cliente que fez o pedido
  const cliente = cliente_nome; 

  console.log('Dados recebidos para receive-pedido-fornecedor:', {
    produtos_count: produtos ? produtos.length : 0,
    total_pedido, data_pedido, cliente_nome, cliente_cnpj
  });

  if (!produtos || !Array.isArray(produtos) || produtos.length === 0 || total_pedido === undefined || cliente === undefined) {
    return res.status(400).json({ error: 'Dados do pedido para fornecedor incompletos (produtos, total_pedido, cliente são obrigatórios).' });
  }

  const connection = await req.pool.getConnection();
  try {
    await connection.beginTransaction();

    // Encontrar o id_ambiente (ID do cliente) pelo CNPJ
    // Remove qualquer formatação do CNPJ antes de buscar no banco
    const cliente_cnpj_cleaned = cliente_cnpj.replace(/\D/g, ''); 
    const [ambienteRows] = await connection.execute(
      'SELECT Codigo FROM tb_Ambientes_Fornecedor WHERE Documento = ? AND Ativo = "S"', 
      [cliente_cnpj_cleaned]
    );

    const idAmbienteCliente = ambienteRows.length > 0 ? ambienteRows[0].Codigo : null;
    
    if (!idAmbienteCliente) {
      throw new Error(`CNPJ do cliente/ambiente '${cliente_cnpj}' não encontrado ou inativo no banco de dados do fornecedor.`);
    }

    // Inserir pedido principal na tb_Pedidos_Fornecedor
    // A coluna id_ambiente agora recebe o Codigo do ambiente do CLIENTE
    const [resultPedido] = await connection.execute(
      'INSERT INTO tb_Pedidos_Fornecedor (data_hora_lancamento, id_ambiente, valor_total, status, cliente_origem) VALUES (NOW(), ?, ?, ?, ?)',
      [idAmbienteCliente, total_pedido, 'recebido', cliente_nome] // 'recebido' ou outro status inicial
    );
    const newPedidoId = resultPedido.insertId;

    // Inserir itens do pedido na tb_Pedidos_Produtos_Fornecedor
    for (const item of produtos) {
      await connection.execute(
        'INSERT INTO tb_Pedidos_Produtos_Fornecedor (id_pedido, id_produto, quantidade, preco_unitario, valor_total) VALUES (?, ?, ?, ?, ?)',
        [newPedidoId, item.id_produto, item.quantidade, item.valor_unitario, item.total_produto]
      );
    }

    await connection.commit();
    res.json({ success: true, message: 'Pedido para fornecedor recebido e processado com sucesso!', codigo_pedido: newPedidoId });

  } catch (error) {
    await connection.rollback();
    console.error('Erro ao processar pedido para fornecedor:', error);
    res.status(500).json({ error: 'Erro interno do servidor ao processar pedido para fornecedor.', details: error.message });
  } finally {
    connection.release();
  }
});

// Inicia o servidor
app.listen(PORT, () => {
  console.log(`Servidor de sincronização ERP rodando na porta ${PORT}`);
});
