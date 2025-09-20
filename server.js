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

    // **NOVO** Lógica para lidar com a rota de autenticação de usuário fornecedor
    // Para esta rota específica, o CNPJ no header é o CNPJ do usuário individual, não do ambiente do fornecedor.
    if (req.path === '/api/sync/authenticate-fornecedor-user') {
      if (usuario === SUPPLIER_SYNC_USER && senha === SUPPLIER_SYNC_PASS) {
        req.isSupplierAuth = true;
        // Não precisamos de dados de ambiente específicos aqui, apenas a conexão e permissão
        console.log('Permitindo acesso para autenticação de usuário fornecedor individual.');
        return next(); 
      } else {
        console.warn('Credenciais de sincronização de fornecedor inválidas para autenticação de usuário:', usuario);
        return res.status(401).json({ error: 'Credenciais de sincronização de fornecedor inválidas para login de usuário.' });
      }
    }

    // // ORIGINAL: Limpa o CNPJ para autenticação de ClienteApp, pois o BD armazena sem formatação para eles
    // // Apenas aplica se não for o usuário de sincronização do fornecedor, para evitar conflitos
    let cnpj_cleaned = cnpj.replace(/\D/g, ''); // Limpa o CNPJ para ClienteApp, Fornecedor Sync espera formatado

    // CASO 2: Autenticação para Fornecedor Sync (via headers cnpj, usuario, senha) - Prioritário agora
    if (usuario === SUPPLIER_SYNC_USER && senha === SUPPLIER_SYNC_PASS) {
      // Para Fornecedor Sync, o CNPJ no DB (tb_Ambientes_Fornecedor) pode estar com ou sem formatação.
      // Usaremos o CNPJ como veio no header, pois a tabela Documento o armazena formatado.
      const [supplierSyncEnvRows] = await req.pool.execute(
        'SELECT Codigo FROM tb_Ambientes_Fornecedor WHERE Documento = ? AND Usuario = ? AND Senha = ? AND Ativo = "S"',
        [cnpj, SUPPLIER_SYNC_USER, SUPPLIER_SYNC_PASS] 
      );

      if (supplierSyncEnvRows.length > 0) {
        req.isSupplierAuth = true;
        req.environment = supplierSyncEnvRows[0];
        console.log('Ambiente autenticado como Fornecedor Sync. Ambiente:', req.environment.Codigo);
      } else {
        console.warn('Credenciais de sincronização de fornecedor inválidas (CNPJ não encontrado ou inativo):', cnpj);
        return res.status(401).json({ error: 'Credenciais de sincronização de fornecedor inválidas (CNPJ não encontrado ou inativo).', cnpj: cnpj });
      }
    }
    // CASO 1: Autenticação para ClienteApp (via headers cnpj, usuario, senha, banco_dados)
    // Se não for um usuário de sincronização de fornecedor, tenta como ClienteApp
    else { 
      const [clientRows] = await req.pool.execute(
        'SELECT Codigo as Codigo, Nome as Nome, Senha as Senha, Ativo as Ativo FROM tb_ambientes WHERE Documento = ? AND usuario = ? AND Senha = ? AND Ativo = "S"',
        [cnpj_cleaned, usuario, senha]
      );

      if (clientRows.length > 0) {
        req.isClientAppAuth = true;
        req.environment = clientRows[0]; 
        console.log('Ambiente autenticado como Cliente App. Ambiente:', req.environment.Nome);
      } else {
        console.warn('Autenticação de Cliente App falhou:', cnpj);
        return res.status(401).json({ error: 'Credenciais de Cliente App inválidas.' });
      }
    }
    
    next(); // Continua para a próxima middleware/rota se autenticado
  } catch (error) {
    console.error('Erro na autenticação do ambiente:', error);
    // Erro comum será falha ao obter pool de conexão, por exemplo
    res.status(500).json({ error: 'Erro interno do servidor durante a autenticação', details: error.message });
  } finally {
    // A conexão não deve ser liberada aqui, pois as rotas usarão req.pool
  }
};

// Rotas de API
app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'ok', message: 'Servidor MentorWeb está ativo.' });
});

// Todas as rotas de sincronização utilizam o middleware de autenticação
app.use('/api/sync', authenticateEnvironment);

// Rota para autenticar usuário fornecedor (chamada pelo MentorWeb no login)
app.post('/api/sync/authenticate-fornecedor-user', async (req, res) => {
  // A autenticação do ambiente (banco_dados e credenciais mentorweb_fornecedor) já foi feita no middleware
  // req.pool agora está disponível e autenticado para acesso ao banco do FornecedorApp
  if (!req.isSupplierAuth) {
    return res.status(403).json({ 
      error: 'Acesso negado', 
      details: 'Esta rota é exclusiva para autenticação de sistema de fornecedor.' 
    });
  }

  const { cnpj_cpf, usuario, senha, banco_dados } = req.body; // Dados do usuário individual a ser autenticado

  if (!cnpj_cpf || !usuario || !senha || !banco_dados) {
    return res.status(400).json({ success: false, error: 'Documento, usuário, senha e banco de dados são obrigatórios.' });
  }

  const connection = await req.pool.getConnection();
  try {
    console.log('Autenticando usuário fornecedor no ERP...');
    // Ajuste a query conforme sua estrutura de tabelas de usuário no ERP do fornecedor
    // Use `Documento` sem limpeza se ele estiver formatado no seu DB (como no caso tb_Ambientes_Fornecedor)
    // Se o Documento estiver sem formatação, aplique cnpj_cpf.replace(/\D/g, '')
    const [rows] = await connection.execute(
      `SELECT 
        ID_Pessoa, 
        Documento, 
        Nome, 
        Usuario, 
        Senha, 
        ID_Ambiente_ERP, 
        Nome_Ambiente, 
        Ativo 
      FROM tb_Pessoas 
      WHERE Documento = ? AND Usuario = ? AND Senha = ? AND Ativo = "S"`,
      [cnpj_cpf, usuario, senha] // Use cnpj_cpf diretamente se Documento for formatado no DB
    );

    if (rows.length > 0) {
      const user = rows[0];
      res.json({
        success: true,
        user: {
          ID_Pessoa: user.ID_Pessoa,
          Documento: user.Documento,
          Nome: user.Nome,
          usuario: user.Usuario,
          Ativo: user.Ativo,
          id_ambiente_erp: user.ID_Ambiente_ERP,
          nome_ambiente: user.Nome_Ambiente
        }
      });
    } else {
      res.status(401).json({ success: false, error: 'Usuário ou senha inválidos no ERP do fornecedor.' });
    }

  } catch (error) {
    console.error('Erro ao autenticar usuário fornecedor:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Erro interno do servidor ao autenticar usuário fornecedor', 
      details: error.message 
    });
  } finally {
    connection.release();
  }
});


// Rota para enviar produtos do ERP para o MentorWeb (ClienteApp)
app.get('/api/sync/send-produtos', async (req, res) => {
  if (!req.isClientAppAuth) {
    return res.status(403).json({ 
      error: 'Acesso negado', 
      details: 'Esta rota é exclusiva para autenticação de cliente.' 
    });
  }

  const connection = await req.pool.getConnection();
  try {
    console.log('Buscando produtos para cliente...');
    
    // Buscar produtos ativos - ajuste conforme sua estrutura de tabelas
    const [rows] = await connection.execute(
      `SELECT 
        codigo as codigo,
        produto as produto,
        codigo_barras,
        preco_venda,
        estoque,
        ativo
      FROM tb_Produtos 
      WHERE ativo = 'S'
      ORDER BY produto`
    );

    console.log(`Encontrados ${rows.length} produtos.`);

    const produtos = rows.map(row => ({
      codigo: row.codigo,
      produto: row.produto,
      codigo_barras: row.codigo_barras || '',
      preco_venda: parseFloat(row.preco_venda) || 0,
      estoque: parseInt(row.estoque) || 0,
      ativo: row.ativo
    }));

    res.json({
      success: true,
      produtos: produtos,
      total: produtos.length
    });

  } catch (error) {
    console.error('Erro ao buscar produtos:', error);
    res.status(500).json({ 
      error: 'Erro interno do servidor', 
      details: error.message 
    });
  } finally {
    connection.release();
  }
});

// Rota para enviar clientes do ERP para o MentorWeb (ClienteApp)
app.get('/api/sync/send-clientes', async (req, res) => {
  if (!req.isClientAppAuth) {
    return res.status(403).json({ 
      error: 'Acesso negado', 
      details: 'Esta rota é exclusiva para autenticação de cliente.' 
    });
  }
  const connection = await req.pool.getConnection();
  try {
    console.log('Buscando clientes para cliente...');
    const [rows] = await connection.execute(
      `SELECT 
        codigo as codigo, 
        nome as nome, 
        cnpj, 
        cpf, 
        ativo 
      FROM tb_Clientes 
      WHERE ativo = 'S' 
      ORDER BY nome`
    );
    console.log(`Encontrados ${rows.length} clientes.`);
    const clientes = rows.map(row => ({
      codigo: row.codigo,
      nome: row.nome,
      cnpj: row.cnpj || '',
      cpf: row.cpf || '',
      ativo: row.ativo
    }));
    res.json({ success: true, clientes: clientes, total: clientes.length });
  } catch (error) {
    console.error('Erro ao buscar clientes:', error);
    res.status(500).json({ success: false, error: 'Erro interno do servidor', details: error.message });
  } finally {
    connection.release();
  }
});

// Rota para enviar formas de pagamento do ERP para o MentorWeb (ClienteApp)
app.get('/api/sync/send-formas-pagamento', async (req, res) => {
  if (!req.isClientAppAuth) {
    return res.status(403).json({ 
      error: 'Acesso negado', 
      details: 'Esta rota é exclusiva para autenticação de cliente.' 
    });
  }
  const connection = await req.pool.getConnection();
  try {
    console.log('Buscando formas de pagamento para cliente...');
    const [rows] = await connection.execute(
      `SELECT 
        codigo as codigo, 
        forma_pagamento as forma, 
        ativo 
      FROM tb_FormasPagamento 
      WHERE ativo = 'S' 
      ORDER BY forma_pagamento`
    );
    console.log(`Encontradas ${rows.length} formas de pagamento.`);
    const formas = rows.map(row => ({
      codigo: row.codigo,
      forma_pagamento: row.forma,
      ativo: row.ativo
    }));
    res.json({ success: true, formas: formas, total: formas.length });
  } catch (error) {
    console.error('Erro ao buscar formas de pagamento:', error);
    res.status(500).json({ success: false, error: 'Erro interno do servidor', details: error.message });
  } finally {
    connection.release();
  }
});

// Rota para enviar comandas do ERP para o MentorWeb (ClienteApp)
app.get('/api/sync/send-comandas', async (req, res) => {
  if (!req.isClientAppAuth) {
    return res.status(403).json({ 
      error: 'Acesso negado', 
      details: 'Esta rota é exclusiva para autenticação de cliente.' 
    });
  }
  const connection = await req.pool.getConnection();
  try {
    console.log('Buscando comandas para cliente...');
    const [rows] = await connection.execute(
      `SELECT 
        codigo as codigo, 
        comanda as comanda, 
        ativo 
      FROM tb_Comandas 
      WHERE ativo = 'S' 
      ORDER BY comanda`
    );
    console.log(`Encontradas ${rows.length} comandas.`);
    const comandas = rows.map(row => ({
      codigo: row.codigo,
      comanda: row.comanda,
      ativo: row.ativo
    }));
    res.json({ success: true, comandas: comandas, total: comandas.length });
  } catch (error) {
    console.error('Erro ao buscar comandas:', error);
    res.status(500).json({ success: false, error: 'Erro interno do servidor', details: error.message });
  } finally {
    connection.release();
  }
});

// Rota para receber pedidos do MentorWeb no ERP (ClienteApp)
app.post('/api/sync/receive-pedidos', async (req, res) => {
  if (!req.isClientAppAuth) {
    return res.status(403).json({ 
      error: 'Acesso negado', 
      details: 'Esta rota é exclusiva para autenticação de cliente.' 
    });
  }
  const connection = await req.pool.getConnection();
  try {
    const pedidosRecebidos = req.body.pedidos;
    const lctoErpList = [];

    for (const pedido of pedidosRecebidos) {
      // Inserir Pedido na tabela tb_Pedidos (ajuste os nomes das colunas e os valores)
      const [pedidoResult] = await connection.execute(
        `INSERT INTO tb_Pedidos (data, hora, id_cliente, id_forma_pagamento, id_local_retirada, total_produtos, status)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [
          pedido.data,
          pedido.hora,
          pedido.id_cliente,
          pedido.id_forma_pagamento,
          pedido.id_local_retirada,
          pedido.total_produtos,
          'pendente' // Status inicial no ERP
        ]
      );
      const idPedidoErp = pedidoResult.insertId;
      lctoErpList.push({ id_pedido_mentorweb: pedido.id_pedido_mentorweb, id_pedido_erp: idPedidoErp });

      // Inserir Itens do Pedido na tabela tb_Pedido_Itens (ajuste os nomes das colunas e os valores)
      for (const item of pedido.itens) {
        await connection.execute(
          `INSERT INTO tb_Pedido_Itens (id_pedido_erp, id_produto, quantidade, unitario, total_produto)
           VALUES (?, ?, ?, ?, ?)`,
          [
            idPedidoErp,
            item.id_produto,
            item.quantidade,
            item.unitario,
            item.total_produto
          ]
        );
      }
    }

    res.status(200).json({ success: true, message: 'Pedidos recebidos e processados.', pedidos_inseridos: lctoErpList });
  } catch (error) {
    console.error('Erro ao receber pedidos:', error);
    res.status(500).json({ success: false, error: 'Erro interno do servidor', details: error.message });
  } finally {
    connection.release();
  }
});

// Rota para enviar produtos do fornecedor para o MentorWeb
app.get('/api/sync/send-produtos-fornecedor', async (req, res) => {
  if (!req.isSupplierAuth) {
    return res.status(403).json({ 
      error: 'Acesso negado', 
      details: 'Esta rota é exclusiva para autenticação de fornecedor.' 
    });
  }

  const connection = await req.pool.getConnection();
  try {
    console.log('Buscando produtos do fornecedor...');
    
    // Buscar produtos ativos do fornecedor
    // Ajuste a query conforme sua estrutura de tabelas
    const [rows] = await connection.execute(
      `SELECT 
        id as id,
        produto as nome,
        codigo_barras,
        preco_venda as preco_unitario,
        estoque
      FROM tb_Produtos 
      WHERE ativo = 'S'
      ORDER BY produto`
    );

    console.log(`Encontrados ${rows.length} produtos do fornecedor.`);

    const produtos = rows.map(row => ({
      id: row.id,
      nome: row.nome,
      codigo_barras: row.codigo_barras || '',
      preco_unitario: parseFloat(row.preco_unitario) || 0,
      estoque: parseInt(row.estoque) || 0
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

// Rota para receber pedidos no ERP do fornecedor
app.post('/api/sync/receive-pedido-fornecedor', async (req, res) => {
  if (!req.isSupplierAuth) {
    return res.status(403).json({ 
      error: 'Acesso negado', 
      details: 'Esta rota é exclusiva para autenticação de fornecedor.' 
    });
  }

  const connection = await req.pool.getConnection();
  try {
    const { produtos, total_pedido, data_pedido, cliente_nome, cliente_cnpj } = req.body;

    console.log(`Recebendo pedido de ${cliente_nome} (${cliente_cnpj}) para o total de R$ ${total_pedido}`);

    // Exemplo de inserção de pedido (ajuste conforme a sua tabela de pedidos de entrada)
    const [pedidoResult] = await connection.execute(
      `INSERT INTO tb_Pedidos_Entrada (data_pedido, total_pedido, cliente_nome, cliente_cnpj, status)
       VALUES (?, ?, ?, ?, ?)`,
      [
        data_pedido,
        total_pedido,
        cliente_nome,
        cliente_cnpj,
        'recebido' // Status inicial no ERP do fornecedor
      ]
    );

    const idPedidoFornecedorErp = pedidoResult.insertId;

    // Exemplo de inserção de itens do pedido (ajuste conforme sua tabela de itens de pedido de entrada)
    for (const item of produtos) {
      await connection.execute(
        `INSERT INTO tb_Pedidos_Entrada_Itens (id_pedido_entrada, id_produto_fornecedor, nome_produto, quantidade, valor_unitario, total_produto)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [
          idPedidoFornecedorErp,
          item.id_produto, // ID do produto no ERP do fornecedor
          item.nome_produto, // Nome do produto para referência
          item.quantidade,
          item.valor_unitario,
          item.total_produto
        ]
      );
    }

    res.status(200).json({ 
      success: true, 
      message: 'Pedido recebido com sucesso no ERP do fornecedor.', 
      codigo_pedido: idPedidoFornecedorErp 
    });

  } catch (error) {
    console.error('Erro ao receber pedido no ERP do fornecedor:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Erro interno do servidor ao receber pedido no fornecedor', 
      details: error.message 
    });
  } finally {
    connection.release();
  }
});


app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
