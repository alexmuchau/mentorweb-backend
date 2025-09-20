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

    // CASO 1: Autenticação para Fornecedor (via headers 'usuario' e 'senha' específicos)
    if (usuario === SUPPLIER_SYNC_USER && senha === SUPPLIER_SYNC_PASS) {
      req.isSupplierAuth = true;
      const connection = await req.pool.getConnection();
      try {
        const cleanedCnpj = cnpj.replace(/\D/g, ''); // Remover formatação
        const [rows] = await connection.execute('SELECT Codigo, Documento, Nome FROM tb_Ambientes_Fornecedor WHERE Documento = ? AND Ativo = \'S\'', [cleanedCnpj]);
        if (rows.length > 0) {
          req.environment = rows[0]; // Armazena os dados do ambiente autenticado
          console.log(`Ambiente autenticado como Fornecedor Sync para CNPJ: ${cnpj}`);
          next();
        } else {
          return res.status(401).json({ success: false, error: 'Credenciais de sincronização de fornecedor inválidas (CNPJ não encontrado ou inativo).' });
        }
      } finally {
        connection.release();
      }
    } 
    // CASO 2: Autenticação para ClienteApp (via headers 'usuario', 'senha' e 'cnpj' do cliente)
    else {
      // Aqui, o 'cnpj' no header é o CNPJ do cliente/empresa do aplicativo
      // O 'usuario' e 'senha' no header são as credenciais do usuário do ERP (não usuário do MentorWeb)
      req.isClientAppAuth = true;
      const connection = await req.pool.getConnection();
      try {
        // Assume-se que 'usuario' e 'senha' nos headers são do usuário do ERP que está se autenticando
        // Esta é uma lógica de exemplo, pode precisar ser ajustada para o seu ERP
        const [rows] = await connection.execute('SELECT Codigo, Documento, Nome FROM tb_Ambientes_Fornecedor WHERE Documento = ? AND Ativo = \'S\'', [cnpj.replace(/\D/g, '')]);
        if (rows.length > 0) {
          req.environment = rows[0];
          console.log(`Ambiente autenticado como ClienteApp Sync para CNPJ: ${cnpj}`);
          next();
        } else {
          return res.status(401).json({ success: false, error: 'Credenciais de sincronização de cliente inválidas (CNPJ não encontrado ou inativo).' });
        }
      } finally {
        connection.release();
      }
    }
  } catch (error) {
    console.error('Erro na autenticação de ambiente:', error);
    return res.status(500).json({ success: false, error: 'Erro interno do servidor na autenticação de ambiente.', details: error.message });
  }
};


// Rotas Protegidas
app.get('/api/sync/send-produtos', authenticateEnvironment, async (req, res) => {
  const connection = await req.pool.getConnection();
  try {
    const [rows] = await connection.execute('SELECT codigo, produto, codigo_barras, preco_venda, estoque, ativo FROM tb_produtos');
    res.json({ success: true, produtos: rows });
  } catch (error) {
    console.error('Erro ao buscar produtos:', error);
    res.status(500).json({ success: false, error: 'Erro ao buscar produtos.' });
  } finally {
    connection.release();
  }
});

app.get('/api/sync/send-clientes', authenticateEnvironment, async (req, res) => {
  const connection = await req.pool.getConnection();
  try {
    const [rows] = await connection.execute('SELECT codigo, nome, cnpj, cpf, ativo FROM tb_clientes');
    res.json({ success: true, clientes: rows });
  } catch (error) {
    console.error('Erro ao buscar clientes:', error);
    res.status(500).json({ success: false, error: 'Erro ao buscar clientes.' });
  } finally {
    connection.release();
  }
});

app.get('/api/sync/send-formas-pagamento', authenticateEnvironment, async (req, res) => {
  const connection = await req.pool.getConnection();
  try {
    const [rows] = await connection.execute('SELECT codigo, forma_pagamento, ativo FROM tb_formas_pagamento');
    res.json({ success: true, formas: rows });
  } catch (error) {
    console.error('Erro ao buscar formas de pagamento:', error);
    res.status(500).json({ success: false, error: 'Erro ao buscar formas de pagamento.' });
  } finally {
    connection.release();
  }
});

app.get('/api/sync/send-comandas', authenticateEnvironment, async (req, res) => {
  const connection = await req.pool.getConnection();
  try {
    const [rows] = await connection.execute('SELECT codigo, comanda, ativo FROM tb_comandas');
    res.json({ success: true, comandas: rows });
  } catch (error) {
    console.error('Erro ao buscar comandas:', error);
    res.status(500).json({ success: false, error: 'Erro ao buscar comandas.' });
  } finally {
    connection.release();
  }
});

app.post('/api/sync/receive-pedidos', authenticateEnvironment, async (req, res) => {
  const { pedidos } = req.body; // 'pedidos' é um array de objetos de pedido
  const connection = await req.pool.getConnection();
  
  if (!pedidos || !Array.isArray(pedidos) || pedidos.length === 0) {
    return res.status(400).json({ success: false, error: 'Array de pedidos vazio ou inválido.' });
  }

  try {
    await connection.beginTransaction();
    const insertedPedidos = [];

    for (const pedido of pedidos) {
      const {
        id_pedido_mentorweb, // ID do MentorWeb para referência
        data,
        hora,
        id_cliente,
        id_forma_pagamento,
        id_local_retirada,
        total_produtos,
        itens
      } = pedido;

      // Inserir na tabela tb_pedidos
      const [pedidoResult] = await connection.execute(
        'INSERT INTO tb_pedidos (data, hora, id_cliente, id_forma_pagamento, id_local_retirada, total_produtos, status, id_pedido_sistema_externo, origem) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [data, hora, id_cliente, id_forma_pagamento, id_local_retirada, total_produtos, 'recebido', id_pedido_mentorweb, 'MentorWeb']
      );

      const newPedidoId = pedidoResult.insertId;
      const insertedItens = [];

      // Inserir os itens do pedido na tabela tb_pedidos_produtos
      if (itens && Array.isArray(itens)) {
        for (const item of itens) {
          const [itemResult] = await connection.execute(
            'INSERT INTO tb_pedidos_produtos (id_pedido_erp, id_produto, quantidade, unitario, total_produto) VALUES (?, ?, ?, ?, ?)',
            [newPedidoId, item.id_produto, item.quantidade, item.unitario, item.total_produto]
          );
          insertedItens.push({ ...item, id_lcto_erp: itemResult.insertId });
        }
      }

      insertedPedidos.push({
        id_pedido_erp: newPedidoId,
        id_pedido_mentorweb: id_pedido_mentorweb,
        itens: insertedItens
      });
    }

    await connection.commit();
    res.json({ success: true, message: 'Pedidos recebidos e processados com sucesso.', pedidos_inseridos: insertedPedidos });
  } catch (error) {
    await connection.rollback();
    console.error('Erro ao receber pedidos:', error);
    res.status(500).json({ success: false, error: 'Erro ao processar pedidos.', details: error.message });
  } finally {
    connection.release();
  }
});

app.get('/api/sync/send-produtos-fornecedor', authenticateEnvironment, async (req, res) => {
  const connection = await req.pool.getConnection();
  try {
    // Certifique-se de que os nomes das colunas aqui correspondem exatamente à sua tabela tb_Produtos_Fornecedor
    const [rows] = await connection.execute('SELECT id, nome, preco_unitario, Ativo as ativo FROM tb_Produtos_Fornecedor');
    res.json({ success: true, produtos: rows });
  } catch (error) {
    console.error('Erro ao buscar produtos do fornecedor:', error);
    res.status(500).json({ success: false, error: 'Erro ao buscar produtos do fornecedor.' });
  } finally {
    connection.release();
  }
});

app.post('/api/sync/receive-pedido-fornecedor', authenticateEnvironment, async (req, res) => {
  // Desestruturar os dados do corpo da requisição
  const { produtos, total_pedido, data_pedido, cliente_nome, cliente_cnpj } = req.body;

  // IMPORTANTE: Mapear cliente_nome para a variável 'cliente' que é usada na validação
  // Esta linha garante que 'cliente' não será undefined se 'cliente_nome' estiver presente
  const cliente = cliente_nome;

  // Validação dos dados essenciais
  if (!produtos || !Array.isArray(produtos) || produtos.length === 0 || total_pedido === undefined || cliente === undefined) {
    // Adicionar um log detalhado para entender qual parte da validação falhou
    console.error('receive-pedido-fornecedor Validation Failed:', {
      hasProdutos: !!produtos,
      isArrayProdutos: Array.isArray(produtos),
      isProdutosEmpty: produtos && produtos.length === 0,
      isTotalPedidoUndefined: total_pedido === undefined,
      isClienteUndefined: cliente === undefined, // Isso agora deve ser false se cliente_nome existe
      receivedClienteName: cliente_nome // O valor real recebido
    });
    return res.status(400).json({ success: false, error: 'Dados do pedido para fornecedor incompletos (produtos, total_pedido, cliente são obrigatórios).' });
  }

  const connection = await req.pool.getConnection();
  try {
    await connection.beginTransaction();

    // Mapear cliente_cnpj (formatado pelo frontend) para o formato sem pontuação para busca no banco
    const cleanedClienteCnpj = cliente_cnpj.replace(/\D/g, ''); 

    // Buscar o Codigo do ambiente do cliente comprador na tabela tb_Ambientes_Fornecedor
    // A busca deve ser feita pelo Documento (CNPJ/CPF)
    const [ambienteRows] = await connection.execute('SELECT Codigo FROM tb_Ambientes_Fornecedor WHERE Documento = ? AND Ativo = \'S\'', [cleanedClienteCnpj]);
    
    let idAmbienteCliente = null;
    if (ambienteRows.length > 0) {
      idAmbienteCliente = ambienteRows[0].Codigo;
    } else {
      // Se o cliente não for encontrado por CNPJ, logar e retornar um erro específico
      console.error(`CNPJ do cliente/ambiente '${cliente_cnpj}' não encontrado ou inativo na tabela tb_Ambientes_Fornecedor do fornecedor. Pedido de: ${cliente_nome}`);
      throw new Error(`CNPJ do cliente '${cliente_cnpj}' não cadastrado ou inativo na base do fornecedor. Verifique o cadastro em tb_Ambientes_Fornecedor.`);
    }

    // Inserir o pedido principal
    const [pedidoResult] = await connection.execute(
      'INSERT INTO tb_Pedidos_Fornecedor (data_hora_lancamento, id_ambiente, valor_total, status, cliente_origem) VALUES (?, ?, ?, ?, ?)',
      [data_pedido, idAmbienteCliente, total_pedido, 'recebido', cliente_nome]
    );

    const newPedidoId = pedidoResult.insertId;

    // Inserir os itens do pedido
    if (produtos && Array.isArray(produtos)) {
      for (const produto of produtos) {
        await connection.execute(
          'INSERT INTO tb_Pedidos_Produtos_Fornecedor (id_pedido, id_produto, quantidade, preco_unitario, valor_total) VALUES (?, ?, ?, ?, ?)',
          [newPedidoId, produto.id_produto, produto.quantidade, produto.valor_unitario, produto.total_produto]
        );
      }
    }

    await connection.commit();
    res.json({ success: true, message: 'Pedido de fornecedor recebido e processado com sucesso.', codigo_pedido: newPedidoId });
  } catch (error) {
    await connection.rollback();
    console.error('Erro ao processar pedido de fornecedor:', error);
    res.status(500).json({ success: false, error: 'Erro ao processar pedido de fornecedor.', details: error.message });
  } finally {
    connection.release();
  }
});


app.post('/api/sync/authenticate-fornecedor-user', async (req, res) => {
  const { usuario, senha, cnpj_cpf, banco_dados } = req.body;

  if (!cnpj_cpf || !usuario || !senha || !banco_dados) {
    return res.status(400).json({ success: false, error: 'Documento, usuário, senha e banco de dados são obrigatórios para autenticação.' });
  }

  try {
    const pool = await getDatabasePool(banco_dados);
    const connection = await pool.getConnection();

    try {
      const cleanedCnpjCpf = cnpj_cpf.replace(/\D/g, ''); // Remover formatação
      const [rows] = await connection.execute(
        'SELECT Codigo, ID_Pessoa, Documento, Nome, Senha, Ativo, DHU, IDUser, usuario FROM tb_Ambientes_Fornecedor WHERE Documento = ? AND usuario = ? AND Senha = ? AND Ativo = \'S\'',
        [cleanedCnpjCpf, usuario, senha]
      );

      if (rows.length > 0) {
        const user = rows[0];
        res.json({
          success: true,
          user: {
            ID_Pessoa: user.ID_Pessoa,
            Documento: user.Documento,
            Nome: user.Nome,
            usuario: user.usuario,
            Ativo: user.Ativo,
            // Adicionar campos de ambiente se a tabela os contiver ou se houver um mapeamento
            id_ambiente_erp: user.Codigo, // Mapeando Codigo para id_ambiente_erp
            nome_ambiente: user.Nome     // Mapeando Nome para nome_ambiente
          }
        });
      } else {
        res.status(401).json({ success: false, error: 'Usuário, senha ou documento inválido, ou usuário inativo.' });
      }
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Erro ao autenticar usuário fornecedor com ERP:', error);
    res.status(500).json({ success: false, error: 'Erro interno do servidor durante a autenticação.', details: error.message });
  }
});

// Rota de saúde para verificar conectividade
app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'ok', message: 'ERP Sync server is running.' });
});

// Iniciar o servidor
app.listen(PORT, () => {
  console.log(`ERP Sync server is running on port ${PORT}`);
});
