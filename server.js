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
    database: databaseName,
    port: process.env.DB_PORT || 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
  });

  // Testar a conexão
  try {
    const connection = await newPool.getConnection();
    await connection.query('SELECT 1');
    connection.release();
    console.log(`Pool de conexão criado e testado para o banco de dados: ${databaseName}`);
  } catch (error) {
    console.error(`Erro ao criar ou testar pool para o banco de dados ${databaseName}:`, error);
    delete dbPools[databaseName];
    throw new Error(`Não foi possível conectar ao banco de dados ${databaseName}.`);
  }

  dbPools[databaseName] = newPool;
  return newPool;
}

// Middleware de autenticação de ambiente
const authenticateEnvironment = async (req, res, next) => {
  console.log('--- MIDDLEWARE authenticateEnvironment ---');
  console.log('Headers recebidos:', {
    cnpj: req.headers.cnpj,
    usuario: req.headers.usuario,
    senha: req.headers.senha ? '*'.repeat(req.headers.senha.length) : 'não informado',
    banco_dados: req.headers.banco_dados
  });
  console.log('Body da requisição:', JSON.stringify(req.body, null, 2));

  const { cnpj, usuario, senha, banco_dados } = req.headers;

  // Inicializa req.pool e flags
  req.pool = null; 
  req.isClientAppAuth = false;
  req.isSupplierAuth = false;
  req.environment = null;

  if (!cnpj || !usuario || !senha || !banco_dados) {
    console.error('ERRO: Credenciais de ambiente incompletas');
    return res.status(400).json({ 
      error: 'Credenciais de ambiente incompletas', 
      details: 'Headers CNPJ, Usuário, Senha e Banco de Dados são obrigatórios.',
      received: { cnpj: !!cnpj, usuario: !!usuario, senha: !!senha, banco_dados: !!banco_dados }
    });
  }

  try {
    console.log(`Tentando conectar ao banco: ${banco_dados}`);
    req.pool = await getDatabasePool(banco_dados);
    console.log(`Conexão estabelecida com sucesso para: ${banco_dados}`);

    // Define as informações do ambiente
    req.environment = { cnpj, usuario, senha, banco_dados, tipo: 'desconhecido' };

    // Verifica se as credenciais de ambiente correspondem ao usuário de sincronização de fornecedor
    if (usuario === SUPPLIER_SYNC_USER && senha === SUPPLIER_SYNC_PASS) {
        req.isSupplierAuth = true;
        req.environment.tipo = 'fornecedor_sync';
        console.log('Autenticado como fornecedor_sync');
    } else {
        req.isClientAppAuth = true;
        req.environment.tipo = 'cliente';
        console.log('Autenticado como cliente');
    }
    
    console.log('Middleware authenticateEnvironment concluído com sucesso');
    return next();

  } catch (error) {
    console.error(`ERRO no middleware authenticateEnvironment para banco ${banco_dados}:`, error);
    return res.status(500).json({ 
      error: 'Erro interno do servidor durante a autenticação do ambiente', 
      details: error.message,
      banco_dados: banco_dados
    });
  }
};

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Rotas de Sincronização

// Rotas para muchaucom_mentor (cliente) - Nomes de tabelas originais
app.get('/api/sync/send-produtos', authenticateEnvironment, async (req, res) => {
  if (req.environment.banco_dados !== 'muchaucom_mentor') {
      return res.status(403).json({ success: false, error: 'Acesso negado. Esta rota é apenas para o banco muchaucom_mentor.' });
  }
  try {
    const [rows] = await req.pool.execute('SELECT codigo, produto, codigo_barras, preco_venda, estoque, ativo FROM tb_produtos WHERE ativo = "S"');
    res.json({ success: true, produtos: rows });
  } catch (error) {
    console.error('Erro ao buscar produtos:', error);
    res.status(500).json({ success: false, error: 'Erro ao buscar produtos', details: error.message });
  }
});

app.get('/api/sync/send-clientes', authenticateEnvironment, async (req, res) => {
    if (req.environment.banco_dados !== 'muchaucom_mentor') {
        return res.status(403).json({ success: false, error: 'Acesso negado. Esta rota é apenas para o banco muchaucom_mentor.' });
    }
    try {
        const [rows] = await req.pool.execute('SELECT codigo, nome, cnpj, cpf, ativo FROM tb_clientes WHERE ativo = "S"');
        res.json({ success: true, clientes: rows });
    } catch (error) {
        console.error('Erro ao buscar clientes:', error);
        res.status(500).json({ success: false, error: 'Erro ao buscar clientes', details: error.message });
    }
});

app.get('/api/sync/send-formas-pagamento', authenticateEnvironment, async (req, res) => {
    if (req.environment.banco_dados !== 'muchaucom_mentor') {
        return res.status(403).json({ success: false, error: 'Acesso negado. Esta rota é apenas para o banco muchaucom_mentor.' });
    }
    try {
        const [rows] = await req.pool.execute('SELECT codigo, forma_pagamento, ativo FROM tb_formas_pagamento WHERE ativo = "S"');
        res.json({ success: true, formas: rows });
    } catch (error) {
        console.error('Erro ao buscar formas de pagamento:', error);
        res.status(500).json({ success: false, error: 'Erro ao buscar formas de pagamento', details: error.message });
    }
});

app.get('/api/sync/send-comandas', authenticateEnvironment, async (req, res) => {
    if (req.environment.banco_dados !== 'muchaucom_mentor') {
        return res.status(403).json({ success: false, error: 'Acesso negado. Esta rota é apenas para o banco muchaucom_mentor.' });
    }
    try {
        const [rows] = await req.pool.execute('SELECT codigo, comanda, ativo FROM tb_comandas WHERE ativo = "S"');
        res.json({ success: true, comandas: rows });
    } catch (error) {
        console.error('Erro ao buscar comandas:', error);
        res.status(500).json({ success: false, error: 'Erro ao buscar comandas', details: error.message });
    }
});

app.post('/api/sync/receive-pedidos', authenticateEnvironment, async (req, res) => {
    console.log('=== ROTA receive-pedidos INICIADA ===');
    console.log('Banco de dados:', req.environment.banco_dados);
    console.log('Tipo de ambiente:', req.environment.tipo);
    console.log('Dados recebidos:', JSON.stringify(req.body, null, 2));

    if (req.environment.banco_dados !== 'muchaucom_mentor') {
        console.error('ERRO: Banco de dados incorreto');
        return res.status(403).json({ 
            success: false, 
            error: 'Acesso negado. Esta rota é apenas para o banco muchaucom_mentor.',
            banco_atual: req.environment.banco_dados
        });
    }

    const { pedidos } = req.body;
    let connection;

    if (!pedidos || !Array.isArray(pedidos) || pedidos.length === 0) {
        console.error('ERRO: Dados de pedidos inválidos');
        console.log('Pedidos recebidos:', pedidos);
        return res.status(400).json({ 
            success: false, 
            error: 'Dados de pedidos inválidos.',
            details: 'O campo "pedidos" deve ser um array não vazio',
            received: typeof pedidos
        });
    }

    try {
        console.log(`Processando ${pedidos.length} pedidos...`);
        connection = await req.pool.getConnection();
        await connection.beginTransaction();
        console.log('Transação iniciada');

        const pedidos_inseridos = [];

        for (let i = 0; i < pedidos.length; i++) {
            const pedido = pedidos[i];
            console.log(`Processando pedido ${i + 1}/${pedidos.length}:`, pedido);

            // Validar campos obrigatórios
            if (!pedido.data || !pedido.hora || !pedido.id_cliente || !pedido.id_forma_pagamento || !pedido.total_produtos) {
                throw new Error(`Pedido ${i + 1}: Campos obrigatórios ausentes (data, hora, id_cliente, id_forma_pagamento, total_produtos)`);
            }

            if (!pedido.itens || !Array.isArray(pedido.itens) || pedido.itens.length === 0) {
                throw new Error(`Pedido ${i + 1}: Lista de itens ausente ou vazia`);
            }

            // Inserir na tabela tb_pedidos
            console.log(`Inserindo pedido ${i + 1} na tb_pedidos...`);
            const [pedidoResult] = await connection.execute(
                `INSERT INTO tb_pedidos (data, hora, id_cliente, id_forma_pagamento, id_local_retirada, total_produtos, status, origem)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    pedido.data,
                    pedido.hora,
                    pedido.id_cliente,
                    pedido.id_forma_pagamento,
                    pedido.id_local_retirada || null,
                    pedido.total_produtos,
                    pedido.status || 'recebido',
                    'mentorweb'
                ]
            );

            const id_pedido_inserido = pedidoResult.insertId;
            console.log(`Pedido inserido com ID: ${id_pedido_inserido}`);

            // Inserir itens do pedido em tb_pedidos_produtos
            console.log(`Inserindo ${pedido.itens.length} itens do pedido...`);
            for (let j = 0; j < pedido.itens.length; j++) {
                const item = pedido.itens[j];
                console.log(`Inserindo item ${j + 1}:`, item);

                // Validar campos obrigatórios do item
                if (!item.id_produto || !item.quantidade || !item.unitario || !item.total_produto) {
                    throw new Error(`Pedido ${i + 1}, Item ${j + 1}: Campos obrigatórios ausentes (id_produto, quantidade, unitario, total_produto)`);
                }

                await connection.execute(
                    `INSERT INTO tb_pedidos_produtos (id_pedido_erp, id_produto, quantidade, unitario, total_produto)
                     VALUES (?, ?, ?, ?, ?)`,
                    [
                        id_pedido_inserido,
                        item.id_produto,
                        item.quantidade,
                        item.unitario,
                        item.total_produto
                    ]
                );
            }

            pedidos_inseridos.push({ 
                id_pedido_erp: id_pedido_inserido, 
                id_pedido_mentorweb: pedido.id_pedido_mentorweb 
            });
        }

        await connection.commit();
        console.log('Transação commitada com sucesso');
        
        const response = { 
            success: true, 
            message: 'Pedidos recebidos e processados com sucesso.', 
            pedidos_inseridos,
            total_processados: pedidos_inseridos.length
        };
        
        console.log('Resposta enviada:', response);
        res.json(response);

    } catch (error) {
        console.error('ERRO ao processar pedidos:', error);
        if (connection) {
            await connection.rollback();
            console.log('Transação revertida');
        }
        res.status(500).json({ 
            success: false, 
            error: 'Erro ao receber pedidos', 
            details: error.message,
            stack: error.stack
        });
    } finally {
        if (connection) {
            connection.release();
            console.log('Conexão liberada');
        }
    }
    
    console.log('=== ROTA receive-pedidos FINALIZADA ===');
});

// Rotas para muchaucom_pisciNew (fornecedor) - Nomes de tabelas ajustados
app.get('/api/sync/send-produtos-fornecedor', authenticateEnvironment, async (req, res) => {
    if (req.environment.banco_dados !== 'muchaucom_pisciNew') {
        return res.status(403).json({ success: false, error: 'Acesso negado. Esta rota é apenas para o banco muchaucom_pisciNew.' });
    }
    if (req.environment.tipo !== 'fornecedor_sync') {
        return res.status(403).json({ success: false, error: 'Acesso negado. Apenas usuários de sincronização de fornecedor podem acessar esta rota.' });
    }

    try {
        const [rows] = await req.pool.execute('SELECT id, nome, preco_unitario, Ativo FROM tb_Produtos_Fornecedor WHERE Ativo = "S"'); 
        const produtosFormatados = rows.map(p => ({
            id: p.id,
            produto: p.nome,
            preco_venda: p.preco_unitario,
            ativo: p.Ativo
        }));

        res.json({ success: true, produtos: produtosFormatados });
    } catch (error) {
        console.error('Erro ao buscar produtos para fornecedor:', error);
        res.status(500).json({ success: false, error: 'Erro ao buscar produtos para fornecedor', details: error.message });
    }
});

app.post('/api/sync/receive-pedido-fornecedor', authenticateEnvironment, async (req, res) => {
    if (req.environment.banco_dados !== 'muchaucom_pisciNew') {
        return res.status(403).json({ success: false, error: 'Acesso negado. Esta rota é apenas para o banco muchaucom_pisciNew.' });
    }
    if (req.environment.tipo !== 'fornecedor_sync') {
        return res.status(403).json({ success: false, error: 'Acesso negado. Apenas usuários de sincronização de fornecedor podem acessar esta rota.' });
    }

    const { produtos, total_pedido, data_pedido, cliente } = req.body;
    let connection;

    if (!produtos || !Array.isArray(produtos) || produtos.length === 0 || !total_pedido || !data_pedido || !cliente) {
        return res.status(400).json({ success: false, error: 'Dados de pedido de fornecedor incompletos ou inválidos.' });
    }

    try {
        connection = await req.pool.getConnection();
        await connection.beginTransaction();

        const [pedidoResult] = await connection.execute(
            `INSERT INTO tb_Pedidos_Fornecedor (data_hora_lancamento, valor_total, status, id_pedido_sistema_externo, id_ambiente)
             VALUES (?, ?, ?, ?, ?)`,
            [
                data_pedido,
                total_pedido,
                'processando',
                cliente,
                299 
            ]
        );

        const id_pedido_inserido = pedidoResult.insertId;

        for (const item of produtos) {
            await connection.execute(
                `INSERT INTO tb_Pedidos_Produtos_Fornecedor (id_pedido, id_produto, quantidade, preco_unitario, valor_total)
                 VALUES (?, ?, ?, ?, ?)`,
                [
                    id_pedido_inserido,
                    item.id_produto,
                    item.quantidade,
                    item.valor_unitario,
                    item.total_produto
                ]
            );
        }

        await connection.commit();
        res.json({ success: true, message: 'Pedido de fornecedor recebido e processado.', codigo_pedido: id_pedido_inserido });

    } catch (error) {
        if (connection) await connection.rollback();
        console.error('Erro ao receber pedido de fornecedor:', error);
        res.status(500).json({ success: false, error: 'Erro ao receber pedido de fornecedor', details: error.message });
    } finally {
        if (connection) connection.release();
    }
});

app.post('/api/sync/authenticate-fornecedor-user', async (req, res) => {
  const { cnpj_cpf, usuario, senha } = req.body;
  const { banco_dados, cnpj: header_cnpj_empresa, usuario: header_usuario_empresa, senha: header_senha_empresa } = req.headers;
  
  let connection;

  console.log('--- AUTENTICAÇÃO DE USUÁRIO FORNECEDOR ---');
  console.log('Body (usuário final):', { cnpj_cpf, usuario, senha: senha ? '*'.repeat(senha.length) : 'não informado' });
  console.log('Headers (ambiente de sync):', { banco_dados, header_cnpj_empresa, header_usuario_empresa, header_senha_empresa: header_senha_empresa ? '*'.repeat(header_senha_empresa.length) : 'não informado' });
  console.log('-----------------------------------------');

  if (!banco_dados || !header_cnpj_empresa || !header_usuario_empresa || !header_senha_empresa) {
    return res.status(400).json({ error: 'Credenciais de ambiente incompletas nos headers.' });
  }
  if (!cnpj_cpf || !usuario || !senha) {
    return res.status(400).json({ error: 'Credenciais de usuário final incompletas no body.' });
  }

  if (header_usuario_empresa !== SUPPLIER_SYNC_USER || header_senha_empresa !== SUPPLIER_SYNC_PASS) {
      return res.status(401).json({ error: 'Credenciais de sincronização de fornecedor inválidas nos headers.' });
  }

  try {
    const pool = await getDatabasePool(banco_dados); 
    connection = await pool.getConnection();

    const [rows] = await connection.execute(
        `SELECT
            ID_Pessoa, Documento, Nome AS NomePessoa, usuario, Ativo,
            Codigo AS id_ambiente_erp, Nome AS nome_ambiente
        FROM tb_Ambientes_Fornecedor
        WHERE Documento = ? AND usuario = ? AND Senha = ? AND Ativo = 'S'`,
        [cnpj_cpf, usuario, senha]
    );
    
    if (rows.length > 0) {
        const user = rows[0];
        res.json({
            success: true,
            user: {
                ID_Pessoa: user.ID_Pessoa,
                Documento: user.Documento,
                Nome: user.NomePessoa,
                usuario: user.usuario,
                Ativo: user.Ativo,
                id_ambiente_erp: user.id_ambiente_erp,
                nome_ambiente: user.nome_ambiente
            }
        });
    } else {
        res.status(401).json({ success: false, error: 'Usuário ou senha inválidos.' });
    }

  } catch (error) {
    console.error('Erro na autenticação de usuário fornecedor:', error);
    res.status(500).json({ success: false, error: 'Erro interno no servidor.', details: error.message });
  } finally {
    if (connection) {
      connection.release();
    }
  }
});

// Iniciar o servidor
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
