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
  console.log('senha:', req.headers.senha);
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
    // Tenta obter o pool para o banco_dados. Este pool já é testado na função getDatabasePool.
    req.pool = await getDatabasePool(banco_dados); 

    // Define as informações do ambiente
    req.environment = { cnpj, usuario, senha, banco_dados, tipo: 'desconhecido' };

    // Verifica se as credenciais de ambiente correspondem ao usuário de sincronização de fornecedor
    if (usuario === SUPPLIER_SYNC_USER && senha === SUPPLIER_SYNC_PASS) {
        req.isSupplierAuth = true; // Marca como autenticação de fornecedor (serviço)
        req.environment.tipo = 'fornecedor_sync';
    } else {
        // Se não for o usuário de sync de fornecedor, tenta autenticar como ClienteApp padrão
        // Você pode adicionar uma validação mais robusta aqui se necessário para ClientApp
        req.isClientAppAuth = true; // Marca como autenticação de cliente (serviço)
        req.environment.tipo = 'cliente'; 
    }
    
    return next(); // Autenticação de ambiente bem-sucedida, prossegue para a rota.

  } catch (error) {
    console.error(`Erro no middleware authenticateEnvironment para banco ${banco_dados}:`, error);
    // Se o erro for na obtenção do pool, ou seja, banco de dados não existe/credenciais inválidas
    if (error.message && error.message.includes('Não foi possível conectar ao banco de dados')) {
        return res.status(401).json({ error: 'Falha na conexão com o banco de dados do ambiente.', details: error.message });
    }
    // Erros gerais de SQL ou outros erros internos do servidor
    return res.status(500).json({ error: 'Erro interno do servidor durante a autenticação do ambiente', details: error.message });
  }
};

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Rotas de Sincronização
// As rotas que usam authenticateEnvironment passarão pelo middleware
// e terão acesso a req.pool e req.environment

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
    if (req.environment.banco_dados !== 'muchaucom_mentor') {
        return res.status(403).json({ success: false, error: 'Acesso negado. Esta rota é apenas para o banco muchaucom_mentor.' });
    }

    const { pedidos } = req.body;
    let connection;

    if (!pedidos || !Array.isArray(pedidos) || pedidos.length === 0) {
        return res.status(400).json({ success: false, error: 'Dados de pedidos inválidos.' });
    }

    try {
        connection = await req.pool.getConnection();
        await connection.beginTransaction();

        const pedidos_inseridos = [];

        for (const pedido of pedidos) {
            // Inserir na tabela tb_pedidos
            const [pedidoResult] = await connection.execute(
                `INSERT INTO tb_pedidos (data, hora, id_cliente, id_forma_pagamento, id_local_retirada, total_produtos, status, id_pedido_sistema_externo, origem)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    pedido.data,
                    pedido.hora,
                    pedido.id_cliente,
                    pedido.id_forma_pagamento,
                    pedido.id_local_retirada,
                    pedido.total_produtos,
                    pedido.status,
                    pedido.id_pedido_mentorweb, // Usando id_pedido_mentorweb para id_pedido_sistema_externo
                    'mentorweb' // Valor fixo para origem
                ]
            );

            const id_pedido_inserido = pedidoResult.insertId;

            // Inserir itens do pedido em tb_pedidos_produtos
            for (const item of pedido.itens) {
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
            pedidos_inseridos.push({ id_pedido_erp: id_pedido_inserido, id_pedido_mentorweb: pedido.id_pedido_mentorweb });
        }

        await connection.commit();
        res.json({ success: true, message: 'Pedidos recebidos e processados com sucesso.', pedidos_inseridos });

    } catch (error) {
        if (connection) await connection.rollback();
        console.error('Erro ao receber pedidos:', error);
        res.status(500).json({ success: false, error: 'Erro ao receber pedidos', details: error.message });
    } finally {
        if (connection) connection.release();
    }
});


// Rotas para muchaucom_pisciNew (fornecedor) - Nomes de tabelas ajustados

// ROTA PARA FORNECEDORES: Buscar produtos para o aplicativo de fornecedores
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

// ROTA PARA FORNECEDORES: Receber pedidos do aplicativo de fornecedores
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

        // Inserir na tabela tb_Pedidos_Fornecedor
        const [pedidoResult] = await connection.execute(
            `INSERT INTO tb_Pedidos_Fornecedor (data_hora_lancamento, valor_total, status, id_pedido_sistema_externo, id_ambiente)
             VALUES (?, ?, ?, ?, ?)`,
            [
                data_pedido,
                total_pedido,
                'processando',
                cliente,
                // id_ambiente: Usar o Codigo da tb_Ambientes_Fornecedor que representa o ambiente.
                // Como este endpoint é chamado pelo MentorWeb com as credenciais do fornecedor_sync,
                // e não há um campo 'id_ambiente' no payload atual do `send_pedido_fornecedor` do MentorWeb,
                // você precisará determinar como este valor será fornecido.
                // Sugestão: Se cada fornecedor_app tem um único ambiente, você pode buscar essa informação
                // usando o CNPJ/usuario nos headers para encontrar o ambiente associado.
                // Por agora, estou usando um valor fixo de exemplo (ID do ambiente do fornecedor).
                // VOCÊ DEVE AJUSTAR ESTE VALOR PARA O ID DO AMBIENTE REAL NO SEU ERP!
                // Exemplo: 299, 399, etc. conforme tb_Ambientes_Fornecedor
                // Usarei 299 como placeholder, mas você deve obter isso dinamicamente se houver múltiplos ambientes por CNPJ
                299 
            ]
        );

        const id_pedido_inserido = pedidoResult.insertId;

        // Inserir os itens do pedido na tabela tb_Pedidos_Produtos_Fornecedor
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


// ROTA ESPECIAL: Autenticação de usuário fornecedor para login (não usa authenticateEnvironment para pegar pool)
app.post('/api/sync/authenticate-fornecedor-user', async (req, res) => {
  const { cnpj_cpf, usuario, senha } = req.body;
  const { banco_dados, cnpj: header_cnpj_empresa, usuario: header_usuario_empresa, senha: header_senha_empresa } = req.headers;
  
  let connection;

  console.log('--- AUTENTICAÇÃO DE USUÁRIO FORNECEDOR ---');
  console.log('Body (usuário final):', { cnpj_cpf, usuario, senha });
  console.log('Headers (ambiente de sync):', { banco_dados, header_cnpj_empresa, header_usuario_empresa, header_senha_empresa });
  console.log('-----------------------------------------');

  // Validações básicas
  if (!banco_dados || !header_cnpj_empresa || !header_usuario_empresa || !header_senha_empresa) {
    return res.status(400).json({ error: 'Credenciais de ambiente incompletas nos headers.' });
  }
  if (!cnpj_cpf || !usuario || !senha) {
    return res.status(400).json({ error: 'Credenciais de usuário final incompletas no body.' });
  }

  // Autentica as credenciais de sincronização de fornecedor nos headers
  if (header_usuario_empresa !== SUPPLIER_SYNC_USER || header_senha_empresa !== SUPPLIER_SYNC_PASS) {
      return res.status(401).json({ error: 'Credenciais de sincronização de fornecedor inválidas nos headers.' });
  }

  try {
    const pool = await getDatabasePool(banco_dados); 
    connection = await pool.getConnection();

    // A consulta agora é na tb_Ambientes_Fornecedor para autenticar o usuário final
    // e pegar os dados do ambiente (Codigo e Nome)
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
                Nome: user.NomePessoa, // Nome da pessoa/usuário
                usuario: user.usuario,
                Ativo: user.Ativo,
                id_ambiente_erp: user.id_ambiente_erp, // Codigo da tb_Ambientes_Fornecedor
                nome_ambiente: user.nome_ambiente // Nome da tb_Ambientes_Fornecedor
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
