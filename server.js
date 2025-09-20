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

// Pool de conexões MySQL
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  connectionLimit: 10,
  acquireTimeout: 60000,
  timeout: 60000,
  reconnect: true
});

// Middleware de autenticação de ambiente
const authenticateEnvironment = async (req, res, next) => {
  const { cnpj, usuario, senha, banco_dados } = req.headers;

  console.log('--- HEADERS RECEBIDOS ---');
  console.log('cnpj:', cnpj);
  console.log('usuario:', usuario);
  console.log('senha:', senha);
  console.log('banco_dados:', banco_dados);
  console.log('-------------------------');

  if (!cnpj || !usuario || !senha || !banco_dados) {
    return res.status(400).json({ 
      error: 'Headers de autenticação obrigatórios: cnpj, usuario, senha, banco_dados' 
    });
  }

  // CASO ESPECIAL: Autenticação de fornecedor (headers especiais)
  if (cnpj === 'fornecedor_auth' && usuario === 'fornecedor_auth' && senha === 'fornecedor_auth') {
    console.log('>>> AUTENTICAÇÃO DE FORNECEDOR DETECTADA <<<');
    console.log('Usando banco de dados:', banco_dados);
    
    try {
      await pool.query(`USE \`${banco_dados}\``);
      console.log(`Conectado ao banco de dados do fornecedor: ${banco_dados}`);
      req.isSupplierAuth = true;
      return next();
    } catch (error) {
      console.error(`Erro ao conectar no banco do fornecedor ${banco_dados}:`, error);
      return res.status(500).json({ 
        error: 'Erro ao conectar com banco de dados do fornecedor',
        details: error.message 
      });
    }
  }

  // CASO NORMAL: Autenticação de ClienteApp
  try {
    console.log('>>> AUTENTICAÇÃO DE CLIENTE DETECTADA <<<');
    console.log('Conectando ao banco:', banco_dados);
    
    await pool.query(`USE \`${banco_dados}\``);
    
    // IMPORTANTE: Para ClienteApp, usa tb_ambientes (minúsculas)
    const [rows] = await pool.execute(
      'SELECT * FROM tb_ambientes WHERE cnpj = ? AND usuario = ? AND senha = ? AND ativo = "S"',
      [cnpj, usuario, senha]
    );

    if (rows.length === 0) {
      return res.status(401).json({ 
        error: 'Credenciais de ambiente inválidas',
        details: `CNPJ: ${cnpj}, Usuário: ${usuario}` 
      });
    }

    console.log(`Autenticação ClienteApp bem-sucedida para: ${cnpj}`);
    req.environmentData = rows[0];
    return next();

  } catch (error) {
    console.error('Erro na autenticação de ambiente:', error);
    return res.status(500).json({ 
      error: 'Erro interno na autenticação de ambiente',
      details: error.message 
    });
  }
};

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// ROTA ESPECIAL: Autenticação de usuário fornecedor
app.post('/api/sync/authenticate-fornecedor-user', async (req, res) => {
  const { cnpj_cpf, usuario, senha } = req.body;
  const { banco_dados } = req.headers;

  console.log('=== ROTA DE AUTENTICAÇÃO DE FORNECEDOR ===');
  console.log('CNPJ/CPF:', cnpj_cpf);
  console.log('Usuário:', usuario);
  console.log('Banco de dados:', banco_dados);

  if (!cnpj_cpf || !usuario || !senha || !banco_dados) {
    return res.status(400).json({ 
      error: 'CNPJ/CPF, usuário, senha e banco_dados são obrigatórios' 
    });
  }

  try {
    // Conectar no banco de dados do fornecedor
    await pool.query(`USE \`${banco_dados}\``);
    console.log(`Conectado ao banco do fornecedor: ${banco_dados}`);

    // IMPORTANTE: Para fornecedor, usa tb_Ambientes (com A maiúsculo)
    const [rows] = await pool.execute(
      'SELECT * FROM tb_Ambientes WHERE Documento = ? AND usuario = ? AND senha = ? AND Ativo = "S"',
      [cnpj_cpf, usuario, senha]
    );

    if (rows.length === 0) {
      console.log('Usuário não encontrado ou credenciais inválidas');
      return res.status(401).json({ 
        error: 'Credenciais inválidas ou usuário inativo' 
      });
    }

    const user = rows[0];
    console.log('Usuário autenticado com sucesso:', {
      ID_Pessoa: user.ID_Pessoa,
      Nome: user.Nome,
      Documento: user.Documento
    });

    res.json({
      success: true,
      user: {
        ID_Pessoa: user.ID_Pessoa,
        Nome: user.Nome,
        Documento: user.Documento,
        usuario: user.usuario,
        Ativo: user.Ativo
      }
    });

  } catch (error) {
    console.error('Erro na autenticação de fornecedor:', error);
    res.status(500).json({ 
      error: 'Erro interno na autenticação',
      details: error.message 
    });
  }
});

// Aplicar middleware de autenticação a todas as rotas sync (exceto a rota de autenticação de fornecedor)
app.use('/api/sync', (req, res, next) => {
  if (req.path === '/authenticate-fornecedor-user') {
    return next(); // Pular middleware para esta rota específica
  }
  return authenticateEnvironment(req, res, next);
});

// Rota para envio de produtos
app.get('/api/sync/send-produtos', async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT * FROM tb_produto WHERE ativo = "S"');
    res.json({ 
      success: true, 
      produtos: rows,
      total: rows.length 
    });
  } catch (error) {
    console.error('Erro ao buscar produtos:', error);
    res.status(500).json({ 
      error: 'Erro ao buscar produtos',
      details: error.message 
    });
  }
});

// Rota para envio de clientes
app.get('/api/sync/send-clientes', async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT * FROM tb_cliente WHERE ativo = "S"');
    res.json({ 
      success: true, 
      clientes: rows,
      total: rows.length 
    });
  } catch (error) {
    console.error('Erro ao buscar clientes:', error);
    res.status(500).json({ 
      error: 'Erro ao buscar clientes',
      details: error.message 
    });
  }
});

// Rota para envio de formas de pagamento
app.get('/api/sync/send-formas-pagamento', async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT * FROM tb_forma_pagamento WHERE ativo = "S"');
    res.json({ 
      success: true, 
      formas: rows,
      total: rows.length 
    });
  } catch (error) {
    console.error('Erro ao buscar formas de pagamento:', error);
    res.status(500).json({ 
      error: 'Erro ao buscar formas de pagamento',
      details: error.message 
    });
  }
});

// Rota para envio de comandas
app.get('/api/sync/send-comandas', async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT * FROM tb_comanda WHERE ativo = "S"');
    res.json({ 
      success: true, 
      comandas: rows,
      total: rows.length 
    });
  } catch (error) {
    console.error('Erro ao buscar comandas:', error);
    res.status(500).json({ 
      error: 'Erro ao buscar comandas',
      details: error.message 
    });
  }
});

// Rota para recebimento de pedidos
app.post('/api/sync/receive-pedidos', async (req, res) => {
  try {
    const { pedidos } = req.body;
    
    if (!pedidos || !Array.isArray(pedidos)) {
      return res.status(400).json({ 
        error: 'Array de pedidos é obrigatório' 
      });
    }

    const results = [];
    for (const pedido of pedidos) {
      try {
        const [result] = await pool.execute(
          'INSERT INTO tb_pedido (data, hora, id_cliente, id_forma_pagamento, id_local_retirada, total_produtos, status) VALUES (?, ?, ?, ?, ?, ?, ?)',
          [pedido.data, pedido.hora, pedido.id_cliente, pedido.id_forma_pagamento, pedido.id_local_retirada, pedido.total_produtos, 'processando']
        );
        
        const pedidoId = result.insertId;
        
        for (const item of pedido.itens || []) {
          await pool.execute(
            'INSERT INTO tb_pedido_produto (id_pedido, id_produto, quantidade, unitario, total_produto) VALUES (?, ?, ?, ?, ?)',
            [pedidoId, item.id_produto, item.quantidade, item.unitario, item.total_produto]
          );
        }
        
        results.push({ 
          id_original: pedido.id, 
          id_erp: pedidoId, 
          status: 'success' 
        });
        
      } catch (itemError) {
        console.error(`Erro ao processar pedido ${pedido.id}:`, itemError);
        results.push({ 
          id_original: pedido.id, 
          status: 'error', 
          error: itemError.message 
        });
      }
    }

    res.json({ 
      success: true, 
      results,
      total_processados: results.length 
    });

  } catch (error) {
    console.error('Erro ao receber pedidos:', error);
    res.status(500).json({ 
      error: 'Erro ao processar pedidos',
      details: error.message 
    });
  }
});

// Rota para envio de produtos do fornecedor
app.get('/api/sync/send-produtos-fornecedor', async (req, res) => {
  try {
    if (!req.isSupplierAuth) {
      return res.status(401).json({ 
        error: 'Acesso não autorizado para produtos de fornecedor' 
      });
    }

    // IMPORTANTE: Para fornecedor, usa tb_Produto (com P maiúsculo)
    const [rows] = await pool.execute('SELECT * FROM tb_Produto WHERE Ativo = "S"');
    res.json({ 
      success: true, 
      produtos: rows,
      total: rows.length 
    });
  } catch (error) {
    console.error('Erro ao buscar produtos do fornecedor:', error);
    res.status(500).json({ 
      error: 'Erro ao buscar produtos do fornecedor',
      details: error.message 
    });
  }
});

// Rota para recebimento de pedido do fornecedor
app.post('/api/sync/receive-pedido-fornecedor', async (req, res) => {
  try {
    if (!req.isSupplierAuth) {
      return res.status(401).json({ 
        error: 'Acesso não autorizado para pedidos de fornecedor' 
      });
    }

    const { cliente, itens, total_pedido } = req.body;
    
    if (!cliente || !itens || !Array.isArray(itens) || !total_pedido) {
      return res.status(400).json({ 
        error: 'Cliente, itens (array) e total_pedido são obrigatórios' 
      });
    }

    // IMPORTANTE: Para fornecedor, usa tb_Pedido (com P maiúsculo)
    const [result] = await pool.execute(
      'INSERT INTO tb_Pedido (Cliente, Data_Pedido, Total_Pedido, Status) VALUES (?, NOW(), ?, ?)',
      [cliente, total_pedido, 'Novo']
    );
    
    const pedidoId = result.insertId;
    
    for (const item of itens) {
      await pool.execute(
        'INSERT INTO tb_PedidoProduto (ID_Pedido, ID_Produto, Quantidade, Valor_Unitario, Total_Produto) VALUES (?, ?, ?, ?, ?)',
        [pedidoId, item.id_produto, item.quantidade, item.valor_unitario, item.total_produto]
      );
    }
    
    res.json({ 
      success: true, 
      id_pedido_erp: pedidoId,
      status: 'Pedido recebido com sucesso' 
    });

  } catch (error) {
    console.error('Erro ao receber pedido do fornecedor:', error);
    res.status(500).json({ 
      error: 'Erro ao processar pedido do fornecedor',
      details: error.message 
    });
  }
});

// Middleware de tratamento de erros
app.use((error, req, res, next) => {
  console.error('Erro não tratado:', error);
  res.status(500).json({ 
    error: 'Erro interno do servidor',
    details: error.message 
  });
});

// Middleware para rotas não encontradas
app.use((req, res) => {
  res.status(404).json({ 
    error: 'Rota não encontrada',
    path: req.path,
    method: req.method 
  });
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`Servidor ERP rodando na porta ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM recebido. Fechando servidor graciosamente...');
  pool.end();
  process.exit(0);
});
