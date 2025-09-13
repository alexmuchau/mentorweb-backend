const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middlewares de segurança
app.use(helmet());
app.use(compression());
app.use(morgan('combined'));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// CORS
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
  credentials: true
}));

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Pool de conexões MySQL
const createConnectionPool = (database) => {
  return mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: database,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    acquireTimeout: 60000,
    timeout: 60000,
    reconnect: true
  });
};

// Conexões por ambiente
const connections = new Map();

// Middleware de autenticação por ambiente
const authenticateEnvironment = async (req, res, next) => {
  try {
    const { cnpj, usuario, senha, banco_dados } = req.headers;

    if (!cnpj || !usuario || !senha || !banco_dados) {
      return res.status(401).json({ 
        error: 'Credenciais obrigatórias: cnpj, usuario, senha, banco_dados' 
      });
    }

    // Verificar se já existe conexão para este banco
    if (!connections.has(banco_dados)) {
      connections.set(banco_dados, createConnectionPool(banco_dados));
    }

    const pool = connections.get(banco_dados);

    // Verificar credenciais na tabela tb_ambientes
    const [rows] = await pool.execute(
      'SELECT * FROM tb_ambientes WHERE cnpj = ? AND usuario = ? AND senha = ? AND banco_dados = ? AND ativo = "S"',
      [cnpj, usuario, senha, banco_dados]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    req.pool = pool;
    req.ambiente = rows[0];
    next();
  } catch (error) {
    console.error('Erro na autenticação:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
};

// Rotas da API

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

// Sincronizar dados do MentorWeb para ERP
app.post('/api/sync/receive-pedidos', authenticateEnvironment, async (req, res) => {
  const connection = await req.pool.getConnection();
  
  try {
    await connection.beginTransaction();

    const { pedidos } = req.body;
    const processedOrders = [];

    for (const pedido of pedidos) {
      // Inserir pedido principal
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
        pedido.id_local_retirada || null,
        pedido.total_produtos
      ]);

      const pedidoErpId = pedidoResult.insertId;

      // Inserir itens do pedido
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
        mentorweb_id: pedido.id,
        erp_id: pedidoErpId,
        status: 'processado'
      });
    }

    await connection.commit();

    res.json({
      success: true,
      message: `${processedOrders.length} pedidos processados com sucesso`,
      pedidos_processados: processedOrders,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    await connection.rollback();
    console.error('Erro ao processar pedidos:', error);
    res.status(500).json({ 
      error: 'Erro ao processar pedidos', 
      details: error.message 
    });
  } finally {
    connection.release();
  }
});

// Enviar dados do ERP para MentorWeb
app.get('/api/sync/send-clientes', authenticateEnvironment, async (req, res) => {
  try {
    const [clientes] = await req.pool.execute(`
      SELECT codigo, nome, cnpj, cpf, ativo 
      FROM tb_clientes 
      WHERE ativo = 'S'
      ORDER BY nome
    `);

    res.json({
      success: true,
      data: clientes,
      total: clientes.length,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Erro ao buscar clientes:', error);
    res.status(500).json({ error: 'Erro ao buscar clientes' });
  }
});

app.get('/api/sync/send-produtos', authenticateEnvironment, async (req, res) => {
  try {
    const [produtos] = await req.pool.execute(`
      SELECT codigo, produto, codigo_barras, preco_venda, ativo 
      FROM tb_produtos 
      WHERE ativo = 'S'
      ORDER BY produto
    `);

    res.json({
      success: true,
      data: produtos,
      total: produtos.length,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Erro ao buscar produtos:', error);
    res.status(500).json({ error: 'Erro ao buscar produtos' });
  }
});

app.get('/api/sync/send-formas-pagamento', authenticateEnvironment, async (req, res) => {
  try {
    const [formas] = await req.pool.execute(`
      SELECT codigo, forma_pagamento, ativo 
      FROM tb_formas_pagamento 
      WHERE ativo = 'S'
      ORDER BY forma_pagamento
    `);

    res.json({
      success: true,
      data: formas,
      total: formas.length,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Erro ao buscar formas de pagamento:', error);
    res.status(500).json({ error: 'Erro ao buscar formas de pagamento' });
  }
});

app.get('/api/sync/send-comandas', authenticateEnvironment, async (req, res) => {
  try {
    const [comandas] = await req.pool.execute(`
      SELECT codigo, comanda, ativo 
      FROM tb_comandas 
      WHERE ativo = 'S'
      ORDER BY comanda
    `);

    res.json({
      success: true,
      data: comandas,
      total: comandas.length,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Erro ao buscar comandas:', error);
    res.status(500).json({ error: 'Erro ao buscar comandas' });
  }
});

// Confirmar processamento de pedidos (ERP -> MentorWeb)
app.post('/api/sync/confirm-pedidos', authenticateEnvironment, async (req, res) => {
  try {
    const { pedidos_confirmados } = req.body;
    const confirmations = [];

    for (const confirmacao of pedidos_confirmados) {
      await req.pool.execute(`
        UPDATE tb_pedidos 
        SET status = 'confirmado', data_confirmacao = NOW() 
        WHERE codigo = ?
      `, [confirmacao.erp_id]);

      confirmations.push({
        erp_id: confirmacao.erp_id,
        status: 'confirmado'
      });
    }

    res.json({
      success: true,
      message: `${confirmations.length} pedidos confirmados`,
      confirmacoes: confirmations,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Erro ao confirmar pedidos:', error);
    res.status(500).json({ error: 'Erro ao confirmar pedidos' });
  }
});

// Relatórios
app.get('/api/reports/pedidos-periodo', authenticateEnvironment, async (req, res) => {
  try {
    const { data_inicio, data_fim } = req.query;

    const [pedidos] = await req.pool.execute(`
      SELECT 
        p.codigo,
        p.data,
        p.hora,
        c.nome as cliente_nome,
        fp.forma_pagamento,
        p.total_produtos,
        p.status,
        COUNT(pp.id) as total_itens
      FROM tb_pedidos p
      LEFT JOIN tb_clientes c ON p.id_cliente = c.codigo
      LEFT JOIN tb_formas_pagamento fp ON p.id_forma_pagamento = fp.codigo
      LEFT JOIN tb_pedidos_produtos pp ON p.codigo = pp.id_pedido_erp
      WHERE p.data BETWEEN ? AND ?
      GROUP BY p.codigo
      ORDER BY p.data DESC, p.hora DESC
    `, [data_inicio, data_fim]);

    res.json({
      success: true,
      data: pedidos,
      total: pedidos.length,
      periodo: { data_inicio, data_fim },
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Erro no relatório:', error);
    res.status(500).json({ error: 'Erro ao gerar relatório' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    error: 'Erro interno do servidor',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint não encontrado' });
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('Received SIGTERM, closing server...');
  
  // Fechar todas as conexões
  for (const [database, pool] of connections) {
    await pool.end();
    console.log(`Conexão fechada para banco: ${database}`);
  }
  
  process.exit(0);
});

app.listen(PORT, () => {
  console.log(`🚀 Servidor MentorWeb ERP rodando na porta ${PORT}`);
  console.log(`📊 Ambiente: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔗 Health check: http://localhost:${PORT}/health`);
});