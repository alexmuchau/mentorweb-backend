// scripts/setup-database.js
const mysql = require('mysql2/promise');
const fs = require('fs');
require('dotenv').config();

async function setupDatabase() {
  const connection = await mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    multipleStatements: true
  });

  try {
    console.log('🔄 Configurando banco de dados...');

    // Criar banco se não existir
    const dbName = process.env.DB_NAME || 'mentorweb_erp';
    await connection.execute(`CREATE DATABASE IF NOT EXISTS \`${dbName}\`;`);

    // Inserir dados iniciais
    console.log('📝 Inserindo dados iniciais...');

    // Ambiente padrão
    await connection.execute(`
      INSERT IGNORE INTO ${dbName}.tb_ambientes 
      (codigo, usuario, senha, banco_dados, cnpj, nome_empresa, licencas_liberadas, ativo) 
      VALUES 
      (1, 'admin', '123456', '${dbName}', '12.345.678/0001-90', 'Empresa Demo', 10, 'S')
    `);

    // Clientes de exemplo
    await connection.execute(`
      INSERT IGNORE INTO ${dbName}.tb_clientes (codigo, nome, cnpj, cpf, ativo) VALUES
      (1, 'João Silva', NULL, '123.456.789-00', 'S'),
      (2, 'Maria Santos', NULL, '987.654.321-00', 'S'),
      (3, 'Empresa ABC Ltda', '12.345.678/0001-90', NULL, 'S')
    `);

    // Produtos de exemplo
    await connection.execute(`
      INSERT IGNORE INTO ${dbName}.tb_produtos (codigo, produto, codigo_barras, preco_venda, ativo) VALUES
      (1, 'Café Expresso', '7891234567890', 3.50, 'S'),
      (2, 'Pão de Açúcar', '7891234567891', 5.90, 'S'),
      (3, 'Suco Natural', '7891234567892', 8.00, 'S'),
      (4, 'Sanduíche Natural', '7891234567893', 12.50, 'S')
    `);

    // Formas de pagamento
    await connection.execute(`
      INSERT IGNORE INTO ${dbName}.tb_formas_pagamento (codigo, forma_pagamento, ativo) VALUES
      (1, 'Dinheiro', 'S'),
      (2, 'Cartão de Crédito', 'S'),
      (3, 'Cartão de Débito', 'S'),
      (4, 'PIX', 'S'),
      (5, 'Transferência', 'S')
    `);

    // Comandas
    await connection.execute(`
      INSERT IGNORE INTO ${dbName}.tb_comandas (codigo, comanda, ativo) VALUES
      (1, 'Mesa 01', 'S'),
      (2, 'Mesa 02', 'S'),
      (3, 'Balcão', 'S'),
      (4, 'Delivery', 'S')
    `);

    console.log('✅ Banco de dados configurado com sucesso!');
    console.log(`📊 Banco: ${dbName}`);
    console.log('🔑 Credenciais de teste:');
    console.log('   CNPJ: 12.345.678/0001-90');
    console.log('   Usuário: admin');
    console.log('   Senha: 123456');

  } catch (error) {
    console.error('❌ Erro ao configurar banco:', error);
  } finally {
    await connection.end();
  }
}

setupDatabase();