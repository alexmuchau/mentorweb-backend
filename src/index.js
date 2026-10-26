// Entrada do Cloudflare Worker: MentorWeb ERP Sync (ponte Base44 <-> MySQL do WHM).
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { config } from './config.js';
import { mountRoutes } from './express-compat.js';
import './routes.js'; // registra as rotas em express-compat

const hono = new Hono();

// CORS (equivalente ao cors() do server.js; ALLOWED_ORIGINS vazio = qualquer origem)
hono.use('*', (c, next) =>
  cors({
    origin: config.allowedOrigins === '*' ? '*' : config.allowedOrigins,
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization', 'cnpj', 'usuario', 'senha', 'banco_dados'],
    credentials: true,
  })(c, next)
);

hono.get('/api/health', (c) => c.json({ status: 'OK', timestamp: new Date().toISOString() }));

mountRoutes(hono);

// Toda resposta é JSON — evita o erro "is not valid JSON" no cliente (Base44) quando algo falha.
hono.notFound((c) => c.json({ success: false, error: 'Rota não encontrada.' }, 404));
hono.onError((error, c) => {
  console.error(`[${new Date().toISOString()}]`, 'Erro não tratado:', error);
  return c.json({ success: false, error: 'Erro interno do servidor', details: error.message }, 500);
});

export default hono;
