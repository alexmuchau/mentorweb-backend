// Mini-roteador com a assinatura do Express — app.get/post(path, ...handlers) com handlers (req, res, next).
// Permite manter as rotas de negócio idênticas às do server.js original, rodando sobre Hono/Workers.
//
// Superfície suportada (é tudo que o server.js usava):
//   req.headers (chaves minúsculas), req.body, req.query, req.params + propriedades que middlewares anexam
//   res.status(n).json(obj)
import { withRequestPools } from './db.js';

const MAX_BODY_BYTES = 10 * 1024 * 1024; // mesmo limite do express.json({ limit: '10mb' })

const routes = [];

export const app = {
  get: (path, ...handlers) => routes.push({ method: 'GET', path, handlers }),
  post: (path, ...handlers) => routes.push({ method: 'POST', path, handlers }),
};

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

async function parseBody(request) {
  if (request.method === 'GET' || request.method === 'HEAD') return {};

  const length = Number(request.headers.get('content-length') || 0);
  if (length > MAX_BODY_BYTES) throw new HttpError(413, 'Corpo da requisição excede 10mb.');

  const type = (request.headers.get('content-type') || '').toLowerCase();
  const text = await request.text();
  if (!text) return {};

  if (type.includes('application/json')) {
    try {
      return JSON.parse(text);
    } catch {
      throw new HttpError(400, 'JSON inválido no corpo da requisição.');
    }
  }
  if (type.includes('application/x-www-form-urlencoded')) {
    return Object.fromEntries(new URLSearchParams(text));
  }
  return {};
}

function jsonResponse(status, payload) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  });
}

async function runChain(c, handlers) {
  return withRequestPools(async () => {
    let body;
    try {
      body = await parseBody(c.req.raw);
    } catch (error) {
      if (error instanceof HttpError) return jsonResponse(error.status, { success: false, error: error.message });
      throw error;
    }

    const req = {
      headers: Object.fromEntries(c.req.raw.headers),
      body,
      query: c.req.query(),
      params: c.req.param(),
    };

    let response = null;
    const res = {
      statusCode: 200,
      status(code) { this.statusCode = code; return this; },
      json(payload) { response = jsonResponse(this.statusCode, payload); return this; },
    };

    let index = 0;
    const next = async () => {
      const handler = handlers[index++];
      if (handler) await handler(req, res, next);
    };
    await next();

    return response || jsonResponse(500, { success: false, error: 'Rota não retornou resposta.' });
  });
}

export function mountRoutes(hono) {
  for (const { method, path, handlers } of routes) {
    hono.on(method, path, (c) => runChain(c, handlers));
  }
}
