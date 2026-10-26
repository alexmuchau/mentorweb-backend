# AGENTS.md — mentorweb-backend

Guia para quem (humano ou agente) for mexer neste repositório.

## O que é

API HTTP em JSON que serve de **ponte entre o aplicativo Base44 (MentorWeb) e o MySQL de um servidor WHM/HostGator**
(IP `162.240.226.40`, porta 3306). O Base44 chama esta API; ela autentica o ambiente, executa SQL no banco
do cliente (um banco MySQL por cliente, ex.: `ipesiste_Palacio_Dos_Parafusos`) e devolve JSON.

Domínio de negócio: ERP de varejo/distribuição — clientes, produtos, formas de pagamento, comandas, pedidos,
indicadores/analytics e um módulo de **pedidos cliente → fornecedor**.

## Produção

| Item | Valor |
|---|---|
| URL | `https://mentorweb.muchau.com.br` (Cloudflare Worker `mentorweb-backend`, domínio customizado) |
| Conta Cloudflare | `Muchau04@gmail.com's Account` (zona `muchau.com.br`) |
| Banco | MySQL no WHM, `DB_HOST=162.240.226.40:3306` |
| Health check | `GET /api/health` |

### Histórico: por que migramos para Cloudflare Workers

Antes, a API era um servidor Express (`server.js`) no próprio WHM, acessado pelo IP cru (`http://162.240.226.40:3334`).
As funções do Base44 passaram a falhar com `SyntaxError: Unexpected token 'e', "error code: 1003" is not valid JSON`:
`error code: 1003` é o Cloudflare bloqueando **acesso direto por IP** (a infra do Base44 sai pelo Cloudflare).
A resposta é texto puro, não JSON, daí o erro de parse. A correção foi usar um **nome de domínio** e hospedar
a API no próprio Cloudflare Workers; o IP do WHM agora só é usado pelo Worker para falar com o MySQL por TCP
(o bloqueio 1003 vale para HTTP, não para sockets TCP).

## Estrutura

```
src/
  index.js          Entrada do Worker (Hono): CORS, /api/health, 404/500 sempre em JSON
  express-compat.js Mini-roteador com assinatura do Express (app.get/post, (req,res,next)) sobre o Hono
  routes.js         As 21 rotas de negócio (portadas de server.js; lógica preservada)
  auth.js           authenticateEnvironment (middleware de autenticação por headers)
  db.js             Conexão MySQL por requisição (mysql2 + TCP sockets do Workers)
  config.js         Leitura das variáveis de ambiente / secrets
wrangler.jsonc      Config do Worker (vars não secretas, domínio, compat flags)
.dev.vars           Secrets para desenvolvimento local (NÃO versionado)
server.js           LEGADO: servidor Express antigo no WHM. Mantido só como referência/rollback.
setupDatabase.js    Script antigo de seed do banco (não faz parte do Worker)
```

### Decisões de arquitetura

- **Rotas portadas, não reescritas.** `routes.js` mantém o código do Express (`(req, res)`, `res.status().json()`).
  `express-compat.js` adapta isso ao Hono. A superfície suportada é pequena de propósito: `req.headers` (minúsculas),
  `req.body`, `req.query`, `req.params`, `res.status(n).json(obj)`. Se precisar de mais (ex.: `res.send`), implemente lá.
- **Sem pool global.** Workers não compartilham sockets entre requisições. `db.js` cria um "pool" **por requisição**
  (`withRequestPools`, via `AsyncLocalStorage`): `getConnection()` reaproveita conexões abertas na mesma requisição,
  `release()` devolve à lista ociosa e tudo é destruído no fim. A API imita a do `mysql2` Pool
  (`getConnection/execute/query/beginTransaction/commit/rollback/release`).
- **`mysql2` com `disableEval: true`** (obrigatório no Workers) e `compatibility_flags: ["nodejs_compat"]`.
- **Fuso horário `-03:00`** (`DB_TIMEZONE`). O servidor antigo rodava em America/Sao_Paulo e o `mysql2` lia
  `DATETIME` no fuso local; sem isso as datas mudam 3h para o Base44 (`...T03:00:00.000Z` vs `...T00:00:00.000Z`).
- **Toda resposta é JSON**, inclusive 404, JSON de entrada inválido e erros não tratados.
- Removidos de propósito: `helmet`, `compression`, `morgan` (Cloudflare já comprime e loga) e `express-rate-limit`
  (use regras de rate limiting/WAF no painel Cloudflare se necessário).

## Rotas (contrato com o Base44)

Autenticação por **headers**: `cnpj`, `usuario`, `senha`, `banco_dados`. `banco_dados` escolhe o banco MySQL do cliente.

- **Cliente (ClienteApp)** — middleware `authenticateEnvironment`: headers conferidos na tabela `tb_ambientes` (`ativo = 'S'`) **ou**
  credencial de fornecedor (`req.isSupplierAuth`). Sob `/api/sync/`:
  `GET send-clientes`, `send-produtos`, `send-formas-pagamento`, `send-comandas`, `send-pedidos-list`, `send-analytics`;
  `POST receive-pedidos`, `send-itens-pedido`, `send-indicadores`, `send-pedido-fornecedor` (só ClienteApp).
- **Fornecedor** — com `authenticateEnvironment` (exige `isSupplierAuth`, ou seja, `usuario`/`senha` = `SUPPLIER_SYNC_USER`/`SUPPLIER_SYNC_PASS`):
  `GET send-produtos-fornecedor`; `POST receive-pedido-fornecedor`, `receive-pedido-cliente-fornecedor` (aceita qualquer ambiente autenticado),
  `send-produtos-fornecedor-para-cliente`, `get-status-pedidos-fornecedor` (ver pendência 2).
  Sem o middleware, validando os headers manualmente: `GET send-ambientes-fornecedor`, `POST authenticate-fornecedor-user`, `cancel-pedido-fornecedor`.
- **Admin** — `POST /api/erp/inativar-usuario-fornecedor`, exige `SYSTEM_ADMIN_USER`/`SYSTEM_ADMIN_PASS` nos headers.
- **SEM AUTENTICAÇÃO** — `POST /api/sync/update-comanda-status` e `POST /api/sync/get-comandas` recebem `databaseName` no corpo e
  não validam nenhuma credencial (ver pendência 3).

Para a lista exata e as regras de cada rota, leia `src/routes.js` (cada rota é autocontida).

## Variáveis de ambiente

Não secretas (em `wrangler.jsonc` → `vars`): `DB_HOST`, `DB_PORT`, `DB_TIMEZONE`, `ALLOWED_ORIGINS` (vazio = qualquer origem), `DB_SSL` (opcional, `true` liga TLS; não testado).

Secrets (**nunca** no código/git; sem valor padrão — se faltar, a requisição falha com erro claro):
`DB_USER`, `DB_PASSWORD`, `SUPPLIER_SYNC_USER`, `SUPPLIER_SYNC_PASS`, `SYSTEM_ADMIN_USER`, `SYSTEM_ADMIN_PASS`.

- Local: arquivo `.dev.vars` (já no `.gitignore`), um `CHAVE=valor` por linha.
- Produção: `npx wrangler secret put NOME` ou, em lote, `npx wrangler secret bulk arquivo.json`.
  Listar: `npx wrangler secret list`.

## Desenvolvimento

```bash
npm install
npm run dev          # wrangler dev em http://localhost:8787 (lê .dev.vars; conecta no MySQL real do WHM)
npm run tail         # logs ao vivo da produção
```

Atenção: `wrangler dev` usa o **banco de produção** (não existe ambiente de homologação). Prefira testar rotas de leitura;
rotas de escrita (`receive-*`, `update-comanda-status`, `cancel-*`, `send-pedido-fornecedor`) gravam dados reais.

### Como foi validada a migração
Compararam-se as respostas do Worker com as do servidor antigo (mesmos headers, mesmo banco) rota a rota; as rotas de
leitura testadas voltaram **byte a byte idênticas** (exceto texto de erro com acentos, que o servidor antigo devolvia corrompido).
Rotas de escrita **não** foram exercitadas contra o banco real.

## Deploy

```bash
npx wrangler login     # uma vez (OAuth no navegador)
npm run deploy         # wrangler deploy → publica em mentorweb.muchau.com.br
```

O domínio customizado (`routes` em `wrangler.jsonc`) cria o DNS automaticamente; a zona `muchau.com.br` precisa estar na mesma conta.
Rollback: `npx wrangler rollback` (versão anterior do Worker) ou `npx wrangler versions list`.

Se trocar um secret, rode `wrangler secret put`; não precisa redeploy.

## Pendências e pontos de atenção conhecidos

1. **Base44 ainda precisa apontar para a nova URL** (`https://mentorweb.muchau.com.br`, sem porta) no lugar de `http://162.240.226.40:3334`.
   Depois de validado, desligue o Node/PM2 no WHM (portas 3333/3334).
2. **Bug herdado:** `POST /api/sync/get-status-pedidos-fornecedor` testa `req.isSupplierSync`, que nunca é definido →
   sempre responde 403 (era assim no servidor antigo). O flag certo provavelmente é `req.isSupplierAuth`. Não corrigido por mudar comportamento.
3. **Rotas sem autenticação (herdado):** `update-comanda-status` e `get-comandas` aceitam qualquer chamador que saiba o nome de um banco,
   permitindo ler e alterar comandas de qualquer cliente. Recomenda-se exigir `authenticateEnvironment` (confirmar antes se o Base44 envia os headers nessas chamadas).
4. **Segurança do MySQL:** a porta 3306 do WHM está aberta para a internet e o Workers não tem IP fixo para liberar no firewall.
   Use um usuário MySQL dedicado ao Worker, com privilégios mínimos e senha forte. Opções melhores: Cloudflare Hyperdrive/Tunnel.
   O tráfego Worker→MySQL hoje **não é criptografado** (`DB_SSL` existe, mas não foi validado com o MySQL do WHM).
5. **Limites do Workers:** no plano Free há ~10 ms de CPU por requisição; `send-produtos` (~2,2 MB) funcionou, mas
   monitore erros "exceeded CPU" (`npm run tail`). O plano pago (US$ 5/mês) elimina esse risco.
6. **Credenciais de sistema antigas** (`mentorweb_sync_forn_2024`, `admin_inativar_2024`) estiveram no git (`server.js` e histórico).
   Considere rotacioná-las: troque os secrets e atualize o Base44 ao mesmo tempo.
7. `setupDatabase.js` e `server.js` são legado; `server.js` depende de `express`, `helmet` etc. (ainda em `dependencies`).
   Quando o WHM for desligado, remova-os junto das dependências.
8. Sem testes automatizados (`npm test` é placeholder). A verificação foi por comparação manual com o servidor antigo.

## Convenções

- Código e mensagens de erro em português; mantenha o formato `{ success, error, details }` das respostas.
- Sempre `connection.release()` em `finally`; transações com `beginTransaction/commit/rollback`.
- Nunca coloque segredos no código; novos segredos entram em `config.js` com `required(...)` e em `.dev.vars` + `wrangler secret`.
