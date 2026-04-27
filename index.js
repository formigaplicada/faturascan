// ============================================================
// FATURASCAN BACKEND
// Node.js + Express + Cloud Run + Firestore + Google OAuth
// ============================================================

require('dotenv').config();

const express    = require('express');
const cors       = require('cors');
const { google } = require('googleapis');
const { Firestore } = require('@google-cloud/firestore');

const app  = express();
const db   = new Firestore({ projectId: process.env.GOOGLE_CLOUD_PROJECT });
const PORT = process.env.PORT || 3000;

// ── MIDDLEWARES ───────────────────────────────────────────────
app.use(express.json());
app.use(cors({
  origin: [
    process.env.FRONTEND_URL || 'https://faturascan.com',
    'http://localhost:5500',   // dev local
    'http://127.0.0.1:5500',
  ],
  credentials: true,
}));

// ── OAUTH CLIENT ─────────────────────────────────────────────
function criarOAuthClient() {
  return new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    `${process.env.BACKEND_URL}/auth/callback`
  );
}

// ── SCOPES ───────────────────────────────────────────────────
// login + leitura de perfil + Drive (só ficheiros criados pela app)
const SCOPES = [
  'openid',
  'email',
  'profile',
  'https://www.googleapis.com/auth/drive.file',
];

// ============================================================
// AUTH — ROTAS
// ============================================================

// GET /auth/login
// Redireciona o contabilista para o ecrã de login Google
app.get('/auth/login', (req, res) => {
  const oauth2Client = criarOAuthClient();
  const url = oauth2Client.generateAuthUrl({
    access_type:  'offline',   // obtém refresh_token
    prompt:       'consent',   // garante refresh_token sempre
    scope:        SCOPES,
  });
  res.redirect(url);
});

// GET /auth/callback
// Google redireciona para aqui após login
app.get('/auth/callback', async (req, res) => {
  const { code } = req.query;

  if (!code) {
    return res.redirect(`${process.env.FRONTEND_URL}conta?erro=sem_codigo`);
  }

  try {
    const oauth2Client = criarOAuthClient();
    const { tokens }   = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);

    // Obter perfil do contabilista
    const oauth2      = google.oauth2({ version: 'v2', auth: oauth2Client });
    const { data }    = await oauth2.userinfo.get();

    const contabilista_id = data.id; // ID Google único

    // Guardar/actualizar contabilista no Firestore
    const ref = db.collection('contabilistas').doc(contabilista_id);
    await ref.set({
      google_id:     data.id,
      email:         data.email,
      nome:          data.name,
      foto:          data.picture || null,
      access_token:  tokens.access_token,
      refresh_token: tokens.refresh_token || null, // só vem na 1ª vez
      token_expiry:  tokens.expiry_date   || null,
      atualizado_em: new Date().toISOString(),
    }, { merge: true }); // merge para não apagar refresh_token se já existir

    // Criar sessão simples via cookie (token próprio)
    const session_token = gerarToken();
    await db.collection('sessoes').doc(session_token).set({
      contabilista_id,
      criado_em:  new Date().toISOString(),
      expira_em:  new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(), // 7 dias
    });

    // Redirecionar para o frontend com o token de sessão
    res.redirect(`${process.env.FRONTEND_URL}conta?session=${session_token}`);

  } catch (err) {
    console.error('Erro no callback OAuth:', err);
    res.redirect(`${process.env.FRONTEND_URL}conta?erro=auth_falhou`);
  }
});

// GET /auth/me
// Devolve os dados do contabilista autenticado
app.get('/auth/me', autenticar, async (req, res) => {
  try {
    const doc = await db.collection('contabilistas').doc(req.contabilista_id).get();
    if (!doc.exists) return res.status(404).json({ erro: 'Contabilista não encontrado' });

    const dados = doc.data();
    res.json({
      id:            dados.google_id,
      email:         dados.email,
      nome:          dados.nome,
      foto:          dados.foto,
      pasta_drive_id: dados.pasta_drive_id || null,
      pasta_drive_nome: dados.pasta_drive_nome || null,
      onboarding_completo: !!dados.pasta_drive_id,
    });
  } catch (err) {
    console.error('Erro em /auth/me:', err);
    res.status(500).json({ erro: 'Erro interno' });
  }
});

// GET /auth/token
// Devolve o access_token actual para o Google Drive Picker no frontend
app.get('/auth/token', autenticar, async (req, res) => {
  try {
    const doc   = await db.collection('contabilistas').doc(req.contabilista_id).get();
    const dados = doc.data();

    // Se o token expirou, renovar
    const oauth2Client = criarOAuthClient();
    oauth2Client.setCredentials({
      access_token:  dados.access_token,
      refresh_token: dados.refresh_token,
      expiry_date:   dados.token_expiry,
    });

    oauth2Client.on('tokens', async (tokens) => {
      if (tokens.access_token) {
        await db.collection('contabilistas').doc(req.contabilista_id).update({
          access_token: tokens.access_token,
          token_expiry: tokens.expiry_date || null,
        });
      }
    });

    const { token } = await oauth2Client.getAccessToken();
    res.json({ access_token: token });
  } catch (err) {
    console.error('Erro em /auth/token:', err);
    res.status(500).json({ erro: 'Erro ao obter token' });
  }
});

// POST /auth/logout
app.post('/auth/logout', autenticar, async (req, res) => {
  try {
    await db.collection('sessoes').doc(req.session_token).delete();
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ erro: 'Erro ao terminar sessão' });
  }
});

// ============================================================
// ONBOARDING — CONFIGURAR PASTA DO DRIVE VIA PICKER
// ============================================================

// POST /onboarding/pasta
// Recebe o ID da pasta escolhida pelo Google Drive Picker
// e cria uma subpasta "FaturaScan" dentro dela.
// Com drive.file só podemos aceder a ficheiros que a app cria —
// por isso criamos a subpasta e usamos essa como raiz.
app.post('/onboarding/pasta', autenticar, async (req, res) => {
  const { pasta_pai_id, pasta_pai_nome } = req.body;

  if (!pasta_pai_id) {
    return res.status(400).json({ erro: 'pasta_pai_id obrigatório' });
  }

  try {
    const drive = await criarDriveClient(req.contabilista_id);

    // Criar subpasta "FaturaScan" dentro da pasta escolhida pelo contabilista
    const pasta = await drive.files.create({
      requestBody: {
        name:     'FaturaScan',
        mimeType: 'application/vnd.google-apps.folder',
        parents:  [pasta_pai_id],
      },
      fields: 'id, name',
    });

    const pasta_id   = pasta.data.id;
    const pasta_nome = `FaturaScan (em ${pasta_pai_nome || 'Drive'})`;

    // Guardar no Firestore
    await db.collection('contabilistas').doc(req.contabilista_id).update({
      pasta_drive_id:   pasta_id,
      pasta_drive_nome: pasta_nome,
      onboarding_em:    new Date().toISOString(),
    });

    res.json({
      ok:    true,
      pasta: { id: pasta_id, nome: pasta_nome },
    });

  } catch (err) {
    console.error('Erro ao criar pasta:', err);
    res.status(500).json({ erro: 'Erro ao criar pasta no Drive: ' + err.message });
  }
});

// ============================================================
// CLIENTES
// ============================================================

// GET /clientes
// Lista todos os clientes do contabilista
app.get('/clientes', autenticar, async (req, res) => {
  try {
    const snap = await db
      .collection('contabilistas').doc(req.contabilista_id)
      .collection('clientes')
      .orderBy('criado_em', 'desc')
      .get();

    const clientes = snap.docs.map(doc => ({
      id:        doc.id,
      ...doc.data(),
      // não expor dados sensíveis
      access_token:  undefined,
      refresh_token: undefined,
    }));

    res.json({ clientes });
  } catch (err) {
    console.error('Erro ao listar clientes:', err);
    res.status(500).json({ erro: 'Erro ao listar clientes' });
  }
});

// POST /clientes
// Criar novo cliente
app.post('/clientes', autenticar, async (req, res) => {
  const { nif, nome, email } = req.body;

  // Validações
  if (!nif || !/^\d{9}$/.test(nif)) {
    return res.status(400).json({ erro: 'NIF inválido — deve ter 9 dígitos.' });
  }
  if (!nome) {
    return res.status(400).json({ erro: 'Nome obrigatório.' });
  }

  try {
    const contabilista_ref = db.collection('contabilistas').doc(req.contabilista_id);
    const contabilista     = (await contabilista_ref.get()).data();

    if (!contabilista.pasta_drive_id) {
      return res.status(400).json({ erro: 'Configura primeiro a pasta do Drive no onboarding.' });
    }

    // Verificar se NIF já existe
    const existente = await contabilista_ref
      .collection('clientes')
      .where('nif', '==', nif)
      .get();

    if (!existente.empty) {
      return res.status(409).json({ erro: 'Este NIF já existe na lista de clientes.' });
    }

    // Criar pasta do cliente no Drive
    const drive       = await criarDriveClient(req.contabilista_id);
    const pasta_drive = await drive.files.create({
      requestBody: {
        name:     nif,
        mimeType: 'application/vnd.google-apps.folder',
        parents:  [contabilista.pasta_drive_id],
      },
      fields: 'id, name',
    });

    const pasta_cliente_id = pasta_drive.data.id;

    // Criar subpastas inbox e por_classificar
    await Promise.all([
      drive.files.create({ requestBody: { name: 'inbox',           mimeType: 'application/vnd.google-apps.folder', parents: [pasta_cliente_id] }, fields: 'id' }),
      drive.files.create({ requestBody: { name: 'por_classificar', mimeType: 'application/vnd.google-apps.folder', parents: [pasta_cliente_id] }, fields: 'id' }),
    ]);

    // Gerar token de 8 dígitos
    const token = gerarToken8();

    // Link da app
    const link = `https://faturascan.com/app/?c=${req.contabilista_id}&k=${token}&n=${nif}`;

    // Guardar cliente no Firestore
    const cliente_ref = contabilista_ref.collection('clientes').doc(token);
    await cliente_ref.set({
      nif,
      nome,
      email:          email || null,
      token,
      link,
      pasta_drive_id: pasta_cliente_id,
      criado_em:      new Date().toISOString(),
      faturas_semana: 0,
      faturas_mes:    0,
      faturas_ano:    0,
    });

    res.json({
      ok: true,
      cliente: { token, nif, nome, link, pasta_drive_id: pasta_cliente_id },
    });

  } catch (err) {
    console.error('Erro ao criar cliente:', err);
    res.status(500).json({ erro: 'Erro ao criar cliente: ' + err.message });
  }
});

// DELETE /clientes/:token
// Remover cliente (não apaga a pasta do Drive)
app.delete('/clientes/:token', autenticar, async (req, res) => {
  try {
    await db
      .collection('contabilistas').doc(req.contabilista_id)
      .collection('clientes').doc(req.params.token)
      .delete();

    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ erro: 'Erro ao remover cliente' });
  }
});

// ============================================================
// MIDDLEWARE — AUTENTICAÇÃO
// Verifica o session token enviado no header Authorization
// ============================================================
async function autenticar(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.replace('Bearer ', '').trim();

  if (!token) {
    return res.status(401).json({ erro: 'Não autenticado' });
  }

  try {
    const sessao_doc = await db.collection('sessoes').doc(token).get();
    if (!sessao_doc.exists) {
      return res.status(401).json({ erro: 'Sessão inválida ou expirada' });
    }

    const sessao = sessao_doc.data();
    if (new Date(sessao.expira_em) < new Date()) {
      await sessao_doc.ref.delete();
      return res.status(401).json({ erro: 'Sessão expirada' });
    }

    req.contabilista_id = sessao.contabilista_id;
    req.session_token   = token;
    next();

  } catch (err) {
    console.error('Erro na autenticação:', err);
    res.status(500).json({ erro: 'Erro interno' });
  }
}

// ============================================================
// HELPER — criar cliente Drive autenticado com tokens do contabilista
// ============================================================
async function criarDriveClient(contabilista_id) {
  const doc    = await db.collection('contabilistas').doc(contabilista_id).get();
  const dados  = doc.data();

  const oauth2Client = criarOAuthClient();
  oauth2Client.setCredentials({
    access_token:  dados.access_token,
    refresh_token: dados.refresh_token,
    expiry_date:   dados.token_expiry,
  });

  // Se o token expirou, renovar automaticamente e guardar
  oauth2Client.on('tokens', async (tokens) => {
    if (tokens.access_token) {
      await db.collection('contabilistas').doc(contabilista_id).update({
        access_token: tokens.access_token,
        token_expiry: tokens.expiry_date || null,
      });
    }
  });

  return google.drive({ version: 'v3', auth: oauth2Client });
}

// ============================================================
// HELPERS
// ============================================================
function extrairIdDrive(url) {
  // Suporta formatos:
  // https://drive.google.com/drive/folders/ID
  // https://drive.google.com/drive/u/0/folders/ID
  const match = url.match(/folders\/([a-zA-Z0-9_-]+)/);
  if (match) return match[1];

  // ID directo (sem URL)
  if (/^[a-zA-Z0-9_-]{25,}$/.test(url.trim())) return url.trim();

  return null;
}

function gerarToken() {
  return Math.random().toString(36).substring(2) + Date.now().toString(36);
}

function gerarToken8() {
  return String(Math.floor(10568000 + Math.random() * 90813000));
}

// ── HEALTH CHECK ─────────────────────────────────────────────
app.get('/', (req, res) => res.json({ ok: true, servico: 'faturascan-backend' }));

// ── START ─────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`FaturaScan backend a correr na porta ${PORT}`);
});
