require("dotenv").config();

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const pool = require("./db");

const OpenAI = require("openai");
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

const app = express();
app.use(cors());
app.use(express.json());

// =========================
// HELPERS
// =========================
const sha256 = (text) =>
  crypto.createHash("sha256").update(text).digest("hex");

const companyTokenSecret = process.env.JWT_SECRET || "segredo";

// =========================
// MIDDLEWARE DE AUTENTICAÇÃO (EMPRESA)
// =========================
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Token não fornecido" });

  const parts = authHeader.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer") {
    return res
      .status(401)
      .json({ error: "Formato do token inválido. Use: Bearer <token>" });
  }

  const token = parts[1];

  try {
    const decoded = jwt.verify(token, companyTokenSecret);
    // token de empresa: { id: companies.id, email, company_key }
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Token inválido" });
  }
};

const getCompanyIdFromToken = (req) => Number(req.user?.id);

// =========================
// MIDDLEWARE DE AUTENTICAÇÃO (ATENDENTE)
// =========================
const attendantAuthMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Token não fornecido" });

  const parts = authHeader.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer") {
    return res
      .status(401)
      .json({ error: "Formato do token inválido. Use: Bearer <token>" });
  }

  const token = parts[1];

  try {
    const decoded = jwt.verify(token, companyTokenSecret);
    // token atendente: { type:"attendant", attendant_id, company_id, role }
    if (decoded?.type !== "attendant") {
      return res.status(403).json({ error: "Token não é de atendente" });
    }
    req.attendant = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Token inválido" });
  }
};

// =========================
// ROTA RAIZ
// =========================
app.get("/", (req, res) => {
  res.json({
    ok: true,
    service: "ativva-api",
    routes: {
      health: "GET /health",
      register: "POST /register",
      login: "POST /login",
      me: "GET /me (protected)",

      companies: "GET /companies (protected)",
      webhook: "POST /webhook/:companyKey (x-api-key + body phone/message)",

      // Atendimento Humano (Painel Empresa)
      conversations: "GET /conversations?status=open (protected)",
      conversationMessages: "GET /conversations/:id/messages (protected)",
      assignConversation: "PUT /conversations/:id/assign (protected)",
      sendManualMessage: "POST /conversations/:id/messages (protected)",

      // Atendentes (CRUD)
      attendantsCreate: "POST /attendants (protected)",
      attendantsList: "GET /attendants (protected)",
      attendantsUpdate: "PATCH /attendants/:id (protected)",
      attendantsLogin: "POST /attendants/login",
      attendantMe: "GET /attendants/me (attendant token)",
    },
  });
});

// =========================
// HEALTHCHECK
// =========================
app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, db: true });
  } catch (e) {
    res.json({ ok: false, db: false, error: e.message });
  }
});

// =========================
// REGISTER (empresa)
// =========================
app.post("/register", async (req, res) => {
  try {
    const { name, email, password, prompt } = req.body;

    if (!name || !email || !password || !prompt) {
      return res.status(400).json({
        error: "Campos obrigatórios: name, email, password, prompt",
      });
    }

    const password_hash = sha256(password);

    const company_key = `${name
      .toLowerCase()
      .replace(/\s+/g, "-")
      .replace(/[^a-z0-9\-]/g, "")}-${Date.now()}`;

    const api_key = `ativva_sk_${crypto.randomBytes(16).toString("hex")}`;

    const result = await pool.query(
      `INSERT INTO companies (name, email, password_hash, company_key, prompt, api_key)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, name, email, company_key, prompt, api_key, created_at`,
      [name, email, password_hash, company_key, prompt, api_key]
    );

    res.json({ company: result.rows[0] });
  } catch (e) {
    if (e.code === "23505") {
      return res.status(409).json({ error: "Email já cadastrado." });
    }
    res.status(500).json({ error: e.message });
  }
});

// =========================
// LOGIN (empresa)
// =========================
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Informe email e password" });
    }

    const password_hash = sha256(password);

    const result = await pool.query(
      "SELECT id, name, email, password_hash, company_key, api_key FROM companies WHERE email = $1",
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Email não encontrado" });
    }

    const user = result.rows[0];

    if (user.password_hash !== password_hash) {
      return res.status(401).json({ error: "Senha incorreta" });
    }

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        company_key: user.company_key,
      },
      companyTokenSecret,
      { expiresIn: "7d" }
    );

    return res.json({
      message: "Login realizado com sucesso",
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        company_key: user.company_key,
        api_key: user.api_key,
      },
      token,
    });
  } catch (e) {
    console.error("Erro no login:", e);
    res.status(500).json({ error: e.message });
  }
});

// =========================
// /ME (empresa)
// =========================
app.get("/me", authMiddleware, (req, res) => {
  res.json({
    message: "Usuário autenticado",
    user: req.user,
  });
});

// =========================
// LISTAR EMPRESAS (protegido)
// =========================
app.get("/companies", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, name, email, company_key, api_key, created_at FROM companies ORDER BY id ASC"
    );
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// =========================
// WEBHOOK (x-api-key) + Conversas/Mensagens
// =========================
app.post("/webhook/:companyKey", async (req, res) => {
  try {
    const { companyKey } = req.params;
    const { phone, message } = req.body;

    if (!phone || !message) {
      return res.status(400).json({
        error: "Campos obrigatórios: phone, message",
      });
    }

    // 1) Buscar empresa (inclui api_key)
    const companyRes = await pool.query(
      "SELECT id, name, prompt, api_key FROM companies WHERE company_key = $1",
      [companyKey]
    );

    if (companyRes.rows.length === 0) {
      return res.status(404).json({ error: "company_key inválida" });
    }

    const company = companyRes.rows[0];

    // 2) Validar API key recebida
    const clientApiKey = req.headers["x-api-key"];
    if (!clientApiKey) {
      return res
        .status(401)
        .json({ error: "API Key não fornecida (use header x-api-key)" });
    }
    if (clientApiKey !== company.api_key) {
      return res.status(403).json({ error: "API Key inválida" });
    }

    // 3) Verificar/abrir conversa
    const convFind = await pool.query(
      `SELECT id FROM conversations
       WHERE company_id = $1 AND user_phone = $2 AND status = 'open'
       ORDER BY id DESC
       LIMIT 1`,
      [company.id, phone]
    );

    let conversationId;

    if (convFind.rows.length === 0) {
      const newConversation = await pool.query(
        `INSERT INTO conversations (company_id, user_phone, status)
         VALUES ($1, $2, 'open')
         RETURNING id`,
        [company.id, phone]
      );

      conversationId = newConversation.rows[0].id;
    } else {
      conversationId = convFind.rows[0].id;
    }

    // 4) Salvar mensagem do usuário
    await pool.query(
      `INSERT INTO messages (conversation_id, sender, content)
       VALUES ($1, 'user', $2)`,
      [conversationId, message]
    );

    // 5) Gerar resposta IA
    const ai = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: company.prompt },
        { role: "user", content: message },
      ],
    });

    const aiReply =
      ai.choices?.[0]?.message?.content?.trim() || "Sem resposta.";

    // 6) Salvar resposta IA
    await pool.query(
      `INSERT INTO messages (conversation_id, sender, content)
       VALUES ($1, 'ai', $2)`,
      [conversationId, aiReply]
    );

    return res.json({
      conversation_id: conversationId,
      reply: aiReply,
    });
  } catch (e) {
    console.error("Erro no webhook:", e);
    return res.status(500).json({ error: e.message });
  }
});

// =======================================================
// ✅ ATENDIMENTO HUMANO (Painel Empresa) - ROTAS (JWT Empresa)
// =======================================================

// Listar conversas
app.get("/conversations", authMiddleware, async (req, res) => {
  try {
    const companyId = getCompanyIdFromToken(req);
    const { status } = req.query;

    if (status) {
      const r = await pool.query(
        `SELECT id, company_id, user_phone, status, assigned_attendant_id, created_at
         FROM conversations
         WHERE company_id = $1 AND status = $2
         ORDER BY id DESC`,
        [companyId, String(status)]
      );
      return res.json(r.rows);
    }

    const result = await pool.query(
      `SELECT id, company_id, user_phone, status, assigned_attendant_id, created_at
       FROM conversations
       WHERE company_id = $1
       ORDER BY id DESC`,
      [companyId]
    );

    return res.json(result.rows);
  } catch (e) {
    console.error("Erro ao listar conversas:", e);
    return res.status(500).json({ error: e.message });
  }
});

// Mensagens de uma conversa
app.get("/conversations/:id/messages", authMiddleware, async (req, res) => {
  try {
    const companyId = getCompanyIdFromToken(req);
    const conversationId = Number(req.params.id);

    const conv = await pool.query(
      `SELECT id FROM conversations WHERE id = $1 AND company_id = $2`,
      [conversationId, companyId]
    );
    if (conv.rows.length === 0) {
      return res
        .status(404)
        .json({ error: "Conversa não encontrada para esta empresa" });
    }

    const result = await pool.query(
      `SELECT id, conversation_id, sender, content, created_at
       FROM messages
       WHERE conversation_id = $1
       ORDER BY id ASC`,
      [conversationId]
    );

    return res.json(result.rows);
  } catch (e) {
    console.error("Erro ao listar mensagens:", e);
    return res.status(500).json({ error: e.message });
  }
});

// Assumir/Atribuir conversa a um atendente
app.put("/conversations/:id/assign", authMiddleware, async (req, res) => {
  try {
    const companyId = getCompanyIdFromToken(req);
    const conversationId = Number(req.params.id);
    const { attendant_id } = req.body;

    if (!attendant_id) {
      return res.status(400).json({ error: "attendant_id é obrigatório" });
    }

    // valida se atendente pertence à mesma empresa
    const att = await pool.query(
      `SELECT id FROM attendants WHERE id = $1 AND company_id = $2`,
      [Number(attendant_id), companyId]
    );
    if (att.rows.length === 0) {
      return res
        .status(400)
        .json({ error: "attendant_id inválido (não pertence a esta empresa)" });
    }

    const updated = await pool.query(
      `UPDATE conversations
       SET assigned_attendant_id = $1,
           status = 'human'
       WHERE id = $2 AND company_id = $3
       RETURNING id, company_id, user_phone, status, assigned_attendant_id, created_at`,
      [Number(attendant_id), conversationId, companyId]
    );

    if (updated.rows.length === 0) {
      return res
        .status(404)
        .json({ error: "Conversa não encontrada para esta empresa" });
    }

    return res.json({
      message: "Conversa atribuída ao atendente",
      conversation: updated.rows[0],
    });
  } catch (e) {
    console.error("Erro ao atribuir conversa:", e);
    return res.status(500).json({ error: e.message });
  }
});

// Enviar mensagem manual como atendente (registrar no histórico)
app.post("/conversations/:id/messages", authMiddleware, async (req, res) => {
  try {
    const companyId = getCompanyIdFromToken(req);
    const conversationId = Number(req.params.id);
    const { content } = req.body;

    if (!content) {
      return res.status(400).json({ error: "content é obrigatório" });
    }

    const conv = await pool.query(
      `SELECT id FROM conversations WHERE id = $1 AND company_id = $2`,
      [conversationId, companyId]
    );
    if (conv.rows.length === 0) {
      return res
        .status(404)
        .json({ error: "Conversa não encontrada para esta empresa" });
    }

    const msg = await pool.query(
      `INSERT INTO messages (conversation_id, sender, content)
       VALUES ($1, 'attendant', $2)
       RETURNING id, conversation_id, sender, content, created_at`,
      [conversationId, content]
    );

    return res.json({
      message: "Mensagem enviada pelo atendente",
      sent: msg.rows[0],
    });
  } catch (e) {
    console.error("Erro ao enviar mensagem do atendente:", e);
    return res.status(500).json({ error: e.message });
  }
});

// =======================================================
// ✅ CRUD DE ATENDENTES (JWT Empresa)
// =======================================================

// Criar atendente
app.post("/attendants", authMiddleware, async (req, res) => {
  try {
    const companyId = getCompanyIdFromToken(req);
    const { name, email, password, role } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        error: "Campos obrigatórios: name, email, password",
      });
    }

    const password_hash = sha256(password);
    const safeRole = role === "admin" ? "admin" : "agent";

    // garante unicidade por empresa (sem depender de constraint do banco)
    const exists = await pool.query(
      `SELECT id FROM attendants WHERE company_id = $1 AND email = $2`,
      [companyId, email]
    );
    if (exists.rows.length > 0) {
      return res.status(409).json({ error: "Email de atendente já cadastrado nesta empresa." });
    }

    const created = await pool.query(
      `INSERT INTO attendants (company_id, name, email, password_hash, role, status)
       VALUES ($1, $2, $3, $4, $5, 'offline')
       RETURNING id, company_id, name, email, role, status, created_at`,
      [companyId, name, email, password_hash, safeRole]
    );

    return res.json({ attendant: created.rows[0] });
  } catch (e) {
    console.error("Erro ao criar atendente:", e);
    return res.status(500).json({ error: e.message });
  }
});

// Listar atendentes
app.get("/attendants", authMiddleware, async (req, res) => {
  try {
    const companyId = getCompanyIdFromToken(req);

    const result = await pool.query(
      `SELECT id, company_id, name, email, role, status, created_at
       FROM attendants
       WHERE company_id = $1
       ORDER BY id ASC`,
      [companyId]
    );

    return res.json(result.rows);
  } catch (e) {
    console.error("Erro ao listar atendentes:", e);
    return res.status(500).json({ error: e.message });
  }
});

// Atualizar atendente (nome, email, role, status, senha)
app.patch("/attendants/:id", authMiddleware, async (req, res) => {
  try {
    const companyId = getCompanyIdFromToken(req);
    const attendantId = Number(req.params.id);
    const { name, email, role, status, password } = req.body;

    // valida role/status
    const safeRole = role ? (role === "admin" ? "admin" : "agent") : null;
    const safeStatus = status ? (status === "online" ? "online" : "offline") : null;

    // monta update dinâmico
    const fields = [];
    const values = [];
    let i = 1;

    if (name) {
      fields.push(`name = $${i++}`);
      values.push(name);
    }
    if (email) {
      fields.push(`email = $${i++}`);
      values.push(email);
    }
    if (safeRole) {
      fields.push(`role = $${i++}`);
      values.push(safeRole);
    }
    if (safeStatus) {
      fields.push(`status = $${i++}`);
      values.push(safeStatus);
    }
    if (password) {
      fields.push(`password_hash = $${i++}`);
      values.push(sha256(password));
    }

    if (fields.length === 0) {
      return res.status(400).json({ error: "Nenhum campo para atualizar." });
    }

    values.push(attendantId);
    values.push(companyId);

    const updated = await pool.query(
      `UPDATE attendants
       SET ${fields.join(", ")}
       WHERE id = $${i++} AND company_id = $${i++}
       RETURNING id, company_id, name, email, role, status, created_at`,
      values
    );

    if (updated.rows.length === 0) {
      return res.status(404).json({ error: "Atendente não encontrado para esta empresa." });
    }

    return res.json({ attendant: updated.rows[0] });
  } catch (e) {
    console.error("Erro ao atualizar atendente:", e);
    return res.status(500).json({ error: e.message });
  }
});

// =======================================================
// ✅ LOGIN DE ATENDENTE (token próprio)
// =======================================================
app.post("/attendants/login", async (req, res) => {
  try {
    const { email, password, company_key } = req.body;

    if (!email || !password || !company_key) {
      return res.status(400).json({
        error: "Campos obrigatórios: email, password, company_key",
      });
    }

    // achar company_id pelo company_key
    const c = await pool.query(
      `SELECT id FROM companies WHERE company_key = $1`,
      [company_key]
    );
    if (c.rows.length === 0) {
      return res.status(404).json({ error: "company_key inválida" });
    }

    const companyId = c.rows[0].id;
    const password_hash = sha256(password);

    const att = await pool.query(
      `SELECT id, company_id, name, email, password_hash, role, status
       FROM attendants
       WHERE company_id = $1 AND email = $2
       LIMIT 1`,
      [companyId, email]
    );

    if (att.rows.length === 0) {
      return res.status(401).json({ error: "Credenciais inválidas." });
    }

    const attendant = att.rows[0];
    if (attendant.password_hash !== password_hash) {
      return res.status(401).json({ error: "Credenciais inválidas." });
    }

    const token = jwt.sign(
      {
        type: "attendant",
        attendant_id: attendant.id,
        company_id: attendant.company_id,
        role: attendant.role,
      },
      companyTokenSecret,
      { expiresIn: "7d" }
    );

    return res.json({
      message: "Login do atendente realizado com sucesso",
      attendant: {
        id: attendant.id,
        company_id: attendant.company_id,
        name: attendant.name,
        email: attendant.email,
        role: attendant.role,
        status: attendant.status,
      },
      token,
    });
  } catch (e) {
    console.error("Erro no login do atendente:", e);
    return res.status(500).json({ error: e.message });
  }
});

// info do atendente logado
app.get("/attendants/me", attendantAuthMiddleware, (req, res) => {
  return res.json({
    message: "Atendente autenticado",
    attendant: req.attendant,
  });
});

// =========================
// 404
// =========================
app.use((req, res) => {
  res.status(404).json({ error: "Rota não encontrada" });
});

const PORT = Number(process.env.PORT || 3000);
app.listen(PORT, () => {
  console.log(`🔥 Servidor rodando na porta ${PORT}`);
});