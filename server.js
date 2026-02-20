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
// MIDDLEWARE DE AUTENTICAÇÃO (JWT)
// =========================
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ error: "Token não fornecido" });
  }

  const parts = authHeader.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer") {
    return res.status(401).json({ error: "Formato do token inválido. Use: Bearer <token>" });
  }

  const token = parts[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "segredo");
    req.user = decoded; // { id, email, company_key, iat, exp }
    next();
  } catch (e) {
    return res.status(401).json({ error: "Token inválido" });
  }
};

// =========================
// HELPER: garantir isolamento por empresa (multi-tenant)
// =========================
const getCompanyIdFromToken = (req) => {
  // No seu login, você assina token com { id: user.id } (onde user.id = companies.id)
  return Number(req.user?.id);
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

      // Atendimento Humano (Painel)
      conversations: "GET /conversations?status=open (protected)",
      conversationMessages: "GET /conversations/:id/messages (protected)",
      assignConversation: "PUT /conversations/:id/assign (protected)",
      sendManualMessage: "POST /conversations/:id/messages (protected)",
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
// REGISTER (gera company_key + api_key)
// =========================
app.post("/register", async (req, res) => {
  try {
    const { name, email, password, prompt } = req.body;

    if (!name || !email || !password || !prompt) {
      return res.status(400).json({
        error: "Campos obrigatórios: name, email, password, prompt",
      });
    }

    const password_hash = crypto
      .createHash("sha256")
      .update(password)
      .digest("hex");

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
// LOGIN
// =========================
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Informe email e password" });
    }

    const password_hash = crypto
      .createHash("sha256")
      .update(password)
      .digest("hex");

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
      process.env.JWT_SECRET || "segredo",
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
// ROTA PROTEGIDA /ME
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
      return res.status(401).json({ error: "API Key não fornecida (use header x-api-key)" });
    }
    if (clientApiKey !== company.api_key) {
      return res.status(403).json({ error: "API Key inválida" });
    }

    // 3) Verificar/abrir conversa
    let conversationRes = await pool.query(
      `SELECT id FROM conversations
       WHERE company_id = $1 AND user_phone = $2 AND status = 'open'
       ORDER BY id DESC
       LIMIT 1`,
      [company.id, phone]
    );

    let conversationId;

    if (conversationRes.rows.length === 0) {
      const newConversation = await pool.query(
        `INSERT INTO conversations (company_id, user_phone, status)
         VALUES ($1, $2, 'open')
         RETURNING id`,
        [company.id, phone]
      );

      conversationId = newConversation.rows[0].id;
    } else {
      conversationId = conversationRes.rows[0].id;
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

    const aiReply = ai.choices?.[0]?.message?.content?.trim() || "Sem resposta.";

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
// ✅ ATENDIMENTO HUMANO (Painel) - ROTAS PROTEGIDAS (JWT)
// =======================================================

// 1) Listar conversas da empresa
app.get("/conversations", authMiddleware, async (req, res) => {
  try {
    const companyId = getCompanyIdFromToken(req);
    const { status } = req.query;

    // filtro opcional por status
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

// 2) Listar mensagens de uma conversa
app.get("/conversations/:id/messages", authMiddleware, async (req, res) => {
  try {
    const companyId = getCompanyIdFromToken(req);
    const conversationId = Number(req.params.id);

    // garante que a conversa pertence à empresa
    const conv = await pool.query(
      `SELECT id FROM conversations WHERE id = $1 AND company_id = $2`,
      [conversationId, companyId]
    );
    if (conv.rows.length === 0) {
      return res.status(404).json({ error: "Conversa não encontrada para esta empresa" });
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

// 3) Atribuir conversa a um atendente (assumir)
app.put("/conversations/:id/assign", authMiddleware, async (req, res) => {
  try {
    const companyId = getCompanyIdFromToken(req);
    const conversationId = Number(req.params.id);
    const { attendant_id } = req.body;

    if (!attendant_id) {
      return res.status(400).json({ error: "attendant_id é obrigatório" });
    }

    // garante que a conversa é da empresa
    const updated = await pool.query(
      `UPDATE conversations
       SET assigned_attendant_id = $1,
           status = 'human'
       WHERE id = $2 AND company_id = $3
       RETURNING id, company_id, user_phone, status, assigned_attendant_id, created_at`,
      [Number(attendant_id), conversationId, companyId]
    );

    if (updated.rows.length === 0) {
      return res.status(404).json({ error: "Conversa não encontrada para esta empresa" });
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

// 4) Enviar mensagem manual como atendente
app.post("/conversations/:id/messages", authMiddleware, async (req, res) => {
  try {
    const companyId = getCompanyIdFromToken(req);
    const conversationId = Number(req.params.id);
    const { content } = req.body;

    if (!content) {
      return res.status(400).json({ error: "content é obrigatório" });
    }

    // garante que a conversa pertence à empresa
    const conv = await pool.query(
      `SELECT id, user_phone, status FROM conversations WHERE id = $1 AND company_id = $2`,
      [conversationId, companyId]
    );
    if (conv.rows.length === 0) {
      return res.status(404).json({ error: "Conversa não encontrada para esta empresa" });
    }

    // salva mensagem do atendente
    const msg = await pool.query(
      `INSERT INTO messages (conversation_id, sender, content)
       VALUES ($1, 'attendant', $2)
       RETURNING id, conversation_id, sender, content, created_at`,
      [conversationId, content]
    );

    // (FUTURO) Aqui entra: enviar essa mensagem pro WhatsApp

    return res.json({
      message: "Mensagem enviada pelo atendente",
      sent: msg.rows[0],
    });
  } catch (e) {
    console.error("Erro ao enviar mensagem do atendente:", e);
    return res.status(500).json({ error: e.message });
  }
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