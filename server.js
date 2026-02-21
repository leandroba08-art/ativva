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
// CONFIG Z-API (ENV)
// =========================
const ZAPI_INSTANCE_ID = process.env.ZAPI_INSTANCE_ID;
const ZAPI_INSTANCE_TOKEN = process.env.ZAPI_INSTANCE_TOKEN;
const ZAPI_CLIENT_TOKEN = process.env.ZAPI_CLIENT_TOKEN;

// Node 18+ tem fetch global. No Render costuma ter.
// Se não tiver, instale node-fetch e importe.
async function sendZapiMessage({ phone, message }) {
  if (!ZAPI_INSTANCE_ID || !ZAPI_INSTANCE_TOKEN) {
    throw new Error("Z-API instanceId/instanceToken não configurados no ENV");
  }
  if (!ZAPI_CLIENT_TOKEN) {
    throw new Error("Z-API client-token não configurado no ENV");
  }

  const url = `https://api.z-api.io/instances/${ZAPI_INSTANCE_ID}/token/${ZAPI_INSTANCE_TOKEN}/send-text`;

  const resp = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "client-token": ZAPI_CLIENT_TOKEN, // ✅ ESTE HEADER é obrigatório
    },
    body: JSON.stringify({
      phone, // ex: 557488492703
      message,
    }),
  });

  const data = await resp.json().catch(() => ({}));

  if (!resp.ok) {
    console.error("Erro envio Z-API:", data);
    throw new Error("Erro Z-API");
  }

  return data;
}

// =========================
// AUTH MIDDLEWARE (JWT)
// =========================
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) return res.status(401).json({ error: "Token não fornecido" });

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "segredo");
    req.user = decoded;
    next();
  } catch {
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
      conversations: "GET /conversations (protected)",
      conversation_messages: "GET /conversations/:id/messages (protected)",
      close_conversation: "POST /conversations/:id/close (protected)",
      webhook_company: "POST /webhook/:companyKey (x-api-key)",
      zapi_webhook: "POST /zapi/webhook (Z-API -> ATIVVA)",
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
// REGISTER
// =========================
app.post("/register", async (req, res) => {
  try {
    const { name, email, password, prompt } = req.body;

    if (!name || !email || !password || !prompt) {
      return res.status(400).json({
        error: "Campos obrigatórios: name, email, password, prompt",
      });
    }

    const password_hash = crypto.createHash("sha256").update(password).digest("hex");

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
    if (e.code === "23505") return res.status(409).json({ error: "Email já cadastrado." });
    res.status(500).json({ error: e.message });
  }
});

// =========================
// LOGIN
// =========================
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Informe email e password" });

    const password_hash = crypto.createHash("sha256").update(password).digest("hex");

    const result = await pool.query(
      "SELECT id, name, email, password_hash, company_key, api_key FROM companies WHERE email = $1",
      [email]
    );

    if (result.rows.length === 0) return res.status(404).json({ error: "Email não encontrado" });

    const user = result.rows[0];
    if (user.password_hash !== password_hash) return res.status(401).json({ error: "Senha incorreta" });

    const token = jwt.sign(
      { id: user.id, email: user.email, company_key: user.company_key },
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
// /ME
// =========================
app.get("/me", authMiddleware, (req, res) => {
  res.json({ message: "Usuário autenticado", user: req.user });
});

// =========================
// /COMPANIES
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
// LISTAR CONVERSAS (painel)
// =========================
app.get("/conversations", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, company_id, user_phone, status, assigned_attendant_id, created_at
       FROM conversations
       ORDER BY id DESC
       LIMIT 200`
    );
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// =========================
// LISTAR MENSAGENS DE UMA CONVERSA
// =========================
app.get("/conversations/:id/messages", authMiddleware, async (req, res) => {
  try {
    const conversationId = Number(req.params.id);
    const result = await pool.query(
      `SELECT id, conversation_id, sender, content, created_at
       FROM messages
       WHERE conversation_id = $1
       ORDER BY id ASC`,
      [conversationId]
    );
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// =========================
// ENCERRAR CONVERSA (MVP)
// =========================
app.post("/conversations/:id/close", authMiddleware, async (req, res) => {
  try {
    const conversationId = Number(req.params.id);

    // Se sua tabela tiver status:
    await pool.query(
      `UPDATE conversations
       SET status = 'closed'
       WHERE id = $1`,
      [conversationId]
    );

    return res.json({ ok: true, message: "Conversa encerrada", conversation_id: conversationId });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// =========================
// WEBHOOK EXTERNO (x-api-key) - mantém o que já tinha
// =========================
app.post("/webhook/:companyKey", async (req, res) => {
  try {
    const { companyKey } = req.params;
    const { phone, message } = req.body;

    if (!phone || !message) {
      return res.status(400).json({ error: "Campos obrigatórios: phone, message" });
    }

    const companyRes = await pool.query(
      "SELECT id, name, prompt, api_key FROM companies WHERE company_key = $1",
      [companyKey]
    );
    if (companyRes.rows.length === 0) return res.status(404).json({ error: "company_key inválida" });

    const company = companyRes.rows[0];

    const clientApiKey = req.headers["x-api-key"];
    if (!clientApiKey) return res.status(401).json({ error: "API Key não fornecida" });
    if (clientApiKey !== company.api_key) return res.status(403).json({ error: "API Key inválida" });

    const response = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: company.prompt },
        { role: "user", content: message },
      ],
    });

    const aiReply = response.choices?.[0]?.message?.content?.trim() || "Sem resposta.";

    // salva no modelo simples (conversations com user_message/ai_response)
    await pool.query(
      `INSERT INTO conversations (company_id, user_message, ai_response)
       VALUES ($1, $2, $3)`,
      [company.id, message, aiReply]
    );

    res.json({ company: { id: company.id, name: company.name }, reply: aiReply });
  } catch (e) {
    console.error("Erro webhook:", e);
    res.status(500).json({ error: e.message });
  }
});

// =========================
// Z-API WEBHOOK (principal)
// =========================
app.post("/zapi/webhook", async (req, res) => {
  try {
    console.log("📩 ZAPI PAYLOAD:", JSON.stringify(req.body, null, 2));

    // A Z-API manda a mensagem aqui:
    const phone = req.body?.phone; // ex: 557488492703
    const incomingText = req.body?.text?.message; // "Oi"

    if (!phone || !incomingText) {
      return res.status(200).json({ ok: true, ignored: true, reason: "Sem phone/text.message" });
    }

    // ✅ MVP: se você tiver só 1 empresa, use company_key fixo via ENV:
    // process.env.DEFAULT_COMPANY_KEY = minha-empresa-...
    // (ou depois a gente mapeia instanceId -> company_id)
    const DEFAULT_COMPANY_KEY = process.env.DEFAULT_COMPANY_KEY;
    if (!DEFAULT_COMPANY_KEY) {
      return res.status(500).json({ error: "DEFAULT_COMPANY_KEY não configurado no Render" });
    }

    const companyRes = await pool.query(
      "SELECT id, name, prompt FROM companies WHERE company_key = $1",
      [DEFAULT_COMPANY_KEY]
    );
    if (companyRes.rows.length === 0) {
      return res.status(500).json({ error: "DEFAULT_COMPANY_KEY inválido no banco" });
    }
    const company = companyRes.rows[0];

    // 1) acha conversa aberta
    const conversationRes = await pool.query(
      `SELECT id, status, assigned_attendant_id
       FROM conversations
       WHERE company_id = $1 AND user_phone = $2
       ORDER BY id DESC
       LIMIT 1`,
      [company.id, phone]
    );

    let conversationId;
    let status = "open";
    let assignedAttendantId = null;

    if (conversationRes.rows.length === 0) {
      const newConversation = await pool.query(
        `INSERT INTO conversations (company_id, user_phone, status)
         VALUES ($1, $2, 'open')
         RETURNING id, status, assigned_attendant_id`,
        [company.id, phone]
      );
      conversationId = newConversation.rows[0].id;
      status = newConversation.rows[0].status;
      assignedAttendantId = newConversation.rows[0].assigned_attendant_id;
    } else {
      conversationId = conversationRes.rows[0].id;
      status = conversationRes.rows[0].status;
      assignedAttendantId = conversationRes.rows[0].assigned_attendant_id;
    }

    // 2) salva msg do usuário
    await pool.query(
      `INSERT INTO messages (conversation_id, sender, content)
       VALUES ($1, 'user', $2)`,
      [conversationId, incomingText]
    );

    // 3) DECISÃO IA vs HUMANO (✅ aqui é o ponto do seu problema)
    console.log("DEBUG CONVERSATION:");
console.log("status:", status);
console.log("assigned_attendant_id:", assignedAttendantId);
    const shouldUseHuman = status !== "open" || assignedAttendantId !== null;

    if (shouldUseHuman) {
      const humanMsg = "Um atendente humano irá responder você em instantes.";
      await sendZapiMessage({ phone, message: humanMsg });

      await pool.query(
        `INSERT INTO messages (conversation_id, sender, content)
         VALUES ($1, 'system', $2)`,
        [conversationId, humanMsg]
      );

      return res.status(200).json({ ok: true, mode: "human", conversation_id: conversationId });
    }

    // 4) IA responde
    const aiResp = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: company.prompt },
        { role: "user", content: incomingText },
      ],
    });

    const aiReply = aiResp.choices?.[0]?.message?.content?.trim() || "Sem resposta.";

    // 5) salva msg IA
    await pool.query(
      `INSERT INTO messages (conversation_id, sender, content)
       VALUES ($1, 'ai', $2)`,
      [conversationId, aiReply]
    );

    // 6) envia no WhatsApp
    await sendZapiMessage({ phone, message: aiReply });

    return res.status(200).json({ ok: true, mode: "ai", conversation_id: conversationId, reply: aiReply });
  } catch (e) {
    console.error("❌ Erro Z-API webhook:", e);
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