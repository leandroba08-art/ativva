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

const jwtSecret = process.env.JWT_SECRET || "segredo";

// =========================
// HELPERS
// =========================
const sha256 = (text) =>
  crypto.createHash("sha256").update(text).digest("hex");

// =========================
// AUTH EMPRESA
// =========================
const authMiddleware = (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: "Token não fornecido" });

  const token = auth.split(" ")[1];

  try {
    req.user = jwt.verify(token, jwtSecret);
    next();
  } catch {
    res.status(401).json({ error: "Token inválido" });
  }
};

// =========================
// AUTH ATENDENTE
// =========================
const attendantAuth = (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: "Token não fornecido" });

  const token = auth.split(" ")[1];

  try {
    const decoded = jwt.verify(token, jwtSecret);
    if (decoded.type !== "attendant")
      return res.status(403).json({ error: "Token inválido para atendente" });

    req.attendant = decoded;
    next();
  } catch {
    res.status(401).json({ error: "Token inválido" });
  }
};

// =========================
// ROOT
// =========================
app.get("/", (req, res) => {
  res.json({
    ok: true,
    service: "ativva-api",
  });
});

// =========================
// HEALTH
// =========================
app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true });
  } catch (e) {
    res.json({ ok: false, error: e.message });
  }
});

// =========================
// REGISTER EMPRESA
// =========================
app.post("/register", async (req, res) => {
  try {
    const { name, email, password, prompt } = req.body;

    const password_hash = sha256(password);

    const company_key =
      name.toLowerCase().replace(/\s+/g, "-") + "-" + Date.now();

    const api_key =
      "ativva_sk_" + crypto.randomBytes(16).toString("hex");

    const result = await pool.query(
      `INSERT INTO companies
       (name,email,password_hash,company_key,prompt,api_key)
       VALUES ($1,$2,$3,$4,$5,$6)
       RETURNING id,name,email,company_key,api_key`,
      [name, email, password_hash, company_key, prompt, api_key]
    );

    res.json(result.rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// =========================
// LOGIN EMPRESA
// =========================
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const password_hash = sha256(password);

  const result = await pool.query(
    "SELECT * FROM companies WHERE email = $1",
    [email]
  );

  if (!result.rows.length)
    return res.status(404).json({ error: "Email não encontrado" });

  const user = result.rows[0];

  if (user.password_hash !== password_hash)
    return res.status(401).json({ error: "Senha incorreta" });

  const token = jwt.sign(
    { id: user.id, company_key: user.company_key },
    jwtSecret,
    { expiresIn: "7d" }
  );

  res.json({
    token,
    company_key: user.company_key,
    api_key: user.api_key,
  });
});

// =========================
// WEBHOOK COM IA DECISÃO
// =========================
app.post("/webhook/:companyKey", async (req, res) => {
  try {
    const { companyKey } = req.params;
    const { phone, message } = req.body;

    const companyRes = await pool.query(
      "SELECT * FROM companies WHERE company_key = $1",
      [companyKey]
    );

    if (!companyRes.rows.length)
      return res.status(404).json({ error: "company_key inválida" });

    const company = companyRes.rows[0];

    if (req.headers["x-api-key"] !== company.api_key)
      return res.status(403).json({ error: "API Key inválida" });

    // CLASSIFICAÇÃO
    const classification = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        {
          role: "system",
          content:
            'Responda apenas com HUMAN ou AI. HUMAN se cliente quiser atendente.',
        },
        { role: "user", content: message },
      ],
    });

    const decision =
      classification.choices[0].message.content.trim().toUpperCase();

    // BUSCAR/CRIAR CONVERSA
    let conv = await pool.query(
      `SELECT id FROM conversations
       WHERE company_id=$1 AND user_phone=$2
       ORDER BY id DESC LIMIT 1`,
      [company.id, phone]
    );

    let conversationId;

    if (!conv.rows.length) {
      const newConv = await pool.query(
        `INSERT INTO conversations (company_id,user_phone,status)
         VALUES ($1,$2,'open') RETURNING id`,
        [company.id, phone]
      );
      conversationId = newConv.rows[0].id;
    } else {
      conversationId = conv.rows[0].id;
    }

    await pool.query(
      `INSERT INTO messages (conversation_id,sender,content)
       VALUES ($1,'user',$2)`,
      [conversationId, message]
    );

    if (decision === "HUMAN") {
      await pool.query(
        `UPDATE conversations SET status='human' WHERE id=$1`,
        [conversationId]
      );

      return res.json({
        handoff: true,
        message: "Vou transferir você para um atendente humano.",
      });
    }

    // RESPONDER IA
    const ai = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: company.prompt },
        { role: "user", content: message },
      ],
    });

    const reply =
      ai.choices[0].message.content || "Sem resposta.";

    await pool.query(
      `INSERT INTO messages (conversation_id,sender,content)
       VALUES ($1,'ai',$2)`,
      [conversationId, reply]
    );

    res.json({ handoff: false, reply });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// =========================
// ENCERRAR CONVERSA
// =========================
app.put("/conversations/:id/close", authMiddleware, async (req, res) => {
  await pool.query(
    "UPDATE conversations SET status='closed' WHERE id=$1",
    [req.params.id]
  );
  res.json({ message: "Conversa encerrada" });
});

// =========================
// REABRIR CONVERSA
// =========================
app.put("/conversations/:id/reopen", authMiddleware, async (req, res) => {
  await pool.query(
    "UPDATE conversations SET status='open' WHERE id=$1",
    [req.params.id]
  );
  res.json({ message: "Conversa reaberta" });
});

// =========================
// 404
// =========================
app.use((req, res) => {
  res.status(404).json({ error: "Rota não encontrada" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Servidor rodando na porta " + PORT));