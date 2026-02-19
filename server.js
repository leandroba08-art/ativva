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
// MIDDLEWARE DE AUTENTICAÇÃO
// =========================
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ error: "Token não fornecido" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "segredo");

    req.user = decoded; 
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
      webhook: "POST /webhook/:companyKey (secured with API Key)",
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
// REGISTER (gera API KEY)
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

    // gerar API key
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
// LISTAR EMPRESAS
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
// WEBHOOK (agora com API KEY)
// =========================
app.post("/webhook/:companyKey", async (req, res) => {
  try {
    const { companyKey } = req.params;
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({ error: "Campo obrigatório: message" });
    }

    // verificar empresa
    const companyRes = await pool.query(
      "SELECT id, name, prompt, api_key FROM companies WHERE company_key = $1",
      [companyKey]
    );

    if (companyRes.rows.length === 0) {
      return res.status(404).json({ error: "company_key inválida" });
    }

    const company = companyRes.rows[0];

    // validar API key recebida
    const clientApiKey = req.headers["x-api-key"];

    if (!clientApiKey) {
      return res.status(401).json({ error: "API Key não fornecida" });
    }

    if (clientApiKey !== company.api_key) {
      return res.status(403).json({ error: "API Key inválida" });
    }

    // chamada real à IA
    const response = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: company.prompt },
        { role: "user", content: message },
      ],
    });

    const aiReply =
      response.choices?.[0]?.message?.content?.trim() || "Sem resposta.";

    await pool.query(
      `INSERT INTO conversations (company_id, user_message, ai_response)
       VALUES ($1, $2, $3)`,
      [company.id, message, aiReply]
    );

    res.json({
      company: { id: company.id, name: company.name },
      reply: aiReply,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
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