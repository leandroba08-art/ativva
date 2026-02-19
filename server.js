// server.js (COMPLETO)
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const pool = require("./db");

const OpenAI = require("openai");
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

const app = express();

app.use(cors());
app.use(express.json());

// ✅ Rota raiz (para parar o 404 na URL base e mostrar que está vivo)
app.get("/", (req, res) => {
  res.json({
    ok: true,
    service: "ativva-api",
    routes: {
      health: "GET /health",
      register: "POST /register",
      companies: "GET /companies",
      webhook: "POST /webhook/:companyKey",
    },
  });
});

// ✅ Healthcheck (testa se API e DB estão OK)
app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    return res.json({ ok: true, db: true });
  } catch (e) {
    return res.json({ ok: false, db: false, error: e.message });
  }
});

// ✅ Criar empresa/cliente (multi-tenant)
app.post("/register", async (req, res) => {
  try {
    const { name, email, password, prompt } = req.body;

    if (!name || !email || !password || !prompt) {
      return res.status(400).json({
        error: "Campos obrigatórios: name, email, password, prompt",
      });
    }

    // 🔐 LOGIN (gera token JWT)
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email e senha obrigatórios." });
    }

    // Hash da senha enviada
    const password_hash = crypto
      .createHash("sha256")
      .update(password)
      .digest("hex");

    // Busca empresa pelo email
    const userRes = await pool.query(
      "SELECT id, name, email, password_hash FROM companies WHERE email = $1",
      [email]
    );

    if (userRes.rows.length === 0) {
      return res.status(401).json({ error: "Credenciais inválidas." });
    }

    const user = userRes.rows[0];

    if (user.password_hash !== password_hash) {
      return res.status(401).json({ error: "Credenciais inválidas." });
    }

    // Gerar token JWT
    const jwt = require("jsonwebtoken");
    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "2h" }
    );

    return res.json({
      message: "Login realizado com sucesso",
      token,
      user: { id: user.id, name: user.name, email: user.email }
    });
  } catch (e) {
    console.error("❌ /login error:", e);
    return res.status(500).json({ error: e.message });
  }
});

    // Simples (MVP). Depois a gente troca por bcrypt + JWT.
    const password_hash = crypto.createHash("sha256").update(password).digest("hex");

    const company_key = `${name
      .toLowerCase()
      .replace(/\s+/g, "-")
      .replace(/[^a-z0-9\-]/g, "")}-${Date.now()}`;

    const result = await pool.query(
      `INSERT INTO companies (name, email, password_hash, company_key, prompt)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, name, email, company_key, prompt, created_at`,
      [name, email, password_hash, company_key, prompt]
    );

    return res.json({ company: result.rows[0] });
  } catch (e) {
    // Email duplicado (constraint unique)
    if (e.code === "23505") {
      return res.status(409).json({ error: "Email já cadastrado." });
    }
    return res.status(500).json({ error: e.message });
  }
});

// ✅ Listar empresas (para pegar o company_key)
app.get("/companies", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, name, email, company_key, created_at FROM companies ORDER BY id ASC"
    );
    return res.json(result.rows);
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// ✅ Webhook com IA real (usa prompt salvo no banco)
// Chamada: POST /webhook/:companyKey  body: { "message": "..." }
app.post("/webhook/:companyKey", async (req, res) => {
  try {
    const { companyKey } = req.params;
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({ error: "Campo obrigatório: message" });
    }

    // Busca empresa pelo company_key
    const companyRes = await pool.query(
      "SELECT id, name, prompt FROM companies WHERE company_key = $1",
      [companyKey]
    );

    if (companyRes.rows.length === 0) {
      return res.status(404).json({ error: "company_key inválida" });
    }

    const company = companyRes.rows[0];

    // Chamada real à IA
    const response = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: company.prompt },
        { role: "user", content: message },
      ],
    });

    const aiReply = response.choices?.[0]?.message?.content?.trim() || "Sem resposta.";

    // Salva conversa
    await pool.query(
      `INSERT INTO conversations (company_id, user_message, ai_response)
       VALUES ($1, $2, $3)`,
      [company.id, message, aiReply]
    );

    return res.json({
      company: { id: company.id, name: company.name },
      reply: aiReply,
    });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// ✅ Fallback 404 em JSON
app.use((req, res) => {
  res.status(404).json({ error: "Rota não encontrada" });
});

const PORT = Number(process.env.PORT || 3000);
app.listen(PORT, () => {
  console.log(`🔥 Servidor rodando na porta ${PORT}`);
});

// ==========================
// LOGIN
// ==========================
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Informe email e password" });
    }

    // Hash da senha enviada
    const password_hash = crypto
      .createHash("sha256")
      .update(password)
      .digest("hex");

    // Buscar usuário na tabela companies
    const result = await pool.query(
      "SELECT id, name, email, password_hash, company_key FROM companies WHERE email = $1",
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Email não encontrado" });
    }

    const user = result.rows[0];

    // Comparar hash
    if (user.password_hash !== password_hash) {
      return res.status(401).json({ error: "Senha incorreta" });
    }

    // Gerar token JWT (opcional)
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
      },
      token,
    });

  } catch (e) {
    console.error("Erro no login:", e);
    return res.status(500).json({ error: e.message });
  }
});