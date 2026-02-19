require("dotenv").config();
const express = require("express");
const cors = require("cors");
const pool = require("./db");
const OpenAI = require("openai");

const app = express();
app.use(cors());
app.use(express.json());

// OpenAI client
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

/**
 * GET /health
 * - Testa se o servidor está no ar e se o banco conecta
 */
app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, db: true });
  } catch (e) {
    res.status(500).json({ ok: false, db: false, error: e.message });
  }
});

/**
 * POST /register
 * - Cadastra uma empresa no banco
 * Body JSON:
 * {
 *   "name": "...",
 *   "email": "...",
 *   "password": "...",
 *   "prompt": "..."
 * }
 */
app.post("/register", async (req, res) => {
  try {
    const { name, email, password, prompt } = req.body;

    if (!name || !email || !password || !prompt) {
      return res.status(400).json({
        error: "Campos obrigatórios: name, email, password, prompt",
      });
    }

    // MVP: salvar senha sem hash (vamos melhorar com bcrypt depois)
    const password_hash = password;

    const company_key =
      name.toLowerCase().replace(/[^a-z0-9]+/g, "") + "-" + Date.now();

    const result = await pool.query(
      `INSERT INTO companies (name, email, password_hash, company_key, prompt)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, name, email, company_key, prompt, created_at`,
      [name, email, password_hash, company_key, prompt]
    );

    return res.status(201).json({
      message: "Empresa cadastrada com sucesso",
      company: result.rows[0],
    });
  } catch (e) {
    if (String(e.message).includes("duplicate key")) {
      return res.status(409).json({ error: "Email já cadastrado" });
    }
    return res.status(500).json({ error: e.message });
  }
});

/**
 * GET /companies
 * - Lista empresas para você copiar o company_key
 */
app.get("/companies", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, name, email, company_key, created_at FROM companies ORDER BY id DESC"
    );
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/**
 * POST /webhook/:companyKey
 * - Busca empresa pelo company_key
 * - Usa IA real com prompt salvo no banco
 * - Salva conversa em conversations
 *
 * Body JSON:
 * { "message": "..." }
 */
app.post("/webhook/:companyKey", async (req, res) => {
  try {
    const { companyKey } = req.params;
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({ error: "Campo obrigatório: message" });
    }

    // Buscar empresa no banco
    const c = await pool.query(
      "SELECT id, name, prompt FROM companies WHERE company_key = $1",
      [companyKey]
    );

    if (c.rows.length === 0) {
      return res.status(404).json({ error: "Empresa não encontrada" });
    }

    const company = c.rows[0];

    // IA real usando o prompt da empresa
    const response = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: company.prompt },
        { role: "user", content: message },
      ],
    });

    const aiReply = response.choices?.[0]?.message?.content || "Sem resposta da IA.";

    // Salvar conversa no banco
    await pool.query(
      "INSERT INTO conversations (company_id, user_message, ai_response) VALUES ($1, $2, $3)",
      [company.id, message, aiReply]
    );

    res.json({ reply: aiReply });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/**
 * Fallback 404
 */
app.use((req, res) => {
  res.status(404).json({ error: "Rota não encontrada" });
});

const PORT = Number(process.env.PORT || 3000);
app.listen(PORT, () => {
  console.log(`🔥 Ativva API rodando em http://localhost:${PORT}`);
});
