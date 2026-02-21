console.log("ZAPI_INSTANCE_ID:", process.env.ZAPI_INSTANCE_ID);
console.log("ZAPI_TOKEN:", process.env.ZAPI_TOKEN ? "OK" : "MISSING");
console.log("ZAPI_CLIENT_TOKEN:", process.env.ZAPI_CLIENT_TOKEN ? "OK" : "MISSING");

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

const ZAPI_INSTANCE_ID = process.env.ZAPI_INSTANCE_ID;
const ZAPI_TOKEN = process.env.ZAPI_TOKEN;

// =========================
// HELPERS
// =========================
const sha256 = (text) =>
  crypto.createHash("sha256").update(text).digest("hex");

async function sendZapiMessage(phone, text) {
  const url = `https://api.z-api.io/instances/${ZAPI_INSTANCE_ID}/token/${ZAPI_TOKEN}/send-text`;

  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      phone,
      message: text,
    }),
  });

  const data = await response.json();

  if (!response.ok) {
    console.error("Erro envio Z-API:", data);
    throw new Error("Erro Z-API");
  }

  return data;
}

// =========================
// ROOT
// =========================
app.get("/", (req, res) => {
  res.json({ ok: true, service: "ativva-api" });
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
// WEBHOOK Z-API
// =========================
app.post("/zapi/webhook", async (req, res) => {
  try {
    console.log("📩 ZAPI PAYLOAD:", JSON.stringify(req.body, null, 2));

    res.sendStatus(200); // responde rápido

    const body = req.body;

    // 🔎 Ajuste automático para diferentes formatos
    const phone =
      body.phone ||
      body.from ||
      body?.data?.phone ||
      body?.data?.from;

    const message =
      body.message ||
      body.body ||
      body?.text?.message ||
      body?.data?.message ||
      body?.data?.text?.message;

    if (!phone || !message) {
      console.log("⚠️ Payload ignorado");
      return;
    }

    // =========================
    // BUSCAR EMPRESA (MVP: primeira)
    // =========================
    const companyRes = await pool.query(
      "SELECT * FROM companies ORDER BY id ASC LIMIT 1"
    );

    if (!companyRes.rows.length) return;
    const company = companyRes.rows[0];

    // =========================
    // BUSCAR OU CRIAR CONVERSA
    // =========================
    let conv = await pool.query(
      `SELECT id,status FROM conversations
       WHERE company_id=$1 AND user_phone=$2
       ORDER BY id DESC LIMIT 1`,
      [company.id, phone]
    );

    let conversationId;
    let currentStatus;

    if (!conv.rows.length) {
      const newConv = await pool.query(
        `INSERT INTO conversations (company_id,user_phone,status)
         VALUES ($1,$2,'open') RETURNING id,status`,
        [company.id, phone]
      );
      conversationId = newConv.rows[0].id;
      currentStatus = newConv.rows[0].status;
    } else {
      conversationId = conv.rows[0].id;
      currentStatus = conv.rows[0].status;
    }

    // Salvar mensagem usuário
    await pool.query(
      `INSERT INTO messages (conversation_id,sender,content)
       VALUES ($1,'user',$2)`,
      [conversationId, message]
    );

    // =========================
    // SE JÁ ESTÁ HUMANO
    // =========================
    if (currentStatus === "human") {
      await sendZapiMessage(
        phone,
        "Um atendente humano irá responder você em instantes."
      );
      return;
    }

    // =========================
    // CLASSIFICAÇÃO IA
    // =========================
    const classification = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        {
          role: "system",
          content:
            'Responda apenas HUMAN ou AI. HUMAN se cliente quiser atendente.',
        },
        { role: "user", content: message },
      ],
    });

    const decision =
      classification.choices[0].message.content.trim().toUpperCase();

    if (decision === "HUMAN") {
      await pool.query(
        `UPDATE conversations SET status='human' WHERE id=$1`,
        [conversationId]
      );

      await sendZapiMessage(
        phone,
        "Vou transferir você para um atendente humano."
      );

      return;
    }

    // =========================
    // RESPOSTA IA
    // =========================
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

    await sendZapiMessage(phone, reply);

  } catch (e) {
    console.error("❌ Erro Z-API webhook:", e);
  }
});

// =========================
// 404
// =========================
app.use((req, res) => {
  res.status(404).json({ error: "Rota não encontrada" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("🔥 Servidor rodando na porta " + PORT));