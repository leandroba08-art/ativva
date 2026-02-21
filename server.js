const jwt = require("jsonwebtoken");
const pool = require("./db");

const OpenAI = require("openai");
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

const app = express();
app.use(cors());
app.use(express.json());

// =============================
// CONFIGURAÇÕES Z-API
// =============================
const ZAPI_INSTANCE_ID = process.env.ZAPI_INSTANCE_ID;
const ZAPI_INSTANCE_TOKEN = process.env.ZAPI_INSTANCE_TOKEN;
const ZAPI_CLIENT_TOKEN = process.env.ZAPI_CLIENT_TOKEN;

// =============================
// FUNÇÃO ENVIO Z-API
// =============================
async function sendZapiMessage(phone, message) {
  const url = `https://api.z-api.io/instances/${ZAPI_INSTANCE_ID}/token/${ZAPI_INSTANCE_TOKEN}/send-text`;

  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "client-token": ZAPI_CLIENT_TOKEN,
    },
    body: JSON.stringify({
      phone,
      message,
    }),
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    console.error("Erro envio Z-API:", data);
    throw new Error("Erro Z-API");
  }

  return data;
}

// =============================
// AUTH MIDDLEWARE
// =============================
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Token não fornecido" });

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: "Token inválido" });
  }
}

// =============================
// HEALTH
// =============================
app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false });
  }
});

// =============================
// REGISTER
// =============================
app.post("/register", async (req, res) => {
  try {
    const { name, email, password, prompt } = req.body;

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
      `INSERT INTO companies (name,email,password_hash,company_key,prompt,api_key)
       VALUES ($1,$2,$3,$4,$5,$6)
       RETURNING id,name,email,company_key,api_key`,
      [name, email, password_hash, company_key, prompt, api_key]
    );

    res.json(result.rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// =============================
// LOGIN
// =============================
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const password_hash = crypto
      .createHash("sha256")
      .update(password)
      .digest("hex");

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
      {
        id: user.id,
        company_key: user.company_key,
      },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ token, user });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// =============================
// Z-API WEBHOOK
// =============================
app.post("/zapi/webhook", async (req, res) => {
  try {
    console.log("📩 ZAPI PAYLOAD:", JSON.stringify(req.body, null, 2));

    const phone = req.body?.phone;
    const incomingText = req.body?.text?.message;

    if (!phone || !incomingText) {
      return res.status(200).json({ ignored: true });
    }

    const DEFAULT_COMPANY_KEY = process.env.DEFAULT_COMPANY_KEY;

    const companyRes = await pool.query(
      "SELECT id, prompt FROM companies WHERE company_key = $1",
      [DEFAULT_COMPANY_KEY]
    );

    if (!companyRes.rows.length)
      return res.status(500).json({ error: "Empresa não encontrada" });

    const company = companyRes.rows[0];

    // BUSCA CONVERSA
    let conversationRes = await pool.query(
      `SELECT * FROM conversations
       WHERE company_id = $1 AND user_phone = $2
       ORDER BY id DESC LIMIT 1`,
      [company.id, phone]
    );

    let conversationId;
    let conversationStatus = "open";
    let assignedAttendant = null;

    if (!conversationRes.rows.length) {
      const newConversation = await pool.query(
        `INSERT INTO conversations (company_id,user_phone,status)
         VALUES ($1,$2,'open')
         RETURNING *`,
        [company.id, phone]
      );

      conversationId = newConversation.rows[0].id;
    } else {
      conversationId = conversationRes.rows[0].id;
      conversationStatus = conversationRes.rows[0].status;
      assignedAttendant =
        conversationRes.rows[0].assigned_attendant_id;
    }

    // SALVA MSG USUÁRIO
    await pool.query(
      `INSERT INTO messages (conversation_id,sender,content)
       VALUES ($1,'user',$2)`,
      [conversationId, incomingText]
    );

    // DECISÃO IA vs HUMANO
    const useHuman =
      conversationStatus !== "open" || assignedAttendant !== null;

    if (useHuman) {
      const humanMessage =
        "Um atendente humano irá responder você em instantes.";

      await sendZapiMessage(phone, humanMessage);

      await pool.query(
        `INSERT INTO messages (conversation_id,sender,content)
         VALUES ($1,'system',$2)`,
        [conversationId, humanMessage]
      );

      return res.json({ mode: "human" });
    }

    // RESPOSTA IA
    const aiResponse = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: company.prompt },
        { role: "user", content: incomingText },
      ],
    });

    const aiReply =
      aiResponse.choices?.[0]?.message?.content || "Sem resposta.";

    await pool.query(
      `INSERT INTO messages (conversation_id,sender,content)
       VALUES ($1,'ai',$2)`,
      [conversationId, aiReply]
    );

    await sendZapiMessage(phone, aiReply);

    return res.json({ mode: "ai", reply: aiReply });
  } catch (e) {
    console.error("Erro webhook:", e);
    return res.status(500).json({ error: e.message });
  }
});

// =============================
// ENCERRAR CONVERSA
// =============================
app.post("/conversations/:id/close", authMiddleware, async (req, res) => {
  try {
    await pool.query(
      `UPDATE conversations SET status='closed' WHERE id=$1`,
      [req.params.id]
    );

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// =============================
app.use((req, res) => {
  res.status(404).json({ error: "Rota não encontrada" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("🔥 Servidor rodando na porta", PORT);
});