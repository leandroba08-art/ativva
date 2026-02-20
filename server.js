// =========================
// ENCERRAR CONVERSA
// =========================
app.put("/conversations/:id/close", authMiddleware, async (req, res) => {
  try {
    const companyId = getCompanyIdFromToken(req);
    const conversationId = Number(req.params.id);

    const updated = await pool.query(
      `UPDATE conversations
       SET status = 'closed',
           assigned_attendant_id = NULL
       WHERE id = $1 AND company_id = $2
       RETURNING id, company_id, user_phone, status, assigned_attendant_id, created_at`,
      [conversationId, companyId]
    );

    if (updated.rows.length === 0) {
      return res.status(404).json({
        error: "Conversa não encontrada para esta empresa",
      });
    }

    return res.json({
      message: "Conversa encerrada com sucesso",
      conversation: updated.rows[0],
    });
  } catch (e) {
    console.error("Erro ao encerrar conversa:", e);
    return res.status(500).json({ error: e.message });
  }
});

// =========================
// REABRIR CONVERSA
// =========================
app.put("/conversations/:id/reopen", authMiddleware, async (req, res) => {
  try {
    const companyId = getCompanyIdFromToken(req);
    const conversationId = Number(req.params.id);

    const updated = await pool.query(
      `UPDATE conversations
       SET status = 'open'
       WHERE id = $1 AND company_id = $2
       RETURNING id, company_id, user_phone, status, assigned_attendant_id, created_at`,
      [conversationId, companyId]
    );

    if (updated.rows.length === 0) {
      return res.status(404).json({
        error: "Conversa não encontrada para esta empresa",
      });
    }

    return res.json({
      message: "Conversa reaberta com sucesso",
      conversation: updated.rows[0],
    });
  } catch (e) {
    console.error("Erro ao reabrir conversa:", e);
    return res.status(500).json({ error: e.message });
  }
});