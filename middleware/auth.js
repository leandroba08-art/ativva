const jwt = require("jsonwebtoken");

module.exports = function auth(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ error: "Token não enviado" });
  }

  const token = authHeader.replace("Bearer ", "");

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // salva dados do usuário na requisição
    next();
  } catch (e) {
    return res.status(401).json({ error: "Token inválido" });
  }
};