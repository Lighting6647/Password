const server = require('../server.cjs');

module.exports = async (req, res) => {
  try {
    return await server.requestHandler(req, res);
  } catch (err) {
    console.error('API Error:', err);
    res.statusCode = 500;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.end(JSON.stringify({ ok: false, error: err.message, stack: err.stack }));
  }
};
