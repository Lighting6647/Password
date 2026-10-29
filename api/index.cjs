const server = require('../server.cjs');

module.exports = async (req, res) => {
  return await server.requestHandler(req, res);
};
