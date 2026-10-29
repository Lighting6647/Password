const server = require('../server.cjs');

module.exports = (req, res) => {
  return server.emit('request', req, res);
};
