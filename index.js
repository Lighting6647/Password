const server = require('./server.cjs');
const handler = server.requestHandler || server;
module.exports = handler;
module.exports.default = handler;
