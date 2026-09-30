const tls = require("tls");

const [host, port] = process.argv.slice(2);
if (!host || !port) throw new Error("usage: node_tls_client.js HOST PORT");
const socket = tls.connect({
  host,
  port: Number(port),
  rejectUnauthorized: false,
  minVersion: "TLSv1.3",
  maxVersion: "TLSv1.3",
}, () => {
  console.log(`TLS protocol: ${socket.getProtocol()}`);
  socket.end();
});
socket.on("error", (error) => {
  console.error(error.stack || error);
  process.exitCode = 1;
});
