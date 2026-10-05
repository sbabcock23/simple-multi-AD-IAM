'use strict';
const net = require('net');

/**
 * Tiny in-process SMTP sink (no STARTTLS, no AUTH) that captures every message
 * so tests can assert on the alert e-mails the app sends via nodemailer.
 */
async function startFakeSmtp() {
  const messages = [];
  const server = net.createServer((socket) => {
    let inData = false;
    let buf = '';
    let current = { from: '', to: [], data: '' };
    const send = (line) => socket.write(`${line}\r\n`);
    send('220 fake-smtp ESMTP ready');
    socket.on('data', (chunk) => {
      buf += chunk.toString('utf8');
      for (;;) {
        if (inData) {
          const end = buf.indexOf('\r\n.\r\n');
          if (end === -1) return;
          current.data = buf.slice(0, end);
          buf = buf.slice(end + 5);
          inData = false;
          messages.push({ ...current, receivedAt: Date.now() });
          current = { from: '', to: [], data: '' };
          send('250 2.0.0 queued');
          continue;
        }
        const nl = buf.indexOf('\r\n');
        if (nl === -1) return;
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 2);
        const cmd = line.slice(0, 4).toUpperCase();
        if (cmd === 'EHLO') { socket.write('250-fake-smtp\r\n250 8BITMIME\r\n'); }
        else if (cmd === 'HELO') send('250 fake-smtp');
        else if (cmd === 'MAIL') { current.from = (line.match(/<([^>]*)>/) || [])[1] || ''; send('250 OK'); }
        else if (cmd === 'RCPT') { current.to.push((line.match(/<([^>]*)>/) || [])[1] || ''); send('250 OK'); }
        else if (cmd === 'DATA') { inData = true; send('354 End data with <CR><LF>.<CR><LF>'); }
        else if (cmd === 'RSET') send('250 OK');
        else if (cmd === 'NOOP') send('250 OK');
        else if (cmd === 'QUIT') { send('221 Bye'); socket.end(); return; }
        else send('502 Command not implemented');
      }
    });
    socket.on('error', () => {});
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();

  // Header folding (RFC 5322) can split long subjects across lines; unfold for easy matching.
  const unfold = (s) => s.replace(/\r\n[ \t]+/g, ' ');

  return {
    port,
    messages,
    /** Resolves with the first captured message matching `predicate(unfoldedData, msg)`. */
    async waitFor(predicate, timeoutMs = 8000) {
      const started = Date.now();
      for (;;) {
        const hit = messages.find((m) => predicate(unfold(m.data), m));
        if (hit) return { ...hit, data: unfold(hit.data) };
        if (Date.now() - started > timeoutMs) {
          throw new Error(`Timed out waiting for e-mail; captured ${messages.length} message(s): `
            + messages.map((m) => unfold(m.data).split('\r\n').find((l) => /^subject:/i.test(l))).join(' | '));
        }
        await new Promise((r) => setTimeout(r, 50));
      }
    },
    /** Asserts that no message matching the predicate shows up within `ms`. */
    async expectNone(predicate, ms = 800) {
      await new Promise((r) => setTimeout(r, ms));
      return !messages.some((m) => predicate(unfold(m.data), m));
    },
    stop: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

module.exports = { startFakeSmtp };
