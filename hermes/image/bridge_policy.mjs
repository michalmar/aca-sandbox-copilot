import {
  appendFileSync, existsSync, lstatSync, mkdirSync, renameSync, statSync, writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { timingSafeEqual } from 'node:crypto';

export const LOG_BYTES = 256 * 1024;
const EVENTS = new Set([
  'starting', 'connected', 'disconnected', 'loggedOut', 'owner-mismatch',
  'logout-failed', 'pair-required', 'pair-failed', 'send-denied', 'bridge-output',
]);

export function normalizeJid(value, domain) {
  if (typeof value !== 'string') throw new Error('Invalid WhatsApp identity');
  const match = value.match(/^([0-9]{1,20})(?::[0-9]+)?@(s\.whatsapp\.net|lid)$/);
  if (!match || (domain && match[2] !== domain)) throw new Error('Invalid WhatsApp identity');
  return `${match[1]}@${match[2]}`;
}

export function verifiedIds(user, ownerPhone) {
  if (!/^\+[1-9][0-9]{7,14}$/.test(ownerPhone)) throw new Error('Invalid configured owner');
  const jid = normalizeJid(user?.id, 's.whatsapp.net');
  if (jid !== `${ownerPhone.slice(1)}@s.whatsapp.net`) throw new Error('Paired owner mismatch');
  const ids = new Set([jid]);
  if (user?.lid) ids.add(normalizeJid(user.lid, 'lid'));
  return ids;
}

export function boundedLog(directory, event) {
  if (!EVENTS.has(event)) throw new Error('Unclassified bridge log event');
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const file = path.join(directory, 'bridge.log');
  for (const candidate of [directory, file, `${file}.1`]) {
    if (existsSync(candidate) && lstatSync(candidate).isSymbolicLink()) {
      throw new Error('Refusing a symlink log destination');
    }
  }
  const line = `${JSON.stringify({ time: new Date().toISOString(), event })}\n`;
  if (existsSync(file) && statSync(file).size + Buffer.byteLength(line) > LOG_BYTES) {
    renameSync(file, `${file}.1`);
  }
  appendFileSync(file, line, { mode: 0o600 });
}

export function createPolicy({ ownerPhone, mode, replyPrefix, sessionDir, pairOnly = false,
  pairJson = false, interactive = false, bridgeKey = '' }) {
  if (mode !== 'self-chat') throw new Error('Only self-chat is supported by this image');
  if (typeof replyPrefix !== 'string' || !replyPrefix.trim() || replyPrefix.length > 128) {
    throw new Error('A bounded nonempty reply prefix is mandatory');
  }
  if (!/^\+[1-9][0-9]{7,14}$/.test(ownerPhone)) throw new Error('Configured owner is mandatory');
  if (pairJson || (pairOnly && !interactive)) throw new Error('Pairing requires the approved interactive control terminal');
  if (!pairOnly && !/^[a-f0-9]{64}$/.test(bridgeKey)) throw new Error('An ephemeral bridge key is mandatory');
  let user = null;
  const directory = path.dirname(sessionDir);
  function record(event) {
    boundedLog(directory, event);
  }
  function status(state) {
    if (!EVENTS.has(state)) throw new Error('Invalid bridge state');
    const destination = path.join(directory, 'connection-state.json');
    if (existsSync(destination) && lstatSync(destination).isSymbolicLink()) {
      throw new Error('Refusing a symlink state destination');
    }
    const temporary = path.join(directory, `.connection-state-${process.pid}.json`);
    writeFileSync(temporary, JSON.stringify({ state }), { mode: 0o600 });
    renameSync(temporary, destination);
    record(state);
  }
  function isOwn(chatId) {
    try {
      return typeof chatId === 'string' && verifiedIds(user, ownerPhone).has(normalizeJid(chatId));
    } catch {
      return false;
    }
  }
  function own(chatId) {
    if (!isOwn(chatId)) {
      record('send-denied');
      throw new Error('Outbound destination is not the verified owner self-chat');
    }
  }
  function prefix(text) {
    if (typeof text !== 'string' || !text || text.length > 4096) {
      throw new Error('Only bounded text messages are permitted');
    }
    const result = text.startsWith(replyPrefix) ? text : `${replyPrefix}${text}`;
    if (result.length > 4096) throw new Error('Prefixed text exceeds the message limit');
    return result;
  }
  function body(message) {
    return message?.message?.conversation ?? message?.message?.extendedTextMessage?.text;
  }
  return {
    record, status, own, prefix,
    async connected(socket) {
      try {
        verifiedIds(socket.user, ownerPhone);
      } catch {
        status('owner-mismatch');
        if (pairOnly) {
          let timeout;
          try {
            await Promise.race([
              socket.logout(),
              new Promise((_, reject) => {
                timeout = setTimeout(() => reject(new Error('logout timeout')), 15000);
              }),
            ]);
          } catch {
            status('logout-failed');
            throw new Error('Wrong newly paired account; logout failed, unlink this device manually');
          } finally {
            clearTimeout(timeout);
          }
        }
        throw new Error('Paired owner mismatch');
      }
      user = socket.user;
      status('connected');
    },
    wrapSocket(socket) {
      const send = socket.sendMessage.bind(socket);
      const presence = socket.sendPresenceUpdate.bind(socket);
      const read = socket.readMessages.bind(socket);
      socket.sendMessage = async (chatId, payload) => {
        own(chatId);
        if (!payload || Object.keys(payload).some(key => ![
          'text', 'edit', 'mentions', 'contextInfo', 'linkPreview',
        ].includes(key))) throw new Error('Only text messages are permitted');
        const safe = { text: prefix(payload.text), linkPreview: null };
        if (payload.edit) {
          own(payload.edit.remoteJid);
          if (payload.edit.fromMe !== true || typeof payload.edit.id !== 'string'
              || !/^[A-Za-z0-9_-]{1,128}$/.test(payload.edit.id)) throw new Error('Invalid self-chat edit');
          safe.edit = { remoteJid: payload.edit.remoteJid, fromMe: true, id: payload.edit.id };
        }
        return send(chatId, safe, {});
      };
      socket.sendPresenceUpdate = async (type, chatId) => {
        own(chatId);
        return presence(type, chatId);
      };
      socket.readMessages = async (keys) => {
        for (const key of keys) own(key.remoteJid);
        return read(keys);
      };
    },
    acceptsInbound(message) {
      if (!message?.key?.fromMe || !isOwn(message.key.remoteJid)) return false;
      const text = body(message);
      return typeof text === 'string' && text.length > 0 && text.length <= 16000
        && !text.startsWith(replyPrefix);
    },
    textMessage(message) {
      return { ...message, message: { conversation: body(message) } };
    },
    middleware(req, res, next) {
      const key = req.headers['x-hermes-bridge-key'];
      if (typeof key !== 'string' || key.length !== bridgeKey.length
          || !timingSafeEqual(Buffer.from(key), Buffer.from(bridgeKey))) {
        return res.status(403).json({ error: 'Bridge authentication required' });
      }
      const allowed = new Set(['GET /health', 'GET /messages', 'POST /send', 'POST /edit', 'POST /typing']);
      const route = `${req.method} ${req.path}`;
      if (!allowed.has(route) && !(req.method === 'GET' && req.path.startsWith('/chat/'))) {
        return res.status(403).json({ error: 'Managed self-chat is text-only; endpoint disabled' });
      }
      if (req.path !== '/health' && req.path !== '/messages') {
        try {
          own(req.body?.chatId ?? decodeURIComponent(req.path.slice('/chat/'.length)));
        } catch {
          return res.status(403).json({ error: 'Only the verified owner self-chat is permitted' });
        }
      }
      if (req.method === 'GET' && req.path.startsWith('/chat/')) {
        return res.json({ name: 'Self', isGroup: false, participants: [] });
      }
      return next();
    },
    qr(qr, render) {
      if (!pairOnly || !interactive) {
        status('pair-required');
        throw new Error('Pairing requires control.py pair in an interactive terminal');
      }
      render(qr, { small: true }, output => process.stdout.write(`${output}\n`));
    },
  };
}

export function installSafeConsole(policy) {
  for (const method of ['log', 'warn', 'error', 'info', 'debug']) {
    console[method] = () => policy.record('bridge-output');
  }
}
