import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createPolicy, normalizeJid, LOG_BYTES, boundedLog } from '../bridge_policy.mjs';

const ownerPhone = '+420777123456';
const jid = '420777123456@s.whatsapp.net';
const lid = '987654321@lid';
const key = 'a'.repeat(64);
const prefix = '[Hermes] ';

function fixture(t, extra = {}) {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'hermes-bridge-test-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const options = { ownerPhone, mode: 'self-chat', replyPrefix: prefix,
    sessionDir: path.join(directory, 'session'), bridgeKey: key, ...extra };
  const policy = createPolicy(options);
  const sent = [];
  const socket = {
    user: { id: '420777123456:5@s.whatsapp.net', lid: '987654321:9@lid', name: 'PRIVATE_NAME' },
    sendMessage: async (...args) => { sent.push(['send', ...args]); return { key: { id: 'offline-id' } }; },
    sendPresenceUpdate: async (...args) => sent.push(['presence', ...args]),
    readMessages: async (...args) => sent.push(['read', ...args]),
    logout: async () => sent.push(['logout']),
  };
  policy.wrapSocket(socket);
  return { directory, policy, socket, sent, options };
}

test('startup rejects every non-self mode, missing owner, empty prefix and pair-json', t => {
  const { options } = fixture(t);
  for (const patch of [
    { mode: 'bot' }, { mode: 'open' }, { replyPrefix: '' }, { replyPrefix: ' ' },
    { ownerPhone: '' }, { bridgeKey: '' }, { pairOnly: true }, { pairJson: true },
  ]) assert.throws(() => createPolicy({ ...options, ...patch }));
});

test('exact device-normalized own JID and LID are the only outbound targets', async t => {
  const { policy, socket, sent } = fixture(t);
  await policy.connected(socket);
  for (const target of [jid, lid, '420777123456:6@s.whatsapp.net']) {
    await socket.sendMessage(target, { text: 'hello' });
  }
  for (const target of ['420777123457@s.whatsapp.net', '987654322@lid', '420777123456@g.us',
    '420777123456@s.whatsapp.net.attacker', jid + '/path', '', null]) {
    await assert.rejects(socket.sendMessage(target, { text: 'must not send' }));
    await assert.rejects(socket.sendPresenceUpdate('composing', target));
    await assert.rejects(socket.readMessages([{ remoteJid: target, id: 'message' }]));
  }
  assert.equal(sent.length, 3);
});

test('send cannot precede verified pairing, including direct sendMessage callers', async t => {
  const { socket, sent } = fixture(t);
  await assert.rejects(socket.sendMessage(jid, { text: 'not yet' }));
  assert.equal(sent.length, 0);
});

test('all outbound media, files, polls, locations and contacts are rejected', async t => {
  const { policy, socket, sent } = fixture(t);
  await policy.connected(socket);
  for (const payload of [
    { image: Buffer.from('private') }, { video: { url: 'https://attacker.invalid' } },
    { document: { url: '/mnt/data/secrets/google/credentials.json' } }, { audio: Buffer.from('private') },
    { poll: { name: 'question' } }, { location: { latitude: 1, longitude: 2 } },
    { contacts: { contacts: [] } }, { text: 'hello', viewOnce: true },
  ]) await assert.rejects(socket.sendMessage(jid, payload));
  assert.equal(sent.length, 0);
});

test('each emitted chunk is prefixed once and append replay is ignored after process restart', async t => {
  const first = fixture(t);
  await first.policy.connected(first.socket);
  for (const text of [prefix + 'first', 'second', 'third']) await first.socket.sendMessage(jid, { text });
  const next = fixture(t);
  await next.policy.connected(next.socket);
  for (const [, target, payload] of first.sent) {
    assert.ok(payload.text.startsWith(prefix));
    assert.equal(payload.text.split(prefix).length - 1, 1);
    assert.equal(next.policy.acceptsInbound({ key: { remoteJid: target, fromMe: true },
      message: { conversation: payload.text } }), false);
  }
  assert.equal(next.policy.acceptsInbound({ key: { remoteJid: jid, fromMe: true },
    message: { conversation: 'new self-chat prompt' } }), true);
  // This is echo protection, not an exactly-once delivery claim.
});

test('text edit stays on self-chat and link previews/quoted media/mentions cannot escape', async t => {
  const { policy, socket, sent } = fixture(t);
  await policy.connected(socket);
  await socket.sendMessage(jid, {
    text: 'https://attacker.invalid', mentions: ['another@s.whatsapp.net'],
    contextInfo: { externalAdReply: { sourceUrl: 'https://attacker.invalid' } },
    edit: { remoteJid: jid, fromMe: true, id: 'own-message' },
  }, { quoted: { message: { documentMessage: { url: 'https://attacker.invalid' } } } });
  const [, , payload, options] = sent[0];
  assert.equal(payload.linkPreview, null);
  assert.deepEqual(options, {});
  assert.equal(payload.mentions, undefined);
  assert.equal(payload.contextInfo, undefined);
  await assert.rejects(socket.sendMessage(jid, { text: 'x', edit: {
    remoteJid: 'other@s.whatsapp.net', fromMe: true, id: 'message',
  } }));
  await assert.rejects(socket.sendMessage(jid, { text: 'x', edit: {
    remoteJid: jid, fromMe: false, id: 'message',
  } }));
});

test('non-self inbound, attachments and quoted attachment content are never handed to extraction', async t => {
  const { policy, socket } = fixture(t);
  await policy.connected(socket);
  for (const message of [
    { key: { remoteJid: jid, fromMe: false }, message: { conversation: 'foreign' } },
    { key: { remoteJid: '111111111@s.whatsapp.net', fromMe: true }, message: { conversation: 'foreign' } },
    { key: { remoteJid: jid, fromMe: true }, message: { imageMessage: { url: 'https://attacker.invalid' } } },
  ]) assert.equal(policy.acceptsInbound(message), false);
  const message = { key: { remoteJid: jid, fromMe: true }, message: {
    extendedTextMessage: { text: 'plain', contextInfo: { quotedMessage: { documentMessage: { url: 'private' } } } },
  } };
  assert.deepEqual(policy.textMessage(message).message, { conversation: 'plain' });
});

test('normal owner traffic to other chats does not masquerade as denied outbound sends', async t => {
  const { policy, socket, directory } = fixture(t);
  await policy.connected(socket);
  for (let index = 0; index < 1000; index++) {
    assert.equal(policy.acceptsInbound({
      key: { remoteJid: '420777123457@s.whatsapp.net', fromMe: true },
      message: { conversation: 'owner phone traffic' },
    }), false);
  }
  const log = () => readFileSync(path.join(directory, 'bridge.log'), 'utf8').trim().split('\n').map(JSON.parse);
  assert.equal(log().filter(entry => entry.event === 'send-denied').length, 0);
  await assert.rejects(socket.sendMessage('420777123457@s.whatsapp.net', { text: 'forbidden' }));
  assert.equal(log().filter(entry => entry.event === 'send-denied').length, 1);
});

test('wrong newly paired account is logged out, never accepted, and diagnostics omit identifiers', async t => {
  const { policy, socket, sent, directory } = fixture(t, { pairOnly: true, interactive: true });
  socket.user.id = '420777123457:1@s.whatsapp.net';
  await assert.rejects(policy.connected(socket), /owner mismatch/i);
  assert.deepEqual(sent, [['logout']]);
  const log = readFileSync(path.join(directory, 'bridge.log'), 'utf8');
  assert.ok(log.includes('owner-mismatch'));
  assert.ok(!log.includes('420777123457'));
  assert.ok(!log.includes('PRIVATE_NAME'));
});

test('QR is refused outside interactive pair-only; normal gateway never prints QR', t => {
  const { policy } = fixture(t);
  let printed = false;
  assert.throws(() => policy.qr('SECRET_QR', () => { printed = true; }));
  assert.equal(printed, false);
});

test('localhost bridge endpoints require ephemeral key, then exact owner, then text-only route', async t => {
  const { policy, socket } = fixture(t);
  await policy.connected(socket);
  function invoke(method, route, body = {}, suppliedKey = key) {
    const result = {};
    const response = { status(code) { result.status = code; return this; },
      json(value) { result.value = value; return this; } };
    policy.middleware({ method, path: route, body, headers: { 'x-hermes-bridge-key': suppliedKey } },
      response, () => { result.next = true; });
    return result;
  }
  assert.equal(invoke('GET', '/health', {}, 'wrong').status, 403);
  assert.equal(invoke('POST', '/send', { chatId: jid }).next, true);
  assert.equal(invoke('POST', '/send', { chatId: 'foreign@s.whatsapp.net' }).status, 403);
  for (const route of ['/send-media', '/send-poll', '/send-location', '/read', '/unknown']) {
    assert.equal(invoke('POST', route, { chatId: jid }).status, 403);
  }
  assert.deepEqual(invoke('GET', '/chat/' + jid).value, { name: 'Self', isGroup: false, participants: [] });
});

test('bridge logs rotate within two bounded files and cannot accept arbitrary payloads', t => {
  const { directory } = fixture(t);
  for (let i = 0; i < 12000; i++) boundedLog(directory, 'bridge-output');
  const files = readdirSync(directory).filter(name => name.startsWith('bridge.log'));
  assert.equal(files.length, 2);
  for (const file of files) assert.ok(statSync(path.join(directory, file)).size <= LOG_BYTES);
  assert.throws(() => boundedLog(directory, 'PRIVATE_TOKEN'));
});
