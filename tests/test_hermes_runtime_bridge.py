"""Real patched Node entrypoint, isolated from WhatsApp and personal accounts."""

from __future__ import annotations

from contextlib import contextmanager
import http.client
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
import unittest

IN_IMAGE = os.environ.get("HERMES_RUNTIME_IMAGE_TESTS") == "1"
BRIDGE = Path("/opt/hermes/scripts/whatsapp-bridge/bridge.js")

LOADER = """
export async function resolve(specifier, context, next) {
  if (process.env.HERMES_RUNTIME_IMAGE_TESTS !== '1') throw new Error('Test-only loader');
  if (specifier === '@whiskeysockets/baileys' && context.parentURL?.endsWith('/bridge.js')) {
    return { url: new URL('./baileys-fixture.mjs', import.meta.url).href, shortCircuit: true };
  }
  return next(specifier, context);
}
"""

BAILEYS = """
import { EventEmitter } from 'node:events';
import { appendFileSync, readFileSync } from 'node:fs';
export * from '/opt/hermes/scripts/whatsapp-bridge/node_modules/@whiskeysockets/baileys/lib/index.js';
if (process.env.HERMES_RUNTIME_IMAGE_TESTS !== '1') throw new Error('Test-only Baileys');
const record = value => appendFileSync(process.env.HERMES_BRIDGE_TEST_CAPTURE, JSON.stringify(value) + '\\n');
export function makeWASocket(options) {
  const mode = process.env.HERMES_BRIDGE_TEST_MODE;
  const ev = new EventEmitter();
  const user = { id: (mode.startsWith('wrong-owner') ? '420777123457' : '420777123456') + ':7@s.whatsapp.net',
    lid: '987654321:8@lid', name: 'PRIVATE_CONTACT' };
  let sequence = 0;
  const socket = {
    ev, user,
    async sendMessage(target, payload, sendOptions) {
      record({ event: 'send', target, payload, options: sendOptions });
      return { key: { id: `fixture-${++sequence}`, remoteJid: target, fromMe: true }, message: payload };
    },
    async sendPresenceUpdate(type, target) { record({ event: 'presence', type, target }); },
    async readMessages(keys) { record({ event: 'read', keys }); },
    async logout() {
      record({ event: 'logout' });
      if (mode === 'wrong-owner-logout-failed') throw new Error('Fixture logout failed');
    },
    async groupMetadata() { throw new Error('Contact metadata must not be requested'); },
    end() {},
  };
  const emit = async (event, value) => {
    for (const handler of ev.listeners(event)) await handler(value);
  };
  setInterval(() => {}, 1000);
  setTimeout(async () => {
    if (mode === 'qr') {
      await emit('connection.update', { qr: 'OFFLINE_FAKE_QR_NOT_AN_ACCOUNT' });
      return;
    }
    options.auth.creds.registered = true;
    options.auth.creds.me = user;
    await emit('creds.update', {});
    await emit('connection.update', { connection: 'open' });
    const batches = JSON.parse(readFileSync(process.env.HERMES_BRIDGE_TEST_BATCHES, 'utf8'));
    for (const batch of batches) await emit('messages.upsert', batch);
    record({ event: 'ready' });
  }, 20).unref();
  return socket;
}
"""


@unittest.skipUnless(IN_IMAGE, "requires the true amd64 image and explicit offline test opt-in")
class RuntimeBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import test_hermes_runtime_image as fixtures
        fixtures.RuntimeImageTests.setUpClass()
        cls.runtime = fixtures.RuntimeImageTests.runtime_module
        cls.value = fixtures.RuntimeImageTests.runtime

    @contextmanager
    def bridge(self, root, *, fake=False, mode="connected", pair=False, tty=False, batches=(),
               whatsapp_mode="self-chat"):
        from lifecycle import Child, prove_bridge_absent
        import pty
        import select
        prove_bridge_absent()
        environment = self.runtime.child_environment(self.value)
        key = secrets.token_hex(32)
        environment.update(HERMES_SANDBOX_BRIDGE_KEY=key, HERMES_RUNTIME_IMAGE_TESTS="1")
        command = ["/usr/local/bin/node"]
        capture = root / "calls.jsonl"
        if fake:
            (root / "loader.mjs").write_text(LOADER)
            (root / "baileys-fixture.mjs").write_text(BAILEYS)
            (root / "batches.json").write_text(json.dumps(batches))
            environment.update(
                HERMES_BRIDGE_TEST_MODE=mode, HERMES_BRIDGE_TEST_CAPTURE=str(capture),
                HERMES_BRIDGE_TEST_BATCHES=str(root / "batches.json"),
            )
            command += ["--loader", str(root / "loader.mjs")]
        command += [str(BRIDGE), "--port", "3000", "--session", str(root / "session"), "--mode", whatsapp_mode]
        if pair:
            command += ["--pair-only"]
            environment["HERMES_SANDBOX_PAIR_APPROVED"] = "1"
        output_path = root / "process-output"
        terminal = bytearray()
        master = None
        with output_path.open("wb") as output:
            if tty:
                master, slave = pty.openpty()
                process = subprocess.Popen(command, env=environment, cwd="/mnt/data", stdin=slave,
                                           stdout=slave, stderr=slave, start_new_session=True, umask=0o077)
                os.close(slave)
            else:
                process = subprocess.Popen(command, env=environment, cwd="/mnt/data", stdin=subprocess.DEVNULL,
                                           stdout=output, stderr=output, start_new_session=True, umask=0o077)
            child = Child("real-node-bridge", process)

            def pump():
                child.capture()
                if master is not None and select.select([master], [], [], 0)[0]:
                    try:
                        terminal.extend(os.read(master, 65536))
                    except OSError as exc:
                        import errno
                        if exc.errno != errno.EIO:
                            raise

            def wait(predicate, timeout=12):
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    pump()
                    if predicate():
                        return
                    if process.poll() is not None:
                        break
                    time.sleep(0.05)
                self.fail(output_path.read_text()[-4000:] + terminal[-4000:].decode(errors="replace"))

            try:
                yield process, key, capture, terminal, wait
            finally:
                child.stop(timeout=4)
                pump()
                if master is not None:
                    os.close(master)
                prove_bridge_absent()
                self.assertEqual(child.live(), [], "bridge descendants survived cleanup")

    def request(self, key, method, path, body=None):
        headers = {"x-hermes-bridge-key": key} if key is not None else {}
        if body is not None:
            headers["content-type"] = "application/json"
        connection = http.client.HTTPConnection("127.0.0.1", 3000, timeout=4)
        try:
            connection.request(method, path, body=None if body is None else json.dumps(body), headers=headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def ready(self, key):
        try:
            return self.request(key, "GET", "/health")[0] == 200
        except (ConnectionError, OSError):
            return False

    def test_actual_patched_bridge_parses_and_starts_with_locked_baileys(self):
        source = BRIDGE.read_text()
        self.assertTrue(source.startswith("#!/usr/bin/env node\n"))
        self.assertEqual(source.count("#!/usr/bin/env node"), 1)
        for script in (BRIDGE, BRIDGE.parent / "managed-policy.mjs"):
            subprocess.run(["/usr/local/bin/node", "--check", str(script)], check=True, capture_output=True)
        with tempfile.TemporaryDirectory(dir="/mnt/data", prefix="bridge-start-") as directory:
            root = Path(directory)
            with self.bridge(root) as (process, key, _, _, wait):
                wait(lambda: self.ready(key))
                self.assertIsNone(process.poll())
                self.assertIn('"starting"', (root / "bridge.log").read_text())
                for supplied_key, method, path, body in (
                    (None, "GET", "/health", None),
                    (None, "POST", "/send", {"chatId": "420777123456@s.whatsapp.net", "message": "blocked"}),
                    (key, "POST", "/send", {"chatId": "420777123457@s.whatsapp.net", "message": "blocked"}),
                    (key, "POST", "/send-media", {}), (key, "POST", "/read", {}),
                ):
                    self.assertEqual(self.request(supplied_key, method, path, body)[0], 403)
                self.assertNotIn(key, (root / "bridge.log").read_text())

    def test_actual_pair_entrypoint_rejects_non_tty_and_survives_offline_terminal_start(self):
        with tempfile.TemporaryDirectory(dir="/mnt/data", prefix="bridge-pair-") as directory:
            root = Path(directory)
            with self.bridge(root, pair=True) as (process, _, _, _, _):
                self.assertNotEqual(process.wait(timeout=10), 0)
            text = (root / "process-output").read_text()
            self.assertIn("approved interactive control terminal", text)
            self.assertNotIn("Scan this QR", text)
            with self.bridge(root, whatsapp_mode="bot") as (process, _, _, _, _):
                self.assertNotEqual(process.wait(timeout=10), 0)
            self.assertIn("Only self-chat", (root / "process-output").read_text())
            with self.bridge(root, pair=True, tty=True) as (process, _, _, _, wait):
                started = time.monotonic()
                wait(lambda: (root / "bridge.log").exists() and time.monotonic() - started >= 3)
                self.assertIsNone(process.poll())

    def test_real_entrypoint_fake_baileys_enforces_owner_text_prefix_and_restart_replay(self):
        jid = self.value["owner"]["whatsapp_phone"][1:] + "@s.whatsapp.net"
        prefix = self.runtime.managed_environment(self.value)["WHATSAPP_REPLY_PREFIX"]

        def message(identifier, text, target=jid):
            return {"key": {"id": identifier, "remoteJid": target, "fromMe": True},
                    "messageTimestamp": int(time.time()), "pushName": "PRIVATE_CONTACT",
                    "message": {"conversation": text}}

        batches = [{"type": "append", "messages": [
            message("old-echo", prefix + "previous response"),
            message("foreign-owner-traffic", "private", "420777123457@s.whatsapp.net"),
            message("fresh-self", "fresh self-chat"),
        ]}]
        with tempfile.TemporaryDirectory(dir="/mnt/data", prefix="bridge-events-") as directory:
            root = Path(directory)
            for restart in range(2):
                with self.bridge(root, fake=True, batches=batches) as (process, key, capture, _, wait):
                    wait(lambda: self.ready(key) and capture.exists() and '"ready"' in capture.read_text())
                    status, messages = self.request(key, "GET", "/messages")
                    self.assertEqual(status, 200)
                    self.assertEqual([entry["body"] for entry in messages], ["fresh self-chat"])
                    self.assertTrue(all(entry["senderName"] == "Owner" for entry in messages))
                    self.assertNotIn("PRIVATE_CONTACT", json.dumps(messages))
                    self.assertTrue(all(entry["chatName"] == "Self" for entry in messages))
                    self.assertFalse(any(json.loads(line)["event"] == "send-denied"
                                         for line in (root / "bridge.log").read_text().splitlines()))
                    if restart:
                        continue
                    for text in ("Context references are disabled in managed Sandbox mode.", prefix + "already prefixed"):
                        self.assertEqual(self.request(key, "POST", "/send", {"chatId": jid, "message": text})[0], 200)
                    self.assertEqual(self.request(key, "POST", "/send", {"chatId": jid, "message": "x" * 5000})[0], 200)
                    self.assertEqual(self.request(key, "POST", "/send", {
                        "chatId": jid, "message": prefix + "y" * 5000,
                    })[0], 200)
                    for invalid_text in (prefix, {"text": "not a string"}):
                        self.assertEqual(self.request(key, "POST", "/send", {
                            "chatId": jid, "message": invalid_text,
                        })[0], 500)
                    self.assertEqual(self.request(key, "POST", "/edit", {
                        "chatId": jid, "messageId": "fixture-1", "message": prefix + "edited",
                    })[0], 200)
                    self.assertEqual(self.request(key, "POST", "/typing", {"chatId": jid})[0], 200)
                    self.assertEqual(self.request(key, "GET", "/chat/" + jid)[1],
                                     {"name": "Self", "isGroup": False, "participants": []})
                    for path in ("/send-media", "/send-poll", "/send-location", "/read"):
                        self.assertEqual(self.request(key, "POST", path, {"chatId": jid})[0], 403)
                    self.assertEqual(self.request(key, "POST", "/send", {
                        "chatId": "420777123457@s.whatsapp.net", "message": "forbidden",
                    })[0], 403)
                    calls = [json.loads(line) for line in capture.read_text().splitlines()]
                    sent = [entry for entry in calls if entry["event"] == "send"]
                    self.assertEqual(len(sent), 7)
                    self.assertTrue(all(entry["target"] == jid and entry["options"] == {} for entry in sent))
                    self.assertTrue(all(entry["payload"]["text"].count(prefix) == 1 for entry in sent))
                    self.assertTrue(all(len(entry["payload"]["text"]) <= 4096 for entry in sent))
                    self.assertTrue(all(entry["payload"]["linkPreview"] is None for entry in sent))
                    text = [entry["payload"]["text"][len(prefix):] for entry in sent]
                    self.assertEqual(text[:2], ["Context references are disabled in managed Sandbox mode.", "already prefixed"])
                    self.assertEqual("".join(text[2:4]), "x" * 5000)
                    self.assertEqual("".join(text[4:6]), "y" * 5000)
                    self.assertEqual(text[6], "edited")
                    self.assertIsNone(process.poll())
                capture.unlink()
                (root / "bridge.log").unlink()

    def test_real_pair_callbacks_activate_only_owner_and_report_failed_logout(self):
        for mode, expected, marker in (
            ("connected", 0, "connected"), ("wrong-owner", 78, "owner-mismatch"),
            ("wrong-owner-logout-failed", 78, "logout-failed"),
        ):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(dir="/mnt/data", prefix="bridge-owner-") as directory:
                root = Path(directory)
                with self.bridge(root, fake=True, mode=mode, pair=True, tty=True) as (process, key, capture, _, wait):
                    wait(lambda: process.poll() is not None)
                    self.assertEqual(process.returncode, expected)
                self.assertEqual(json.loads((root / "connection-state.json").read_text())["state"], marker)
                calls = [json.loads(line) for line in capture.read_text().splitlines()]
                self.assertEqual(sum(entry["event"] == "logout" for entry in calls), int(mode != "connected"))
                diagnostic = (root / "bridge.log").read_text()
                self.assertNotIn("PRIVATE_CONTACT", diagnostic)
                self.assertNotIn(key, diagnostic)
                if mode == "connected":
                    self.runtime.verified_identity(self.runtime.read_json(root / "session/creds.json"),
                                                   self.value["owner"]["whatsapp_phone"])

    def test_real_pair_qr_callback_writes_only_to_approved_terminal(self):
        with tempfile.TemporaryDirectory(dir="/mnt/data", prefix="bridge-qr-") as directory:
            root = Path(directory)
            with self.bridge(root, fake=True, mode="qr", pair=True, tty=True) as (process, _, _, terminal, wait):
                wait(lambda: "\u2584".encode() in terminal)
                self.assertIsNone(process.poll())
                log = (root / "bridge.log").read_text()
                self.assertNotIn("OFFLINE_FAKE_QR", log)
                self.assertNotIn("\u2584", log)


if __name__ == "__main__":
    unittest.main()
