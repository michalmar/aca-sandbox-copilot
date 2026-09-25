"""A test-only loopback bridge for the actual native WhatsApp adapter."""

from __future__ import annotations

import os
import time


def main() -> None:
    if os.environ.get("HERMES_RUNTIME_IMAGE_TESTS") != "1":
        raise RuntimeError("the fake bridge is restricted to explicit offline image tests")
    from aiohttp import web
    from test_hermes_runtime_fake_provider import append_record

    key = os.environ["HERMES_SANDBOX_BRIDGE_KEY"]
    owner = os.environ["HERMES_SANDBOX_OWNER_PHONE"].lstrip("+") + "@s.whatsapp.net"
    capture = os.environ["HERMES_RUNTIME_BRIDGE_CAPTURE"]
    delivered = False
    append_record(capture, {"event": "started", "pid": os.getpid()})

    async def handle(request):
        nonlocal delivered
        if request.headers.get("X-Hermes-Bridge-Key") != key:
            return web.json_response({"error": "unauthorized"}, status=401)
        if request.method == "GET" and request.path == "/health":
            return web.json_response({"status": "connected", "sendReadReceipts": False, "mode": "self-chat"})
        if request.method == "GET" and request.path == "/messages":
            if delivered:
                return web.json_response([])
            delivered = True
            return web.json_response([{
                "messageId": f"offline-inbound-{os.getpid()}", "chatId": owner, "senderId": owner,
                "senderName": "Owner", "isGroup": False, "fromMe": True, "isSelfChat": True,
                "hasMedia": False, "body": os.environ.get(
                    "HERMES_RUNTIME_WHATSAPP_PROMPT", "Offline actual WhatsApp adapter P4 prompt",
                ),
                "timestamp": int(time.time()),
            }])
        if request.method == "GET" and request.path == "/chat/" + owner:
            return web.json_response({"id": owner, "name": "Self", "isGroup": False, "participants": []})
        if request.method == "POST" and request.path in {"/send", "/edit", "/typing"}:
            payload = await request.json()
            if payload.get("chatId") != owner:
                append_record(capture, {"event": "wrong-target", "path": request.path})
                return web.json_response({"error": "own chat required"}, status=403)
            append_record(capture, {"event": "request", "path": request.path, "payload": payload})
            return web.json_response({"success": True, "messageId": "offline-outbound"})
        append_record(capture, {"event": "unexpected-route", "path": request.path})
        return web.json_response({"error": "unsupported"}, status=403)

    application = web.Application(client_max_size=64 * 1024)
    application.router.add_route("*", "/{path:.*}", handle)
    web.run_app(application, host="127.0.0.1", port=3000, access_log=None, print=None)


if __name__ == "__main__":
    main()
