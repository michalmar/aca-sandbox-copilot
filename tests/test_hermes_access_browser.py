"""Native renderer evidence for the text-only browser resource boundary."""

import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

from aiohttp import WSMsgType, web
from aiohttp.test_utils import TestServer

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "hermes/image"))
import access_proxy


class BrowserResourcePolicyTests(unittest.TestCase):
    def test_only_same_origin_resources_and_exact_local_websocket_are_allowed(self):
        policy = access_proxy.browser_policy("http://127.0.0.1:18765")
        directives = dict(part.strip().split(" ", 1) for part in policy.split(";"))
        self.assertEqual(directives["connect-src"], "'self' ws://127.0.0.1:18765")
        self.assertEqual(directives["img-src"], "'self' data: blob:")
        for kind in ("media-src", "object-src", "frame-src", "base-uri", "frame-ancestors"):
            self.assertEqual(directives[kind], "'none'")
        self.assertEqual(directives["default-src"], "'self'")
        self.assertNotIn("*", policy)
        for value in ("http://localhost:18765", "https://canary.invalid", "http://127.0.0.1:18765/"):
            with self.assertRaises(ValueError):
                access_proxy.browser_policy(value)

    @unittest.skipUnless(os.environ.get("HERMES_BROWSER_IMAGE_TEST") == "1", "requires the native offline image")
    def test_actual_markdown_renderer_never_autoloads_local_canary_resources(self):
        source = Path("/opt/hermes")
        self.assertTrue((source / "web/src/components/Markdown.tsx").is_file())
        script = r"""
const fs = require("fs"), esbuild = require("/opt/hermes/node_modules/esbuild");
const React = require("/opt/hermes/node_modules/react");
const server = require("/opt/hermes/node_modules/react-dom/server");
const Module = require("module");
const file = "/opt/hermes/web/src/components/Markdown.tsx";
const compiled = esbuild.transformSync(fs.readFileSync(file, "utf8"), {
    loader: "tsx", format: "cjs", jsx: "automatic"
});
const module = new Module(file);
module.filename = file;
module.paths = Module._nodeModulePaths("/opt/hermes/web/src/components");
module._compile(compiled.code, file);
const canary = "http://127.0.0.1:19876/local-canary?data=synthetic";
const payloads = [
    "![image](" + canary + ")",
    '<img src="' + canary + '">',
    '<iframe src="' + canary + '"></iframe>',
    '<video src="' + canary + '" autoplay></video>',
    '<audio src="' + canary + '" autoplay></audio>',
    '<link rel="stylesheet" href="' + canary + '">',
    '<object data="' + canary + '"></object>',
    '<div style="background:url(' + canary + ')">text</div>',
];
for (const content of payloads) {
    const html = server.renderToStaticMarkup(React.createElement(module.exports.Markdown, {content}));
    if (/<(img|iframe|video|audio|object|embed|script|link)\b/i.test(html))
        throw new Error("Automatic resource node was generated");
    if (/href=/.test(html) && !html.includes('rel="noreferrer"'))
        throw new Error("External link lacks referrer protection");
}
console.log("Native Markdown: eight local synthetic canaries cannot create automatic resource nodes.");
"""
        process = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=30)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertIn("eight local synthetic canaries", process.stdout)
        chat = (source / "web/src/pages/ChatPage.tsx").read_text()
        self.assertIn("new WebLinksAddon()", chat)
        self.assertNotIn("ImageAddon", chat)
        self.assertNotIn("dangerouslySetInnerHTML", chat)
        history = (source / "web/src/pages/SessionsPage.tsx").read_text()
        self.assertIn("<Markdown content={msg.content}", history)


@unittest.skipUnless(
    os.environ.get("HERMES_BROWSER_REAL_IMAGE_TEST") == "1",
    "requires the isolated Playwright verification layer, not a production dependency",
)
class BrowserCspEnforcementTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_browser_renders_native_markdown_and_blocks_autoload_canaries(self):
        canary_hits = []

        async def canary(request):
            if request.path == "/health":
                return web.Response(status=204)
            canary_hits.append(request.path)
            return web.Response(text="Synthetic fixture only.")

        app = web.Application()
        app.router.add_get("/{path:.*}", canary)
        canary_server = TestServer(app)
        await canary_server.start_server()
        self.addAsyncCleanup(canary_server.close)
        canary_url = str(canary_server.make_url("/resource?value=synthetic-only"))
        payloads = [
            f"![remote image]({canary_url})",
            f'<img src="{canary_url}"><iframe src="{canary_url}"></iframe>',
            f'<video autoplay src="{canary_url}"></video><audio autoplay src="{canary_url}"></audio>',
            f'<object data="{canary_url}"></object><link rel="stylesheet" href="{canary_url}">',
        ]
        entry = (
            'import React from "react"; import {createRoot} from "react-dom/client";'
            'import {Markdown} from "./web/src/components/Markdown.tsx";'
            f"const payloads = {json.dumps(payloads)};"
            'createRoot(document.getElementById("native-markdown")).render('
            'React.createElement("div", {id:"rendered"}, ...payloads.map('
            '(content,i)=>React.createElement(Markdown,{content,key:i}))));'
        )
        builder = r"""
const fs=require("fs"), esbuild=require("/opt/hermes/node_modules/esbuild");
const result=esbuild.buildSync({
  stdin:{contents:fs.readFileSync(0,"utf8"),loader:"jsx",resolveDir:"/opt/hermes"},
  bundle:true,write:false,format:"iife",platform:"browser",minify:true,jsx:"automatic"
});
process.stdout.write(result.outputFiles[0].contents);
"""
        build = await asyncio.create_subprocess_exec(
            "node", "-e", builder, stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            script, build_error = await asyncio.wait_for(build.communicate(entry.encode()), 60)
        finally:
            if build.returncode is None:
                build.terminate()
                await build.wait()
        self.assertEqual(build.returncode, 0, build_error.decode())
        origin = ""

        async def page(request):
            if request.path == "/assets/native.js":
                return web.Response(body=script, content_type="application/javascript")
            if request.path == "/assets/native.css":
                return web.Response(text="#native-markdown { color: rgb(17, 34, 51); }", content_type="text/css")
            if request.path == "/api/ws":
                socket = web.WebSocketResponse()
                await socket.prepare(request)
                async for message in socket:
                    if message.type == WSMsgType.TEXT:
                        await socket.send_str(message.data)
                return socket
            return web.Response(
                text=(
                    '<!doctype html><html><head><link rel="stylesheet" href="/assets/native.css"></head>'
                    '<body><div id="native-markdown"></div><script>window.fixtureBootstrap=42;</script>'
                    '<script src="/assets/native.js"></script></body></html>'
                ),
                content_type="text/html",
                headers={
                    "Content-Security-Policy": access_proxy.browser_policy(origin),
                    "Referrer-Policy": "no-referrer",
                },
            )

        app = web.Application()
        app.router.add_get("/{path:.*}", page)
        server = TestServer(app)
        await server.start_server()
        self.addAsyncCleanup(server.close)
        origin = str(server.make_url("")).rstrip("/")
        driver = r"""
const fs=require("fs"), {chromium}=require("/opt/hermes-browser/node_modules/playwright");
const input=JSON.parse(fs.readFileSync(0,"utf8"));
(async()=>{
  const browser=await chromium.launch({headless:true,args:["--no-sandbox","--disable-dev-shm-usage"]});
  try {
    const page=await browser.newPage();
    const pageErrors=[];
    page.on("pageerror",error=>pageErrors.push(error.message));
    const health=await page.request.get(input.canary.split("/resource")[0]+"/health");
    if(health.status()!==204) throw Error("Local canary is not reachable");
    await page.goto(input.origin,{waitUntil:"networkidle"});
    await page.waitForSelector("#rendered").catch(error=>{
      throw Error(error.message+"; page errors: "+pageErrors.join("; "))
    });
    const result=await page.evaluate(async ({canary,origin})=>{
      const result={
        bootstrap:window.fixtureBootstrap,
        color:getComputedStyle(document.getElementById("native-markdown")).color,
        nativeResourceNodes:document.querySelectorAll("#rendered img,#rendered iframe,#rendered video,#rendered audio,#rendered object,#rendered link").length
      };
      result.websocket=await new Promise((resolve,reject)=>{
        const socket=new WebSocket(origin.replace("http:","ws:")+"/api/ws");
        socket.onopen=()=>socket.send("first-party-websocket");
        socket.onmessage=event=>{resolve(event.data);socket.close()};
        socket.onerror=()=>reject(Error("First-party websocket blocked"));
      });
      const violations=[];
      document.addEventListener("securitypolicyviolation",event=>violations.push(event.violatedDirective));
      result.remoteImage=await new Promise(resolve=>{
        const image=new Image();image.onload=()=>resolve("loaded");image.onerror=()=>resolve("blocked");
        image.src=canary;document.body.appendChild(image);
      });
      try {await fetch(canary);result.remoteFetch="loaded"} catch {result.remoteFetch="blocked"}
      await new Promise(resolve=>setTimeout(resolve,100));
      result.violations=violations;
      return result;
    },input);
    console.log(JSON.stringify(result));
  } finally {await browser.close()}
})().catch(error=>{console.error(error);process.exitCode=1});
"""
        process = await asyncio.create_subprocess_exec(
            "node", "-e", driver, stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            output, errors = await asyncio.wait_for(
                process.communicate(json.dumps({"origin": origin, "canary": canary_url}).encode()), 90,
            )
        finally:
            if process.returncode is None:
                process.terminate()
                await process.wait()
        self.assertEqual(process.returncode, 0, errors.decode())
        evidence = json.loads(output)
        self.assertEqual(evidence["bootstrap"], 42)
        self.assertEqual(evidence["color"], "rgb(17, 34, 51)")
        self.assertEqual(evidence["nativeResourceNodes"], 0)
        self.assertEqual(evidence["websocket"], "first-party-websocket")
        self.assertEqual(evidence["remoteImage"], "blocked")
        self.assertEqual(evidence["remoteFetch"], "blocked")
        self.assertIn("img-src", evidence["violations"])
        self.assertIn("connect-src", evidence["violations"])
        self.assertEqual(canary_hits, [])


if __name__ == "__main__":
    unittest.main()
