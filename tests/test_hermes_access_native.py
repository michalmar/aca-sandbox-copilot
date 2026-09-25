"""P3: real browser and dashboard, both proxies, and explicit offline Azure fakes."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import platform
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest

import aiohttp
from aiohttp import WSMsgType, web
from aiohttp.test_utils import TestServer
from azure.core.credentials import AccessToken

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "hermes/image"))
import access_hermes
import access_proxy
import hermes_common
from test_hermes_access_proxy import MappedClient
from test_hermes_deploy_filesystem import MountedFilesystemSandbox

TARGET = "https://hermes-image-test--8080.swedencentral.adcproxy.io"
ORIGIN = "http://127.0.0.1:18765"
FAKE_BEARER = "explicit-offline-ingress-credential"


@unittest.skipUnless(
    os.environ.get("HERMES_NATIVE_ACCESS_IMAGE_TEST") == "1",
    "requires the composed native image plus the isolated browser verification layer",
)
class NativeAccessImageTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        if (
            platform.system() != "Linux" or platform.machine() != "x86_64"
            or os.getuid() != 0 or not os.path.ismount("/mnt/data")
            or {
                name for _, name in socket.if_nameindex()
                if int(Path("/sys/class/net", name, "flags").read_text(), 16) & 1
            } != {"lo"}
            or Path("/proc/net/route").read_text().splitlines()[1:]
        ):
            raise RuntimeError("P3 requires one root amd64 --network none container and disposable data mount.")
        if list(Path("/mnt/data").iterdir()):
            raise RuntimeError("Refusing a nonempty P3 data mount.")
        self.scenario = os.environ.get("HERMES_P3_SCENARIO", "normal")
        if self.scenario not in {"normal", "clarify-single", "clarify-batch", "interrupt", "references"}:
            raise RuntimeError("Unknown explicit native-browser fixture scenario.")
        sys.path[:0] = ["/opt/hermes-sandbox", "/opt/hermes"]
        import runtime
        from lifecycle import Child
        from test_hermes_runtime_image import write_bootstrap
        from test_hermes_runtime_profile import sample_runtime

        self.clients = []
        self.servers = []
        self.process = None
        self.bootstrap = tempfile.TemporaryDirectory(prefix="hermes-p3-")
        self.addCleanup(self.bootstrap.cleanup)
        self.addAsyncCleanup(self.close_stack)
        document = sample_runtime()
        runtime.private_directory(runtime.HOME)
        runtime.atomic_json(runtime.RUNTIME, document)
        runtime.apply_profile(document, configured=False)
        write_bootstrap(self.bootstrap.name)
        self.capture = Path("/mnt/data/p3-wire.jsonl")
        self.rpc_capture = Path("/mnt/data/p3-rpc.jsonl")
        self.reference_marker = None
        self.reference_url = None
        self.reference_hits = []
        if self.scenario == "references":
            self.reference_marker = "offline-reference-canary-" + secrets.token_hex(12)
            for directory in (Path("/mnt/data/secrets"), Path("/mnt/data/secrets/google")):
                runtime.private_directory(directory)
            runtime.atomic_json(
                Path("/mnt/data/secrets/google/credentials.json"), {"test_only_canary": self.reference_marker},
            )

            async def reference_canary(request):
                if request.path == "/health":
                    return web.Response(status=204)
                self.reference_hits.append(request.path)
                return web.Response(text=self.reference_marker)

            canary = web.Application()
            canary.router.add_route("*", "/{path:.*}", reference_canary)
            canary_base = await self.server(canary)
            self.reference_url = canary_base + "/reference"
            probe_client = await self.client()
            async with probe_client.get(canary_base + "/health") as reachable:
                self.assertEqual(reachable.status, 204)
        environment = {
            **runtime.child_environment(document),
            "PYTHONPATH": f"{self.bootstrap.name}:/runtime-tests:/opt/hermes-sandbox:/opt/hermes",
            "HERMES_RUNTIME_IMAGE_TESTS": "1", "HERMES_RUNTIME_WIRE_CAPTURE": str(self.capture),
            "HERMES_RUNTIME_TEST_SURFACE": "full-access-browser",
            "HERMES_RUNTIME_CAPTURE_RPC": str(self.rpc_capture), "TERM": "xterm-256color",
        }
        if self.scenario in {"clarify-single", "clarify-batch", "interrupt"}:
            environment["HERMES_RUNTIME_TUI_SCENARIO"] = self.scenario
        self.log_path = Path(self.bootstrap.name, "dashboard.log")
        with self.log_path.open("wb") as log:
            process = subprocess.Popen(
                ["/opt/hermes/.venv/bin/hermes", "dashboard", "--host", "127.0.0.1",
                 "--port", "9119", "--no-open", "--skip-build"],
                cwd="/mnt/data", env=environment, stdout=log, stderr=log, start_new_session=True,
            )
        self.process = Child("p3-dashboard", process)
        self.inner = access_proxy.Proxy(access_key=access_proxy.create_access_key())
        await self.server(self.inner.app, host="0.0.0.0", port=8080)
        self.ingress_calls = 0
        self.reject_ingress = False
        self.token_calls = 0
        self.key_reads = 0
        ingress_client = await self.client(auto_decompress=False, trace_configs=[access_proxy.no_redirect_trace()])

        def wire_headers(headers):
            return {key: value for key, value in headers.items()
                    if key.lower() not in {"connection", "upgrade", "transfer-encoding"}
                    and not key.lower().startswith("sec-websocket-")}

        async def ingress(request):
            self.ingress_calls += 1
            if self.reject_ingress or request.headers.get("Authorization") != "Bearer " + FAKE_BEARER:
                return web.Response(status=401, text="Explicit offline ingress rejection.")
            destination = "http://127.0.0.1:8080" + request.raw_path
            headers = wire_headers(request.headers)
            if request.headers.get("Upgrade", "").lower() == "websocket":
                try:
                    upstream = await ingress_client.ws_connect(
                        destination, headers=headers, max_msg_size=access_proxy.MAX_FRAME + 1,
                    )
                except aiohttp.WSServerHandshakeError as error:
                    return web.Response(status=error.status, headers=wire_headers(error.headers), body=b"")
                downstream = web.WebSocketResponse(max_msg_size=access_proxy.MAX_FRAME + 1)
                await downstream.prepare(request)

                async def pump(source, target):
                    async for message in source:
                        if message.type == WSMsgType.TEXT:
                            await target.send_str(message.data)
                        elif message.type == WSMsgType.BINARY:
                            await target.send_bytes(message.data)
                    await target.close()

                tasks = [asyncio.create_task(pump(downstream, upstream)), asyncio.create_task(pump(upstream, downstream))]
                try:
                    await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                finally:
                    for task in tasks:
                        task.cancel()
                    await asyncio.gather(*tasks, return_exceptions=True)
                    await upstream.close()
                    await downstream.close()
                return downstream
            async with ingress_client.request(
                request.method, destination, headers=headers,
                data=request.content.iter_chunked(access_proxy.CHUNK) if request.can_read_body else None,
                allow_redirects=False,
            ) as upstream:
                result = web.StreamResponse(status=upstream.status, headers=wire_headers(upstream.headers))
                await result.prepare(request)
                async for chunk in upstream.content.iter_chunked(access_proxy.CHUNK):
                    await result.write(chunk)
                return result

        app = web.Application()
        app.router.add_route("*", "/{path:.*}", ingress)
        ingress_url = await self.server(app)
        fixture = self

        class PrivateKeySdk(MountedFilesystemSandbox):
            def read_file(self, path):
                if path != hermes_common.ACCESS_KEY_PATH:
                    raise AssertionError("Only the tmpfs access key may be read by the relay fixture.")
                fixture.key_reads += 1
                return super().read_file(path)

        class OwnerCredential:
            def get_token(self, *scopes):
                if scopes != (hermes_common.INGRESS_SCOPE,):
                    raise AssertionError("Unexpected owner relay token scope.")
                fixture.token_calls += 1
                return AccessToken(FAKE_BEARER, int(time.time()) + 3600)

        self.credentials = access_hermes.AzureRelayCredentials(
            SimpleNamespace(credential=OwnerCredential()), PrivateKeySdk(),
        )
        local_client = await self.client(auto_decompress=False, trace_configs=[access_proxy.no_redirect_trace()])
        self.local = access_proxy.Proxy(
            local_origin=ORIGIN, target=TARGET, token_provider=self.credentials.bearer,
            key_provider=self.credentials.access_key, client=MappedClient(local_client, TARGET, ingress_url),
        )
        await self.server(self.local.app, port=18765)
        self.browser = await self.client(cookie_jar=aiohttp.CookieJar(unsafe=True))
        self.token = None
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline and process.poll() is None:
            self.process.capture()
            async with self.browser.get(ORIGIN + "/chat", timeout=aiohttp.ClientTimeout(total=3)) as response:
                if response.status == 200:
                    html = await response.text()
                    match = re.search(r'window\.__HERMES_SESSION_TOKEN__="([^"]+)"', html)
                    if match:
                        self.token = match[1]
                        self.assertNotIn(FAKE_BEARER, html)
                        self.assertFalse(self.inner.key in html, "The transport key reached dashboard HTML.")
                        break
            await asyncio.sleep(0.2)
        self.assertIsNotNone(self.token, "The actual dashboard did not bootstrap through every proxy hop.")
        self.headers = {"Origin": ORIGIN, "X-Hermes-Session-Token": self.token}

    async def client(self, **kwargs):
        client = aiohttp.ClientSession(**kwargs)
        self.clients.append(client)
        return client

    async def server(self, app, *, host="127.0.0.1", port=0):
        server = TestServer(app, host=host, port=port)
        await server.start_server()
        self.servers.append(server)
        return str(server.make_url("")).rstrip("/")

    async def close_stack(self):
        for client in reversed(self.clients):
            await client.close()
        for server in reversed(self.servers):
            await server.close()
        if self.process is not None:
            await asyncio.to_thread(self.process.stop, timeout=8)

    async def test_native_browser_chat_reconnect_events_and_owner_relay_contract(self):
        async with self.browser.get(ORIGIN + "/api/status", headers=self.headers) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(response.headers["Content-Security-Policy"], access_proxy.browser_policy(ORIGIN))
            await response.read()
        previous_reads = self.key_reads
        self.inner.key = access_proxy.create_access_key()
        async with self.browser.get(ORIGIN + "/api/status", headers=self.headers) as response:
            self.assertEqual(response.status, 200)
            await response.read()
        self.assertEqual(self.key_reads, previous_reads + 1)
        self.reject_ingress = True
        previous_calls = self.ingress_calls
        async with self.browser.get(ORIGIN + "/api/status", headers=self.headers) as response:
            self.assertEqual(response.status, 401)
            await response.read()
        self.assertEqual(self.ingress_calls, previous_calls + 1)
        self.assertEqual(self.key_reads, previous_reads + 1)
        self.reject_ingress = False
        for route in ("/api/config", "/api/gateway/start", "/api/cron"):
            async with self.browser.post(ORIGIN + route, headers=self.headers, json={}) as response:
                self.assertEqual(response.status, 403)
                self.assertIn("Managed mode", await response.text())
        async with self.browser.ws_connect(
            ORIGIN + "/api/events", params={"token": self.token, "channel": "p3-readonly"}, headers=self.headers,
        ) as events:
            await events.send_json({
                "jsonrpc": "2.0", "id": "read-only-events", "method": "client.capabilities",
                "params": {"server_requests": True},
            })
            async with asyncio.timeout(10):
                while True:
                    message = await events.receive_json()
                    if message.get("id") == "read-only-events":
                        self.assertIn("Managed mode", message["error"]["message"])
                        break
            self.assertFalse(events.closed)
        driver = r"""
const fs=require("fs"),{chromium}=require("/opt/hermes-browser/node_modules/playwright");
const input=JSON.parse(fs.readFileSync(0,"utf8"));
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
function records(file){return fs.existsSync(file)?fs.readFileSync(file,"utf8").trim().split("\n").filter(Boolean).map(line=>JSON.parse(line)):[]}
(async()=>{
  const browser=await chromium.launch({headless:true,args:["--no-sandbox","--disable-dev-shm-usage"]});
  try {
    const page=await browser.newPage({viewport:{width:1280,height:900}});
    await page.addInitScript(()=>{
      window.hermesCspViolations=[];
      document.addEventListener("securitypolicyviolation",event=>{
        let location=event.blockedURI;
        try {const url=new URL(location);location=url.origin+url.pathname}
        catch {location=["inline","eval"].includes(location)?location:"other"}
        window.hermesCspViolations.push({directive:event.effectiveDirective,location});
      });
    });
    let text="",transportLeak=false;
    const sockets=[],styles=[],failures=[],pageErrors=[],wsPaths=new Set();
    page.on("pageerror",error=>pageErrors.push(error.name));
    page.on("request",request=>{
      const headers=request.headers();
      if(headers.authorization||headers["x-hermes-access-key"])transportLeak=true;
    });
    page.on("response",response=>{
      const path=new URL(response.url()).pathname;
      if(path.endsWith(".css"))styles.push(response.status());
      if(response.status()>=500)failures.push({path,status:response.status()});
    });
    page.on("websocket",socket=>{
      const url=new URL(socket.url());
      wsPaths.add(url.pathname);
      if(url.pathname!=="/api/pty")return;
      sockets.push({attach:url.searchParams.get("attach")});
      socket.on("framereceived",event=>{
        text=(text+(Buffer.isBuffer(event.payload)?event.payload.toString():event.payload)).slice(-4*1024*1024);
      });
    });
    async function waitFor(predicate,label,seconds=50){
      const end=Date.now()+seconds*1000;
      while(Date.now()<end){if(predicate())return;await delay(100)}
      throw Error(label+"; HTTP failures="+JSON.stringify(failures)+"; page error types="+JSON.stringify(pageErrors));
    }
    await page.goto(input.origin+"/chat",{waitUntil:"domcontentloaded"});
    await page.waitForSelector(".xterm-screen",{timeout:45000});
    await waitFor(()=>records(input.rpc).some(frame=>frame.method==="session.create"&&frame.params?.cols),"Native TUI handshake");
    await delay(2000);
    const main=()=>records(input.capture).filter(record=>record.tools!==null);
    const replies=method=>records(input.rpc+".responses").filter(frame=>frame.request_method===method&&frame.result);
    const terminal=()=>text.replace(/\x1b\[[0-?]*[ -/]*[@-~]/g,"").replace(/\s+/g,"");
    async function enter(prompt){
      await page.locator(".xterm-helper-textarea").focus();
      await page.keyboard.type(prompt,{delay:5});
      await delay(600);
      await page.keyboard.press("Enter");
    }
    async function submit(prompt,count){
      await enter(prompt);
      await waitFor(()=>main().length>=count,"Native model request");
      await waitFor(()=>text.includes("Offline P4 response"),"Native PTY response");
    }
    const bootstrap=await page.evaluate(()=>typeof window.__HERMES_SESSION_TOKEN__==="string");
    let firstViolations=[],interaction={};
    if(input.scenario==="normal"){
      await page.locator(".xterm-helper-textarea").focus();
      const longSlash="/co"+"x".repeat(300),longPath="./"+"x".repeat(300);
      for(const [method,key,prompt,expected] of [
        ["complete.slash","text",longSlash,longSlash],
        ["complete.path","word","see https://example.com/x and/or "+longPath,longPath]
      ]){
        await page.keyboard.type(prompt,{delay:5});
        await waitFor(()=>{
          const request=records(input.rpc).filter(frame=>frame.method===method&&frame.params?.[key]===expected).slice(-1)[0];
          return request&&replies(method).some(frame=>frame.id===request.id);
        },"Native long "+method+" completion");
        await page.keyboard.press("Tab");
        await page.keyboard.press("Control+u");
      }
      const previousColumns=replies("terminal.resize").slice(-1)[0]?.result.cols;
      await page.setViewportSize({width:1440,height:900});
      await waitFor(()=>replies("terminal.resize").some(frame=>frame.result.cols!==previousColumns),"Real browser terminal resize");
      for(const method of ["complete.path","complete.slash"]){
        if(replies(method).some(frame=>JSON.stringify(frame.result)!=='{"items":[]}'))throw Error("Managed completion returned nonempty or unexpected data");
      }
      if(records(input.capture).length!==0)throw Error("Completion or resize issued a model request");
      await submit("Offline full-hop P3 first prompt",1);
      firstViolations=await page.evaluate(()=>window.hermesCspViolations);
      const before=sockets.length;
      text="";
      await page.reload({waitUntil:"domcontentloaded"});
      await page.waitForSelector(".xterm-screen",{timeout:45000});
      await waitFor(()=>sockets.length>before,"Actual browser PTY reconnect");
      await delay(2000);
      await submit("Offline full-hop P3 second prompt",2);
      const beforeContext=records(input.capture).length;
      await enter("/context");
      await waitFor(()=>replies("slash.exec").some(frame=>frame.result.output?.includes("Conversation: 4 messages")),"Actual live context reply");
      await waitFor(()=>terminal().includes("Conversation:4messages"),"Rendered live context");
      if(records(input.capture).length!==beforeContext)throw Error("Context issued an extra model request");
      const previous=records(input.rpc).find(frame=>frame.method==="prompt.submit").params.session_id;
      await page.keyboard.press("Escape");
      await delay(300);
      await enter("/new");
      await waitFor(()=>terminal().includes("Startanewsession?"),"Native new-session confirmation");
      await page.keyboard.type("y");
      await waitFor(()=>replies("session.close").some(frame=>frame.result.closed)
        &&replies("session.create").some(frame=>frame.result.session_id!==previous),"Actual session close and replacement",15);
      interaction={context:true,sessionClosed:true,completion:true,resize:true};
    } else if(input.scenario==="references"){
      for(const prompt of [
        "summarise @file:secrets/google/credentials.json",
        "summarise @url:"+input.referenceUrl
      ]){
        text="";
        await enter(prompt);
        await waitFor(()=>terminal().includes("ContextreferencesaredisabledinmanagedSandboxmode."),"Visible managed reference refusal");
        if(records(input.capture).length)throw Error("A blocked context reference invoked the model");
        if(text.includes(input.referenceMarker))throw Error("Private reference marker reached the terminal");
      }
      text="";
      await submit("Offline after blocked references",1);
      interaction={referencesRejected:true,recovered:true};
    } else if(input.scenario.startsWith("clarify-")){
      await enter("Offline native TUI P4 prompt");
      await waitFor(()=>text.includes("Pick a color")&&records(input.rpc+".responses").some(frame=>frame.method==="clarify"),"Rendered native clarify");
      await page.keyboard.press("Enter");
      if(input.scenario==="clarify-batch"){
        await waitFor(()=>replies("clarify.lock").some(frame=>JSON.stringify(frame.result.remaining)==='["q1"]'),"First batch answer locked");
        if(main().some(record=>record.tool_results.length))throw Error("Batch completed before the second answer");
        await waitFor(()=>text.includes("Pick a shape"),"Rendered second clarify question");
        await delay(300);
        await page.keyboard.press("Enter");
        await waitFor(()=>replies("clarify.lock").some(frame=>frame.result.remaining?.length===0),"Final batch answer locked");
      }
      await waitFor(()=>main().some(record=>record.tool_results.length),"Clarify reached the native model");
      await waitFor(()=>text.includes("Offline P4 response"),"Assistant resumed after clarify");
      const result=JSON.parse(main().find(record=>record.tool_results.length).tool_results.slice(-1)[0]);
      interaction={answers:input.scenario==="clarify-batch"?result.responses.map(item=>item.user_response):[result.user_response]};
    } else {
      await enter("Offline long streaming prompt");
      await waitFor(()=>text.includes("Offline stream running"),"Actual stream before Ctrl+C");
      const started=performance.now();
      await page.keyboard.press("Control+c");
      await waitFor(()=>replies("session.interrupt").some(frame=>frame.result.status==="interrupted"),"Native interrupt result",8);
      await waitFor(()=>records(input.capture+".stream").some(record=>record.event==="closed"),"Native streaming transport closed",8);
      const stopped=performance.now()-started;
      if(stopped>=8000)throw Error("Native stream interruption exceeded eight seconds");
      text="";
      await enter("Offline after interrupt");
      await waitFor(()=>main().some(record=>record.user_prompt==="Offline after interrupt")&&text.includes("Offline P4 response"),"Next prompt after interruption");
      interaction={interrupted:true,nextPrompt:true,closedMilliseconds:Math.round(stopped)};
    }
    const cspViolations=firstViolations.concat(await page.evaluate(()=>window.hermesCspViolations));
    const uiErrors=records(input.rpc+".responses")
      .filter(frame=>frame.error&&["complete.path","complete.slash","terminal.resize"].includes(frame.request_method))
      .map(frame=>({method:frame.request_method,code:frame.error.code}));
    if(input.screenshot)await page.screenshot({path:input.screenshot});
    console.log(JSON.stringify({
      bootstrap,transportLeak,styles,failures,pageErrors,cspViolations,uiErrors,interaction,wsPaths:[...wsPaths],
      ptyConnections:sockets.length,
      sameAttach:sockets.length>1&&Boolean(sockets[0].attach)&&sockets[0].attach===sockets[sockets.length-1].attach,
      nativeResponse:text.includes("Offline P4 response")
    }));
  } finally {await browser.close()}
})().catch(error=>{console.error(error);process.exitCode=1});
"""
        process = await asyncio.create_subprocess_exec(
            "node", "-e", driver, stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            output, errors = await asyncio.wait_for(process.communicate(json.dumps({
                "origin": ORIGIN, "capture": str(self.capture), "rpc": str(self.rpc_capture),
                "screenshot": os.environ.get("HERMES_P3_SCREENSHOT"), "scenario": self.scenario,
                "referenceUrl": self.reference_url, "referenceMarker": self.reference_marker,
            }).encode()), 180)
        finally:
            if process.returncode is None:
                process.terminate()
                await process.wait()
        self.assertEqual(process.returncode, 0, errors.decode())
        evidence = json.loads(output)
        self.assertTrue(evidence["bootstrap"])
        self.assertTrue(evidence["nativeResponse"])
        self.assertFalse(evidence["transportLeak"])
        if self.scenario == "normal":
            self.assertTrue(evidence["sameAttach"])
            self.assertGreaterEqual(evidence["ptyConnections"], 2)
            self.assertEqual(evidence["interaction"], {
                "context": True, "sessionClosed": True, "completion": True, "resize": True,
            })
        elif self.scenario == "references":
            self.assertEqual(evidence["interaction"], {"referencesRejected": True, "recovered": True})
            self.assertEqual(self.reference_hits, [])
            marker = self.reference_marker.encode()
            for directory in (Path("/mnt/data/hermes"), Path(self.bootstrap.name)):
                for path in directory.rglob("*"):
                    if path.is_file():
                        self.assertLess(path.stat().st_size, access_proxy.MAX_BODY)
                        self.assertFalse(marker in path.read_bytes(), "Reference marker reached " + path.name)
        elif self.scenario.startswith("clarify-"):
            self.assertEqual(
                evidence["interaction"]["answers"],
                ["Blue", "Round"] if self.scenario == "clarify-batch" else ["Blue"],
            )
        else:
            self.assertTrue(evidence["interaction"]["interrupted"])
            self.assertTrue(evidence["interaction"]["nextPrompt"])
            self.assertLess(evidence["interaction"]["closedMilliseconds"], 8000)
        self.assertTrue(evidence["styles"])
        self.assertTrue(all(status == 200 for status in evidence["styles"]))
        self.assertEqual(evidence["failures"], [])
        self.assertEqual(evidence["pageErrors"], [])
        self.assertEqual(evidence["cspViolations"], [])
        self.assertEqual(evidence["uiErrors"], [])
        self.assertTrue({"/api/pty", "/api/ws", "/api/events"} <= set(evidence["wsPaths"]))
        records = [json.loads(line) for line in self.capture.read_text().splitlines()]
        main = [record for record in records if record["tools"] is not None]
        self.assertGreaterEqual(len(main), 1 if self.scenario == "references" else 2)
        for record in main:
            self.assertEqual(record["surface"], "full-access-browser")
            self.assertEqual(sorted(record["tools"]), ["clarify", "memory"])
            self.assertTrue(record["test_bearer"])
        frames = [json.loads(line) for line in self.rpc_capture.read_text().splitlines()]
        expected_prompts = (
            ["Offline full-hop P3 first prompt", "Offline full-hop P3 second prompt"] if self.scenario == "normal"
            else ["Offline long streaming prompt", "Offline after interrupt"] if self.scenario == "interrupt"
            else [
                "summarise @file:secrets/google/credentials.json", "summarise @url:" + self.reference_url,
                "Offline after blocked references",
            ] if self.scenario == "references"
            else ["Offline native TUI P4 prompt"]
        )
        prompts = [frame["params"] for frame in frames if frame.get("method") == "prompt.submit"]
        self.assertEqual([prompt["text"] for prompt in prompts], expected_prompts)
        self.assertEqual(len({prompt["session_id"] for prompt in prompts}), 1)
        attempts = Path(str(self.capture) + ".network-attempts")
        self.assertFalse(attempts.exists(), "Native fixture attempted external networking.")
        self.assertFalse(self.token in self.log_path.read_text(), "Native dashboard logged its browser session token.")
        if self.reference_marker:
            self.assertFalse(self.reference_marker in self.capture.read_text(), "Reference marker reached model capture.")
        self.assertEqual(self.token_calls, 1)
        print("P3_BROWSER=" + json.dumps({"scenario": self.scenario, **evidence["interaction"]}, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
