# Personal Hermes on Azure Container Apps Sandboxes

This is a **separate, managed, text-only Hermes pilot** on
[Azure Container Apps Sandboxes](https://sandboxes.azure.com), not an Azure
Container App, Dynamic Session, or Foundry hosted agent. It does not replace
or change this repository's Copilot deployment, image, scheduler, or `.env`.

## Explicit temporary MVP egress opt-in

**WARNING: `allow-all-mvp` removes outbound network isolation. All internet
destinations are permitted, with no TLS inspection. A compromised prompt/model
path could exfiltrate personal data to any destination.** Owner-only Entra
ingress, exact model-visible tools, managed HTTP/native RPC restrictions,
WhatsApp self-chat guards, and Google read-only scopes remain mandatory, but
they are not an outbound network boundary.

The user selected **No inspection + Allow all egress** for the temporary MVP.
To accept that risk deliberately, set this in the separate `.env.hermes` or
explicitly in the process environment:

```dotenv
HERMES_EGRESS_MODE=allow-all-mvp
```

The sample leaves this value blank. Deploy, replacement, deployment checks,
and owner-relay access reject a missing, misspelled, or unverified mode before
constructing configuration or Azure clients. There is no default Allow mode
and no automatic service-error fallback. The raw sandbox request is exactly:

```json
{"defaultAction":"Allow","trafficInspection":"None"}
```

There are no hostname or advanced rules in the request. Both its raw create
response and an authenticated GET must independently satisfy the MVP predicate;
SDK typed conversion or a later matching GET cannot excuse a create mismatch.
The root legacy fields retain `Allow`/`None` (known spelling is case-normalized;
null is not `"None"`), and root `hostRules`/`rules` must be absent, null, or empty
arrays.

The explicit compatibility predicate recognizes the official
[`2026-09-01-preview` data-plane schema](https://github.com/Azure/azure-rest-api-specs/blob/799f241aaa07e2485e0b06cc8f6f3b3caefd29da/specification/app/data-plane/ContainerApps/models/sandboxes.tsp):

| Readback field | Required MVP behavior |
| --- | --- |
| Root `enforcementMode` | Absent or exactly `Enforced`/`Audit`; null and unknown values fail. Both documented modes are accepted only because this profile claims no deny/rule enforcement boundary. |
| `http` | Absent, or an object with explicit, case-exact `defaultAction: Allow` and `trafficInspection: None`. Neither field is inherited; omitted inspection is rejected because its documented default is Full. |
| `http.hostRules` / `http.rules` | Absent or empty arrays only; null, malformed, or nonempty values fail. |
| `http.enforcementMode` | Absent or exactly `Enforced`/`Audit`; if root and HTTP modes are both present, they must agree. Absence never synthesizes a mode. |
| `http.defaultForward` / extra HTTP fields | Any presence fails, including null or empty values. No forwarding URL, CA data, or nested unknown semantics are accepted. |
| Root `tds`, `transportRules`, `validationWarnings` | Any presence fails name-only, even empty. These documented sections are not ordinary metadata. |

The SDK remains pinned to b4 / `2026-02-01-preview`; the newer schema is a
classification reference, not an API upgrade or proof of cross-version alias
precedence. Both flat and HTTP representations must satisfy their own checks.
This predicate does not recover the omitted values from earlier sealed runs.

Before policy assertions, a redacted observation records fixed-schema field
presence, finite JSON types, array counts, and recognized enum literals only.
It distinguishes absence from null and reports any accepted `Enforced`/`Audit`
without calling it isolation. Unknown values, rules, headers, URLs, CA data,
secret/MI references, credentials, and private runtime configuration are not
traversed or logged. The observation is emitted as a warning before validation
and returned under the deployment check's `egress.readback.observation`.
Its `NOT EVALUATED` marker describes capture time, not the later validation result.
Programmatic deployment can supply `egress_capture` to persist each policy-checked
create/GET observation, including the fresh network precheck, synchronously before
acceptance; capture failure blocks deployment.
Logs alone are not a durable receipt: an authorized live driver must use a
durable sink and separately capture transport/parser failures before a raw
document is available. The pure `egress_policy_observation` helper is shared
with that capture path; no consumed driver is modified or reused.

### Optional durable status evidence

An authorized runner can share one `hermes_common.StatusRecorder(persist_event)`
between `deploy(..., fresh=True, status_capture=recorder)`,
`validate_egress(..., status_capture=recorder)` for its pre-status policy
check and `test_hermes.inspect_deployment(..., capture=recorder, network=True)`.
The existing deployment `egress_capture` callback remains separate. Neither
default CLI output nor a call without a sink produces durable status evidence.
This is a programmatic interface, not a new live-run authorization.

The synchronous sink must persist each record before returning **None**, or
raise. It owns private file permissions, append/atomic-write discipline and the
required file/directory flushes. Async/non-void sinks are rejected, including
on the legacy egress-capture path. A supplied sink failure raises
`StatusCaptureError`, poisons that recorder against reuse, and prevents later
checks or a successful inspection result. Its `operation`, `event`,
`error_category` and optional `prior_error_category` are safe fixed identifiers;
the sink's exception text and paths are suppressed. Ordinary check failures
retain their original exception when their failure receipt can be persisted.

Records use schema version 1, increasing sequence numbers, a closed
`hermes.status.v1.*` operation catalog, and `begin`/`pass`/`fail` events. The
precheck policy snapshot remains `NOT EVALUATED`: a separate capture `pass`
acknowledges that the preceding snapshot sink returned; a validator `pass` is
emitted only after the unchanged core predicate returns. A pass-record write
can itself fail, so no individual file proves its own writer finished or the
whole inspection succeeded. The next `status.mode/begin` establishes entry
into the inspector after the precheck wrapper returned.

The stream follows the existing call order: mode, fresh owner claims, RG GET
and labels/region, group GET and labels/region, streamed ARM-resource ownership,
sandbox/image/volume inventory and contracts, exact-one-volume, a **fresh
repeated** ownership/selection sequence, and the next raw GET's begin/response.
It also covers the subsequent policy/runtime/key/control and optional HTTPS
checks. RG existence uses the existing GET/not-found result; no extra HEAD,
credential request, guest command, port change, retry or cloud operation is
introduced. Interrupted collections retain their count so far and
`complete: false`; a raw GET response is recorded before its consistency check.

Evidence contains only finite type tags, counts, expected-key/name/region/scope
match booleans and approved literals (`DataDisk`, `1Gi`, known policy enums).
It never contains resource IDs, raw labels, credentials, headers, URLs, phone
numbers, arbitrary service values or exception text. Group identity shape and
image base-digest match are **observations**, not new assertions: inventory
still permits older owned images for replacement. These are SDK-normalized
attributes, not raw collection-wire evidence; SDK defaults can erase the
difference between a missing wire field and null. Exact volume type/size
checks are unchanged, with no size normalization or inferred service behavior.

The inspector remains read-only and propagates failures. A deployment runner
must retain its existing fail-closed port/resource/RBAC cleanup; it must not
catch a status-capture failure as a warning and preserve a failed deployment.
This instrumentation does not identify the earlier sealed live failure,
recover missing observations, or change any consumed driver.

Nonempty rules, malformed fields, or conflicting values fail closed.
For this **non-isolating MVP only**, unknown top-level metadata
fields do not block solely because their names are new: diagnostics report their
sorted field names and count, never their values, and explicitly do not rely on
their semantics. Conservative rule/policy/security-bearing names (such as names
containing `rule`, `host`, `allow`, `deny`, `inspect`, `network`, `proxy`, `tls` or
`certificate`) still fail with an actionable name-only diagnostic. Malformed or
oversized names also fail without being echoed. The fixed-schema observation
contains only their count; separate name-only diagnostics retain the existing
bounded field-name policy, never metadata values. This classification is not a
complete service schema or a proof of unrestricted reachability. It does not
change the blocked hardened mode's semantics.

A mismatch does not retry with Partial, Full, or another policy. Existing
sandboxes with different policies are not silently modified.
`HERMES_IDENTITY_HOST` and `HERMES_WHATSAPP_HOSTS` remain reserved inputs for a
future hardened contract; **they do not constrain MVP egress**.

TLS certificate and hostname verification remain enabled. This mode does not
install inspection CAs, configure new proxies, or disable verification.
The unchanged runtime still passes platform-provided `HTTP_PROXY`, `HTTPS_PROXY`
and `NO_PROXY` (including lowercase variants), `SSL_CERT_FILE`,
`REQUESTS_CA_BUNDLE` and `NODE_EXTRA_CA_CERTS` to child processes when present.
Their presence, provenance and effective client trust under `None + Allow`
remain unverified live. The isolated smoke check uses certifi and bypasses
proxy settings, so it does not verify the runtime clients' trust configuration.
CLI warnings and the host diagnostic
status explicitly report the exfiltration risk and lack of isolation. Raw
readback alone does not prove that every internet destination is reachable. Cleanup
does not require accepting this unsafe opt-in: its ownership, confirmation and
disk-preservation checks remain available with a missing or unusable mode.

**Temporary does not mean automatically expiring.** Clearing or changing
`HERMES_EGRESS_MODE` does not alter an existing sandbox's egress or stop its
gateway, WhatsApp or Google credential use; it only blocks subsequent
deploy/test/access commands. Within the currently supported modes, end that
active exposure by cleaning up the owned compute. Default cleanup preserves
the private disk and credentials; it does not revoke OAuth grants or delete
retained data. Removing the local opt-in alone is not revocation.

The opt-in permits the reviewed provisioning path; it is **not evidence of a
successful live deployment** or permission for an agent to create resources.
Cloud scope, existing Foundry inputs/permissions, image publication, and personal
Google/WhatsApp onboarding remain separate explicit decisions.

### Future hardened mode and preserved probe findings

`HERMES_EGRESS_MODE=hardened-unverified` is reserved and always blocked. On
2026-09-24, the Sweden Central Sandbox service rejected creation with `Partial`
inspection and `defaultAction: Deny`:

```text
Partial traffic inspection requires defaultAction 'Allow'
```

The official [egress documentation](https://sandboxes.azure.com/docs/sandboxes/sandbox/egress)
describes `Full` plus `Deny`, but it remains a **separate unverified candidate**,
not an alternative selected by the MVP mode. Full inspection may change TLS/privacy boundaries:
an inspector that terminates TLS can see credentials and content. An isolated
non-personal probe does not authorize personal Google, WhatsApp, or Foundry
traffic through it. CA provenance, delivery/rotation, actual client trust,
hostname enforcement, and platform logging/retention require explicit evidence
and approval. The MVP requests no hostname enforcement under `None`.

The short rejected-policy probe's temporary role and resource group were
verified absent. Exact subscription, tenant, owner, resource, request, and role
assignment identifiers remain in local approval/evidence artifacts, not this
repository. No production deployment or image publication is implied by these
instructions.

A separately approved non-personal Full+Deny experiment created a
running sandbox with suspension disabled, but stopped before opening a port
because the strict policy readback comparison failed. The offending raw fields
were not captured, so this result is **inconclusive about Full policy support**,
not a service rejection or a CA failure. No CA, ingress, WebSocket, or managed
identity traffic was proved. Its temporary role and resource group were also
verified absent.

One newly approved follow-up on 2026-09-25 also reached Running with suspension
disabled and no public ports. Persisted create and authenticated GET summaries
matched `Full`, `Deny`, and the exact requested host rule. **Our verifier stopped
on two extra policy fields**, not an Azure Full-mode rejection. The redactor
retained their count but lost their names and individual value types, leaving
complete policy semantics unresolved. CA, ingress, WebSocket and MI stages
were not reached; this is not a CA/authentication failure. That run's exact
temporary assignment and resource group were independently confirmed absent.
Its approval is consumed and its sealed evidence is unchanged. Nothing in the
MVP choice reinterprets those unknown fields or establishes hardened support.

## Managed boundaries

| Surface | Contract |
| --- | --- |
| Image | Pinned Hermes source `645da6561c724b7ca163d4af9c21de3a6397c9f2`; Linux amd64, Ubuntu 24.04, root runtime, `/mnt/data` working directory. |
| Resources | Dedicated Hermes resource names and Sandbox Group system-assigned identity; 2 CPU, 4 GiB RAM, 20 GiB root, one single-writer 1 GiB DataDisk. Keep at least 256 MiB data headroom. |
| Lifecycle | Raw `autoSuspendPolicy.enabled=false` creation/readback. No idle suspension or disk-resume workaround for this pilot. |
| Configuration | `.env.hermes` only; exact nonsecret schema 1 at `/mnt/data/hermes/runtime.json`. No Copilot `.env` fallback. |
| Foundry | A supplied existing inference endpoint, deployment, API mode, context length, and `https://ai.azure.com/.default` scope. Group managed identity, in-memory tokens; no static API key or automatic model/RBAC provisioning. |
| Browser ingress | Exactly one HTTP 8080 `OnDemand` port, anonymous disabled, exact owner object-ID ACL. Tenant-wide membership is not equivalent to owner authorization. |
| Dashboard | Real native dashboard on `127.0.0.1:9119`; no public 9119, 8642, or 3000. Browser uses the local owner relay, not the raw ingress URL. |
| Tools | Only `clarify` and `memory`, plus exactly three Google read-only tools when eligible. No generic filesystem, shell, browser, install, scheduling, or configuration tools. |
| WhatsApp | Owner self-chat only, text only, locally authenticated bridge. Pairing is explicit and interactive; device keys are sensitive persistent data. |
| Google | Gmail read-only and Calendar events read-only scopes, exact account and calendar allowlists, no attachments or writes. |
| Egress | Deliberate temporary `allow-all-mvp`: `None` inspection + `Allow` default, no rules and **no outbound isolation**. Missing/unknown/hardened-unverified modes block deploy/test/access; no guest package installation or automatic fallback. |

The runtime is a deliberately constrained assistant, not an arbitrary-code
workspace. Native CLI/TUI dispatch and model-visible tool arrays are separately
guarded; an HTTP route allowlist alone would not constrain PTY input.
The native read-only `/context` command has an exact, argument-free TUI grammar;
it is not a general slash-command or external sidebar RPC allowance.
Clarify answers, bounded batch locks, interrupt, and close are admitted only
through their exact native TUI shapes. Response shape validation is not
authorization: the native dispatcher must also match the pending clarify
request, its questions, and the owning session/transport. Approval responses
and external-sidebar command expansion remain forbidden.
Native completion queries return empty items without filesystem, skill, or
plugin enumeration; the paired native handlers make this a harmless UI query,
not file access. Their entire compact ASCII-escaped JSON request, including
the identifier and envelope, must fit within 1 MiB. Terminal resizing accepts
1-1000 columns and is tied to the owning session.
File, URL, git, and plugin `@context` references are refused before expansion or
model invocation, including quiet CLI requests. Ordinary email text remains
literal. The visible refusal is `Context references are disabled in managed
Sandbox mode.`; it does not imply the requested content was read.

## Local preparation

Use Python **3.12**, Azure CLI authenticated with `az login`, and a separate
Hermes environment. The pinned Sandbox SDK is `0.1.0b4`, Azure Identity is
`1.25.3`, and both proxy hops use aiohttp `3.14.3`. Google/MCP dependencies are
shared through `hermes/image/google/requirements.txt`.

macOS/Linux:

```console
python3.12 -m venv .venv-hermes
.venv-hermes/bin/python -m pip install -r requirements-hermes.txt
cp .env.hermes.sample .env.hermes
```

Windows PowerShell:

```powershell
py -3.12 -m venv .venv-hermes
.venv-hermes\Scripts\python.exe -m pip install -r requirements-hermes.txt
Copy-Item .env.hermes.sample .env.hermes
```

Use that interpreter for subsequent `python` examples. Fill in the intended
subscription, tenant, authenticated owner object ID, dedicated resource names,
and existing inference settings. `HERMES_IMAGE` must be a public immutable
`@sha256:` reference; these scripts neither publish an image nor supply pull
secrets. Do not copy a sample phone/account value as a real identity.
Leave `HERMES_EGRESS_MODE` unset unless accepting the temporary unrestricted
egress risk above. Setting host inputs does not restrict traffic in this mode.

No credentials belong in `.env.hermes`. Process `HERMES_*` variables can override
file values; changed key **names**, not their values, are reported. Check those
warnings before selecting a target. The scripts pin the Azure tenant and pass
the subscription explicitly, without changing shared `az` defaults.

The group resource-ID shape used for explicit mutation confirmation is:

```text
/subscriptions/<subscription>/resourceGroups/<hermes-rg>/providers/Microsoft.App/sandboxGroups/<hermes-group>
```

Creation, replacement, and cleanup reject unowned resources, unexpected
additional writers/volumes, and foreign ports instead of adopting or silently
deleting them. Ownership tags include the owner's tenant and object ID, not
just the application and resource names; an identically named deployment owned
by someone else is not adopted. Data-plane permissions, including the scoped
**Container Apps SandboxGroup Data Owner** role, must be separately authorized;
the production scripts do not assign roles. A new role can take minutes to
propagate.

## Image provenance

The image builds native dashboard, TUI, and WhatsApp bridge artifacts at build
time; the guest does not run npm, pip, or uv installs. The approved build-only
exception is the single unavailable `electron-to-chromium` leaf from `1.5.433`
to exact `1.5.430`, within its parent's `^1.5.427` constraint. Its integrity and
unchanged remainder of the dependency graph must be checked; it is not permission
for additional dependency substitutions.

Local dependency or verification images are not the deployable final image.
The verification-only SDK layer must preserve every installed runtime package
version and must not be confused with production dependencies.

The original upstream dependency set has a declared incompatibility:
`msal==1.36.0` requires `cryptography<49`, while Hermes pins
`cryptography==50.0.0`. The user approved exactly `msal==1.37.0`, using the wheel
SHA-256 `dd17e95a7c71bce75e8108113438ba7c4a086b3bcad4f57a8c09b7af3d753c2d`.
Cryptography `50.0.0`, Azure Identity `1.25.3`, the Hermes commit, and every other
locked version/hash must remain unchanged. This is a single dependency
exception, not authorization for broader upgrades. The build applies it through
normal, hash-required dependency resolution and enforces standard strict
dependency checks. The upstream lock and project metadata remain unchanged;
the generated export preserves all 112 other requirement records, including
versions, markers, and hashes. See the image's
[dependency provenance](../hermes/image/DEPENDENCIES.md) for both approved
exceptions and the generated proof files.

The corrected exact-source production image and fresh SDK/browser layers pass
strict checks locally. The installed 108-package runtime differs from the prior
image only in MSAL; all other versions and dependency metadata are identical.
The verification layers preserve that runtime, its source bytes, and its image
ancestry. Native/Node, production-entrypoint, and all five actual browser
scenarios passed on these images without a runtime source overlay. These are
offline checks with local test providers, not proof of live Azure ingress,
egress, Foundry, or personal Google/WhatsApp access. The explicit mode gate above
remains in force. The MVP request/configuration change does not alter runtime
image sources, dependencies, or the control/runtime schema. Do not downgrade cryptography, inherit a compatibility
override, or bypass dependency resolution.

Build the separate image without publishing it:

```console
docker build --platform linux/amd64 --target final -t hermes-local:645da656 hermes/image
```

Where public package downloads are unavailable, the separately approved
build-only mirrors can be supplied without changing locked versions or disabling
TLS verification:

```console
docker build --platform linux/amd64 --target final --build-arg PYPI_INDEX_URL=https://packagefeedproxy.microsoft.io/pypi/simple --build-arg NPM_REGISTRY=https://packagefeedproxy.microsoft.io/npm/ -t hermes-local:645da656 hermes/image
```

Do not put credentials in build arguments, context, or image history. A cached
dependency overlay is useful for integration work but is not evidence that the
complete source Dockerfile built. The separate manual
`.github/workflows/hermes-image.yml` defaults to no publication; explicit
publication is a separate decision and follows its offline image checks.

## Deployment and access with explicit MVP opt-in

Only after separately approving the cloud scope and deliberately setting
`HERMES_EGRESS_MODE=allow-all-mvp`, use the exact-target interface:

```console
python scripts/deploy_hermes.py --fresh --confirm-target "<full-hermes-group-resource-id>"
python scripts/deploy_hermes.py --replace --confirm-target "<full-hermes-group-resource-id>"
```

Both paths print the unrestricted-egress warning. Missing or unverified modes
still refuse before configuration/Azure access, including `--replace`. Neither
command assigns roles, provisions a model, or publishes an image.

`--fresh` is explicit first-deployment-only behavior: after the existing owner
and ARM ownership checks, the production `provision_group` boundary requires
three consecutive complete, empty SDK inventory rounds. Each round consumes
volumes, sandboxes, disk images, then secrets, using the **same** configured
`AzureClients`, credential, group SDK object, pipeline, and transport/session.
Response envelopes match the pinned SDK per operation: volumes, sandboxes,
and disk images require a `value` list or a bare array; secrets require a
`secrets` list in an object, never an inferred empty list from a missing key.
Secrets pagination uses the same checked `nextLink` contract. No secret
metadata or values are retained. Unknown response shapes fail closed.
Rounds are at least ten seconds apart; there is no sleep after the third pass.
The readiness deadline is 900 seconds. Each complete SDK list read, including
all its pages, has a ten-second budget capped by the remaining deadline;
connection/read timeouts divide that budget without lengthening a smaller
configured timeout. Cyclic pagination is rejected before another read. No
success is accepted after the deadline. These are bounded SDK/network timeout
budgets, not a hard real-time guarantee about OS scheduling or a blocking sink.

HTTP 401/403 records `permission`, resets the streak, and permits only another
bounded read-only round. It is not evidence that role propagation is the cause.
Other transport, parser, unexpected HTTP status, malformed/unfinished list,
nonempty inventory, or ownership failures stop immediately. SDK 0.1.0b4 drops
timeout keyword arguments on list methods, so the helper temporarily wraps
the existing transport's `send` method for these synchronous reads. It enforces
the exact read target, records safe response status/counts, and surfaces denials
before SDK retries can hide them. The wrapper is restored on every exit; no
credential, client, session, token cache, or SDK retry configuration is replaced
or changed. Do not concurrently use this same client during the synchronous gate.

The original, single `list_volumes` boundary is then checked immediately with
operation `hermes.status.v1.provision.volumes.list`. A 403 on that read is still failure,
recorded as `permission` before the existing `RuntimeError` conversion, not a
reason to retry deployment. A finite readiness streak is not an authorization
guarantee. No PUT, image/sandbox creation, or whole deployment is retried by this
helper, and role scopes and all egress/ingress/rollback gates remain unchanged.

**The ordinary CLI retains the SDK's existing retry policy outside these
wrapped readiness reads.** That default includes retries for 403 and can
repeat later GET/PUT/DELETE requests; `--fresh` does not change it. Consequently,
the CLI is **not suitable for an authorized single-attempt live run** whose
contract forbids mutation retries. Its authorized driver must construct and
verify the original ARM/group clients with `retry_total=0` before calling
`deploy(..., fresh=True)`, as required by that run's frozen contract. The
readiness helper neither changes retry configuration nor replaces those
objects. Later unwrapped 403s fail immediately only with that no-retry client
configuration; they must never trigger a replay of `deploy` or resource creation.

Authorized drivers call `deploy(config, clients, fresh=True,
status_capture=recorder, egress_capture=policy_sink)` instead of duplicating an
external readiness loop. The recorder must have a synchronous durable sink;
CLI output alone is not evidence. The closed `readiness.*` operation catalog
records round indexes 1 through 3, streak reset/pass, safe completion counts,
last-page response type, required-items-key presence and item-container type,
elapsed milliseconds, and finite error categories, never credentials, claims,
headers, URLs, IDs, private values, or exception text. A supplied sink failure
stops before further reads or creation.

Fresh mode refuses existing data and cannot be combined with `--replace`.
The deployment's existing inventory read immediately afterward must still be
empty (`provision.fresh-inventory`); newly appearing resources are not adopted
as an idempotent deployment or reused as a recovery disk. This reuses existing
reads, forwards the same recorder through the existing `inventory.*` operations
so a subsequent permission failure has its exact operation, and is not an
atomic exclusion of concurrent owner mutations.
Omit `--fresh` for unchanged existing-deployment checks or recovery using a
preserved DataDisk; those paths do not wait for empty inventory. A readiness
failure precedes data-plane creation. The authorized live runner remains
responsible for its separately approved cleanup of newly created ARM resources
and role assignments. No historical deployment failure is attributed to a
specific propagation, token, or service cause by this contract.

Replacement preserves the same DataDisk, waits for the old writer to disappear,
uploads and verifies the nonsecret runtime atomically, applies controlled
reconfiguration, and checks policy/readiness before opening the owner port.
Before deleting the old writer it reads the gateway state, stops it, and
confirms persistent maintenance. These control reads do not require disk
headroom, but the new sandbox still must pass the normal 256 MiB readiness
gate. The old compute deletion must finish and a direct read must return 404
before any new writer is created.

Only a gateway with running intent is automatically resumed, and only after
the new dashboard and owner port are ready. This includes `running` and
`stopped`: the latter means a paired gateway in restart backoff, not deliberate
maintenance. Deliberate maintenance,
unpaired, or re-pair-required states are not automatically started. The final
gateway state and exact manual resume command are printed. A failed resume or
status read produces an explicit warning without rolling back ready compute;
inspect `control.py status --json` and resolve pairing/configuration before
resuming. A non-running or unreadable old sandbox, or one that cannot confirm
persistent maintenance, is preserved rather than implicitly started or deleted.
For transient failures, use controlled reconfiguration and then stop the gateway
before retrying. For a broken image or unreachable/stopped compute, use the
explicit, disk-preserving recovery procedure under [Cleanup](#cleanup), then
plain deployment. Deployment still requires the explicit mode opt-in and exact
policy readback; recovery does not bypass those checks.

Failure rolls back only a positively identified newly created sandbox, not the
personal disk. Rollback requires a completed deletion and a confirming 404,
then removes only the owned, unreferenced new image. Earlier images are preserved
on failure. Failed or cancelled image-import polling cleans only the newly
created image, before stopping any existing writer. If sandbox creation has an
unknown outcome and no matching new sandbox is positively identified, the image
is preserved too; a single empty list is not proof that creation failed.
An explicit rollback warning means residual resources may remain;
inspect the configured Hermes group rather than assuming cleanup succeeded.
If only obsolete-image cleanup fails after readiness, the new sandbox remains
ready and its ID is returned with an explicit cleanup warning.
Handoff warnings distinguish a refusal before any stop, an issued stop with
unconfirmed compute deletion, and confirmed previous-writer deletion. The
observed pre-stop gateway state is retained even when the stop command fails.
Before a stop, the warning gives only the exact recovery target, not a resume
instruction. After a stop, inspect which compute remains before resuming it.
After confirmed deletion, the warning instead directs a successful deployment
retry followed by explicit resume; it does not suggest recovery of the deleted
writer. A retry observes the saved maintenance state and does not infer the
pre-failure running intent.

Once a separately approved deployment exists:

```console
python scripts/access_hermes.py
```

Open the printed `http://127.0.0.1:8765/` URL on that same computer and keep the
process running. Use `--port` for a different unprivileged loopback port. Do not
forward or share this localhost listener; local OS users/processes are within
the owner workstation's trust boundary, much like an SSH tunnel.

The path is:

```text
browser -> 127.0.0.1 owner relay -> HTTPS Sandbox 8080 -> inner proxy -> 127.0.0.1:9119
```

The tenant-pinned local `AzureCliCredential` obtains the ingress bearer for
`https://auth.adcproxy.io/.default`. The browser never receives it or the private
transport key. A new 32-byte random transport key is created only on verified
`/dev/shm` tmpfs, in a 0700 directory/0600 file, and read into relay RAM through
the SDK. There is no persistent key fallback.

Only an inner 401 carrying `X-Hermes-Access-Key-Expired: 1` permits one
pre-forward key refresh/retry. Generic Azure ingress 401/403 responses do not.
Azure authentication, transport keys, relay declarations, and forwarding
headers are removed before reaching the dashboard. Its native session token
and exact loopback Origin are preserved.

Exact Host/Origin checks, an HttpOnly SameSite cookie, fixed upstreams, and
redirect refusal defend the browser boundary. Responses stream with
backpressure. HTTP bodies are capped at 10 MiB; the sole allowed session PATCH
is narrower, 16 KiB. WebSocket frames are capped at an inclusive 1 MiB with
30-second heartbeats and bounded connections.

The managed route inventory includes the pinned framework and built-in plugin
routes; plugins are not mounted in the managed application. Source changes and
actual registered-route drift fail closed. Management/onboarding/configuration,
cron/kanban writes, installs, lifecycle operations, and side-effectful GETs return
an explicit managed-mode denial. Only vetted reads, bounded session edits,
native Chat/PTY, sidebar RPC, and the read-only event feed remain available.
Forbidden event-feed input is never forwarded and does not disconnect a normal
subscriber.

The MVP guest has no outbound destination isolation; browser protections are
separate and unchanged. The text renderer escapes
HTML and does not turn Markdown images into automatic image elements. Proxy
Content Security Policy restricts resources to the local application and the
exact relay WebSocket endpoint, blocks remote media/frames/objects, and sends
`Referrer-Policy: no-referrer`. External links are user-initiated, not an
authorization to send private content.

## Controlled runtime operations

Use the Python SDK scripts for lifecycle, deployment, checks, and cleanup.
`aca` is reserved for the interactive shell, including human-visible pairing.
Within that shell, the pinned control program is:

```console
/opt/hermes/.venv/bin/python /opt/hermes-sandbox/control.py status --json
/opt/hermes/.venv/bin/python /opt/hermes-sandbox/control.py stop-gateway
/opt/hermes/.venv/bin/python /opt/hermes-sandbox/control.py pair
/opt/hermes/.venv/bin/python /opt/hermes-sandbox/control.py reconfigure
/opt/hermes/.venv/bin/python /opt/hermes-sandbox/control.py start-gateway
```

Do not run these as an indiscriminate sequence. `stop-gateway` enters deliberate
maintenance; `start-gateway` is the explicit resumption. Pairing is an
interactive owner action, not a dashboard endpoint. Reconfigure stops children,
applies the image/runtime-owned profile, validates it, and restores appropriate
process state while preserving deliberate gateway maintenance.

Status has exactly `schema_version`, `dashboard`, `gateway`, `whatsapp`,
`google`, and `disk_free_bytes`. Missing/failed integrations must not look
connected. Unknown free space (`-1`) or insufficient headroom cannot establish
readiness. A failed gateway should not remove the owner's diagnostic/control
path.
This guest control schema does not contain Azure policy. Use
`scripts/test_hermes.py` for the host status envelope's separate `egress` section:
it reports the selected mode, matched known policy fields, the name-only
`readback` metadata, `outbound_isolation: false` and a prominent privacy warning.
`raw_azure_policy` says `KNOWN MVP FIELDS MATCH`, not unrestricted-connectivity
or hardened-network verification. Do not interpret a running component as
hardened networking.

## Google onboarding and diagnostics

Create a Desktop OAuth client in the user's Google project and enable Gmail
and Calendar APIs. Google onboarding needs a separate explicit decision accepting
the personal-data flow under unrestricted MVP egress and completion of the
applicable live deployment checks; local acceptance is not approval to connect.

The unchanged Google helper does **not** require `HERMES_EGRESS_MODE`, print the
MVP warning, or read back Azure egress. Its Google-policy comparison does not
establish an outbound network boundary. Before connecting, run the host
diagnostic with the deliberate opt-in still present and resolve policy errors:

```console
python scripts/test_hermes.py
```

This procedural check is not enforced by the Google helper. Matching known
policy fields is not isolation, complete client-trust evidence, or approval
for personal onboarding. Only after the separate decision and checks above,
run on the owner computer:

```console
python scripts/google_auth_hermes.py connect --client-secrets "<local-desktop-client.json>"
```

The loopback flow uses state and PKCE, requests exactly Gmail read-only and
Calendar events read-only, and does not incrementally reuse broader grants.
Both the consent access token and a subsequent refresh must prove the actual
scope, client, and expected Gmail account. A minimal first-calendar availability
probe requests no event content. Token exchange and tokeninfo use POST bodies,
not secret-bearing URLs.

Only then does the helper compare the deployed Google policy and upload
credentials through B's single private SDK uploader to:

```text
/mnt/data/secrets/google/credentials.json
```

Parents are 0700; the file is a single-link 0600 regular file. Both must be owned
by the root runtime user; an unexpected SDK-written owner fails before commit.
Bytes are uploaded
to a private unpredictable staging file, read back, fsynced, and atomically
renamed. Credentials never enter shell arguments, environment variables, logs,
or ordinary exports. Failed staging does not replace a previously valid file.
The helper does **not** restart the assistant; follow its explicit reconfigure
instruction.

The exact credential fields are `schema_version`, `client_id`, `client_secret`,
`refresh_token`, `expected_email`, `granted_scopes`, and `scope_verified_at`.
No access token or expiry is persisted. Stored scope/account metadata is not
live authorization.

The MCP process uses the Hermes interpreter:

```text
/opt/hermes/.venv/bin/python /opt/hermes-sandbox/google/server.py
```

Its three model-visible tools are:

```text
mcp__google_readonly__gmail_search
mcp__google_readonly__gmail_read
mcp__google_readonly__calendar_events
```

Gmail search returns at most 20 message IDs per page. Message reads are bounded,
text-only, and exclude attachments. Calendar reads require an allowed calendar,
explicit timezone-aware bounds spanning at most 31 days, and at most 50 results.
Outputs are marked untrusted data, not instructions.

Offline and live diagnostics are deliberately different:

```console
/opt/hermes/.venv/bin/python /opt/hermes-sandbox/google/server.py --status --offline
/opt/hermes/.venv/bin/python /opt/hermes-sandbox/google/server.py --status
```

`configured`/offline exit 0 means structurally eligible, **not live connected**.
Known temporary network/quota/API-setup failures may retain exactly the three
descriptors with explicit unavailable/unverified status. Every actual read still
requires current-token scope/account proof before accessing data. Missing,
revoked, wrong-account, wrong-scope, and unknown internal failures fail closed.
An API setup or sharing failure is not automatically an invalid refresh grant.

To revoke access, revoke the Google grant at Google, stop the gateway, disable
the Google runtime policy, and explicitly reconfigure. Removing a local file
alone does not revoke the grant. External OAuth apps in Testing may require
reconnect after seven days. WhatsApp device revocation is a separate linked-device
action; do not confuse deleting local keys with revoking a remote device.

## Checks and recovery

```console
python scripts/test_hermes.py
python scripts/test_hermes.py --network
python -m unittest discover -s tests -p "test_hermes_*.py"
```

The diagnostic script distinguishes raw-policy/runtime checks from unverified
live inference, token-expiry soak, Google reads, WhatsApp delivery, and ingress
identity/WS checks. It requires the explicit MVP opt-in just like deployment and
reports the risk in both stderr and JSON. `--network` performs only a harmless
public-CA HTTPS reachability check to `example.com`, with certificate/hostname
verification, no environment proxy and no redirects. Its result is under
`network`, not the former `partial_network` key. It does not contact a personal
Foundry endpoint or Google/WhatsApp account, does not claim a platform deny, and
cannot prove reachability to every destination. A failed check never changes
trust or policy. Separately approved functional live validation still needs the
six actual clients (`aiohttp`, `httpx`, `httpx2`, `requests`, `httplib2`, and Node)
to reach the required approved service endpoints with normal certificate and
hostname verification. A successful `example.com` smoke check is not that
validation. The reserved hardened mode remains blocked.

Host tests use explicit fakes and never obtain personal credentials. Image-only
tests require the native pinned image and opt-in fixture flags. They use one
`--network none` container, disposable mounted storage, and fake model/bridge/
credential boundaries; do not point a filesystem fixture at personal data.
Offline success does not establish live Azure identity, egress, disk replacement,
or external-account integration.

Set `HERMES_UPSTREAM_SOURCE` to a checkout of the exact pinned Hermes SHA when
running the host route-inventory tests. Without that checkout those tests skip;
an explicitly supplied missing checkout is a failure, not successful inventory
validation. Inside the composed image the source is `/opt/hermes`.

| Image-only flag | Required fixture and scope |
| --- | --- |
| `HERMES_RUNTIME_IMAGE_TESTS=1` | Native managed CLI/TUI/WhatsApp, lifecycle and model-wire checks; A's explicit offline provider/bridge fixtures. |
| `HERMES_ENTRYPOINT_IMAGE_TEST=1` | Directly built production image, fresh offline data mount; real first-upload waiting, dashboard/proxy boot, maintenance, disk-reserve failure/recovery and shutdown. Package-manager sentinels exist only in the disposable test container. |
| `HERMES_UPLOAD_IMAGE_TEST=1` | Root Linux, an empty disposable `/mnt/data` mount, and the SDK verification layer; actual filesystem uploader behavior. Run separately from data-populating runtime tests. |
| `HERMES_BROWSER_IMAGE_TEST=1` | Native compiled dependencies; the actual Markdown renderer, not a substitute renderer. |
| `HERMES_BROWSER_REAL_IMAGE_TEST=1` | Separate Playwright verification layer; a renderer/CSP fixture with a reachable localhost canary. This alone is not full dashboard acceptance. |
| `HERMES_NATIVE_ACCESS_IMAGE_TEST=1` | One amd64 `--network none`, 2 CPU / 4 GiB container with a fresh data mount, the composed runtime, SDK, and test-only Chromium; actual owner-relay/dashboard/Chat/session integration. |

The browser/SDK validation additions are not production dependencies. Merely
enabling a flag on a host or pointing at an unrelated checkout does not satisfy
an image gate. Record pass and skip counts separately.

If authentication fails, check the configured tenant and owner login; do not
switch to a service-principal or shared PAT fallback. If control reports drift,
stop the gateway and use controlled reconfiguration rather than manually changing
generated tools, MCP, models, environment, or profile files. Keep the DataDisk
and use the explicit recovery below if the old image/control path cannot be
repaired. Another writer is never created before the old deletion is confirmed.

## Cleanup

The default cleanup removes only owned Hermes compute and preserves the
DataDisk, conversation history, Google credentials, and WhatsApp device keys:

```console
python scripts/cleanup_hermes.py --confirm-target "<full-hermes-group-resource-id>"
```

Disk-preserving cleanup uses the same confirmed-maintenance handoff as
replacement and confirms compute deletion before removing its images.
Redeploying that preserved disk leaves the gateway in maintenance; after
checking the new deployment, resume it explicitly in the owner shell:

```console
/opt/hermes/.venv/bin/python /opt/hermes-sandbox/control.py start-gateway
```

By default it refuses a non-running/unreadable old sandbox or an unconfirmed
maintenance state rather than guessing its persistent intent. For a transient
control failure, use the owner shell to run `control.py reconfigure`, then
`control.py stop-gateway`, verify `control.py status --json`, and retry cleanup.
For persistent image failures, stopped compute, or an unreachable control
socket, explicit recovery can remove only that owned compute while retaining
the disk:

```console
python scripts/cleanup_hermes.py --confirm-target "<full-hermes-group-resource-id>" --confirm-unquiesced-writer "<full-hermes-group-resource-id>/sandboxes/<exact-sandbox-id>"
```

Use the exact full writer target printed by the refusal or warning; repeat `--env-file`
if the original configuration used a nondefault path. The format is checked
before Azure calls, and the value must match the current single owned sandbox
before any command or delete. A missing/partial/wrong target is not a broad
force-cleanup permission. Cleanup attempts `stop-gateway` only for running
compute and reports its before/after gateway observations separately from the
stop result and status-read errors. It records only sanitized states/error types
and never starts or resumes compute or the gateway. A successful stop is not
reported as failed merely because the following status read failed.
Deletion still must complete, return 404 on
a direct read, and leave an empty sandbox inventory before image cleanup.
This flag does not authorize DataDisk deletion.

**Recovery explicitly accepts unconfirmed persistent gateway intent.**
Interrupted writes may not have been flushed. A saved `running` intent can
briefly start the gateway with the old on-disk runtime on the next boot.
Controlled `reconfigure` changes saved `failed` intent to `running` and can
start a paired gateway with the newly uploaded runtime. Review this risk before
using the confirmation; the final deployment state is always reported, or a
status warning is emitted if it cannot be read. Then use plain deployment, not
`--replace`, because the old compute has been removed. The production network
gate is not bypassed by this recovery option.

Explicitly authorized data deletion does not need to preserve gateway intent,
but still requires confirmed compute absence before deleting the disk. An
unreachable control path can use the same exact-writer confirmation alongside
the separate data-deletion confirmation.

Personal data deletion is a **separate explicit action**, not covered by approval
to delete a throwaway probe:

```console
python scripts/cleanup_hermes.py --confirm-target "<full-hermes-group-resource-id>" --delete-data --confirm-volume "<full-hermes-group-resource-id>/volumes/<hermes-volume-name>"
```

Only add `--delete-group` when that dedicated group/RG should also be removed;
it requires the same explicit data confirmation and rejects unexpected resources
or secrets. External Google grants and WhatsApp linked devices must be revoked
separately. Any cleanup error requires inspecting residual owned resources;
never report absence from a failed delete request alone.
