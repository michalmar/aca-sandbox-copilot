# Implementační plán: osobní Hermes v ACA Sandbox

Stav: plán schválen Opus 5.5 po třetím review (9,5/10); lokální
implementace následně přijata s hodnocením A 9,60/10, B7 10/10
a C 10/10. Dočasná B8 změna pro MVP egress byla samostatně přijata
v review 9,2 -> 9,9/10 a přesný finální zdroj ještě v neskórovaném
uzavření bez blockerů. B9 kompatibilita s novou HTTP egress schema
byla přijata 9,6 -> 9,9/10. B11 bezpečná status/inventory diagnostika
byla přijata 9,7 -> 9,9/10. B13 sustained readiness byla po opravě
skutečné SDK envelope vady přijata 7,7 -> 9,5/10.
U A nezůstávají opravitelné nálezy; zbývající odpočet je za přiznanou
strukturální složitost, nikoli neopravené vady. Přesné lokální image
a jejich integrační brány prošly. Všech 50 implementačních souborů bylo
předáno do hlavního checkoutu a znovu ověřeno včetně celé hostitelské sady.
Tři skutečné MVP deploy pokusy byly bezpečně ukončeny a plně uklizeny.
B9 odstranil první policy-schema blocker a druhý pokus živě prokázal
root/HTTP `Allow + None + Enforced`; zastavil se však v následné status
cestě bez dostatečně přesného checkpointu. B11 přidává diagnostiku této
cesty. Třetí pokus odhalil nestabilní data-plane readiness: jeden
úspěšný průchod následoval za 4,5 s HTTP 403. B13 zpřísňuje fresh
readiness. Čtvrtý cloudový pokus zůstává BLOCKED na samostatném schválení.
Souhlasy a výsledky jsou v §11; další pokus není automaticky povolený.
Datum: 2026-09-26.

## 1. Cíl, rozsah a potvrzená rozhodnutí

Výsledkem je samostatný osobní Hermes v **Azure Container Apps Sandbox**,
nikoli běžná Container App, Dynamic Session nebo Foundry hosted agent.
Stávající Copilot sandbox, jeho image, scheduler, AgentMail a všechny tři
způsoby startu tmux zůstanou funkčně beze změny.

| Oblast | Rozhodnutí |
| --- | --- |
| WhatsApp | Vlastní existující účet, Baileys linked device, režim `self-chat`. Uživatel píše sám sobě. Žádné nové číslo, Business Cloud API ani veřejný webhook. Uživatel výslovně přijal riziko omezení účtu a změn neoficiálního protokolu. |
| Dostupnost | Samostatný, stále běžící Hermes gateway. Automatické uspávání je vypnuté; nejde o úlohu pro stávající Copilot worker. |
| Web | Vestavěný Hermes dashboard včetně skutečného Chat/TUI přes WebSocket. Nevytváříme nový frontend. |
| Síť | Uživatel upřesnil, že veřejná HTTPS adresa je přijatelná, pokud je přístup povolen pouze jeho Entra účtu. To je autentizovaný veřejný ingress, **nikoli síťově privátní endpoint**. |
| Přístup z prohlížeče | Lokální Python přístupový proces po `az login`, prohlížeč na localhostu, Azure bearer token přidává proces mimo prohlížeč. Uživatel zvolil tuto variantu místo nové Entra app registration. |
| LLM | Existující inference endpoint a model deployment ve Foundry dodá uživatel. Hermes používá nativní provider `azure-foundry`, autentizaci `entra_id` a Managed Identity Sandbox Group. |
| Google | Konektory provozuje Hermes, ne Foundry. Osobní Google OAuth, pouze čtení/vyhledávání Gmailu a událostí. Žádné odesílání, změny událostí ani širší Workspace oprávnění. |
| Persistentní tajemství | Uživatel výslovně schválil uložení Google refresh tokenu a WhatsApp device keys na chráněném DataDisk; nikoli v image, Gitu, logu nebo běžném exportu. |
| MVP egress | Uživatel po vysvětlení rizika výslovně zvolil dočasný režim bez inspekce a s povolením veškerého odchozího provozu. Musí být aktivován přesně `HERMES_EGRESS_MODE=allow-all-mvp`; nejde o fallback ani bezpečný cílový stav. |
| Orchestrace | Nejdříve review plánu Opus 5.5; potom tři implementační podsession. Každá má implementátora a vlastního nezávislého kritika. |
| Git a cloud | Bez automatických commitů, pushů, PR, publikace image, přihlašování osobních účtů nebo změn existující Foundry infrastruktury. Živé operace až s konkrétními vstupy a schváleným cílem. |

Mimo rozsah: vytváření Foundry, nasazování modelů, WhatsApp Business,
scale-to-zero, hlas/STT/TTS, skupinové konverzace, autonomní komunikace s
cizími lidmi, Google write tools a nový veřejný webhook.

## 2. Podklady a zjištěné odlišnosti

Výchozí rešerše: session „Hermes azure integration“,
`370c0c77-137c-4007-a5c9-8fdb8ad5a904`, report
`research/hermes-agent-running-on-azure-container.md` v jejích artefaktech.
Lokální baseline je `148f791`.

Hermes připneme k ověřenému upstream commitu
`645da6561c724b7ca163d4af9c21de3a6397c9f2` v
[`NousResearch/hermes-agent`](https://github.com/NousResearch/hermes-agent/tree/645da6561c724b7ca163d4af9c21de3a6397c9f2).
Pohyblivý `main` nebo `latest` není reprodukovatelný zdroj instalace.

Doplnění původní rešerše:

- [Nativní Foundry provider](https://hermes-agent.nousresearch.com/docs/guides/azure-foundry/)
  již podporuje Entra ID a obnovování tokenů. Ověřeno také v připnutém
  [`agent/azure_identity_adapter.py`](https://github.com/NousResearch/hermes-agent/blob/645da6561c724b7ca163d4af9c21de3a6397c9f2/agent/azure_identity_adapter.py).
  Není důvod vytvářet vlastní inference proxy nebo ukládat jednorázový JWT.
- [Dashboard](https://hermes-agent.nousresearch.com/docs/user-guide/features/web-dashboard/)
  obsahuje Chat přes PTY/WebSocket; HTTP 200 ze status stránky není důkaz,
  že funguje konverzace. Potřebujeme předem sestavený web i TUI.
- [WhatsApp self-chat](https://hermes-agent.nousresearch.com/docs/user-guide/messaging/whatsapp/)
  je podporovaný režim Baileys bridge. Šifrovací klíče propojeného zařízení
  musí přežít restart. Odpojený, uspaný sandbox neumí tímto kanálem sám
  přijmout probouzecí zprávu.
- Vestavěný Google Workspace setup v připnutém
  [`setup.py`](https://github.com/NousResearch/hermes-agent/blob/645da6561c724b7ca163d4af9c21de3a6397c9f2/skills/productivity/google-workspace/scripts/setup.py)
  žádá širší scopes včetně zápisu a dalších služeb. Pro potvrzený read-only
  pilot jej nepoužijeme.
- [Sandbox private ingress](https://sandboxes.azure.com/docs/sandboxes/private-endpoints)
  existuje přes Express Environment a Private Endpoint, ale není potřeba
  pro uživatelem zvolenou variantu. Nezaměňujeme jej s Entra port ACL.
- Současný projekt hlásí ztrátu MI prostředí po disk-mode resume. Toto
  omezení neobcházíme uložením `IDENTITY_HEADER` nebo tokenu na disk.

## 3. Architektura a hranice důvěry

| Cesta | Realizace a bezpečnostní hranice |
| --- | --- |
| Browser -> lokální přístupový proces | Bind výhradně `127.0.0.1`; přesná kontrola Host/Origin včetně portu, lokální session ochrana proti CSRF a DNS rebindingu, žádný CORS wildcard. |
| Přístupový proces -> Sandbox HTTPS ingress | `AzureCliCredential(tenant_id=...)` lokálně, průběžné získávání tokenu pro `https://auth.adcproxy.io/.default`; TLS ověřování, pouze pevně zvolený sandbox a port. Token nikdy do URL, JavaScriptu ani browser storage. |
| Azure ingress -> interní dashboard | Publikován pouze port `8080`, `anonymous=false`, přesné owner `objectIds`; tenant filtr pouze po ověření kombinace filtrů. Reverzní proxy předává HTTP i WebSocket na loopback dashboard `9119`; odstraní Azure Authorization a nedůvěryhodné forwarded hlavičky. |
| WhatsApp -> Hermes | Pouze odchozí Baileys spojení, `self-chat`, přesně určený účet, žádné skupiny ani cizí DM. Lokální bridge není publikován. |
| Hermes -> Foundry | Nativní provider a obnovovaný Entra token; identita samostatné Sandbox Group, inference RBAC na konkrétním existujícím resource. |
| Hermes -> Google | Lokální read-only MCP server, Google OAuth majitele, explicitní scopes, explicitně povolené nástroje. |
| Persistentní data | Samostatný single-writer DataDisk na `/mnt/data`, `HERMES_HOME=/mnt/data/hermes`. Žádné sdílení disku nebo identity s Copilotem. |
| Proces uvnitř sandboxu -> loopback management API | Dashboard `9119` a Baileys bridge `3000` mají privilegované operace. Loopback není chráněn cloudovým egress filtrem. Agent nesmí mít nástroj schopný libovolného HTTP requestu, čtení souborů nebo spuštění kódu. |

Dashboard zůstane loopback-only. Samostatný OpenAI-compatible API server
`8642`, WhatsApp bridge port a další management porty se nepublikují.
Nebudeme nastavovat `HERMES_DASHBOARD_INSECURE` ani spoléhat na to, že
prohlížeč umí přidat bearer hlavičku do WebSocketu. Loopback dashboard sám
nemá Entra login: jde o upstream model důvěry podobný SSH tunelu.
Uživatele autentizuje Entra ingress; interní session token dashboardu
chrání jeho browser/API relaci, není další nezávislá identita.

Pro druhou nezávislou kontrolu transportu proxy při startu vygeneruje
32 náhodných bajtů do `/dev/shm/hermes/access-key` (adresář 0700,
soubor 0600, ne DataDisk). Při startu musí ověřit tmpfs; pokud není
dostupný, explicitně selže a nepoužije perzistentní náhradu.
Lokální klient je přečte přímo přes Azure SDK file API oprávněného
operátora a přidá `X-Hermes-Access-Key`. Vnitřní proxy jej ověří
konstantně časovým porovnáním před předáním čehokoli dashboardu.
Klíč se nesmí dostat do browseru, URL, logu nebo Azure port konfigurace;
rotuje při restartu proxy. Jen odpověď vnitřní proxy 401 s markerem
`X-Hermes-Access-Key-Expired: 1` dovolí klientovi jednou obnovit klíč
a zkusit request, který ještě nebyl předán dashboardu. Obecné Entra
401/403 se tímto mechanismem neopakují. Nejde o uživatelské MFA ani
náhradu ověření Entra ACL.

Oba proxy hopy vlastní session B a používají stejnou připnutou knihovnu
`aiohttp==3.14.3` (verze z připnutého Hermes). In-sandbox proxy binduje
`0.0.0.0:8080`, upstream je napevno `http://127.0.0.1:9119`.
Předá Host `127.0.0.1:9119`, odstraní Authorization, transportní klíč,
Forwarded a X-Forwarded-*; Origin z lokálního prohlížeče ponechá po
ověření beze změny. Lokální proxy Origin nepřepisuje ani nevymýšlí.
Odstraní hop-by-hop hlavičky s výjimkou řízeného WS upgradu.
Nesmí bufferovat SSE/streaming; oba WS hopy mají ping po 30 s,
omezení zprávy 1 MiB, HTTP body limit 10 MiB a omezené fronty.
Logují pouze metodu, cestu bez query, status a request ID.
Dashboard nese token také v query, proto logování celého URL není přípustné.

Proxy současně vynutí route policy managed profilu (vlastník B).
Zakáže dashboardové onboarding/pairing a změny messaging platforem,
gateway start/stop/restart, cron/kanban mutations, update Hermes,
instalace plugins/skills, změny MCP/tools, modelu, profilu, config a env.
Žádný takový endpoint není povolen ani pomocí side-effectful GET.
Výchozí policy pro management mutations je deny; povolené write/WS
výjimky jsou jen skutečně ověřené chat/session flow. A/B zmapují
přesné upstream routy při implementaci a otestují konkrétní URL/metody.
Inventář metod a cest se připne k upstream commitu; test selže při
jakékoli neklasifikované routě, včetně nového GET. Čtení libovolných
lokálních souborů a tajných hodnot prostředí není povolená read-only akce.
Stejná hranice platí uvnitř povoleného WebSocketu: `/api/ws` nabízí
JSON-RPC i pro mutace. B připne a otestuje allowlist konkrétních zpráv,
nejen upgrade routy; zakázané či neznámé operace se odmítnou před
předáním upstreamu. A omezuje nebezpečné TUI příkazy v jejich skutečném
dispatcheru, nikoli křehkým filtrem jednotlivých kláves proxy.
Povolený chat/PTY nesmí skrytě změnit tools, model, profil nebo služby.
Zakázané akce vracejí 403 s vysvětlením managed režimu, ne úspěšný no-op.
Ve WebSocket protokolu mají odpovídající explicitní chybovou odpověď.
Chat, čtení historie, paměti a stavu zůstanou použitelné; administrace
probíhá řízenou lokální konfigurací a `control.py`.

Přístupový proces nepůsobí jako obecná HTTP proxy: odmítá absolutní cílové
URL, `CONNECT`, cizí Host, neplatný Origin a libovolné přesměrování tokenu.
URL získá z metadat konkrétního Sandboxu a ověří proti očekávanému HTTPS
hostu/regionu/identifikátoru. WebSocket forwarding musí zachovat session,
streaming, zavírání spojení a backpressure. Veřejná URL bez platného tokenu
nesmí zpřístupnit ani status, konfiguraci, assety, soubory nebo WS handshake.

Entra port se vytváří a kontroluje přes raw preview REST, ne pomocí
SDK modelu portu, který v 0.1.0b4 ztrácí `objectIds`/`tenantIds`.
PUT nahrazuje celou sadu portů: očekáváme přesně jeden port a cizí
porty odmítneme, ne potichu smažeme. Explicitně nastavíme
`activationMode=OnDemand`, `protocol=Http`, `anonymous=false`;
raw readback je povinný při každé změně.

Kombinaci `objectIds` a `tenantIds` nepovažujeme bez důkazu za AND.
Preferujeme přesný owner object ID bez širokého tenant allowlistu;
pokud API vyžaduje tenant, musí živý negativní test prokázat, že
neotevírá přístup celému tenantovi. V opačném případě je nasazení BLOCKED.
Stejného tenant non-owner caller zajistí nová Hermes Group MI, která
na produkčním port allowlistu není; její token při testu nikdy nelogujeme.
Na izolovaném echo spike portu nejprve dočasně přidáme MI object ID a
ověříme pozitivní HTTP 200, pak jej odstraníme a požadujeme ingress
401/403. Jinak by odmítnutí všech app-only tokenů dalo falešný důkaz ACL.
Po obou změnách ACL se čeká s omezeným timeoutem na jejich skutečné
uplatnění a zaznamená se zpoždění propagace, zejména doba revokace.
Po celou dobu má spike správný transport key.
Dočasný egress allow pro vlastní port host je explicitní a ověřený raw
readbackem; DNS, timeout ani egress-proxy denial nejsou úspěšným
negativním testem. Původ odpovědi musí být rozlišitelný jako ingress.
Pokud se sandbox nedovolá sám sobě, potřebujeme druhý schválený
throwaway sandbox jako MI caller. Výjimky a dočasné ACL se uklidí
i při chybě; neověřený cleanup blokuje předání.

Read-only preflight dne 2026-09-24 prokázal, že lokální uživatelský
`az login` získá token pro `https://auth.adcproxy.io/.default`, s `oid`,
`tid`, `idtyp=user`. `aud` má hodnotu service application GUID
`9f34678b-7f96-4c6d-ac69-b06b1255b61e`, nikoli doslovného URL scope.
Token nebyl vypsán ani uložen. **To ještě nedokazuje přijetí ingress portem.**

První schválený živý krok session B je malý izolovaný spike:
owner-only port + WS echo, owner uspěje, anonymní/wrong-audience/MI
non-owner selže s výše uvedeným pozitivním kontrolním pokusem.
Spike nese produkční sadu Authorization, X-Hermes-Access-Key, loopback
Origin a X-Hermes-Session-Token pro HTTP i WS; echo v paměti ověří
hlavičky po každém hopu, nikoli jejich hodnoty v logu.
Ověří také skutečné SDK čtení access-key souboru a měří raw idle timeout
bez pingů i 10 minut nečinného WS s pingem po 30 s a reconnect.
Při rotaci transportního klíče ověří také průchod odpovědní hlavičky
`X-Hermes-Access-Key-Expired` přes ingress; bez ní nelze doložit obnovu.
Spike nesmí předběhnout review plánu ani potřebné schválení Azure cíle.
Při selhání nezveřejníme dashboard, nevypneme Entra a neoznačíme CLI
jako náhradu splněného webového požadavku. Web brána zůstane BLOCKED;
další architekturu schválí uživatel. Lokální práce A/C může pokračovat.

## 4. Runtime, image a persistence

Nová image bude v `hermes/image/`, mimo stávající CI glob `image/**`
a mimo build context Copilot image. Základ Ubuntu 24.04,
`linux/amd64`, runtime root a `/mnt/data` respektují zdejší projekt.
Agent nepoběží jako další proces uvnitř Copilot image a nepotřebuje vnořený
Docker. Python bude 3.12; připnutý Hermes vyžaduje `>=3.11,<3.14`.
Nativní gateway pro tento výslovně požadovaný root runtime potřebuje
`HERMES_ALLOW_ROOT_GATEWAY=1`. Nejde o `--yolo`, rozšíření nástrojů
ani povolení libovolných shell/CLI příkazů v managed rozhraní.

Image předem obsahuje Hermes, Azure Identity, potřebné MCP/Google knihovny,
Node, zamčené Baileys závislosti, sestavený dashboard i TUI a reverzní proxy.
Žádné `curl | sh`, instalace z pohyblivého branch nebo stahování volitelných
závislostí během konverzace. Využít upstream lockfiles, kde jsou podporované;
zaznamenat verze a zdrojový SHA. Image nikdy neobsahuje OAuth token, QR,
linked-device session, osobní data ani přihlašovací cache.

Minimální extras: upstream `web`, `pty`, `mcp`, `google`, a pouze
potřebné gateway dependencies (zejména aiohttp/qrcode); ne `[all]`.
MCP je `2.0.0` s `httpx2==2.7.0`; Google knihovny odpovídají upstream
extras. A připne skutečně dostupné base/Node/uv reference při buildu,
zaznamená digesty, použije Node 22 s verzí splňující upstream engines
a ověří lockfiles; nesmí si vymyslet checksum či publikovaný tag.
Baileys `npm ci` běží při buildu v image a zapíše upstream
`node_modules/.hermes-pkg-hash`. Instalace zůstává zapisovatelná pro root,
aby bridge nekopíroval celé node_modules na 1 GiB DataDisk.

Uživatel dne 2026-09-24 samostatně schválil jedinou build výjimku:
v kořenovém upstream `package-lock.json` nahradit pouze leaf
`node_modules/electron-to-chromium` z nedostupné `1.5.433` na přesnou
`1.5.430`, s integritou
`sha512-e1QEj72Y4zd8RlNZVmoTg+iCOSVwpk05IOiiQwdrkwCSVlZfPthevErhE+nckGd2YbsXfp1SkisznhGVIXP2NQ==`.
Jde o dev závislost se statickým mapováním Electron/Chromium; jediný
parent `browserslist` požaduje `^1.5.427`, což náhrada splňuje.
Záznam vygeneruje npm v izolovaném manifestu, při buildu se zkontroluje
původní source hash a shoda všech ostatních položek grafu. Žádný
neomezený `npm update`, změna Hermes commitu ani dalších verzí.
Mírně starší browser-target data jsou přiznaná odchylka, kterou pokryje
review a skutečný web/TUI build. Další nedostupné balíčky tím nejsou
schváleny k náhradě. Původní mirror vracel 404, veřejný registry nebyl
z tohoto prostředí dosažitelný ani alternativním web fetch.

Uživatel následně výslovně schválil jedinou další výjimku: **MSAL
`1.36.0` -> `1.37.0`**, wheel SHA-256
`dd17e95a7c71bce75e8108113438ba7c4a086b3bcad4f57a8c09b7af3d753c2d`.
Původní upstream vynucuje `cryptography==50.0.0`, ale metadata jeho
MSAL 1.36 požadují `<49`; strict check všech 108 instalovaných balíčků
odhalil přesně tuto jednu neshodu. MSAL 1.37 povoluje `<51` a jeho
ostatní hrany odpovídají stávajícím pinům. Cryptography 50, Azure
Identity 1.25.3, Hermes commit a všechny ostatní verze/hashe zůstanou
beze změny. Nástrojově vytvořená náhrada musí prokázat shodu zbytku
grafu a původu; nový build/CI používá přísný standardní `uv pip check`,
nikoli tolerovanou neshodu nebo resolver bypass.
Nová přesná produkční image i její ověřovací vrstva musí zopakovat
skutečné MI/MSAL klientské cesty, nativní/Node/entrypoint a browser testy.
Dřívější úspěšné funkční testy nejsou dokladem čistého grafu závislostí.

Start se nebude spoléhat na to, že sandbox spouští s6 jako PID 1.
Použijeme `tini` a explicitní malý Python supervisor, nikoli závislost
na s6 PID 1. Supervisor řídí dashboard, gateway a proxy, předává
signály, sklízí potomky a omezuje restartování s backoffem. Trvalá chyba
konfigurace nebo crash loop končí viditelným selháním.
Gateway běží s `hermes gateway run --external-supervisor`.
Upstream gateway lock/PID mechanismus znovu neimplementujeme.
Jeden writer znamená jeden sandbox na DataDisk a jeden gateway na home;
současný dashboard a gateway nad SQLite jsou podporované chování.

Bootstrap:

1. Ověří skutečný mount DataDisk, oprávnění, dostupné místo a verzi
   provozní konfigurace; nesmí tiše používat root filesystem jako náhradu.
2. Vytvoří home s `umask 077`, bez přepisování existující osobnosti,
   vzpomínek, historie a přihlašovacích dat.
3. Při bootu aplikuje řízený bezpečný profil z image a ne-tajného
   `runtime.json`. Stejnou operaci výslovně poskytne
   `control.py reconfigure` se zastavenými řízenými procesy.
   Zaznamená jen názvy změněných nastavení, ne hodnoty credentials.
   Pozdější start/restart dashboardu i gateway už profil pouze ověřuje;
   drift odmítne a vyžádá explicitní reconfigure.
4. Stav „WhatsApp ještě nespárován“ a „Google ještě nepřipojen“ rozlišuje
   od stavu „funkční integrace“. Dashboard a diagnostika zůstávají použitelné.
5. Gateway spustí až po existenci platného `creds.json` s účtem
   odpovídajícím `owner.whatsapp_phone`; chybějící pairing není crash loop.
6. Jediná podporovaná cesta párování je interaktivní
   `aca sandbox shell` -> `/opt/hermes-sandbox/control.py pair`.
   Tato operace nejprve atomicky nastaví persistentní desired state
   `maintenance`, zastaví gateway a ověří uvolnění upstream lock/PID
   i ukončení jeho bridge. Supervisor i SIGUSR1 handoff musí maintenance
   respektovat, včetně restartu samotného supervisoru.
7. Pair zavolá bridge `--pair-only` s vynuceným self-chat režimem, bez
   destruktivního upstream wizardu. QR je jen v oprávněném terminálu,
   nikdy v logu. Existující session nesmaže bez explicitního reconnect
   rozhodnutí. Dvě souběžná pair/start volání se serializují; další se
   odmítne. Při chybě zůstává maintenance/re-pair-required s diagnózou.
   Nové párování probíhá v odděleném staging adresáři a aktivuje se
   atomicky až po ověření owner účtu. Nesprávný nově připojený účet
   se odpojí; platné dosavadní credentials se nepřepíší.
8. Po párování znovu ověří číslo/JID/LID a celý managed profil, teprve
   potom vymaže maintenance a spustí gateway. Stav `loggedOut`
   znamená `re-pair-required`, ne nekonečné restarty. Restart vyžádaný
   CLI musí respektovat upstream SIGUSR1/external-supervisor handoff.
   Dashboardové mutace start/restart/pair jsou zakázané v proxy;
   ani pokus o přímý SIGUSR1 během maintenance nesmí spustit gateway.

Pilot drží projektový limit **1 GiB DataDisk**, 2 vCPU, 4 GiB RAM a 20 GiB
root disk. [Hermes doporučuje 2+ GB datového prostoru](https://hermes-agent.nousresearch.com/docs/user-guide/docker/),
proto je 1 GiB omezený pilot, nikoli produkční kapacitní slib. Před použitím
ověřit reálnou spotřebu. Logy rotovat, nezapínat debug payload logging,
nepřijímat neomezené přílohy a hlídat alespoň 256 MiB volného prostoru.
Historii nebo credentials automaticky nemažeme. Případné zvětšení disku
vyžaduje samostatné rozhodnutí a migraci.

Baileys `bridge.log` obsahuje i při vypnutém debug metadata cizích
kontaktů; považujeme jej za secret-class, zamezíme jejich logování malou
připnutou úpravou a zajistíme rotaci otevřeného logu s omezenou velikostí.
Do diagnostických balíčků nepatří. Media cache mají TTL/velikostní limit;
jejich úklid nesmí zasáhnout credentials, paměť ani historii.
Pro první pilot jsou automatické přílohy/hlas vypnuté; text a běžné
formátované odpovědi fungují. Obrazový/dokumentový přenos je samostatné
rozšíření, ne neomezená implicitní funkce.

Změna image/sandbox replacement zachová DataDisk; před výměnou zastaví
gateway a uvolní jediného writera. Záloha SQLite používá korektní backup
nebo zastavený proces, ne kopii živého WAL bez koordinace. Disk-mode resume
není podporovaná cesta k automatickému obnovení tohoto pilotu; při chybě MI
se služba zastaví s diagnózou, nikoli s API-key fallbackem.

Replacement si před stopem přečte schématicky platný stav gateway i při
nízkém či nedostupném měření místa. Před novým writerem vyžaduje potvrzený
maintenance a dokončené odstranění původního compute s přímým GET 404.
Po připravenosti nového dashboardu a portu obnoví pouze dříve běžící
gateway nebo její wanted-running backoff; záměrný maintenance zachová.
Selhání obnovy nesmí vymazat již připravenou instanci ani tvrdit funkční
WhatsApp: vrátí její ID s výslovným varováním a návodem na obnovu.
Disk-preserving cleanup má přísný bezpečný default. Pro nefunkčního
writera nabízí pouze explicitní recovery s potvrzením přesného celého
cíle a upozorněním na neflushnutá data či starý uložený záměr startu.
Žádné implicitní spuštění starého compute nebo mazání osobních dat;
varování rozlišují fázi před stopem, vydaný stop a prokázané odstranění.

## 5. Foundry a Managed Identity

Použijeme tyto nativní parametry:

```yaml
model:
  provider: azure-foundry
  auth_mode: entra_id
  base_url: <dodany HTTPS inference endpoint>
  default: <nazev existujiciho deploymentu>
  api_mode: <chat_completions | codex_responses | anthropic_messages>
  context_length: <overena kapacita deploymentu>
  entra:
    scope: https://ai.azure.com/.default
```

Nejde o projektový Foundry URL ani o ID již hotového Foundry agenta.
API mode a model capabilities se ověří proti dodanému deploymentu,
nikoli odhadem z marketingového názvu. Volání pomocných modelů musí
používat stejný povolený Foundry provider; žádný automatický fallback
do OpenRouter, Nous nebo jiného externího LLM.

Runtime nastaví `AZURE_TOKEN_CREDENTIALS=ManagedIdentityCredential`
a verzi `azure-identity`, která tento výběr podporuje. V image nebude
uživatelský `az login`, service-principal secret nebo statický Foundry klíč.
MI header poskytnutý platformou se neukládá do runtime JSON.

Single-profile režim má `gateway.multiplex_profiles=false`. Pomocné
`auxiliary.*` cesty explicitně míří do stejného Foundry deploymentu;
`fallback_providers=[]`, lokální memory provider a vypnutá telemetrie.
Identita se ověří z gateway i dashboard Chat a z potřebného shellu;
nespoléháme na to, že všechny child procesy automaticky převezmou MI env.
Při fail-closed egress je host lokálního `IDENTITY_ENDPOINT` explicitně
ověřenou platformní výjimkou; header hodnota se nikdy nezobrazuje.

Inference role musí odpovídat skutečnému endpointu:
[aktuální Microsoft dokumentace](https://learn.microsoft.com/azure/ai-foundry/foundry-models/how-to/configure-entra-id)
uvádí pro Foundry inference `Cognitive Services User`, zatímco některé
Hermes návody uvádějí `Azure AI User`/`Foundry User`. Automatizace proto
nepřidělí naslepo Contributor/Owner ani několik rolí „pro jistotu“.
Přijme konkrétní existující resource ID a ověřený inference role definition
ID; vytvoření role assignment je explicitní krok, alternativně jej
provede uživatel. Scope je konkrétní resource, ne celá subscription.

Povinné ověření: správná MI a audience, úspěšné inference a tool calling,
viditelná chyba bez RBAC, zákaz statického-key fallbacku a unit test
obnovení tokenu. Živý dlouhodobý test refresh se vyhodnotí podle skutečného
`expires_on`; dvě rychlá volání nejsou důkaz průchodu expirací.

## 6. Google OAuth a read-only konektor

Malý lokální stdio MCP server `google_readonly` vystaví pouze:

| MCP nástroj | Hermes název | Parametry a limity |
| --- | --- | --- |
| `gmail_search` | `mcp__google_readonly__gmail_search` | `query` max 512 znaků, `max_results` 1–20 (default 10), volitelný omezený page token; bez automatického čtení všech zpráv. |
| `gmail_read` | `mcp__google_readonly__gmail_read` | Validované `message_id`, max 16 000 znaků textu; limit dekódované velikosti, bez příloh. |
| `calendar_events` | `mcp__google_readonly__calendar_events` | `calendar_id` z allowlistu, explicitní RFC3339 `time_min/time_max`, max 31 dnů a 50 událostí; default `primary`. |

Diagnostika účtu je provozní CLI, ne další agent tool.
Server používá stejnou `/opt/hermes/.venv/bin/python` jako Hermes,
zamčené upstream `mcp`/`google` extras a žádný samostatný HTTP server.
Žádné `send`, `modify`, `delete`, draft creation, event insert/update,
Drive, Contacts, Sheets, Docs, generické URL fetch nebo shell execution.
Maxima počtu výsledků, délky obsahu, časového rozsahu a doby requestu
se vynucují v kódu. Přílohy se v pilotu automaticky nestahují.

Požadované scopes:
`https://www.googleapis.com/auth/gmail.readonly` a
`https://www.googleapis.com/auth/calendar.events.readonly`.
Nepoužijeme legacy Google Workspace setup ani inkrementální přidávání
širších scopes ze staré OAuth autorizace. OAuth helper nastaví
`include_granted_scopes=false`, ověří skutečně udělené scopes jako přesnou
množinu a účet přes `gmail.users.getProfile` vůči nakonfigurovanému
osobnímu Gmailu. Užší/širší grant, nedoložené scopes nebo jiný účet odmítne
s instrukcí k nové autorizaci. Stejnou kontrolu provede MCP při startu.

Upřesnění po prvním implementačním review C: známá dočasná síťová,
quota nebo service-setup chyba není důkaz neplatného grantu. Pokud je
credential strukturálně způsobilý, MCP smí zachovat přesně tři popisy
nástrojů, aby se zotavil bez trvalého zmizení tools z připnutého Hermes.
Stav přesto zůstává explicitně nedostupný/neověřený, nikoli connected.
Popis nástroje není oprávnění číst data: každé čtení projde ověřením
aktuálního tokenu, scopes a účtu, než odešle datový požadavek.
Chybějící/strukturálně neplatný credential, prokázaný nesprávný
scope/účet, revokace, rotace a neznámá interní chyba zůstávají fail-closed.
Offline `configured` nesmí být vydáváno za živé `connected`.
Nevzniká další tool, runtime schema ani background recovery timer.

Integrační časový kontrakt: stdio handshake nečeká na vzdálenou Google
autorizaci; okamžitá lokální diagnostika konfigurace zůstává zachována.
První `tools/list` provede jednu proof fázi s celkovým limitem **40 s**
včetně čekání na refresh lock. Ověřený nativní
`tools/mcp_tool_discovery.py` obaluje celý spawn, initialize a tools/list
managed `connect_timeout` limitem 45 s; dřívější předpoklad 60 s byl
pouze přepsaný upstream default. A ponechá `timeout` i `connect_timeout`
45 s, stejně jako dosavadní C limit čtecí operace. Nominální 5s rezerva
musí projít skutečným měřením startu/protokolu v image, pomalé chyby a
zrušení ověřování; není garantovanou dobou startu. Diagnóza musí dorazit
před vnějším timeoutem, nikoli závodit se shodným deadlinem.
Kandidát C4 byl následně ověřen v reálném nativním klientovi v amd64
image, Pythonu 3.12, 2 CPU/4 GiB a `--network none`: handshake 2,373 s,
celá discovery 42,449 s, naměřená rezerva 2,551 s. Zrušení ukončilo
child proces a nový pokus trval 0,820 s; revokovaný credential nevystavil
nástroje. Jde o konkrétní offline měření, ne obecnou garanci latence ani
splnění odděleného WhatsApp/živého Google testu.
Handshake sám nepřiděluje právo číst data. Změna neovlivní živý
`--status`, scope/account kontroly ani množinu povolených nástrojů;
projde novým cíleným review, ne zpětným přisouzením původního skóre.

Uživatel dodá vlastní Google OAuth Desktop client. Consent proběhne
interaktivně na jeho počítači pomocí loopback redirectu a PKCE, nikoli
přes veřejný callback v sandboxu. Upload refreshable credential proběhne
autentizovanou cestou SDK do chráněné části DataDisk, bez kopírování
do tracked `.env`, shell argumentů nebo výstupních logů.

Google refresh token a Baileys linked-device klíče **musí být perzistentní
tajemství**. Uživatel toto uložení výslovně schválil.
Jde o výslovně popsanou odlišnost Hermes od Copilot PAT egress
transformů, ne o tvrzení „žádné secrets na disku“. Soubory mají mód 0600,
adresáře 0700, jsou vyloučené z Gitu a běžných exportů; zálohy mají stejný
režim důvěrnosti. Přístup k Sandbox exec a DataDisk je ekvivalentem
přístupu k těmto účtům. Google credential bude mimo Hermes home:
`/mnt/data/secrets/google/credentials.json`. Každý MCP proces drží
krátkodobý access token jen v RAM; běžný refresh nepřepisuje persistentní
refresh token ani nevyžaduje mezislužbový file lock. Trvalý soubor se mění
pouze řízeným onboarding/reconnect uploadem přes atomický rename.
Pokud provider vrátí nekompatibilní rotaci refresh tokenu, stav se
viditelně označí k opětovnému připojení, ne potichu zahodí.

Hermes používá explicitní MCP tool allowlist; jeho
[`tools.include`](https://github.com/NousResearch/hermes-agent/blob/645da6561c724b7ca163d4af9c21de3a6397c9f2/website/docs/reference/mcp-config-reference.md)
má přednost před `exclude`. Resources/prompts, server-side sampling a
libovolné další MCP servery budou vypnuté, pokud nejsou potřebné.
Read-only capability se nevynucuje pouze promptem nebo MCP hintem:
vynucují ji Google scopes i implementované metody.

Read-only neznamená necitlivá data. Text e-mailů a kalendáře se při dotazu
může dostat do uživatelem zvoleného Foundry modelu a do jeho vlastního
WhatsApp self-chatu. Výstupy proto minimalizovat a komunikovat tuto hranici.
Externí OAuth aplikace ve stavu Testing může mít sedmidenní platnost
refresh tokenu; produkční způsobilost a consent screen dodává uživatel.
Revokace a `invalid_grant` musí zobrazit návod k opětovnému připojení,
nikoli prázdný úspěšný výsledek.

## 7. Bezpečný osobní profil a egress

Výchozí osobnost: soukromý osobní asistent, výchozí jazyk čeština,
časová zóna `Europe/Prague`, transparentní označení nejistoty a důvěrnosti.
Obsah e-mailů, kalendářů, citací a příloh je nedůvěryhodný vstup, ne nová
oprávnění. Persona není bezpečnostní kontrola.

Povolená agent toolset množina je `memory`, `clarify`, `google_readonly`.
Upstream canonical MCP toolset je `mcp-google_readonly` a
`google_readonly` je jeho alias; obě jména patří do povoleného
preflight kontraktu a nesmějí se dostat do globálního deny-listu.
Platformy `cli`, `tui` a `whatsapp` mají explicitní `platform_toolsets`
se stejným seznamem. `api_server`, `cron`, `acp` a nepoužívané platformy
jsou vypnuté a mají prázdné seznamy. Výsledné model-visible názvy jsou
`memory`, `clarify` a přesně tři MCP názvy uvedené v §6; bez Google
credential se Google nástroje nezaregistrují.

Globální `agent.disabled_toolsets` jako poslední backstop zahrne
`terminal`, `file`, `web`, `search`, `x_search`, `browser`, `code_execution`,
`delegation`, `cronjob`, `skills`, `vision`, `video`, `image_gen`,
`video_gen`, `tts`, `computer_use`, `homeassistant`, `kanban`,
`connections`, `project`, `desktop_ui`, `setup`, `bot_room`, `todo`,
`session_search`, `context_engine` a všechny další konkrétní upstream
toolsety kromě tří povolených. Nepoužije zákaz složeného `hermes-cli`
bundle, který by zároveň odstranil povolené tools. Při novém
neznámém registry entry po upgradu preflight selže; jeho schválení
vyžaduje změnu připnutého kontraktu a testů.

Žádné `--yolo`, `--allow-all-tools` ani smart-approval.
Řízené hodnoty: `approvals.mode=manual`,
`security.allow_lazy_installs=false`, multiplex off, fallback off,
žádné remote memory/telemetry/Nous bootstrap/room služby.
Managed profil při každém startu ověří toolsety, model route,
bezpečnostní nastavení, `WHATSAPP_MODE=self-chat`, povolený účet,
odmítnutí cizích DM/skupin a neprázdný `WHATSAPP_REPLY_PREFIX`.
Osobnost/paměť zůstávají uživatelské. Dashboard je owner-only admin;
vědomé root/admin změny nejsou sandboxová izolace před samotným majitelem,
ale příští managed start musí odchylku odmítnout.
„Každý start“ znamená **každé spuštění dashboardu i gateway**, nejen boot
sandboxu: včetně backoff restartu a SIGUSR1 handoff. Ověří se přesné
platformy, `mcp_servers`, toolsety, model/auxiliary route, owner
allowlist, self-chat a neprázdný reply prefix před spawnem.
Explicitní reconfigure aplikuje změnu; běžný start chybný stav potichu
neopravuje a nerozšiřuje.

Defense in depth: A přidá malý testovaný patch k připnutému Baileys bridge.
V této image **bezpodmínečně**, nezávisle na `WHATSAPP_MODE` či jiném
nastavení, odmítne všechny outbound send operace, jejichž chatId není
vlastní ověřené JID/LID; jiný než self-chat mód odmítne už při startu.
Media/file endpointy odmítne,
protože pilot je textový. Při neznámé identitě fail closed.
Patch nesmí zrušit stávající inbound self-chat kontrolu. Ochrana proti
echo smyčkám zahrne neprázdný prefix i replay `append` po restartu;
in-memory dedup sám nestačí. Nenabízíme exactly-once doručení během
libovolného pádu protokolu.

Zbytkové riziko: nedůvěryhodný obsah může ovlivnit lokální paměť nebo
shrnutí; paměť lze prohlédnout/resetovat majitelem. Nemá rozšířit
capabilities ani přesměrovat výstup do cizího chatu.

Dlouhodobý bezpečný cíl zůstává `Deny` s konkrétními Foundry, Azure
identity, Google a WhatsApp cíli. Tento kontrakt není živě prokázán.
Uživatel proto pro aktuální MVP výslovně schválil **dočasnou bezpečnostní
výjimku**: `trafficInspection=None`, `defaultAction=Allow`, bez host
nebo advanced rules. To znamená, že runtime proces schopný síťové
komunikace může kontaktovat libovolnou internetovou destinaci a při
kompromitaci prompt/model cesty může dojít k exfiltraci dat.

Výjimka se nikdy nezapne automaticky po chybě bezpečného režimu.
Deploy, test a access vyžadují přesnou hodnotu
`HERMES_EGRESS_MODE=allow-all-mvp`; prázdná, chybná, neznámá nebo
`hardened-unverified` hodnota selže ještě před vytvořením konfigurace
a Azure operací. Cleanup zůstává dostupný bez souhlasu s výjimkou.
Odstranění lokální proměnné nezastaví již běžící sandbox; aktivní
expozici ukončí odstranění vlastněného compute. Instalace balíčků
probíhá pouze při buildu.

Readback musí mít efektivně `Allow` a `None`; známá rule pole smějí být
jen absent/null/prázdná. Benigní server metadata se vypíší pouze názvem
a počtem bez hodnot a bez bezpečnostního tvrzení. Neznámé názvy
naznačující policy, pravidla, destinace, proxy, TLS, autentizaci nebo
credentials selžou fail closed. Smoke veřejné CA ani readback nejsou
důkazem univerzální dosažitelnosti; skutečné klienty je nutné ověřit
živě s normální kontrolou certifikátu a hostname.

Traffic inspection (`Full`, `Partial`, `None`) je policy-wide, nikoli
per-host. B jako první ověří podporu režimu `Partial` se skutečným
hostname deny/allow a bez TLS MITM, protože Hermes zde nepotřebuje secret
header transforms. Pokud přesný preview kontrakt nestačí, ponechá
deployment BLOCKED a zdokumentuje podporovanou alternativu pro review;
nikdy nezamění `None` za automaticky bezpečný egress nebo nevypne
certifikační ověřování. Full lze použít jen s doloženým trust store pro
Node i Python/httplib2 a funkčním Baileys WS.
Živý diagnostický pokus 2026-09-24 již prokázal, že služba ve
`swedencentral` odmítá `Partial` s `Deny` při vytvoření sandboxu:
`Partial traffic inspection requires defaultAction 'Allow'`.
Image import byl Ready; nejde o chybu image nebo RBAC. Původní kombinace
je tedy BLOCKED. Oficiální dokumentace uvádí `Full + Deny` s host rules,
ale neprokazuje přesný CA/proxy mechanismus, rotaci ani ochranu logů.
`None` není doložená náhrada zachovávající hostname deny; v MVP se
používá vědomě právě bez takového tvrzení.
Full může změnit TLS hranici důvěry: inspekční služba může vidět tokeny,
OAuth credentials a obsah. Platná TLS validace vůči inspektoru není
totéž co původní end-to-end TLS. Osobní použití není automaticky schváleno.
Test zahrne `oauth2.googleapis.com`, `gmail.googleapis.com`,
`www.googleapis.com`, Foundry host, MI host a případné zjištění verze
Baileys při startu. Media/download hosty se při vypnutých přílohách
nepovolují plošně. Nedoložený allowlist zůstává blockerem návratu k hardened režimu,
nikoli dočasného explicitního MVP profilu.

## 8. Rozhraní mezi pracovními proudy

Nová konfigurace: `.env.hermes` a tracked `.env.hermes.sample`, nikdy
automaticky nenačítat existující Copilot `.env`. Přidat přesnou výjimku
do `.gitignore` pro nový sample, ostatní secrets zůstanou ignorované.
Deployment/test/cleanup zůstanou cross-platform Python SDK skripty;
`aca` je potřeba pouze pro interaktivní shell a WhatsApp pairing.

Neměnná společná rozhraní pro první implementaci:

| Kontrakt | Hodnota |
| --- | --- |
| Data mount / home | `/mnt/data`, `/mnt/data/hermes` |
| Ne-tajný runtime soubor | `/mnt/data/hermes/runtime.json`, `schema_version: 1`, pouze explicitně povolená pole |
| Root runtime klíče | `schema_version`, `foundry`, `owner`, `google` |
| Foundry klíče | `endpoint`, `deployment`, `api_mode`, `context_length`, `scope` |
| Owner klíče | `tenant_id`, `object_id`, `whatsapp_phone` |
| Google klíče | `enabled`, `expected_email`, `calendar_ids` |
| Google credential | `/mnt/data/secrets/google/credentials.json`, nikdy v runtime JSON |
| Google credential JSON | Přesně `schema_version: 1`, `client_id`, `client_secret`, `refresh_token`, `expected_email`, `granted_scopes`, `scope_verified_at`; žádné `token_uri`, access token nebo expiry. Scope metadata v souboru není autorita: MCP ověří skutečné scopes a Gmail účet při startu a každém refresh. |
| Google MCP entrypoint | `/opt/hermes-sandbox/google/server.py`, `/opt/hermes/.venv/bin/python`, stdio, server `google_readonly` |
| Google MCP tools | `gmail_search`, `gmail_read`, `calendar_events`; exact `tools.include`, resources/prompts/sampling/elicitation off |
| Ingress / dashboard | `0.0.0.0:8080` Entra-only + transport key -> `127.0.0.1:9119`; obě proxy vlastní B |
| Runtime access key | `/dev/shm/hermes/access-key`, ověřený tmpfs/0600; obnova přes SDK, ne browser |
| WhatsApp | `self-chat`, žádné další platformy; spojení drží gateway |
| Identity | System-assigned MI nové Sandbox Group; inference scope explicitní |
| Lifecycle | Raw create s `autoSuspendPolicy.enabled=false`, raw readback; SDK convenience default není přípustný |
| Gateway lifecycle | Upstream lock + `--external-supervisor`, stavy `maintenance`, `not-paired`, `running`, `re-pair-required`, `failed`; desired state přežije supervisor restart |
| A -> B provozní API | `/opt/hermes-sandbox/control.py status --json`, `stop-gateway`, `start-gateway`, `pair`, `reconfigure`; idempotentní řízení, single pairing, žádný kill-by-name; reconfigure aplikuje image/runtime profil při zastavených procesech |
| Status JSON | Přesně `schema_version`, `dashboard`, `gateway`, `whatsapp`, `google`, `disk_free_bytes`; při nedostupném měření má disk explicitní sentinel `-1` (ne úspěšnou nulu). Žádné credentials ani osobní obsah; diagnostika přežije chybu dílčí komponenty. |
| B -> C upload helper | `upload_private_file(sandbox, *, destination: str, content: bytes) -> None`; restricted fixed destination, temp file 0600 + atomický rename, výjimka při chybě |
| B -> C host API | Lazy import `Config.from_env`, context manager `AzureClients.create`, `get_sandbox`, `read_runtime(sandbox)` a výše uvedený upload helper z `scripts/hermes_common.py`; bez samostatné konfigurační vrstvy |
| Python knihovny | `azure-identity==1.25.3`, `aiohttp==3.14.3`; Google/MCP zamčené verze z připnutého upstream extras |
| Vlastnictví Azure objektů | Nové Hermes-only názvy a labels; žádné sdílení/mazání Copilot objektů |

Očekávaná mapa souborů:

- `hermes/image/`: Dockerfile, bootstrap/profile builder, entrypoint,
  supervisor; `hermes/image/google/`: MCP a jeho závislosti;
  `hermes/image/access_proxy.py`: ingress proxy vlastněná B.
- `scripts/deploy_hermes.py`, `scripts/hermes_common.py`,
  `scripts/access_hermes.py`, `scripts/test_hermes.py`,
  `scripts/cleanup_hermes.py`, `scripts/google_auth_hermes.py`.
- `.env.hermes.sample`, `requirements-hermes.txt`, `.gitignore` (vše B),
  `.github/workflows/hermes-image.yml`, `tests/test_hermes_*.py`.
- `docs/hermes.md` a odkaz v README; tento plán s review záznamem.

Názvy lze před zahájením implementace upravit v review. Po rozdělení
práce se změny společných kontraktů oznamují všem dotčeným session.

## 9. Implementační podsession a kritik

Žádná implementační podsession se nespustí před dokončením review plánu.
Použijeme tři izolované worktree session ve stejném projektu, žádný
factory běh. Implementátoři použijí výchozí model aplikace; každý má
samostatného kritika **Opus 5.5** v odděleném kontextu.

| Session | Vlastnictví | Výstup a závislosti |
| --- | --- | --- |
| A: Runtime a kanály | `hermes/image/**` kromě `google/` a `access_proxy.py`, image workflow, `tests/test_hermes_runtime_*` | Reprodukovatelná image, supervize, Foundry profil, omezené registry, self-chat onboarding/bridge patch. Build zahrne C a proxy B. |
| B: Azure a přístup | Python deployment/access/test/cleanup/common, `hermes/image/access_proxy.py`, env sample, `.gitignore`, pouze nové `requirements-hermes.txt`, `tests/test_hermes_access_*` a `tests/test_hermes_deploy_*` | Oddělené Azure objekty, MI/RBAC, egress, Entra ACL, oba proxy hopy. Po A/C integrace, `docs/hermes.md`, odkaz v README. |
| C: Google read-only | `hermes/image/google/**`, `scripts/google_auth_hermes.py`, `tests/test_hermes_google_*` | Úzký MCP kontrakt, bezpečný OAuth onboarding/upload, přesné scope/account checks a in-memory refresh. |

Hermes workflow má pouze explicitní `workflow_dispatch`, samostatný
image name a opt-in publikaci. Žádný běh nebo push této session
nevznikne sám. Nasazení přijímá image digest; vzorové registry není
důkazem, že image již existuje.

Každá session:

1. přečte tento plán a relevantní zdroje;
2. implementuje pouze vlastněné soubory, bez commit/push/PR; cloudové
   mutace jsou zakázané s výjimkou samostatně schváleného izolovaného
   spike session B v §11;
3. provede cílené testy, předá diff a důkazy svému kritikovi;
4. opraví konkrétní připomínky a předá stejné instanci kritika další
   iteraci; reportuje skóre, zbývající vady a výsledek testů;
5. předá kontrolovatelný patch včetně nových souborů a závěrečný report.
   V izolovaném worktree lze použít `git add -N` a
   `git diff --binary` pouze pro vlastní nové soubory; žádný commit.

Orchestrátor nebude současně editovat jejich soubory. B sloučí patch A/C
ve své integrační session, ověří skutečnou image a společné scénáře,
provede své integrační review a předá jeden kombinovaný patch.
Ten bude přenesen do původního checkoutu jako necommitnuté změny.
Žádné automatické stash/reset/rebase nebo ztráta existující práce.
Před aplikací každého patche `git apply --check`; konflikt se řeší
integrací, ne vynucením. Necommitnutý plán se do nových worktree nekopíruje
automaticky: všechny kickoff prompty obsahují jeho absolutní cestu
v hlavním checkoutu. Plán upravuje výhradně orchestrátor.

### Hodnocení a stop pravidlo

Kritik hodnotí 1–10 vůči plánu a důkazům, ne podle počtu změn.
Rubrika: splnění rozsahu 2, bezpečnost 3, spolehlivost 2,
ověřitelnost/testy 2, jednoduchost a udržovatelnost 1.

Cíl je 10/10. Další iterace opravují konkrétní deficit. Při třech
po sobě jdoucích review bez zlepšení lze proud zastavit s evidovanými
nedostatky. Kritická bezpečnostní/funkční vada zůstává release blockerem
i při stagnaci; „přestali jsme iterovat“ neznamená „hotovo“.
Skóre 10/10 pro plán nebo lokálně ověřený modul není totéž co 10/10
pro živé nasazení. Chybějící účty/credentials se označí BLOCKED, ne PASS.

## 10. Ověření a akceptační brány

Host tier běží v Python 3.14/3.12 bez importu Hermes: validátory, SDK
payloady, OAuth/Google jednotkové testy a mock proxy contract.
Image tier běží v Python 3.12 Linux amd64 pod Dockerem (na tomto arm64
Macu emulace). Docker byl při prvním review vypnutý; uživatel výslovně
schválil spuštění Docker Desktop a lokální buildy. Pokud engine/image
nelze spustit, příslušná brána je BLOCKED, nikdy „nahrazena“ host testem.
Připravený test-entrypoint image spustí **všechny hopy v téže image**:
i lokální přístupový klient, fake ingress, interní falešný model/bridge
a skutečné procesy pod `docker run --network none`. Nejde o spojení
Mac -> izolovaný container, které by nefungovalo. Žádný externí model,
účet nebo runtime package instalace; Azure credential je v harnessu
nahrazena pouze na explicitním testovacím injection pointu.

| Brána | Konkrétní podmínka úspěchu |
| --- | --- |
| P0: review plánu | Nezávislý Opus 5.5 report, vyřešené zásadní připomínky, zaznamenané skóre a otevřené vstupy. Teprve potom implementace. |
| P1: lokální kontrakty | Validace runtime/env, oddělení Copilot/Hermes, raw Entra ACL a suspend-disabled payload/readback. MVP vyžaduje explicitní `allow-all-mvp`, přesné `None` + `Allow`, žádná známá pravidla, name-only diagnostiku a žádný fallback; hardened režim zůstává blocked. Žádný secret v plan/log outputs, správné failure exits. |
| P2: image | Build `linux/amd64`; Hermes/Node/Python verze, web/TUI/stamp artefakty existují, smoke skutečného startu. Network-none test dokládá, že se nevolá npm/pip/uv a bridge běží z image, ne z DataDisk. |
| P3: browser cesta | Offline všechny hopy uvnitř image: lokální proxy -> fake ingress ověřující bearer -> skutečný ingress proxy -> skutečný dashboard. HTML, Chat PTY/WS, streaming/session/reload, ping/reconnect fungují. Wrong key/Host/Origin/proxy target/forwarded headers/body/frame a zakázané management routy se odmítnou; žádný token v logu. |
| P4: agent policy | Fake OpenAI-compatible endpoint zachytí skutečné model-visible `tools` z CLI, dashboard Chat/PTY a WhatsApp adapteru přes fake bridge. Exact equality s §7, také test neznámé platformy. Pokus o terminal/local HTTP/delegaci/skrytý tools upgrade selže před execution. |
| P5: Google offline | Mock API/HTTP limity; přesná grant scope množina, jiný účet/narrow/broad grant, expirace/revokace, dva souběžné MCP procesy bez zápisu refresh tokenu, atomický onboarding upload, žádné write metody. Skutečné stdio ověří zotavení po dočasné startup chybě, explicitní trvalou nedostupnost bez čtení dat a sanitizaci neočekávaných chyb. |
| P6: lifecycle/persistence | `maintenance`, `not-paired`, špatný paired účet, `loggedOut`, souběžný pair/start, CLI SIGUSR1 během pair, zakázaný dashboard restart, shutdown a crash loop bez druhého gateway. Managed drift se odmítne při každém startu. SQLite a WhatsApp identity přežijí skutečnou výměnu sandboxu nad DataDisk. |
| P7: Azure auth živě | Nejprve exact raw `None` + `Allow` readback a šest skutečných klientských TLS/endpoint kontrol bez vypnutí certifikační validace. Potom owner token+WS; anonymní/wrong-audience a MI non-owner odmítnuty na ingressu. MI nejprve pozitivní kontrola s dočasným ACL, pak negativní bez ní; skutečné hlavičky, SDK key read, raw idle i 10 minut WS s pingem a cleanup. Poté inference/tool calling z dashboardu i WhatsAppu přes MI, chybné RBAC selže. |
| P8: WhatsApp živě | QR skutečného owner účtu, nonce a dohledatelná odpověď ve self-chatu; restart během/po send a replay `append` netvoří smyčku. Reconnect bez nového párování; žádná odezva na skupinu/cizí DM, žádný outbound na cizí JID/LID. |
| P9: Google živě | Po vlastním consentu dotaz z webu i self-chatu přečte uživatelem připravený neškodný testovací mail a událost. Účet a scope odpovídají; žádné odeslání ani změna dat. |
| P10: regresní a provozní | Stávající jednotkové testy projdou; existující Copilot soubory/kontrakty nedotčené. Pro MVP jsou doloženy prominentní egress warningy, explicitní opt-in a ukončení expozice cleanupem; odmítnutí zakázaného egressu se znovu vyžaduje až před hardened release. Kapacita disku vyhoví, dokumentován onboarding, obnova, revokace a cleanup. |

Offline test nesmí být prezentován jako test WhatsAppu nebo MI v Azure.
Živé destruktivní/negativní scénáře běží pouze proti označené testovací
instanci, ne proti původnímu Copilot sandboxu nebo produkčním osobním datům.
Long-running token-expiry soak se eviduje odděleně od rychlého smoke.
`test_hermes.py` vždy kontroluje skutečný raw port/lifecycle stav,
nejen manifest. Pro výchozí egress seznam image-tier zaznamená hostname
pokusy při bootu a jednom turnu každého povoleného povrchu bez obsahu
requestů; neočekávané destinace musí mít vysvětlení nebo být zakázané.

## 11. Vstupy pro živé nasazení a předání

Uživatel dne 2026-09-24 výslovně schválil krátký placený izolovaný
auth/WS spike po uzavření review a následné odstranění pouze jeho
testovacích prostředků: výslovně zvolená subscription a tenant, nový RG
`rg-hermes-probe-20260924`, region `swedencentral`. Konkrétní identifikátory
účtu jsou zachované v lokálním auditním artefaktu session
`hermes-azure-approvals.md`, nikoli v tomto verzovaném plánu.
Pokud RG již existuje nebo obsahuje
cizí prostředky, session B nesmí převzít jeho vlastnictví ani jej mazat.
Tento souhlas není povolení k produkčnímu nasazení Hermes, změně
Foundry/RBAC, publikaci image ani připojení osobních Google/WhatsApp dat.
Owner object ID pro spike se ověří z platného uživatelského tokenu bez
výpisu tokenu. Žádné přebírání hodnot z původního Copilot `.env`.

První pokus skončil HTTP 403 na datové rovině nové skupiny, ještě před
vytvořením sandboxu. Jeho RG byl odstraněn a absence ověřena.
Uživatel následně samostatně schválil opakování s dočasnou rolí
`Container Apps SandboxGroup Data Owner`
(`c24cf47c-5077-412d-a19c-45202126392c`) pro aktuálního owner uživatele
ověřeného z uživatelského tokenu, výhradně na nové skupině
`hermes-probe-group` v tomto RG. Přiřazení i testovací prostředky se po
pokusu odstraní; nevztahuje se to na Foundry ani subscription RBAC.
Původní HTTP 403 samo o sobě neprokázalo konkrétní chybějící oprávnění;
účinek role ověřila až následná diagnostika popsaná níže.

Dočasná role již zpřístupnila datovou rovinu; zaznamenané propagace
0,72 s a 102,299 s jsou dva různé pokusy, nikoli garantovaná doba.
Diagnostika následně lokalizovala HTTP 400 na raw sandbox-create:
neslučitelnost `Partial + Deny` popsaná v §7. Předchozí RG i vlastní
přiřazení role byly prokazatelně odstraněny; sandbox nevznikl.

Po vysvětlení změněné TLS/privacy hranice uživatel samostatně schválil
**jeden izolovaný experiment `Full + Deny`**, ve stejném přesném RG,
subscription, tenantovi a rozsahu dočasné role. Nejdříve bez veřejného
portu ověří raw policy, původ CA/proxy přes autentizovanou platformní
cestu, skutečné klienty a negativní TLS/hostname testy. Teprve při úspěchu
naváže původní owner HTTP/WS/MI ACL spike. Nejasný původ CA znamená
STOP a cleanup, nikoli důvěru v certifikát stažený z právě
interceptovaného endpointu. Finální cleanup vždy ověří vlastní
assignment 404 a neexistenci RG.
Tento souhlas nepokrývá Google/WhatsApp osobní data, Foundry inference,
produkční změnu policy, vypnutí TLS validace, libovolný proxy trust,
další cloudové pokusy ani nedoložené garance rotace a platformních logů.

Tento jediný Full experiment již proběhl: vytvoření sandboxu bylo
přijato, sandbox dosáhl Running a raw suspend-disabled stav odpovídal.
Náš ověřovací skript se ale zastavil na porovnání vrácené egress policy,
ještě před nahráním bundle, CA inventářem nebo otevřením portu. Původní
diagnostika nezachovala odlišná pole, takže přesný rozdíl není doložen.
**Není to důkaz nepodpory Full ani chyby CA.** Skupina i vlastní dočasné
přiřazení role byly odstraněny a absence ověřena, přestože mezikrok
obnovy policy hlásil stejnou neshodu. HTTP/WS/MI ACL zůstávají neověřené.
V této fázi další placený pokus schválen nebyl; nejdříve bylo nutné
opravit a offline otestovat ukládání bezpečné diagnostiky před porovnáním.
Produkční deploy zůstává zablokovaný před jakoukoli cloudovou změnou.

Po dokončení lokálního předání a opakování testů v hlavním checkoutu
uživatel dne 2026-09-25 samostatně schválil **jeden nový izolovaný
experiment Full + Deny**, s opravenou diagnostikou, ve stejném přesném
scope a s nejvýše dvěma dočasnými sandboxy (druhý pouze pro MI caller).
Platí stejná úzce omezená dočasná role a povinný ověřený cleanup;
žádná osobní Google/WhatsApp data, Foundry inference, publikace ani
automatické produkční nasazení. Nejasná důvěra v CA znamená stop,
ne vypnutí TLS. Vznikne nový jednorázový run ID a důkazní sada;
předchozí spotřebované souhlasy a výsledky se nepřepisují.
Přesné schválení je v lokálním auditním artefaktu. Experiment proběhl
2026-09-25, 10:10:12–10:14:14 UTC: vytvoření a autentizovaný GET shodně
vrátily `Deny`, `Full` a přesné povolení `oauth2.googleapis.com`.
Jeden sandbox dosáhl Running, auto-suspend byl vypnutý a porty prázdné.
Náš striktní ověřovač se zastavil na **dvou dalších neklasifikovaných
polích policy**. Redakce zachovala jejich počet, ale nikoli názvy,
hodnoty ani jednotlivé typy, takže jejich význam nelze z tohoto důkazu
určit. Známé `rules` bylo nepřítomné/null; to nevylučuje význam dalších
polí. Jde o omezení naší diagnostiky, nikoli prokázané odmítnutí Full,
selhání CA nebo autentizace.

Bundle nebyl nahrán, žádný port otevřen a druhý sandbox nevznikl.
CA, egress enforcement, HTTP/WS a MI allow/revoke zůstaly nedosažené.
Nezávislý nový SDK klient potvrdil neexistenci RG (HEAD i GET 404)
a přesného vlastního role assignmentu (GET 404). Nezůstaly prostředky
ani oprávnění tohoto běhu. Souhlas je spotřebovaný; další cloudový
pokus není schválen. Následuje pouze omezená read-only analýza
ověřovače a veřejného schématu, nikoli domýšlení chybějící odpovědi,
oslabení policy nebo další placené opakování.

Dne 2026-09-26 uživatel následně schválil publikaci přesně otestované
Hermes image a skutečný persistentní MVP deploy s
`HERMES_EGRESS_MODE=allow-all-mvp`. GitHub Actions run `36231347007`
publikoval veřejný `linux/amd64` digest
`ghcr.io/michalmar/aca-sandbox-hermes@sha256:246523149f6db56ff21140315d2fa950103e4c4f70342893118db82106a1557f`.
Správný Azure profil byl výhradně `AZURE_CONFIG_DIR=~/.azure-365`;
subscription, tenant, owner, Foundry `demo-swe`, deployment `gpt-6-sol`,
context cap 800000 a minimální role byly ověřeny před mutací.

Run `eba84cb5-d038-407d-8379-c7e7a009e587` vytvořil nový RG/group,
ownerovi přidělil group-scoped SandboxGroup Data Owner a skupinové MI
Foundry User pouze na `demo-swe`. Image import prošel, jediný sandbox
dosáhl `Running`, `autoSuspend=false`, `ports=[]`; create i
autentizovaný GET shodně vrátily známé `Allow`, `None`, prázdné
`hostRules` a nepřítomné `rules`. B8 však fail closed odmítl dvě nyní
pojmenovaná security-bearing pole `enforcementMode` a `http`, jejichž
hodnoty ani typy stará bezpečná projekce nezachovala. Nebyl nahrán
runtime, otevřen port ani proveden TLS smoke, inference, WhatsApp nebo
Google krok. Není to odmítnutí `Allow + None` službou.

Rollback odstranil sandbox, image, obě přesná role assignment ID,
group i RG. Samostatný nový proces s vyhrazeným Azure profilem potvrdil
RG/group/assignment GET 404; nezůstaly běžící prostředky ani role.
Oficiální TypeSpec `2026-09-01-preview` následně doložil
`enforcementMode` (`Enforced`/`Audit`) a strukturovanou `http` sekci.
Použitý SDK `0.1.0b4` nad `2026-02-01-preview` tato pole zahazuje.
B9 proto bezpečně projektuje pouze přítomnost, typy, počty a schválené
enumy, vyžaduje nezávislé root i HTTP `Allow + None`, prázdná pravidla,
kompatibilní enforcement a odmítá forwarding, `tds`, transport rules,
validation warnings, konflikty a secret-bearing obsah. Další live
deploy vyžaduje nový jednorázový driver, durable capture a nový souhlas.

Uživatel poté samostatně schválil druhý skutečný persistentní pokus.
Run `2b5ec81a-f92f-4c1d-9776-9fead9659766` použil nový driver, role ID
a důkazní prefix. Offline prošlo 31/31 driver negativních testů a
148/148 B9 kontraktů; nový preflight znovu ověřil správný vyhrazený
Azure profil, prázdný cíl, image digest, model a role. Image import,
jediný sandbox, runtime upload/readback, normální TLS smoke, dashboard
readiness a owner-only port 8080 prošly.

Tři dokončené policy gates a čtvrtý bezpečný snapshot ukázaly root i
HTTP `Allow`, `None`, `Enforced`, prázdné `hostRules` a nepřítomné
rules/defaultForward/transport sekce. B9 policy problém je tím pro tuto
živou odpověď vyřešen. Následná reviewed status/network fáze však
vyvolala `RuntimeError` po čtvrtém capture a před dalším doloženým raw
GET. Driver zachoval pouze typ a fázi, nikoli konkrétní subcheck,
bezpečnou kategorii nebo stack; příčinu nelze poctivě určit. Šest
klientských TLS kontrol, MI provenance, owner HTTP/WS a nativní Foundry
inference nebyly dosažené.

Fail-closed cleanup explicitně zavřel port, odstranil sandbox a image,
obě role, group, DataDisk a RG. Nový samostatný proces potvrdil RG,
group i obě assignment ID jako 404. Nezůstaly prostředky ani role.
Read-only trace vymezil přesné pořadí owner claims, RG/group/ARM,
sandbox/image/volume inventory, exact-one-volume, selection a raw GET,
ale neumožnil zpětně přiřadit chybu.

B11 proto přidává volitelný synchronní `StatusRecorder` se 46 pevnými
operation ID, begin/pass/fail událostmi a 28 konečnými chybovými
kategoriemi. Zachovává jen bezpečné typy, počty, schválené literály a
match booleany; nikdy tokeny, hlavičky, URL, telefon, label hodnoty,
arbitrary ID ani exception text. Rozlišuje policy snapshot commit od
validator return a pokrývá skutečnou ownership/inventory/selection/raw
GET cestu bez dalších requestů, guest příkazů nebo změny fail-closed
pravidel. Další live pokus vyžaduje nový driver a nový souhlas.

Uživatel následně výslovně schválil třetí skutečný pokus a požadoval
nepřerušované provedení až do významného selhání nebo finálního
výsledku. Run `7430eaa1-be7c-4d9e-a948-dd78e5501f49` znovu ověřil
vyhrazený Azure profil, cíl, image, Foundry a role. RG/group a správné
owner/group-MI role vznikly a byly přečteny. Externí readiness kontrola
se stejným credential objektem, klientem, pipeline a SDK `list_volumes`
uspěla na druhém bounded GET-only průchodu. Přibližně 4,504 s poté však
první guarded data-plane GET uvnitř reviewovaného `provision_group`
vrátil HTTP 403. Selhání nastalo před DataDiskem, image importem,
sandboxem, portem i B9/B11 runtime branami.

Cleanup odstranil role, group a RG; nový samostatný proces potvrdil
RG/group/obě assignment ID jako 404. Read-only analýza prokázala, že
readiness a deploy používaly stejný objekt klienta, credential, session
i `list_volumes`; neprokázala příčinu. AzureCliCredential sám nemá
aplikační cache, ale azure-core a CLI mají vlastní tokenové/cache vrstvy;
jejich obsah nebyl čten a žádná hypotéza nebyla označena za root cause.

B13 přesouvá readiness do produkčního fresh boundary. Explicitní
`deploy(..., fresh=True)` vyžaduje tři kompletní po sobě jdoucí prázdné
inventory roundy alespoň 10 sekund od sebe během nejvýše 900 sekund,
se stejnými původními klienty a transportem. 401/403 streak resetuje;
ostatní HTTP, transport, parser, shape, ownership, nonempty, timeout
nebo capture chyby zůstávají terminální. Po třetím roundu následuje
okamžitě původní `list_volumes`; žádný PUT, import, create ani celý
deploy se neopakuje.

Každý round ověřuje skutečné SDK envelope pro volumes, sandboxes,
disk images a secrets. Review odhalilo, že `list_secrets` používá
objektové pole `secrets`, zatímco ostatní operace používají `value`
nebo array; původní fixture tuto vadu maskoval. B13 používá přesné
operation-specific klíče, path-sensitive fixtures, bezpečné readiness
events a odmítá malformed, nonempty i cyklickou pagination. Běžný CLI
zachovává SDK retry a není vhodný pro one-shot live driver; budoucí
driver musí vytvořit a ověřit původní ARM/group klienty s
`retry_total=0`. Tři roundy nejsou garance propagace; pozdější 403
stále znamená cleanup.

Pro plán a lokální implementaci nejsou potřeba tajné hodnoty. Až bude
implementace připravená, uživatel bezpečnou lokální konfigurací dodá:

| Vstup | Použití |
| --- | --- |
| Subscription, nový Hermes RG/group a region | Přesně ohraničený cíl; region default `swedencentral`, ověřit preview dostupnost. |
| Tenant ID a owner object ID | Jediný povolený účet na ingressu. Nezaměnit object ID, client ID a e-mail. |
| Foundry resource ID, inference URL, deployment, API mode a context limit | Připojení existujícího modelu, RBAC assignment na jeho scope. Žádná tvorba modelu. |
| Rozhodnutí o inference role assignment | Uživatel jej vytvoří nebo výslovně povolí vytvoření pro novou MI. |
| Veřejně dostupná připnutá Hermes image | Publikuje uživatel/schválený CI postup, ne automatický push z této session. |
| Vlastní WhatsApp číslo a QR pairing | Není nový účet/číslo; session klíče ani QR neposílat do chatu či commitu. |
| Google Desktop OAuth client a očekávaný účet | Osobní consent pro přesně omezené scopes; credentials nenahrávat do konverzace. |
| Neškodný testovací mail/událost | Živé pozitivní testy bez zásahů do cizích účtů. Same-tenant negativní Entra identitu poskytne nová Group MI; její test je povinný. |

Cleanup defaultně zachová DataDisk a credentials. Trvalé smazání vyžaduje
explicitní volbu a přesný potvrzený cíl. Skripty smí pracovat pouze
s objekty označenými jako Hermes deployment; nesmí mazat sdílený RG,
Foundry, model, Google účet nebo původní Copilot infrastrukturu.

## 12. Záznam review

| Iterace | Kritik | Skóre | Závěr |
| --- | --- | --- | --- |
| 1 | Opus 5.5 | 6/10 | Toolset fail-open, loopback trust boundary, neověřený WS/ACL kontrakt, pairing/supervisor konflikty, CI scope a chybějící integrační rozhraní. |
| 2 | Opus 5.5 | 8,5/10 | Vyřešena většina bodů; doplnit nepřepnutelný bridge guard, vynucený maintenance pairing a pozitivní kontrolu negativního MI testu. |
| 3 | Opus 5.5 | 9,5/10 | B1–B3 a N-A až N-D vyřešeny; žádný zbývající textový/design blocker. P0 uzavřena, implementace schválena v rámci bran. Reconfigure/dashboard preflight, route inventory, propagace ACL/odpovědní marker a staging pairing doplněny. Další zvýšení skóre vyžaduje důkazy z implementace a živého spike, ne další přepis plánu. |

### Průběžné implementační review

Stav k 2026-09-25; skóre je vždy lokální a patří konkrétní reviewované
verzi, nikoli automaticky novějšímu kódu nebo živému nasazení.
Úplné nezkrácené reporty a hashe předaných patchů jsou v artefaktech
příslušných session.

| Proud | Dosavadní skóre Opus 5.5 | Stav |
| --- | --- | --- |
| A: runtime a WhatsApp | 6,2 -> 7,8 -> 8,0; náhradní kritik 9,15 -> 9,60/10 | Finální A6 přijata bez opravitelných nálezů či vad důkazů. Opravené lifecycle/RPC, skutečný bridge, pre-tool `@reference` I/O a přísný dependency graph. Prošly přesné image, 121 nativních Python a 12 Node testů, skutečný entrypoint a browser scénáře. Zbývající odpočet je za strukturální patchování upstreamu, dvě schválené výjimky a zdokumentované provozní limity; není důvod vyrábět další nezměněná review nebo tvrdit 10/10. |
| B: Azure a přístup | B7: 7,7 -> 9,15 -> 9,35 -> 9,50 -> 9,75 -> 9,95 -> 10/10; B8 MVP: 9,2 -> 9,9/10 + neskórované ACCEPT; B9 schema: 9,6 -> 9,9/10; B11 status: 9,7 -> 9,9/10; B13 readiness: 7,7 -> 9,5/10 ACCEPT | B7 zůstává historicky schválený hardened základ. B8 zavedl explicitní `allow-all-mvp`, B9 fixed-schema policy a B11 durable status/inventory diagnostiku. Po třetím plně uklizeném same-client 403 blockeru B13 přidává explicitní fresh-only tříroundovou readiness, přesné SDK envelopes a retry-zero driver povinnost bez mutation retry. Změnil/přidal pět host-side souborů; runtime/image/C/workflow/dependency bytes zůstaly identické. Skóre není schválení čtvrtého live pokusu. |
| C: Google read-only | 8,6 -> 9,8 -> 10/10; samostatná integrační revize C4 znovu 10/10 | Předaný C4 patch je nezávisle zreviewovaný, 104 lokálních testů prošlo. Nativní timing/cancellation a fake-bridge WhatsApp tools jsou další offline integrační důkazy. Osobní OAuth/P9/soak tím neprošly. |

Žádný z těchto výsledků neodstraňuje blokaci produkčního deploye ani
nenahrazuje živé Entra/WS/MI ACL, Foundry, WhatsApp či Google ověření.
Původní A kritik po třetím review přestal být dostupný (`No agent found`,
prázdný seznam potomků). Orchestrátor povolil jednoho náhradního Opus
5.5 s úplným předáním reportů, hashů a důkazů pro finální aktuální
runtime. Historická skóre zůstávají beze změny. Náhradní kritik následně
uzavřel finální A6 s manifestem `ce19ab0f...8077f`, nezávisle ověřil
všech 25 zdrojových souborů/módů a 73 navázaných důkazních artefaktů.
Průběžných 9,47 bylo provizorní hodnocení téhož kandidáta před finálními
image důkazy, nikoli uměle přidané další review. Konečných 9,60 je
lokální přijetí; živé/release hodnocení 5,5 zůstává neschválené.

## 13. Lokální předání

Do hlavního checkoutu na `main` byl nejprve aplikován jediný sjednocený
patch A6/B7/C4, SHA-256
`6303b30ed9d1b9f1b6140312b636150aac485051c6f8301591b37b77ed9377a6`.
Následně byl aplikován pouze reviewovaný B8 delta patch pro MVP egress,
SHA-256
`44adce523afbcaed1e83b0f0173c6e79559dd4267e649066f87d2bb94dc435e6`.
Po schema výzkumu byl aplikován reviewovaný B9 delta patch, SHA-256
`6536df22e19e207ec93978f743edc741f9cb15b78cc6a85a6069ffd005b1d938`.
Po druhém plně uklizeném pokusu byl aplikován reviewovaný B11 delta
patch, SHA-256
`03b841a4d50ffae24b946d996a2930400ef43c2d16420e5b8b541a36728c2576`.
Po třetím plně uklizeném pokusu byl aplikován reviewovaný B13 delta
patch, SHA-256
`dd4e93350938f330711b498dd306a67920496f83d06f59a3320f6024435595b9`.
Všech 50 souborů včetně executable bitů odpovídá finálnímu manifestu;
tento plán je samostatný doprovodný dokument. Původní Copilot implementace
zůstala beze změny, kromě odkazu v README a dvou pravidel `.gitignore`.
Nevznikl commit, push, PR ani publikace image.

Finální B13 replay před předáním: B sada **271 celkem / 257 prošlo /
14 image-only přeskočeno**, úplná host sada **503 / 436 / 67** a přesná
existující SDK image **266 / 266 / 0** (původních 52 bran plus 214
policy/lifecycle/status/readiness kontraktů). Všech 38 readiness testů
prošlo na host tier i v SDK image. Přesná množina 67 přeskočených ID
i důvodů odpovídá A6 image-covered sadě. Runtime/image vstupy se
nezměnily, proto se image znovu nestavěly.

Provozní návod je v [hermes.md](hermes.md). Schválení lokálního kódu
neodemyká produkční deploy: zbývá samostatně povolené živé ověření sítě,
identity a osobních integrací uvedených v §10–11.
