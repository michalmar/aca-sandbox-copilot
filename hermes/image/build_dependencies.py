"""Build-only checks against the immutable upstream lock and artifacts."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tomllib
import difflib
import inspect

ROOT = Path("/opt/hermes")
SUPPORT = Path("/opt/hermes-sandbox")
COMMIT = "645da6561c724b7ca163d4af9c21de3a6397c9f2"
UV_LOCK_SHA256 = "5b3798f326209475abca8ef7cbf7c9406f12e687c28c0b540dfe597466f48590"
PYPROJECT_SHA256 = "6f969b9fdff95e7269ec808361e3ae8be5357036e6257e53a3306878cf8c41dd"
MSAL_VERSION = "1.37.0"
MSAL_WHEEL_SHA256 = "dd17e95a7c71bce75e8108113438ba7c4a086b3bcad4f57a8c09b7af3d753c2d"
NPM_LOCK_SHA256 = "193a3a3703499eb7c4b4ce48d3ba1e9dae2be62a48315c1e7ea9545e8be4a067"
ELECTRON_DATA_INTEGRITY = "sha512-e1QEj72Y4zd8RlNZVmoTg+iCOSVwpk05IOiiQwdrkwCSVlZfPthevErhE+nckGd2YbsXfp1SkisznhGVIXP2NQ=="


def locked_bridge_requirements(lock: dict) -> str:
    lines = []
    for name in ("qrcode", "pypng", "setuptools"):
        matches = [p for p in lock["package"] if p["name"] == name]
        if len(matches) != 1:
            raise RuntimeError(f"Expected one locked package: {name}")
        package = matches[0]
        hashes = [w["hash"] for w in package.get("wheels", [])]
        if "sdist" in package:
            hashes.append(package["sdist"]["hash"])
        if not hashes:
            raise RuntimeError(f"No locked hashes: {name}")
        lines.append(f"{name}=={package['version']} " + " ".join(f"--hash={h}" for h in hashes))
    return "\n".join(lines) + "\n"


def bridge_requirements() -> None:
    print(locked_bridge_requirements(tomllib.loads((ROOT / "uv.lock").read_text())), end="")


def python_source_guard() -> dict:
    for name, expected in (("uv.lock", UV_LOCK_SHA256), ("pyproject.toml", PYPROJECT_SHA256)):
        if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != expected:
            raise RuntimeError(f"upstream {name} fingerprint changed; no Python exception was applied")
    lock = tomllib.loads((ROOT / "uv.lock").read_text())
    msal = [package for package in lock["package"] if package["name"] == "msal"]
    if len(msal) != 1 or msal[0]["version"] != "1.36.0":
        raise RuntimeError("the approved MSAL exception no longer matches")
    return lock


def requirement_parts(block: str) -> tuple[str, list[str]]:
    parts = re.split(r"\s+--hash=", block.replace("\\\n", " ").strip())
    if (len(parts) < 2
            or not re.fullmatch(r"[a-z0-9][a-z0-9._-]*==[a-zA-Z0-9.+!-]+(?: ; [^\n]+)?", parts[0])
            or any(not re.fullmatch(r"sha256:[0-9a-f]{64}|md5:[0-9a-f]{32}", value)
                   for value in parts[1:])):
        raise RuntimeError("unexpected generated hash-locked requirement")
    return parts[0], parts[1:]


def requirement_blocks(text: str) -> dict[str, str]:
    starts = list(re.finditer(r"(?m)^([a-z0-9][a-z0-9._-]*)==", text))
    if not starts or starts[0].start() != 0:
        raise RuntimeError("expected only generated pinned requirement records")
    result = {}
    for index, match in enumerate(starts):
        end = starts[index + 1].start() if index + 1 < len(starts) else len(text)
        block = text[match.start():end]
        requirement_parts(block)
        name = re.sub(r"[-_.]+", "-", match[1])
        if name in result:
            raise RuntimeError(f"duplicate locked requirement: {name}")
        result[name] = block
    return result


def validate_python_exception(original: str, applied: str, lock: dict) -> dict:
    before, after = requirement_blocks(original), requirement_blocks(applied)
    if set(before) != set(after) or "msal" not in before:
        raise RuntimeError("the Python exception changed the package set")
    previous, previous_hashes = requirement_parts(before["msal"])
    updated, updated_hashes = requirement_parts(after["msal"])
    package = next(package for package in lock["package"] if package["name"] == "msal")
    locked_hashes = {wheel["hash"] for wheel in package["wheels"]} | {package["sdist"]["hash"]}
    if previous != "msal==1.36.0" or set(previous_hashes) != locked_hashes:
        raise RuntimeError("original MSAL export differs from the immutable upstream lock")
    if updated != f"msal=={MSAL_VERSION}" or updated_hashes != [f"sha256:{MSAL_WHEEL_SHA256}"]:
        raise RuntimeError("the Python exception is not the exact approved MSAL wheel")
    unchanged = {name: block for name, block in before.items() if name != "msal"}
    if unchanged != {name: block for name, block in after.items() if name != "msal"}:
        raise RuntimeError("a non-approved Python requirement or artifact hash changed")
    return {
        "from": previous, "to": updated, "wheel_sha256": MSAL_WHEEL_SHA256,
        "all_other_requirement_records_unchanged": True,
        "unchanged_requirement_records": len(unchanged),
        "unchanged_records_sha256": hashlib.sha256(json.dumps(unchanged, sort_keys=True).encode()).hexdigest(),
        "original_requirements_sha256": hashlib.sha256(original.encode()).hexdigest(),
        "applied_requirements_sha256": hashlib.sha256(applied.encode()).hexdigest(),
    }


def python_exception_diff(original: str, applied: str) -> str:
    return "".join(difflib.unified_diff(
        original.splitlines(keepends=True), applied.splitlines(keepends=True),
        fromfile="a/runtime-requirements.txt", tofile="b/runtime-requirements.txt",
    ))


def python_lock_exception(index_url: str) -> None:
    lock = python_source_guard()
    original = subprocess.check_output([
        "uv", "--no-config", "export", "--frozen", "--no-dev", "--no-emit-project",
        "--no-header", "--no-annotate", "--extra", "web", "--extra", "pty", "--extra", "mcp",
        "--extra", "google", "--extra", "azure-identity", "--extra", "homeassistant",
        "--extra", "anthropic",
    ], cwd=ROOT, text=True) + locked_bridge_requirements(lock)
    before = requirement_blocks(original)
    with tempfile.TemporaryDirectory(prefix="hermes-approved-msal-") as directory:
        inputs = Path(directory, "requirements.in")
        constraints = Path(directory, "constraints.txt")
        generated_path = Path(directory, "generated.txt")
        inputs.write_text(f"msal=={MSAL_VERSION}\n")
        constraints.write_text("".join(block for name, block in before.items() if name != "msal"))
        subprocess.run([
            "uv", "--no-config", "pip", "compile", "--python", sys.executable,
            "--index-url", index_url, "--generate-hashes", "--only-binary", "msal",
            "--no-header", "--no-annotate", "--constraint", str(constraints),
            "--output-file", str(generated_path), str(inputs),
        ], cwd=directory, check=True, stdout=subprocess.DEVNULL)
        generated = generated_path.read_text()
    resolved = requirement_blocks(generated)
    if "msal" not in resolved:
        raise RuntimeError("uv did not generate the approved MSAL requirement")
    for name, block in resolved.items():
        if name != "msal" and name not in before:
            raise RuntimeError(f"MSAL introduced a new dependency: {name}")
        requirement, _hashes = requirement_parts(block)
        expected = f"msal=={MSAL_VERSION}" if name == "msal" else requirement_parts(before[name])[0].split(" ; ")[0]
        if requirement != expected:
            raise RuntimeError(f"MSAL's resolver changed a frozen dependency: {name}")
    requirement, hashes = requirement_parts(resolved["msal"])
    approved_hash = f"sha256:{MSAL_WHEEL_SHA256}"
    if approved_hash not in hashes:
        raise RuntimeError("uv did not resolve the exact approved MSAL wheel hash")
    # uv also lists sdist/weak hashes; only the explicitly approved wheel may be installed.
    replacement = f"{requirement} \\\n    --hash={approved_hash}\n"
    applied = original.replace(before["msal"], replacement, 1)
    proof = validate_python_exception(original, applied, lock)
    python_source_guard()
    SUPPORT.mkdir(parents=True, exist_ok=True)
    (SUPPORT / "runtime-requirements.upstream.txt").write_text(original)
    (SUPPORT / "runtime-requirements.txt").write_text(applied)
    (SUPPORT / "msal-resolver-requirements.txt").write_text(generated)
    (SUPPORT / "python-lock-exception.patch").write_text(python_exception_diff(original, applied))
    (SUPPORT / "python-lock-exception.json").write_text(json.dumps({
        **proof, "upstream_commit": COMMIT, "uv_lock_sha256": UV_LOCK_SHA256,
        "pyproject_sha256": PYPROJECT_SHA256,
        "generator": subprocess.check_output(["uv", "--version"], text=True).strip(),
        "resolver_requirements_sha256": hashlib.sha256(generated.encode()).hexdigest(),
        "provenance": "uv resolver under frozen constraints; only the second explicitly approved dependency exception",
    }, indent=2) + "\n")
    print(json.dumps(proof, sort_keys=True))


def verify_python_dependencies() -> None:
    from packaging.requirements import Requirement
    from packaging.utils import canonicalize_name

    lock = python_source_guard()
    original = (SUPPORT / "runtime-requirements.upstream.txt").read_bytes().decode()
    applied = (SUPPORT / "runtime-requirements.txt").read_bytes().decode()
    proof = validate_python_exception(original, applied, lock)
    recorded = json.loads((SUPPORT / "python-lock-exception.json").read_text())
    if any(recorded.get(key) != value for key, value in proof.items()):
        raise RuntimeError("Python dependency-exception provenance differs from its actual requirements")
    resolved = (SUPPORT / "msal-resolver-requirements.txt").read_bytes()
    if recorded.get("resolver_requirements_sha256") != hashlib.sha256(resolved).hexdigest():
        raise RuntimeError("Python resolver provenance differs from its generated artifact")
    if (SUPPORT / "python-lock-exception.patch").read_bytes() != python_exception_diff(original, applied).encode():
        raise RuntimeError("Python exception patch provenance differs from its actual requirements")
    expected = {"hermes-agent": "0.21.5"}
    for name, block in requirement_blocks(applied).items():
        requirement = Requirement(requirement_parts(block)[0])
        if requirement.marker is None or requirement.marker.evaluate():
            expected[name] = next(iter(requirement.specifier)).version
    distributions = list(importlib.metadata.distributions())
    installed = {
        canonicalize_name(distribution.metadata["Name"]): distribution.version
        for distribution in distributions
    }
    if len(installed) != len(distributions) or installed != expected:
        raise RuntimeError("installed Python distribution set or versions differ from the approved lock")
    subprocess.run(["uv", "--no-config", "pip", "check", "--python", sys.executable], check=True)
    (SUPPORT / "runtime-distributions.json").write_text(json.dumps(installed, indent=2, sort_keys=True) + "\n")


def verify() -> None:
    if sys.version_info[:2] != (3, 12):
        raise RuntimeError("Hermes image requires Python 3.12")
    verify_python_dependencies()
    versions = {
        name: importlib.metadata.version(name)
        for name in ("hermes-agent", "azure-identity", "msal", "cryptography", "openai",
                     "aiohttp", "mcp", "httpx2", "qrcode")
    }
    required = {
        "azure-identity": "1.25.3", "aiohttp": "3.14.3", "mcp": "2.0.0",
        "httpx2": "2.7.0", "qrcode": "7.4.2",
        "msal": MSAL_VERSION, "cryptography": "50.0.0", "openai": "2.24.0",
    }
    if any(versions[name] != version for name, version in required.items()):
        raise RuntimeError("Installed dependency versions differ from the contract")
    for artifact in ("hermes_cli/web_dist/index.html", "ui-tui/dist/entry.js"):
        if not (ROOT / artifact).is_file():
            raise RuntimeError(f"Missing built artifact: {artifact}")
    bridge = ROOT / "scripts/whatsapp-bridge"
    expected = hashlib.sha256((bridge / "package.json").read_bytes()).hexdigest()[:16]
    if (bridge / "node_modules/.hermes-pkg-hash").read_text() != expected:
        raise RuntimeError("Missing or stale Baileys package hashstamp")
    baileys = json.loads((bridge / "node_modules/@whiskeysockets/baileys/package.json").read_text())
    if baileys["version"] != "7.0.0-rc13":
        raise RuntimeError("Unexpected Baileys version")
    versions.update(
        upstream_commit=COMMIT,
        node=subprocess.check_output(["node", "--version"], text=True).strip(),
        uv=subprocess.check_output(["uv", "--version"], text=True).strip(),
        baileys=baileys["version"],
        python=sys.version.split()[0],
        uv_lock_sha256=hashlib.sha256((ROOT / "uv.lock").read_bytes()).hexdigest(),
        npm_lock_sha256=hashlib.sha256((ROOT / "package-lock.json").read_bytes()).hexdigest(),
        bridge_lock_sha256=hashlib.sha256((bridge / "package-lock.json").read_bytes()).hexdigest(),
        python_exception_sha256=hashlib.sha256((SUPPORT / "python-lock-exception.json").read_bytes()).hexdigest(),
        runtime_requirements_sha256=hashlib.sha256((SUPPORT / "runtime-requirements.txt").read_bytes()).hexdigest(),
    )
    (Path("/opt/hermes-sandbox") / "build-versions.json").write_text(
        json.dumps(versions, indent=2) + "\n"
    )
    print(json.dumps(versions, sort_keys=True))


def registry() -> None:
    sys.path.insert(0, str(ROOT))
    import model_tools
    from tools.registry import registry as tools
    inventory = tools.get_tool_to_toolset_map()
    (Path("/opt/hermes-sandbox") / "tool-registry.json").write_text(
        json.dumps(inventory, sort_keys=True, indent=2) + "\n"
    )
    print(f"Pinned built-in registry: {len(inventory)} tools")


def integration() -> None:
    support = Path("/opt/hermes-sandbox")
    if (support / "google/__init__.py").exists():
        raise RuntimeError("Google support must remain a namespace; never shadow google-auth/protobuf")
    sys.path.insert(0, str(support))
    import google.oauth2.credentials
    import google.protobuf
    import access_proxy
    inspect.signature(access_proxy.rpc_allowed).bind({}, surface="tui")
    inspect.signature(access_proxy.rpc_response_allowed).bind({}, surface="tui")
    inspect.signature(access_proxy.validate_route_inventory).bind(ROOT)
    inspect.signature(access_proxy.validate_registered_routes).bind(object())
    access_proxy.validate_route_inventory(ROOT)
    versions = json.loads((support / "build-versions.json").read_text())
    if (versions["upstream_commit"] != COMMIT
            or versions["npm_lock_sha256"] != hashlib.sha256((ROOT / "package-lock.json").read_bytes()).hexdigest()
            or versions["uv_lock_sha256"] != UV_LOCK_SHA256
            or versions["python_exception_sha256"] != hashlib.sha256((support / "python-lock-exception.json").read_bytes()).hexdigest()
            or versions["runtime_requirements_sha256"] != hashlib.sha256((support / "runtime-requirements.txt").read_bytes()).hexdigest()):
        raise RuntimeError("generated build provenance no longer matches the image")
    verify_python_dependencies()
    subprocess.run([sys.executable, "-I", "-c",
                    "from pathlib import Path; import runtime, managed_policy, adapter_policy; "
                    "assert all(Path(m.__file__).resolve().parent == Path('/opt/hermes-sandbox') "
                    "for m in (runtime, managed_policy, adapter_policy))"],
                   env={}, cwd="/", check=True)
    print("Verified Google namespace, B public integration APIs, route inventory and build provenance")


def frontend_lock_exception() -> None:
    """The first approved exception is still exactly one browser-data leaf."""
    lock_path = ROOT / "package-lock.json"
    original_text = lock_path.read_text()
    if hashlib.sha256(original_text.encode()).hexdigest() != NPM_LOCK_SHA256:
        raise RuntimeError("upstream npm lock fingerprint changed; no exception was applied")
    original = json.loads(original_text)
    key = "node_modules/electron-to-chromium"
    previous = original["packages"][key]
    if previous["version"] != "1.5.433" or not previous["dev"]:
        raise RuntimeError("the approved browser-data exception no longer matches")
    parents = [
        (name, field, package[field]["electron-to-chromium"])
        for name, package in original["packages"].items()
        for field in ("dependencies", "optionalDependencies", "peerDependencies", "devDependencies")
        if "electron-to-chromium" in package.get(field, {})
    ]
    if parents != [("node_modules/browserslist", "dependencies", "^1.5.427")]:
        raise RuntimeError("browser-data parent dependency contract changed")
    with tempfile.TemporaryDirectory(prefix="hermes-browser-data-") as directory:
        manifest = {
            "name": "hermes-approved-browser-data-pin", "version": "1.0.0", "private": True,
            "dependencies": {"electron-to-chromium": "1.5.430"},
        }
        Path(directory, "package.json").write_text(json.dumps(manifest))
        subprocess.run(
            ["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund",
             "--registry", sys.argv[2], "--prefix", directory], check=True,
        )
        generated = json.loads(Path(directory, "package-lock.json").read_text())["packages"][key]
    if (generated["version"] != "1.5.430" or generated["integrity"] != ELECTRON_DATA_INTEGRITY
            or generated.get("dependencies") or generated.get("hasInstallScript")):
        raise RuntimeError("npm-generated browser-data entry differs from the exact approval")
    updated = json.loads(original_text)
    updated["packages"][key] = {
        **previous, "version": generated["version"], "integrity": generated["integrity"],
        "resolved": "https://registry.npmjs.org/electron-to-chromium/-/electron-to-chromium-1.5.430.tgz",
    }
    comparison = json.loads(json.dumps(updated))
    comparison["packages"][key] = previous
    if comparison != original:
        raise RuntimeError("a non-approved npm graph entry changed")
    updated_text = json.dumps(updated, indent=2, ensure_ascii=False) + "\n"
    lock_path.write_text(updated_text)
    support = Path("/opt/hermes-sandbox")
    (support / "frontend-lock-exception.patch").write_text("".join(difflib.unified_diff(
        original_text.splitlines(keepends=True), updated_text.splitlines(keepends=True),
        fromfile="a/package-lock.json", tofile="b/package-lock.json",
    )))
    (support / "frontend-lock-exception.json").write_text(json.dumps({
        "upstream_commit": COMMIT, "entry": key, "from": previous, "to": updated["packages"][key],
        "parent_edges": parents, "all_other_graph_entries_unchanged": True,
        "original_lock_sha256": NPM_LOCK_SHA256,
        "applied_lock_sha256": hashlib.sha256(updated_text.encode()).hexdigest(),
        "provenance": "npm-generated exact 1.5.430 entry; single explicit user-approved build-data exception",
    }, indent=2) + "\n")


def runtime_constraints() -> None:
    for distribution in sorted(importlib.metadata.distributions(), key=lambda item: item.metadata["Name"].lower()):
        print(f"{distribution.metadata['Name']}=={distribution.version}")


if __name__ == "__main__":
    if sys.argv[1] == "python-lock-exception":
        python_lock_exception(sys.argv[2])
    else:
        {"bridge-requirements": bridge_requirements, "verify": verify, "registry": registry,
         "frontend-lock-exception": frontend_lock_exception, "runtime-constraints": runtime_constraints,
         "integration": integration}[sys.argv[1]]()
