# Frozen dependencies and approved exceptions

Hermes source remains exactly
`645da6561c724b7ca163d4af9c21de3a6397c9f2`. There are only two explicitly
approved dependency exceptions:

| Package | Original | Approved | Reason |
| --- | --- | --- | --- |
| `electron-to-chromium` | `1.5.433` | `1.5.430` | Available browser-data leaf within the frozen parent's `^1.5.427` range. |
| `msal` | `1.36.0` | `1.37.0` | The original MSAL metadata rejects the required `cryptography==50.0.0`; 1.37.0 accepts it. |

The sole approved MSAL artifact is `msal-1.37.0-py3-none-any.whl`, SHA256
`dd17e95a7c71bce75e8108113438ba7c4a086b3bcad4f57a8c09b7af3d753c2d`.
`azure-identity==1.25.3`, `cryptography==50.0.0`, every other Python
version/artifact hash, selected extras and the original Hermes source
remain unchanged. This is not permission for a general lock refresh.

`build_dependencies.py` guards the exact upstream lock and project
fingerprints before running the pinned uv generator. It keeps those
source files unchanged, exports the frozen selected requirements and
resolves MSAL under all the other original constraints. Only the
approved wheel hash is retained from uv's generated MSAL record; no
sdist or weak hash is accepted. Every non-MSAL exported record, including
markers and artifact hashes, must remain byte-identical.

The image retains original/applied requirements, the one-record patch,
the generator output and equality proof under `/opt/hermes-sandbox`.
`python-lock-exception.json` and `frontend-lock-exception.json` document
the two exceptions. `build-versions.json` binds the applied Python
requirements and exception proof; `runtime-distributions.json` records
the verified installed set. The build context excludes all six generated
Python provenance files so `COPY` cannot replace them with stale local
files. After `COPY`, integration rechecks the original/applied requirement
bytes, the resolver-output hash and the exact derived patch, then
regenerates the verified installed-set record.

Installation uses the normal resolver with `--no-config`, frozen
constraints and hash verification. Neither the upstream override nor
`--no-deps` bypasses package metadata. Standard `uv --no-config pip check`
must succeed for the production build, the separate SDK verification
target and the exact-image CI run before any optional publication.
The manual workflow builds both `final` and `verification`; the SDK
target is never published and its strict check cannot be skipped by
requesting publication.
Native MI/cache/signature, runtime/Node, production-entrypoint and browser
checks are separate gates; they cannot waive a dependency mismatch.

Host-only runtime tests need PyYAML and `packaging`; the latter parses
the same standard dependency markers as the image. They do not import
Hermes or need its full dependency environment.
