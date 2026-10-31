# Minimal Browser-Compatible Implementation of TUF 

[![Conformance](https://github.com/freedomofpress/tuf-browser/actions/workflows/conformance.yml/badge.svg)](https://github.com/sachaservan/tuf-browser/actions/workflows/conformance.yml)

A minimal TypeScript implementation of [The Update Framework (TUF)](https://theupdateframework.io/) specification, optimized for browser compatibility.

This is a lightweight alternative to [tuf-js](https://github.com/theupdateframework/tuf-js) that focuses on core TUF functionality needed for secure software updates in browser environments.

> [!CAUTION]  
> This library has not received an independent security audit. Maintenance is performed by volunteers, and the project is not officially supported or endorsed by the Freedom of the Press Foundation.

## Features

- **Core TUF Security**: Implements essential TUF security guarantees including rollback protection, key rotation, and consistent snapshots
- **Browser-First**: Designed for web browsers with support for LocalStorage, Chrome Extension Storage, and filesystem backends
- **Minimal Dependencies**: Zero external dependencies for maximum compatibility
- **Spec Compliant**: Passes TUF conformance tests for supported features
- **ECDSA & Ed25519 Support**: Uses Web Crypto API for ECDSA-P256 and Ed25519 signatures
  Browsers without native Ed25519 need the application to call `installEd25519Fallback()` from `@freedomofpress/crypto-browser/noble` once at startup.

## Limitations

This minimal implementation intentionally omits certain TUF features to optimize for size and browser compatibility:

- No delegation support
- No RSA key support (ECDSA and Ed25519 only)
- No mirror lists
- No custom download limits

## Usage

```typescript
import { TUFClient } from 'tuf-browser';

// Initialize client with repository URL and root metadata
const client = new TUFClient(
  'https://repository.example.com/metadata/',
  rootMetadata,
  'my-app'
);

// Fetch and verify a target file
const targetData = await client.getTarget('path/to/target.json');
```

## Storage Backends

The library automatically selects the appropriate storage backend based on the runtime environment:

| Environment           | Backend used              | Notes                                                                    |
| --------------------- | ------------------------- | ------------------------------------------------------------------------ |
| Node.js (CLI / tests) | `FSBackend`               | Writes metadata and targets to disk. Required for TUF conformance.       |
| Browser Extension     | `ExtensionStorageBackend` | Uses the `browser.storage.local` API (Firefox/Chrome extension storage). |
| Browser Web Page      | `LocalStorageBackend`     | Uses `localStorage`, minimal persistent storage.                         |

## Development

```bash
# Install dependencies
npm install

# Build the project
npm run build
```

## Example: CLI Usage

Download [1.root.json](https://tuf-repo-cdn.sigstore.dev/1.root.json) or a newer one and trigger a refresh.

```bash
$ node ./dist/cli.js \
    --metadata-dir /tmp/ \
    --metadata-url https://tuf-repo-cdn.sigstore.dev \
    refresh 1.root.json
```

Example output:

```
[TUF] Fetching https://tuf-repo-cdn.sigstore.dev/2.root.json
[TUF] Fetching https://tuf-repo-cdn.sigstore.dev/3.root.json
[TUF] Fetching https://tuf-repo-cdn.sigstore.dev/4.root.json
[TUF] Fetching https://tuf-repo-cdn.sigstore.dev/5.root.json
[TUF] Fetching https://tuf-repo-cdn.sigstore.dev/6.root.json
[TUF] Fetching https://tuf-repo-cdn.sigstore.dev/7.root.json
[TUF] Fetching https://tuf-repo-cdn.sigstore.dev/8.root.json
[TUF] Fetching https://tuf-repo-cdn.sigstore.dev/9.root.json
[TUF] Fetching https://tuf-repo-cdn.sigstore.dev/10.root.json
[TUF] Fetching https://tuf-repo-cdn.sigstore.dev/11.root.json
KeyId 7247f0dbad85b147e1863bade761243cc785dcb7aa410e7105dd3d2b61a36d2c does not match the expected 0c87432c3bf09fd99189fdc32fa5eaedf4e4a5fac7bab73fa04a2e0fc64af6f5, importing anyway the provided one for proper referencing.
KeyId 7247f0dbad85b147e1863bade761243cc785dcb7aa410e7105dd3d2b61a36d2c does not match the expected 0c87432c3bf09fd99189fdc32fa5eaedf4e4a5fac7bab73fa04a2e0fc64af6f5, importing anyway the provided one for proper referencing.
KeyId 7247f0dbad85b147e1863bade761243cc785dcb7aa410e7105dd3d2b61a36d2c does not match the expected 0c87432c3bf09fd99189fdc32fa5eaedf4e4a5fac7bab73fa04a2e0fc64af6f5, importing anyway the provided one for proper referencing.
[TUF] Fetching https://tuf-repo-cdn.sigstore.dev/12.root.json
[TUF] Fetching https://tuf-repo-cdn.sigstore.dev/13.root.json
[TUF] Fetching https://tuf-repo-cdn.sigstore.dev/14.root.json
[TUF] Fetching https://tuf-repo-cdn.sigstore.dev/timestamp.json
[TUF] Fetching https://tuf-repo-cdn.sigstore.dev/162.snapshot.json
[TUF] Fetching https://tuf-repo-cdn.sigstore.dev/13.targets.json
```

The CLI behavior follows the TUF client specification required by the [tuf-conformance](https://github.com/theupdateframework/tuf-conformance) suite.

**Note**: The CLI is a minimal reference implementation for conformance testing. It implements the core `init`, `refresh`, and `download` commands but lacks some commands (e.g., `metadata`) expected by certain conformance tests. For production use, import and use the `TUFClient` class directly rather than relying on the CLI.

## Running the TUF Conformance Test Suite

Requires Python 3.11 and virtualenv.

```bash
git clone https://github.com/theupdateframework/tuf-conformance
cd tuf-conformance
make env/pyvenv.cfg
./env/bin/pytest -v tuf_conformance \
   --entrypoint "/usr/bin/node /tuf-browser/dist/cli.js" \
   --repository-dump-dir /tmp/
```

## Conformance

This implementation passes 75 out of 108 TUF conformance tests. The remaining tests cover intentionally unsupported features (delegations, RSA keys).

### Known Issues & TODOs

The core TUF functionality is implemented (metadata verification, signature checking, rollback protection, hash verification with SHA-256/SHA-512 support). Remaining conformance test failures:

* **Root metadata byte preservation** (`test_metadata_bytes_match`)

  Root metadata is re-serialized on write ([tuf.ts:236](src/tuf.ts#L236) uses `setInCache` → `backend.write`), while other roles correctly use `writeRaw` to preserve bytes.

* **Fast-forward recovery** (3 tests in `test_rollback.py`)

  Partial implementation: cached metadata is cleared when keys rotate ([tuf.ts:245-267](src/tuf.ts#L245-L267)). The code strictly rejects version downgrades rather than attempting recovery.

* **Additional test failures** (~10 remaining tests)

  Various failures related to file downloads, static repositories, and edge cases.


## License

MIT License - see [LICENSE](LICENSE) file for details. Portions of this package incorporate code from [sigstore-js](https://github.com/sigstore/sigstore-js) and are licensed under the Apache License 2.0. These sections are clearly indicated in the corresponding source file headers.

## Acknowledgments

This project is based on the [TUF specification](https://theupdateframework.github.io/specification/v1.0.33/index.html) and adapted from [tuf-js](https://github.com/theupdateframework/tuf-js) and [sigstore-js](https://github.com/sigstore/sigstore-js).
