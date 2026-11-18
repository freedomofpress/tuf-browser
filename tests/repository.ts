// A signed TUF repository for tests, served through a stubbed fetch with a fake clock.
import { canonicalizeOLPC, hexToUint8Array, Uint8ArrayToBase64Url, Uint8ArrayToHex } from "@freedomofpress/crypto-browser";
import { vi } from "vitest";

import { LocalStorageBackend } from "../src/storage/localstorage.js";
import { MemoryBackend } from "../src/storage/memory.js";
import { TUFClient } from "../src/tuf.js";

export const ROLES = ["root", "timestamp", "snapshot", "targets"] as const;
export type Role = (typeof ROLES)[number];

const REPOSITORY_URL = "https://repo.invalid/";
export const TARGET = "file.txt";

// The clock starts before EXPIRES_SOON and tests move it to or past that instant.
const START = new Date("2030-01-01T00:00:00Z");
export const EXPIRES_SOON = "2030-01-02T00:00:00Z";
export const AFTER_EXPIRY = new Date("2030-01-03T00:00:00Z");
const EXPIRES_LATE = "2031-01-01T00:00:00Z";

export const utf8 = (value: string) => new TextEncoder().encode(value);
const text = (bytes: ArrayBuffer | Uint8Array) => new TextDecoder().decode(bytes);
const hex = (buffer: ArrayBuffer) => Uint8ArrayToHex(new Uint8Array(buffer));

// Pretty-printed on purpose: the bytes on the wire differ from canonical JSON,
// so hash pins only hold if the client keeps the raw bytes it downloaded.
const encode = (value: unknown) => utf8(JSON.stringify(value, null, 2));

async function sha256(bytes: Uint8Array) {
  return hex(await crypto.subtle.digest("SHA-256", new Uint8Array(bytes)));
}

// Ed25519 test vectors 1 and 2 of RFC 8032, section 7.1: published keys, for tests only. Fixed keys
// keep the fixture deterministic; WebKit's Ed25519 generateKey intermittently fails.
const TEST_KEYS = {
  signer: {
    secret: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    public: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
  },
  extra: {
    secret: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    public: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
  },
};

async function importTestKey(pair: { secret: string; public: string }) {
  const base64url = (value: string) => Uint8ArrayToBase64Url(hexToUint8Array(value));
  const privateKey = await crypto.subtle.importKey(
    "jwk",
    { kty: "OKP", crv: "Ed25519", d: base64url(pair.secret), x: base64url(pair.public) },
    "Ed25519",
    false,
    ["sign"],
  );
  const key = { keytype: "ed25519", scheme: "ed25519", keyval: { public: pair.public } };
  const keyid = await sha256(utf8(canonicalizeOLPC(key)));
  return { privateKey, key, keyid };
}

interface RepositoryOptions {
  /** Role whose metadata expires at EXPIRES_SOON. Every other role expires late. */
  expiring?: Role;
  consistentSnapshot?: boolean;
  /** Use the default localStorage cache instead of an in-memory backend. */
  localStorage?: boolean;
}

interface PublishOptions {
  /** Timestamp version. */
  version?: number;
  /** Snapshot and targets version. Defaults to the timestamp version. */
  metaVersion?: number;
  content?: Uint8Array;
  /** Give the expiring role a late expiry, as a repository re-signing it would. */
  renew?: boolean;
}

interface RotateRootOptions {
  /** Hand the snapshot role to the second key instead of changing targets. */
  snapshotKey?: boolean;
  targetsThreshold?: number;
}

const localStorageNamespaces = new Set<string>();

/**
 * A signed TUF repository served through a stubbed `fetch`.
 *
 * One key signs every role. A second key is listed for targets only, so a
 * root rotation can raise the targets threshold beyond what is signed.
 */
export async function createRepository(options: RepositoryOptions = {}) {
  const { expiring, consistentSnapshot = true, localStorage: useLocalStorage = false } = options;

  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(START);

  const signer = await importTestKey(TEST_KEYS.signer);
  const extra = await importTestKey(TEST_KEYS.extra);

  const sign = async (signed: unknown) => {
    const message = utf8(canonicalizeOLPC(signed));
    return hex(await crypto.subtle.sign("Ed25519", signer.privateKey, message));
  };

  const singleKey = { keyids: [signer.keyid], threshold: 1 };
  const roles = {
    root: singleKey,
    timestamp: singleKey,
    snapshot: singleKey,
    // Deliberately not in sorted order; the client must not reorder signed data.
    targets: { keyids: [signer.keyid, extra.keyid].sort().reverse(), threshold: 1 },
  };

  const files = new Map<string, Uint8Array>();
  const requests: string[] = [];

  const published = (name: string) => {
    const raw = files.get(name);
    if (!raw) {
      throw new Error(`${name} has not been published`);
    }
    return raw;
  };
  let trustedRoot = "";

  async function publish(options: PublishOptions = {}) {
    const { version = 1, content = utf8("first"), renew = false } = options;
    const metaVersion = options.metaVersion ?? version;
    const targetHash = await sha256(content);

    const pin = async (name: string) => {
      const raw = published(name);
      return { version: metaVersion, length: raw.length, hashes: { sha256: await sha256(raw) } };
    };

    // Order matters: snapshot pins targets, and timestamp pins snapshot.
    for (const role of ["root", "targets", "snapshot", "timestamp"] as const) {
      const roleVersion = role === "root" ? 1 : role === "timestamp" ? version : metaVersion;

      const signed: Record<string, unknown> = {
        _type: role,
        spec_version: "1.0.31",
        version: roleVersion,
        expires: role === expiring && !renew ? EXPIRES_SOON : EXPIRES_LATE,
      };
      if (role === "root") {
        signed.keys = { [signer.keyid]: signer.key, [extra.keyid]: extra.key };
        signed.roles = roles;
        signed.consistent_snapshot = consistentSnapshot;
      } else if (role === "targets") {
        signed.targets = {
          [TARGET]: { length: content.length, hashes: { sha256: targetHash } },
        };
      } else if (role === "snapshot") {
        signed.meta = { "targets.json": await pin("targets.json") };
      } else {
        signed.meta = { "snapshot.json": await pin("snapshot.json") };
      }

      const raw = encode({
        signed,
        signatures: [{ keyid: signer.keyid, sig: await sign(signed) }],
      });

      files.set(`${role}.json`, raw);
      if (role === "root") {
        trustedRoot = text(raw);
      } else {
        files.set(`${roleVersion}.${role}.json`, raw);
      }
    }

    files.set(`${targetHash}.${TARGET}`, content);
    files.set(TARGET, content);
  }

  /** Publishes root version 2, signed by the original key. */
  async function rotateRoot(options: RotateRootOptions = {}) {
    const { snapshotKey = false, targetsThreshold = 2 } = options;

    const metadata = JSON.parse(text(published("root.json")));
    metadata.signed.version = 2;
    if (snapshotKey) {
      metadata.signed.roles.snapshot = { keyids: [extra.keyid], threshold: 1 };
    } else {
      metadata.signed.roles.targets.threshold = targetsThreshold;
    }
    metadata.signatures[0].sig = await sign(metadata.signed);

    files.set("2.root.json", encode(metadata));
  }

  await publish();

  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      const name = new URL(url).pathname.slice(1);
      requests.push(name);

      const data = files.get(name);
      return new Response(data ? new Uint8Array(data) : null, { status: data ? 200 : 404 });
    }),
  );

  const namespace = useLocalStorage ? `expiry-test-${crypto.randomUUID()}` : "test";
  if (useLocalStorage) {
    localStorageNamespaces.add(namespace);
  }
  const backend = useLocalStorage ? new LocalStorageBackend() : new MemoryBackend();

  /** A new client over the same cache, as a fresh page load would create. */
  const client = () =>
    new TUFClient(
      REPOSITORY_URL,
      trustedRoot,
      namespace,
      undefined,
      useLocalStorage ? undefined : { backend },
    );

  const cached = async (role: Role) => (await backend.read(`${namespace}/${role}.json`))?.signed;

  const fetchTarget = async () => text(await client().getTarget(TARGET));

  return {
    client,
    cached,
    fetchTarget,
    files,
    published,
    publish,
    rotateRoot,
    requests,
    namespace,
  };
}

/** Restores the clock and fetch, and removes what localStorage repositories cached. */
export function restoreEnvironment() {
  vi.useRealTimers();
  vi.unstubAllGlobals();

  for (const namespace of localStorageNamespaces) {
    for (const role of ROLES) {
      localStorage.removeItem(`${namespace}/${role}.json`);
    }
  }
  localStorageNamespaces.clear();
}
