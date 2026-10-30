import { canonicalizeOLPC, stringToUint8Array, Uint8ArrayToHex } from "@freedomofpress/crypto-browser";
import { describe, expect, it, vi } from "vitest";

import { checkSignatures, loadKeys } from "./crypto.js";
import { TUFClient } from "./tuf.js";

describe("TUF Browser Integration Tests", () => {
  it("should detect browser environment and use LocalStorage backend", () => {
    expect(typeof localStorage).toBe("object");
  });

  it("should initialize TUFClient in browser", async () => {
    const rootMetadata = `{
      "signatures": [],
      "signed": {
        "_type": "root",
        "spec_version": "1.0",
        "version": 1,
        "expires": "2099-12-31T23:59:59Z",
        "keys": {},
        "roles": {
          "root": { "keyids": [], "threshold": 1 },
          "timestamp": { "keyids": [], "threshold": 1 },
          "snapshot": { "keyids": [], "threshold": 1 },
          "targets": { "keyids": [], "threshold": 1 }
        },
        "consistent_snapshot": false
      }
    }`;

    const client = new TUFClient(
      "https://tuf-repo-cdn.sigstore.dev/",
      rootMetadata,
      "test-namespace"
    );

    expect(client).toBeDefined();
  });

  it("should use LocalStorage for caching in browser", async () => {
    const testKey = "test-tuf-cache-key";
    const testValue = "test-value";

    localStorage.setItem(testKey, testValue);
    const retrieved = localStorage.getItem(testKey);

    expect(retrieved).toBe(testValue);

    localStorage.removeItem(testKey);
  });

  it("should have fetch API available", () => {
    expect(typeof fetch).toBe("function");
  });

  it("should support JSON parsing", () => {
    const json = '{"test": "value"}';
    const parsed = JSON.parse(json);
    expect(parsed.test).toBe("value");
  });

  it("should support crypto operations for signature verification", async () => {
    expect(globalThis.crypto).toBeDefined();
    expect(globalThis.crypto.subtle).toBeDefined();

    const data = new TextEncoder().encode("test");
    const hash = await crypto.subtle.digest("SHA-256", data);

    expect(hash).toBeInstanceOf(ArrayBuffer);
    expect(hash.byteLength).toBe(32);
  });
});

// Key 2f64fb5e from sigstore's 1.root.json, whose keyids were generated as the
// SHA-256 of the OLPC canonical key. Fails if the encoder dialect changes.
describe("loadKeys", () => {
  it("computes sigstore root v1 keyids with OLPC canonical JSON", async () => {
    const keyid = "2f64fb5eac0cf94dd39bb45308b98920055e9a0d8e012a7220787834c60aef97";
    const keys = {
      [keyid]: {
        keyid_hash_algorithms: ["sha256", "sha512"],
        keytype: "ecdsa-sha2-nistp256",
        keyval: {
          public:
            "04cbc5cab2684160323c25cd06c3307178a6b1d1c9b949328453ae473c5ba7527e35b13f298b41633382241f3fd8526c262d43b45adee5c618fa0642c82b8a9803",
        },
        scheme: "ecdsa-sha2-nistp256",
      },
    };
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const imported = await loadKeys(keys);
    expect(imported.has(keyid)).toBe(true);
    expect(warn).not.toHaveBeenCalled();
    warn.mockRestore();
  });
});

describe("checkSignatures", () => {
  it("counts a signature that is not hex as invalid and lets the others reach the threshold", async () => {
    const signed = { _type: "root", version: 1 };
    const canonical = stringToUint8Array(canonicalizeOLPC(signed));
    const keys = new Map<string, CryptoKey>();
    const signatures = [];
    for (const sig of ["zz", null]) {
      const pair = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
      const keyid = Uint8ArrayToHex(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)));
      keys.set(keyid, pair.publicKey);
      signatures.push({
        keyid,
        sig: sig ?? Uint8ArrayToHex(new Uint8Array(await crypto.subtle.sign("Ed25519", pair.privateKey, canonical as BufferSource))),
      });
    }
    const keyids = [...keys.keys()];
    expect(await checkSignatures(keys, keyids, signed, signatures, 1)).toBe(true);
    expect(await checkSignatures(keys, keyids, signed, signatures.slice(0, 1), 1)).toBe(false);
  });
});
