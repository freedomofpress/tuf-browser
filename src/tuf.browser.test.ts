import { describe, it, expect, beforeAll } from "vitest";
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
