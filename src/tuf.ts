import { Uint8ArrayToHex, Uint8ArrayToString } from "@freedomofpress/crypto-browser";
import {
  checkSignatures,
  getRoleKeys,
  loadKeys,
} from "./crypto.js";
import { FileBackend } from "./storage.js";
import { ExtensionStorageBackend } from "./storage/browser.js";
import { FSBackend } from "./storage/filesystem.js";
import { LocalStorageBackend } from "./storage/localstorage.js";
import { MemoryBackend } from "./storage/memory.js";
import {
  HashAlgorithms,
  Meta,
  Metafile,
  Roles,
  Root,
  TOP_LEVEL_ROLE_NAMES,
} from "./types.js";

export interface TUFClientOptions {
  disableCache?: boolean;
}

export class TUFClient {
  private repositoryUrl: string;
  private targetBaseUrl: string;
  private startingRoot: string;
  private namespace: string;
  private backend: FileBackend;

  constructor(
    repositoryUrl: string,
    startingRoot: string,
    namespace: string,
    targetBaseUrl?: string,
    options?: TUFClientOptions,
  ) {
    this.repositoryUrl = repositoryUrl;
    this.targetBaseUrl = targetBaseUrl || repositoryUrl;
    this.startingRoot = startingRoot;
    this.namespace = namespace;

    if (options?.disableCache) {
      this.backend = new MemoryBackend();
    } else if (typeof process !== "undefined" && process.versions?.node) {
      this.backend = new FSBackend();
    } else if (typeof browser !== "undefined" && browser.storage?.local) {
      this.backend = new ExtensionStorageBackend();
    } else if (typeof localStorage !== "undefined") {
      this.backend = new LocalStorageBackend();
    } else {
      this.backend = new MemoryBackend();
    }
  }

  private getCacheKey(key: string): string {
    if (
      key.startsWith("/") ||
      key.startsWith("./") ||
      key.includes("..") ||
      key.includes("\\")
    ) {
      throw new Error(`key contains an invalid pattern (${key})`);
    }

    return `${this.namespace}/${key}.json`;
  }

  private async getFromCache(key: string): Promise<Metafile | undefined> {
    const namespacedKey = this.getCacheKey(key);
    return await this.backend.read(namespacedKey);
  }

  private async setInCache(key: string, value: Metafile): Promise<void> {
    const namespacedKey = this.getCacheKey(key);
    await this.backend.write(namespacedKey, value);
  }

  private async fetchMetafileBase(
    role: string,
    version: number | string,
    target: boolean = false,
  ): Promise<Response> {
    let url;
    role = encodeURIComponent(role);
    if (!target) {
      url =
        version !== -1
          ? `${this.repositoryUrl}${version}.${role}.json`
          : `${this.repositoryUrl}${role}.json`;
    } else {
      url = `${this.repositoryUrl}${version}.${role}`;
    }

    // console.log("[TUF]", "Fetching", url);

    const response = await fetch(url);

    if (!response.ok) {
      throw new Error(
        `Failed to fetch file: ${response.status} ${response.statusText}`,
      );
    }

    return response;
  }

  private validateMetadata(metadata: Metafile): void {
    const seenKeyIds = new Set<string>();
    for (const sig of metadata.signatures) {
      if (seenKeyIds.has(sig.keyid)) {
        throw new Error(`Duplicate signature found for keyid: ${sig.keyid}`);
      }
      seenKeyIds.add(sig.keyid);
    }

    const specVersion = metadata.signed.spec_version;
    if (!specVersion) {
      throw new Error("spec_version is required");
    }
    const parts = specVersion.split(".");
    if (parts.length < 2 || parts.length > 3) {
      throw new Error(`Invalid spec_version format: ${specVersion}`);
    }
    if (!parts.every((p) => /^\d+$/.test(p))) {
      throw new Error(`spec_version parts must be numeric: ${specVersion}`);
    }
    if (parts[0] !== "1") {
      throw new Error(
        `Unsupported spec_version major version: ${parts[0]} (expected 1)`,
      );
    }
  }

  private async fetchMetafileJson(
    role: string,
    version: number | string = -1,
  ): Promise<Metafile> {
    const response = await this.fetchMetafileBase(role, version);
    const metadata = (await response.json()) as Metafile;
    this.validateMetadata(metadata);
    return metadata;
  }

  private async fetchMetafileBinary(
    role: string,
    version: number | string = -1,
    target: boolean = false,
  ): Promise<Uint8Array> {
    const response = await this.fetchMetafileBase(role, version, target);
    return new Uint8Array(await response.arrayBuffer());
  }

  private bootstrapRoot(file: string): Promise<Metafile> {
    try {
      const metadata = JSON.parse(file);
      this.validateMetadata(metadata);
      return metadata;
    } catch (error) {
      throw new Error(`Failed to load the JSON file:  ${error}`);
    }
  }

  private async verifyHashes(
    data: Uint8Array,
    hashes: Record<string, string> | undefined,
    context: string,
  ): Promise<void> {
    if (!hashes) return;

    const hashAlgoMap: Record<string, string> = {
      sha256: HashAlgorithms.SHA256,
      sha384: HashAlgorithms.SHA384,
      sha512: HashAlgorithms.SHA512,
    };

    for (const [algo, expectedHash] of Object.entries(hashes)) {
      const cryptoAlgo = hashAlgoMap[algo];
      if (!cryptoAlgo) {
        throw new Error(`${context}: unsupported hash algorithm '${algo}'`);
      }
      const computedHash = Uint8ArrayToHex(
        new Uint8Array(await crypto.subtle.digest(cryptoAlgo, data as Uint8Array<ArrayBuffer>)),
      );
      if (expectedHash !== computedHash) {
        throw new Error(`${context}: ${algo} hash mismatch`);
      }
    }
  }

  // This function supports ECDSA (256, 385, 521), Ed25519 in Hex or PEM format
  // it is possible to support certain cases of RSA, but it is not really useful for now
  // Returns a mapping keyid (hexstring) -> CryptoKey object
  private async loadRoot(json: Metafile, oldroot?: Root): Promise<Root> {
    if (json.signed._type !== Roles.Root) {
      throw new Error("Loading the wrong metafile as root.");
    }

    let keys: Map<string, CryptoKey>;
    let threshold: number;
    let roleKeys: string[];

    // If no oldroot, this is a fresh start from a trusted file, so it's self signed
    if (oldroot == undefined) {
      keys = await loadKeys(json.signed.keys);
      roleKeys = json.signed.roles.root.keyids;
      threshold = json.signed.roles.root.threshold;
    } else {
      keys = oldroot.keys;
      roleKeys = oldroot.roles["root"].keyids;
      // We should respect the previous threshold, otherwise it does not make sense
      threshold = oldroot.threshold;
    }

    if (
      (await checkSignatures(
        keys,
        roleKeys,
        json.signed,
        json.signatures,
        threshold,
      )) !== true
    ) {
      throw new Error("Failed to verify metafile.");
    }

    // If we are loading a new root, let's load the new keys since we have verified them
    keys = await loadKeys(json.signed.keys);

    if (!Number.isSafeInteger(json.signed.version) || json.signed.version < 1) {
      throw new Error("There is something wrong with the root version number.");
    }

    // Validate required top-level roles exist
    for (const role of TOP_LEVEL_ROLE_NAMES) {
      if (!json.signed.roles[role]) {
        throw new Error(`Missing required top-level role: ${role}`);
      }
    }

    // Validate no duplicate keyids within each role
    for (const [roleName, role] of Object.entries(json.signed.roles)) {
      const keyidSet = new Set(role.keyids);
      if (keyidSet.size !== role.keyids.length) {
        throw new Error(`Duplicate key IDs found in role: ${roleName}`);
      }
    }

    return {
      keys: keys,
      version: json.signed.version,
      expires: new Date(json.signed.expires),
      threshold: json.signed.roles.root.threshold,
      consistent_snapshot: json.signed.consistent_snapshot,
      roles: json.signed.roles,
    };
  }

  private async updateRoot(frozenTimestamp: Date): Promise<Root> {
    let rootJson = await this.getFromCache(Roles.Root);

    // Is this the first time we are running the update meaning we have no cached file?
    if (!rootJson) {
      // Then load the hardcoded startup root
      // console.log("[TUF]", "Starting from hardcoded root");
      // Spec 5.2
      rootJson = await this.bootstrapRoot(this.startingRoot);
    }

    let root = await this.loadRoot(rootJson as Metafile);
    const oldRoot = root;
    let newroot;
    let newrootJson;

    // In theory max version is the maximum integer size, probably 2^32 per the spec, in practice this should be safe for a century
    for (
      let new_version = root.version + 1;
      new_version < Number.MAX_SAFE_INTEGER;
      new_version++
    ) {
      try {
        newrootJson = await this.fetchMetafileJson(Roles.Root, new_version);
      } catch (e) {
        if (e instanceof Error && e.message.includes("Failed to fetch")) {
          break;
        }
        throw e;
      }

      if (newrootJson.signed.version !== new_version) {
        throw new Error(
          `Version mismatch: URL version ${new_version} but file contains version ${newrootJson.signed.version}`,
        );
      }

      if (newrootJson.signed?._type !== Roles.Root) {
        throw new Error("Incorrect metadata type for root.");
      }

      // First check that is properly signed by the previous root
      newroot = await this.loadRoot(newrootJson, root);
      // Spec 5.3.5: Check for rollback attack - version must be exactly N+1
      if (newroot.version !== root.version + 1) {
        throw new Error(
          `Root version must be exactly ${root.version + 1}, got ${newroot.version}. Probable rollback attack.`,
        );
      }

      // Then check it is properly signed by itself as per 5.3.4 of the SPEC
      newroot = await this.loadRoot(newrootJson);
      root = newroot;

      // By spec 5.3.8, we should update the cache now
      await this.setInCache(Roles.Root, newrootJson);
    }

    // We do not cast expires because it is done in loadRoot
    if (root.expires <= frozenTimestamp) {
      // By spec 5.3.10
      throw new Error("Freeze attack on the root metafile.");
    }

    // Fast-forward recovery: If timestamp or snapshot role keys changed, delete cached metadata.
    // This allows recovery from fast-forward attacks after key rotation.
    if (root.version > oldRoot.version) {
      const timestampKeysChanged =
        JSON.stringify(root.roles.timestamp.keyids.sort()) !==
        JSON.stringify(oldRoot.roles.timestamp.keyids.sort());
      const snapshotKeysChanged =
        JSON.stringify(root.roles.snapshot.keyids.sort()) !==
        JSON.stringify(oldRoot.roles.snapshot.keyids.sort());
      const targetsKeysChanged =
        JSON.stringify(root.roles.targets.keyids.sort()) !==
        JSON.stringify(oldRoot.roles.targets.keyids.sort());

      if (timestampKeysChanged) {
        await this.backend.delete(this.getCacheKey(Roles.Timestamp));
        await this.backend.delete(this.getCacheKey(Roles.Snapshot));
        await this.backend.delete(this.getCacheKey(Roles.Targets));
      }
      if (snapshotKeysChanged) {
        await this.backend.delete(this.getCacheKey(Roles.Snapshot));
        await this.backend.delete(this.getCacheKey(Roles.Targets));
      }
      if (targetsKeysChanged) {
        await this.backend.delete(this.getCacheKey(Roles.Targets));
      }
    }

    return root;
  }

  private async updateTimestamp(
    root: Root,
    frozenTimestamp: Date,
  ): Promise<Metafile | null> {
    // Note: TUF spec 5.5.2 allows optional hashes in timestamp metadata.
    // Sigstore omits them for simpler maintenance and smaller metadata.
    // The "consistent snapshot" feature (version checking) provides sufficient protection against mix-and-match attacks.
    // See: https://github.com/sigstore/root-signing/issues/1388

    // Always remember to select only the keys delegated to a specific role
    const keys = getRoleKeys(root.keys, root.roles.timestamp.keyids);

    if (keys.size < 1) {
      throw new Error("No valid keys found for the timestamp role.");
    }

    const cachedTimestamp = await this.getFromCache(Roles.Timestamp);

    // Spec 5.4.1 - Fetch raw bytes to preserve exact serialization
    const newTimestampRaw = await this.fetchMetafileBinary(Roles.Timestamp, -1);
    const newTimestamp = JSON.parse(Uint8ArrayToString(newTimestampRaw));
    this.validateMetadata(newTimestamp);

    if (newTimestamp.signed._type !== Roles.Timestamp) {
      throw new Error(
        `Invalid metadata type: expected ${Roles.Timestamp}, got ${newTimestamp.signed._type}`,
      );
    }

    // Validate required meta field
    if (
      !newTimestamp.signed.meta ||
      !newTimestamp.signed.meta["snapshot.json"]
    ) {
      throw new Error(
        "Timestamp metadata missing required meta['snapshot.json']",
      );
    }

    // Spec 5.4.2
    if (
      (await checkSignatures(
        keys,
        root.roles["timestamp"].keyids,
        newTimestamp.signed,
        newTimestamp.signatures,
        root.roles.timestamp.threshold,
      )) !== true
    ) {
      throw new Error("Failed verifying timestamp role signature(s).");
    }

    // Spec 5.4.3.x apply only if we already have a cached file supposedly
    if (cachedTimestamp !== undefined) {
      // 5.4.3.1 if lower, this is a rollback attack
      if (newTimestamp.signed.version < cachedTimestamp.signed.version) {
        throw new Error(
          "New timestamp file has a lower version that the currently cached one.",
        );
      }
      if (newTimestamp.signed.version == cachedTimestamp.signed.version) {
        // If equal, there is no update - return null to signal no update needed
        return null;
      }
      // 5.4.3.2
      if (
        newTimestamp.signed.meta["snapshot.json"].version <
        cachedTimestamp.signed.meta["snapshot.json"].version
      ) {
        throw new Error(
          "Timestamp has been updated, but snapshot version has been rolled back.",
        );
      }
    }

    if (new Date(newTimestamp.signed.expires) <= frozenTimestamp) {
      throw new Error("Freeze attack on the timestamp metafile.");
    }

    await this.backend.writeRaw(
      this.getCacheKey(Roles.Timestamp),
      newTimestampRaw,
    );
    return newTimestamp;
  }

  private async updateSnapshot(
    root: Root,
    frozenTimestamp: Date,
    timestampMeta: Metafile,
  ): Promise<Meta> {
    const version = timestampMeta.signed.meta["snapshot.json"].version;
    const keys = getRoleKeys(root.keys, root.roles.snapshot.keyids);
    const cachedSnapshot = await this.getFromCache(Roles.Snapshot);

    let newSnapshotRaw;

    // Spec 5.5.1
    if (root.consistent_snapshot) {
      newSnapshotRaw = await this.fetchMetafileBinary(Roles.Snapshot, version);
    } else {
      newSnapshotRaw = await this.fetchMetafileBinary(Roles.Snapshot, -1);
    }

    // Spec 5.5.2: Verify snapshot length and hash if present in timestamp
    const snapshotMeta = timestampMeta.signed.meta["snapshot.json"];
    if (snapshotMeta.length !== undefined) {
      if (newSnapshotRaw.length !== snapshotMeta.length) {
        throw new Error(
          `Snapshot length mismatch: expected ${snapshotMeta.length}, got ${newSnapshotRaw.length}`,
        );
      }
    }
    await this.verifyHashes(newSnapshotRaw, snapshotMeta.hashes, "Snapshot");

    const newSnapshot = JSON.parse(Uint8ArrayToString(newSnapshotRaw));
    this.validateMetadata(newSnapshot);

    if (newSnapshot.signed._type !== Roles.Snapshot) {
      throw new Error(
        `Invalid metadata type: expected ${Roles.Snapshot}, got ${newSnapshot.signed._type}`,
      );
    }

    // Validate required meta field
    if (!newSnapshot.signed.meta || !newSnapshot.signed.meta["targets.json"]) {
      throw new Error(
        "Snapshot metadata missing required meta['targets.json']",
      );
    }

    // Spec 5.5.3
    if (
      (await checkSignatures(
        keys,
        root.roles["snapshot"].keyids,
        newSnapshot.signed,
        newSnapshot.signatures,
        root.roles.snapshot.threshold,
      )) !== true
    ) {
      throw new Error("Failed verifying snapshot role signature(s).");
    }

    // 5.5.4 - Validate version matches (both timestamp and URL if consistent_snapshot)
    if (newSnapshot.signed.version !== version) {
      throw new Error(
        `Snapshot version mismatch: URL version ${version} but file contains version ${newSnapshot.signed.version}`,
      );
    }

    // 5.5.5
    if (cachedSnapshot !== undefined) {
      for (const [target] of Object.entries(cachedSnapshot.signed.meta)) {
        if (target in newSnapshot.signed.meta !== true) {
          throw new Error(
            "Target that was listed in an older snapshot was dropped in a newer one.",
          );
        }
        if (
          newSnapshot.signed.meta[target].version <
          cachedSnapshot.signed.meta[target].version
        ) {
          throw new Error(
            "Target version in newer snapshot is lower than the cached one. Probable rollback attack.",
          );
        }
      }
    }

    // 5.5.6
    if (new Date(newSnapshot.signed.expires) <= frozenTimestamp) {
      throw new Error("Freeze attack on the snapshot metafile.");
    }

    // 5.5.7 - Store raw bytes to preserve exact serialization
    await this.backend.writeRaw(
      this.getCacheKey(Roles.Snapshot),
      newSnapshotRaw,
    );

    // If we reach here, we expect updates, otherwise we would have aborted in the timestamp phase.
    return newSnapshot.signed.meta;
  }

  private async updateTargets(
    root: Root,
    frozenTimestamp: Date,
    snapshot: Meta,
  ) {
    const keys = getRoleKeys(root.keys, root.roles.targets.keyids);

    const cachedTargets = await this.getFromCache(Roles.Targets);

    let newTargetsRaw;

    // Spec 5.6.1, sigstore targets.json does not even have hashes for now
    if (root.consistent_snapshot) {
      newTargetsRaw = await this.fetchMetafileBinary(
        Roles.Targets,
        snapshot[`${Roles.Targets}.json`].version,
      );
    } else {
      newTargetsRaw = await this.fetchMetafileBinary(Roles.Targets, -1);
    }

    // Spec 5.6.2: Verify targets length and hash if present in snapshot
    const targetsMeta = snapshot[`${Roles.Targets}.json`];
    if (targetsMeta.length !== undefined) {
      if (newTargetsRaw.length !== targetsMeta.length) {
        throw new Error(
          `Targets length mismatch: expected ${targetsMeta.length}, got ${newTargetsRaw.length}`,
        );
      }
    }
    await this.verifyHashes(newTargetsRaw, targetsMeta.hashes, "Targets");

    const newTargets = JSON.parse(Uint8ArrayToString(newTargetsRaw));
    this.validateMetadata(newTargets);

    if (newTargets.signed._type !== Roles.Targets) {
      throw new Error(
        `Invalid metadata type: expected ${Roles.Targets}, got ${newTargets.signed._type}`,
      );
    }

    // Spec 5.6.3
    if (
      (await checkSignatures(
        keys,
        root.roles["targets"].keyids,
        newTargets.signed,
        newTargets.signatures,
        root.roles.targets.threshold,
      )) !== true
    ) {
      throw new Error(`Failed verifying targets role.`);
    }

    // 5.6.4 - Check version matches snapshot (and URL if consistent_snapshot)
    const expectedVersion = snapshot[`${Roles.Targets}.json`].version;
    if (newTargets.signed.version !== expectedVersion) {
      throw new Error(
        `Targets version mismatch: URL version ${expectedVersion} but file contains version ${newTargets.signed.version}`,
      );
    }

    // 5.6.5 - Check for rollback attack
    if (
      cachedTargets !== undefined &&
      newTargets.signed.version < cachedTargets.signed.version
    ) {
      throw new Error(
        "Targets version is lower than the cached one. Probable rollback attack.",
      );
    }

    // 5.6.6
    if (new Date(newTargets.signed.expires) <= frozenTimestamp) {
      throw new Error("Freeze attack on the targets metafile.");
    }

    // 5.6.7 - Store raw bytes to preserve exact serialization
    await this.backend.writeRaw(this.getCacheKey(Roles.Targets), newTargetsRaw);
  }

  public async listSignedTargets() {
    const cachedTargets = await this.getFromCache(Roles.Targets);

    const filenames: Array<string> = [];

    if (cachedTargets) {
      for (const filename of Object.keys(cachedTargets.signed.targets)) {
        filenames.push(filename);
      }
    }
    return filenames;
  }

  private async fetchTarget(name: string): Promise<ArrayBuffer> {
    const cachedTargets = await this.getFromCache(Roles.Targets);

    if (cachedTargets === undefined) {
      throw new Error(
        "Failed to find the targets metafile when it should have existed.",
      );
    }

    if (!(name in cachedTargets.signed.targets)) {
      throw new Error(`${name} not present in the targets role.`);
    }

    const targetInfo = cachedTargets.signed.targets[name];
    const targetHashes = targetInfo.hashes;

    let hashForUrl: string;
    if (targetHashes.sha256) {
      hashForUrl = targetHashes.sha256;
    } else if (targetHashes.sha512) {
      hashForUrl = targetHashes.sha512;
    } else {
      throw new Error(
        `No supported hash algorithm found for ${name}. Available: ${Object.keys(targetHashes).join(", ")}`,
      );
    }

    // For consistent snapshots, construct URL preserving directory structure: targets/dir/subdir/HASH.filename
    const lastSlash = name.lastIndexOf("/");
    const targetUrl =
      lastSlash === -1
        ? `${this.targetBaseUrl}${hashForUrl}.${name}` // No directory: HASH.filename
        : `${this.targetBaseUrl}${name.substring(0, lastSlash + 1)}${hashForUrl}.${name.substring(lastSlash + 1)}`; // dir/HASH.filename

    const response = await fetch(targetUrl);
    if (!response.ok) {
      throw new Error(
        `Failed to fetch target: ${response.status} ${response.statusText}`,
      );
    }
    const raw_file = new Uint8Array(await response.arrayBuffer());

    // Verify target file length
    if (raw_file.byteLength !== targetInfo.length) {
      throw new Error(
        `${name} length mismatch: expected ${targetInfo.length}, got ${raw_file.byteLength}`,
      );
    }

    // Verify all target file hashes
    await this.verifyHashes(raw_file, targetHashes, `Target '${name}'`);

    return raw_file.buffer as ArrayBuffer;
  }

  async updateTUF() {
    // Spec 5.1
    const frozenTimestamp = new Date();
    const root: Root = await this.updateRoot(frozenTimestamp);
    const timestampMeta = await this.updateTimestamp(root, frozenTimestamp);

    // If timestamp hasn't changed, no need to update snapshot/targets
    if (timestampMeta === null) {
      return;
    }

    const snapshot = await this.updateSnapshot(
      root,
      frozenTimestamp,
      timestampMeta,
    );
    await this.updateTargets(root, frozenTimestamp, snapshot);
  }

  async getTarget(name: string): Promise<ArrayBuffer> {
    return await this.fetchTarget(name);
  }
}
