import { afterEach, describe, expect, it, vi } from "vitest";

import {
  AFTER_EXPIRY,
  createRepository,
  EXPIRES_SOON,
  restoreEnvironment,
  type Role,
  ROLES,
  TARGET,
  utf8,
} from "./repository.js";

const freezeError = (role: Role) => `Freeze attack on the ${role} metafile.`;

afterEach(restoreEnvironment);

describe("trusted metadata freshness", () => {
  describe("expired cached metadata", () => {
    it.each(ROLES)(
      "rejects expired cached %s on refresh and direct target access",
      async (role) => {
        const repo = await createRepository({ expiring: role });
        await repo.client().updateTUF();

        vi.setSystemTime(AFTER_EXPIRY);

        await expect(repo.client().updateTUF()).rejects.toThrow(freezeError(role));
        await expect(repo.client().getTarget(TARGET)).rejects.toThrow(freezeError(role));
        await expect(repo.client().listSignedTargets()).rejects.toThrow(freezeError(role));
        expect(repo.requests.some((name) => name.endsWith(TARGET))).toBe(false);
      },
    );

    it.each(ROLES)("rejects %s at the exact expiration instant", async (role) => {
      const repo = await createRepository({ expiring: role });
      await repo.client().updateTUF();

      vi.setSystemTime(new Date(EXPIRES_SOON));

      await expect(repo.client().updateTUF()).rejects.toThrow(freezeError(role));
      await expect(repo.client().getTarget(TARGET)).rejects.toThrow(freezeError(role));
    });

    it.each(ROLES)("rejects expired %s through the default localStorage cache", async (role) => {
      const repo = await createRepository({ expiring: role, localStorage: true });
      await repo.client().updateTUF();

      vi.setSystemTime(AFTER_EXPIRY);

      await expect(repo.client().updateTUF()).rejects.toThrow(freezeError(role));
      await expect(repo.client().getTarget(TARGET)).rejects.toThrow(freezeError(role));
      await expect(repo.client().listSignedTargets()).rejects.toThrow(freezeError(role));
    });
  });

  describe("expired timestamp", () => {
    it("does not renew an expired trusted timestamp with the same version", async () => {
      const repo = await createRepository({ expiring: "timestamp" });
      await repo.client().updateTUF();

      await repo.publish({ version: 1, renew: true });
      vi.setSystemTime(AFTER_EXPIRY);

      await expect(repo.client().updateTUF()).rejects.toThrow(freezeError("timestamp"));
    });

    // A refresh that stored timestamp v2 but not its snapshot leaves an incomplete chain. The
    // expired timestamp must stop the next refresh before it tries to fetch the missing snapshot.
    it("rejects an expired timestamp before resuming an interrupted refresh", async () => {
      const repo = await createRepository({ expiring: "timestamp" });
      await repo.client().updateTUF();

      await repo.publish({ version: 2 });
      repo.files.delete("2.snapshot.json");
      await expect(repo.client().updateTUF()).rejects.toThrow("Failed to fetch file: 404");
      expect((await repo.cached("timestamp"))?.version).toBe(2);
      expect((await repo.cached("snapshot"))?.version).toBe(1);

      vi.setSystemTime(AFTER_EXPIRY);

      await expect(repo.client().updateTUF()).rejects.toThrow(freezeError("timestamp"));
    });

    it("rejects a higher-version expired timestamp without losing rollback state", async () => {
      const repo = await createRepository({ expiring: "timestamp" });
      await repo.client().updateTUF();

      await repo.publish({ version: 2 });
      vi.setSystemTime(AFTER_EXPIRY);

      await expect(repo.client().updateTUF()).rejects.toThrow(freezeError("timestamp"));
      expect((await repo.cached("timestamp"))?.version).toBe(1);
    });
  });

  describe("expired downloaded metadata", () => {
    it.each(["snapshot", "targets"] as const)(
      "rejects an expired downloaded %s after a new timestamp",
      async (role) => {
        const repo = await createRepository({ expiring: role });
        await repo.client().updateTUF();

        await repo.publish({ version: 2 });
        vi.setSystemTime(AFTER_EXPIRY);

        await expect(repo.client().updateTUF()).rejects.toThrow(freezeError(role));
        expect((await repo.cached(role))?.version).toBe(1);
      },
    );
  });

  describe("rollback and interrupted updates", () => {
    it("rejects rollback replay after a successful newer refresh", async () => {
      const repo = await createRepository();
      await repo.client().updateTUF();
      const oldTimestamp = repo.published("timestamp.json");

      await repo.publish({ version: 2 });
      await repo.client().updateTUF();
      repo.files.set("timestamp.json", oldTimestamp);

      await expect(repo.client().updateTUF()).rejects.toThrow(
        "New timestamp file has a lower version that the currently cached one.",
      );
      expect((await repo.cached("timestamp"))?.version).toBe(2);
    });

    it("resumes after a timestamp was persisted but snapshot download failed", async () => {
      const repo = await createRepository();
      await repo.client().updateTUF();

      await repo.publish({ version: 2, content: utf8("second") });
      const snapshot = repo.published("2.snapshot.json");
      repo.files.delete("2.snapshot.json");

      await expect(repo.client().updateTUF()).rejects.toThrow("Failed to fetch file: 404");
      await expect(repo.client().getTarget(TARGET)).rejects.toThrow(
        "Cached snapshot version does not match trusted timestamp.",
      );

      repo.files.set("2.snapshot.json", snapshot);
      await repo.client().updateTUF();

      expect(await repo.fetchTarget()).toBe("second");
    });

    it("rejects cached bytes that fail a new timestamp's same-version hash pin", async () => {
      const repo = await createRepository();
      await repo.client().updateTUF();

      await repo.publish({ version: 2, metaVersion: 1, content: utf8("other") });
      repo.files.delete("1.snapshot.json");

      await expect(repo.client().updateTUF()).rejects.toThrow("Failed to fetch file: 404");
      await expect(repo.client().getTarget(TARGET)).rejects.toThrow(
        "Cached snapshot: sha256 hash mismatch",
      );
    });
  });

  describe("root rotation", () => {
    it("deletes timestamp and snapshot rollback floors on snapshot-key rotation", async () => {
      const repo = await createRepository();
      await repo.client().updateTUF();

      await repo.rotateRoot({ snapshotKey: true });
      repo.files.delete("timestamp.json");

      await expect(repo.client().updateTUF()).rejects.toThrow("Failed to fetch file: 404");
      expect((await repo.cached("root"))?.version).toBe(2);
      expect(await repo.cached("timestamp")).toBeUndefined();
      expect(await repo.cached("snapshot")).toBeUndefined();
    });

    it("rechecks cached targets against a rotated root threshold", async () => {
      const repo = await createRepository();
      await repo.client().updateTUF();

      await repo.rotateRoot();

      const error = "Failed verifying cached targets role signature(s).";
      await expect(repo.client().updateTUF()).rejects.toThrow(error);
      await expect(repo.client().getTarget(TARGET)).rejects.toThrow(error);
    });

    it("preserves unsorted signed role keys during a healthy root rotation", async () => {
      const repo = await createRepository();
      await repo.client().updateTUF();

      await repo.rotateRoot({ targetsThreshold: 1 });
      await repo.client().updateTUF();
      expect((await repo.cached("root"))?.version).toBe(2);

      await repo.client().updateTUF();
      expect(await repo.fetchTarget()).toBe("first");
    });
  });

  describe("healthy refreshes", () => {
    it.each([true, false])(
      "serves healthy cached and newly published targets (consistent=%s)",
      async (consistentSnapshot) => {
        const repo = await createRepository({ consistentSnapshot });
        await repo.client().updateTUF();
        await repo.client().updateTUF();

        expect(await repo.fetchTarget()).toBe("first");
        expect(repo.requests.at(-1)).toMatch(
          consistentSnapshot ? /^[a-f0-9]+\.file\.txt$/ : /^file\.txt$/,
        );

        await repo.publish({ version: 2, content: utf8("second") });
        await repo.client().updateTUF();

        expect(await repo.fetchTarget()).toBe("second");
      },
    );

    it("round-trips hash-pinned metadata through the default localStorage cache", async () => {
      const repo = await createRepository({ localStorage: true });
      await repo.client().updateTUF();

      expect(localStorage.getItem(`${repo.namespace}/snapshot.json`)).toContain("__raw_bytes__");

      await repo.client().updateTUF();
      expect(await repo.fetchTarget()).toBe("first");

      await repo.publish({ version: 2, content: utf8("second") });
      await repo.client().updateTUF();
      expect(await repo.fetchTarget()).toBe("second");
    });
  });
});
