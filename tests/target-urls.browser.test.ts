import { afterEach, describe, expect, it } from "vitest";

import { createRepository, restoreEnvironment } from "./repository.js";

afterEach(restoreEnvironment);

describe("target URLs", () => {
  it("fetches the hash-prefixed target name from a repository with consistent snapshots", async () => {
    const repo = await createRepository({ consistentSnapshot: true });
    await repo.client().updateTUF();

    expect(await repo.fetchTarget()).toBe("first");
    expect(repo.requests.at(-1)).toMatch(/^[a-f0-9]{64}\.file\.txt$/);
  });

  it("fetches the plain target name from a repository without consistent snapshots", async () => {
    const repo = await createRepository({ consistentSnapshot: false });
    await repo.client().updateTUF();

    expect(await repo.fetchTarget()).toBe("first");
    expect(repo.requests.at(-1)).toBe("file.txt");
  });
});
