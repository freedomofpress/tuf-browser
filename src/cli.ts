#!/usr/bin/env node

import * as fs from "node:fs/promises";
import * as path from "node:path";

import { FSBackend } from "./storage/filesystem.js";
import { TUFClient } from "./tuf.js";

// Helper to read CLI args
function getFlag(name: string): string | undefined {
  const idx = process.argv.indexOf(name);
  return idx >= 0 ? process.argv[idx + 1] : undefined;
}

async function main() {
  const [, , ...args] = process.argv;

  const metadataDir = getFlag("--metadata-dir");
  const metadataUrl = getFlag("--metadata-url");
  const targetName = getFlag("--target-name");
  const targetBaseUrl = getFlag("--target-base-url");
  const targetDir = getFlag("--target-dir");

  const command = args.find((arg) =>
    ["init", "refresh", "download"].includes(arg),
  );

  if (!command) {
    console.error("Missing command: init | refresh | download");
    process.exit(1);
  }

  if (!metadataDir) {
    console.error("--metadata-dir is required");
    process.exit(1);
  }

  fs.mkdir(metadataDir, { recursive: true });
  const backend = new FSBackend();

  try {
    if (command === "init") {
      const trustedRoot = args[args.indexOf("init") + 1];
      if (!trustedRoot) {
        console.error("Missing path to trusted root file");
        process.exit(1);
      }

      const raw = await fs.readFile(trustedRoot, "utf-8");
      await backend.write(`${metadataDir}/root.json`, JSON.parse(raw));
      process.exit(0);
    }

    if (command === "refresh") {
      if (!metadataUrl) {
        console.error("--metadata-url is required");
        process.exit(1);
      }

      const client = new TUFClient(
        metadataUrl,
        JSON.stringify(await backend.read(`${metadataDir}/root.json`)),
        metadataDir,
        undefined,
        { backend },
      );
      await client.updateTUF();
      process.exit(0);
    }

    if (command === "download") {
      if (!metadataUrl || !targetName || !targetBaseUrl || !targetDir) {
        console.error("Missing required flags for download");
        process.exit(1);
      }

      const client = new TUFClient(
        metadataUrl,
        JSON.stringify(await backend.read(`${metadataDir}/root.json`)),
        metadataDir,
        targetBaseUrl,
        { backend },
      );
      await client.updateTUF();
      const target = await client.getTarget(targetName);

      await fs.mkdir(targetDir, { recursive: true });
      const outPath = path.join(targetDir, path.basename(targetName));
      await fs.writeFile(outPath, new Uint8Array(target));
      process.exit(0);
    }
  } catch (err) {
    console.error(err);
    process.exit(1);
  }
}

main();
