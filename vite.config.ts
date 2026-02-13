/// <reference types="vitest" />
import { defineConfig } from "vite";

export default defineConfig({
  build: {
    outDir: "dist",
    target: "es2020",
    lib: {
      entry: "src/tuf.ts",
      formats: ["es"],
      fileName: "tuf",
    },
  },
  test: {
    globals: true,
    environment: "node",
  },
});
