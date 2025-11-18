/// <reference types="vitest" />
import { defineConfig } from "vite";

export default defineConfig({
  build: {
    minify: false,
    outDir: "dist",
    target: "esnext",
    lib: {
      entry: "src/tuf.ts",
      formats: ["es"],
      fileName: "tuf",
    },
  },
  test: {
    globals: true,
    browser: {
      provider: "playwright",
      enabled: true,
      instances: [
        { browser: "chromium" },
        { browser: "firefox" },
        { browser: "webkit" },
      ],
    },
  },
});
