import type { FileBackend } from "../storage.js";
import type { Metafile } from "../types.js";
import { isRawBytesWrapper, decodeRawBytesWrapper, createRawBytesWrapper } from "./encoding.js";

export class MemoryBackend implements FileBackend {
  private cache = new Map<string, Metafile | { __raw_bytes__: string }>();

  async read(key: string): Promise<Metafile | undefined> {
    const value = this.cache.get(key);
    if (!value) return undefined;
    if (isRawBytesWrapper(value)) {
      return decodeRawBytesWrapper(value);
    }
    return value as Metafile;
  }

  async write(key: string, value: Metafile): Promise<void> {
    this.cache.set(key, value);
  }

  async writeRaw(key: string, value: Uint8Array): Promise<void> {
    this.cache.set(key, createRawBytesWrapper(value));
  }

  async delete(key: string): Promise<void> {
    this.cache.delete(key);
  }
}
