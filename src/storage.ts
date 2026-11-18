// The goal of this class is to support:
//  - Running in a webapp (localstorage)
//  - Running in a browser extension (extensions storage)
//  - Running in node (filesystem)

import { Metafile } from "./types.js";

export interface FileBackend {
  read(key: string): Promise<Metafile | undefined>;
  write(key: string, value: Metafile): Promise<void>;
  readRaw?(key: string): Promise<Uint8Array | undefined>;
  writeRaw(key: string, value: Uint8Array): Promise<void>;
  delete(key: string): Promise<void>;
}
