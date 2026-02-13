import {
  canonicalize,
  HashAlgorithms,
  hexToUint8Array,
  importKey,
  stringToUint8Array,
  Uint8ArrayToHex,
  verifySignature,
} from "@freedomofpress/crypto-browser";
import { Signature, Signed } from "./types.js";

// We use this to remove to select from the root keys only the ones allowed for a specific role
export function getRoleKeys(
  keys: Map<string, CryptoKey>,
  keyids: string[],
): Map<string, CryptoKey> {
  const roleKeys = new Map(keys);

  for (const key of keys.keys()) {
    if (!keyids.includes(key)) {
      roleKeys.delete(key);
    }
  }
  return roleKeys;
}

export async function loadKeys(
  keys: Signed["keys"],
): Promise<Map<string, CryptoKey>> {
  const importedKeys: Map<string, CryptoKey> = new Map();
  for (const keyId in keys) {
    /* Two mandatory ordered logic steps:
            Compute id manually
            And then check for duplicates
        */
    /* A KEYID, which MUST be correct for the specified KEY. Clients MUST calculate each KEYID to verify this is correct for the associated key. Clients MUST ensure that for any KEYID represented in this key list and in other files, only one unique key has that KEYID. */
    /* https://github.com/sigstore/root-signing/issues/1387 */
    const key = keys[keyId];
    const canonicalBytes = stringToUint8Array(canonicalize(key));
    const verified_keyId = Uint8ArrayToHex(
      new Uint8Array(
        await crypto.subtle.digest(HashAlgorithms.SHA256, canonicalBytes as BufferSource),
      ),
    );

    // Check for key duplicates
    if (importedKeys.has(verified_keyId)) {
      throw new Error("Duplicate keyId found!");
    }
    // Per TUF spec, keyId should match the computed hash of the canonical key representation.
    // However, tuf-js doesn't enforce this either, and sigstore introduced mismatched keyIds
    // during their root v11 signing (Feb 2025) that are now permanently in their TUF chain.
    // KeyId verification has no real security purpose (signature verification uses the actual key).
    // See: https://github.com/sigstore/root-signing/issues/1431
    //      https://github.com/sigstore/root-signing/issues/1387
    if (verified_keyId !== keyId) {
      console.warn(
        `KeyId ${keyId} does not match the expected ${verified_keyId}, importing anyway the provided one for proper referencing.`,
      );
    }
    importedKeys.set(
      keyId,
      await importKey(key.keytype, key.scheme, key.keyval.public),
    );
  }

  return importedKeys;
}

export async function checkSignatures(
  keys: Map<string, CryptoKey>,
  roleKeys: string[],
  signed: object,
  signatures: Signature[],
  threshold: number,
): Promise<boolean> {
  if (threshold < 1) {
    throw new Error("Threshold must be at least 1");
  }

  if (threshold > keys.size) {
    throw new Error(
      "Threshold is bigger than the number of keys provided, something is wrong.",
    );
  }

  // Let's keep this set as a reference to verify that there are no duplicate keys used
  const keyIds = new Set(roleKeys);

  // Let's canonicalize first the body
  const signed_canon = canonicalize(signed);

  let valid_signatures = 0;
  for (const signature of signatures) {
    // Step 1, check if keyid is in the keyIds array
    if (!keyIds.has(signature.keyid)) {
      continue;
      // Originally we would throw an error: but it make sense for a new signer to sign the new manifest
      // we just have to be sure not to count it and hit the threshold
      //throw new Error("Signature has an unknown keyId");
    }

    // Step 2, remove the keyid from the available ones
    // We are attempting verification with that keyid, if it fails we should
    // something is wrong anyway, let's pop the keyid to be safe anyway
    keyIds.delete(signature.keyid);

    // Step 3, grab the correct CryptoKey
    const key = keys.get(signature.keyid);
    const sig = hexToUint8Array(signature.sig);

    if (!key) {
      throw new Error("Keyid was empty.");
    }

    // We checked before that the key exists
    if (
      (await verifySignature(
        key,
        stringToUint8Array(signed_canon),
        sig,
      )) === true
    ) {
      // We used to halt on error, but... https://github.com/sigstore/root-signing/issues/1448
      valid_signatures++;
    }
  }

  if (valid_signatures >= threshold) {
    return true;
  } else {
    return false;
  }
}
