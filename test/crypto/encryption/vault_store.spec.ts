import { toLeftE, toRightE } from '@/common/functional/brambl_fp.js';
import { InvalidMac, Mac, VaultStore } from '@/crypto/crypto.js';
import { Aes } from '@/crypto/encryption/cipher/aes.js';
import { SCrypt, SCryptParams } from '@/crypto/encryption/kdf/scrypt.js';
import { describe, expect, test } from 'vitest';

function copyWith<T>(original: T, updates: Partial<T>): T {
  return Object.assign({}, original, updates);
}

describe('Vault store Spec', () => {
  function generateVaultStore(sensitiveInformation: Uint8Array, password: Uint8Array): VaultStore {
    const kdf = new SCrypt(new SCryptParams(SCrypt.generateSalt()));
    const cipher = new Aes();

    const derivedKey = kdf.deriveKey(password);

    const cipherText = cipher.encrypt(sensitiveInformation, derivedKey);
    const mac = new Mac(derivedKey, cipherText);

    return new VaultStore(kdf, cipher, cipherText, mac.value);
  }

  test('Verify decodeCipher produces the plain text secret', () => {
    const sensitiveInformation = 'this is a secret'.bToUint8Array();
    const password = 'this is a password'.bToUint8Array();
    const vaultStore = generateVaultStore(sensitiveInformation, password);

    const decoded = VaultStore.decodeCipher(vaultStore, password);
    const decodedValue = toRightE(decoded);

    expect(decodedValue).toEqual(sensitiveInformation);
  });

  test('Verify decodeCipher returns InvalidMac with a different password', () => {
    const sensitiveInformation = Uint8Array.from(Buffer.from('this is a secret'));
    const password = Uint8Array.from(Buffer.from('this is a password'));
    const vaultStore = generateVaultStore(sensitiveInformation, password);

    const decoded = VaultStore.decodeCipher(vaultStore, Uint8Array.from(Buffer.from('this is a different password')));

    expect(toLeftE(decoded) instanceof InvalidMac).toBe(true);
  });

  test('Verify decodeCipher returns InvalidMac with a corrupted VaultStore', () => {
    const sensitiveInformation = Uint8Array.from(Buffer.from('this is a secret'));
    const password = Uint8Array.from(Buffer.from('this is a password'));
    const vaultStore = generateVaultStore(sensitiveInformation, password);

    // VaultStore is corrupted by changing the cipher text
    const decoded1 = VaultStore.decodeCipher(
      copyWith(vaultStore, { cipherText: Uint8Array.from(Buffer.from('this is an invalid cipher text')) }),
      password,
    );
    expect(toLeftE(decoded1) instanceof InvalidMac).toBe(true);

    // VaultStore is corrupted by changing the mac
    const decoded2 = VaultStore.decodeCipher(
      copyWith(vaultStore, { mac: Uint8Array.from(Buffer.from('this is an invalid mac')) }),
      password,
    );
    expect(toLeftE(decoded2) instanceof InvalidMac).toBe(true);

    // VaultStore is corrupted by changing some parameter in KdfParams
    const kdfParams = new SCryptParams(Uint8Array.from(Buffer.from('invalid salt')));
    const wrongKdf = new SCrypt(kdfParams);
    const decoded3 = VaultStore.decodeCipher(copyWith(vaultStore, { kdf: wrongKdf }), password);
    expect(toLeftE(decoded3) instanceof InvalidMac).toBe(true);
  });
});
