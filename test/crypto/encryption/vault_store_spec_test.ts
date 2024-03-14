import { Mac } from '../../../src/crypto/encryption/mac';
import { Aes } from './../../../src/crypto/encryption/cipher/aes';
import { SCrypt, SCryptParams } from './../../../src/crypto/encryption/kdf/scrypt';
import { VaultStore } from './../../../src/crypto/encryption/vault_store';

function copyWith<T>(original: T, updates: Partial<T>): T {
  return Object.assign({}, original, updates);
}

class InvalidMac extends Error {
  constructor(message?: string) {
    super(message);
    this.name = 'InvalidMac';
  }
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
    const sensitiveInformation = Uint8Array.from(Buffer.from('this is a secret'));
    const password = Uint8Array.from(Buffer.from('this is a password'));
    const vaultStore = generateVaultStore(sensitiveInformation, password);

    const decoded = VaultStore.decodeCipher(vaultStore, password);

    expect(decoded.right).toEqual(sensitiveInformation);
  });

  test('Verify decodeCipher returns InvalidMac with a different password', () => {
    const sensitiveInformation = Uint8Array.from(Buffer.from('this is a secret'));
    const password = Uint8Array.from(Buffer.from('this is a password'));
    const vaultStore = generateVaultStore(sensitiveInformation, password);

    const decoded = VaultStore.decodeCipher(vaultStore, Uint8Array.from(Buffer.from('this is a different password')));

    expect(decoded.left instanceof InvalidMac).toBe(true);
  });

  test('Verify decodeCipher returns InvalidMac with a corrupted VaultStore', () => {
    const sensitiveInformation = Uint8Array.from(Buffer.from('this is a secret'));
    const password = Uint8Array.from(Buffer.from('this is a password'));
    const vaultStore = generateVaultStore(sensitiveInformation, password);

    // VaultStore is corrupted by changing the cipher text
    const decoded1 = VaultStore.decodeCipher(
      copyWith(vaultStore, { cipherText: Uint8Array.from(Buffer.from('this is an invalid cipher text')) }),
      password
    );
    expect(decoded1.left instanceof InvalidMac).toBe(true);

    // VaultStore is corrupted by changing the mac
    const decoded2 = VaultStore.decodeCipher(
      copyWith(vaultStore, { mac: Uint8Array.from(Buffer.from('this is an invalid mac')) }),
      password
    );
    expect(decoded2.left instanceof InvalidMac).toBe(true);

    // VaultStore is corrupted by changing some parameter in KdfParams
    const kdfParams = new SCryptParams(Uint8Array.from(Buffer.from('invalid salt')));
    const wrongKdf = new SCrypt(kdfParams);
    const decoded3 = VaultStore.decodeCipher(copyWith(vaultStore, { kdf: wrongKdf }), password);
    expect(decoded3.left instanceof InvalidMac).toBe(true);
  });
});
