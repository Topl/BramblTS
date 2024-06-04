import { SCrypt, SCryptParams } from '@/crypto/encryption/kdf/scrypt.js';
import { describe, expect, test } from 'vitest';

describe('Scrypt Spec', () => {
  test('verify the same parameters a(salt) and the same secret create the same key', async () => {
    const params = SCryptParams.withGeneratedSalt();
    const sCrypt = new SCrypt(params);
    const secret = 'secret'.bToUint8Array();

    const derivedKey1 = sCrypt.deriveKey(secret);
    const derivedKey2 = sCrypt.deriveKey(secret);
    expect(derivedKey1.equals(derivedKey2)).toBe(true);
  });

  test('verify different parameters (salt) for the same secret creates different keys', async () => {
    const params1 = SCryptParams.withGeneratedSalt();
    let params2 = SCryptParams.withGeneratedSalt();
    while (params2.salt.bEquals(params1.salt)) {
      params2 = SCryptParams.withGeneratedSalt();
    }
    const sCrypt1 = new SCrypt(params1);
    const sCrypt2 = new SCrypt(params2);
    const secret = 'secret'.bToUint8Array();
    const derivedKey1 = sCrypt1.deriveKey(secret);
    const derivedKey2 = sCrypt2.deriveKey(secret);
    expect(derivedKey1.equals(derivedKey2)).toBe(false);
  });

  test('verify different secrets for the same parameters (salt) creates different keys', async () => {
    const params = SCryptParams.withGeneratedSalt();
    const sCrypt = new SCrypt(params);
    const secret1 = 'secret'.bToUint8Array();
    const secret2 = Buffer.concat(['another-secret'.bToUint8Array(), Buffer.alloc(100)]);
    const derivedKey1 = sCrypt.deriveKey(secret1);
    const derivedKey2 = sCrypt.deriveKey(secret2);
    expect(derivedKey1.equals(derivedKey2)).toBe(false);
  });
});
