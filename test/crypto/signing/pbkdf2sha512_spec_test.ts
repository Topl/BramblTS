import { Pbkdf2Sha512 } from './../../../src/crypto/generation/entropy_to_seed';
// import { hexToUint8List } from './test_vectors/ckd_ed25519_vectors';
import { pbkdf2Sha512TestVectors } from './test_vectors/pbkdf2_sha512_vectors';

describe('Pbkdf2Sha512TestVectors Topl test vectors', () => {
  let n = 0;

  for (const vector of pbkdf2Sha512TestVectors) {
    n++;

    test(`Pbkdf2Sha512TestVectors vector ${n}`, () => {
      const expectedResult = Uint8Array.from(
        vector.result.split(' ').map((byte) => parseInt(byte, 16))
      );

      const kdf = new Pbkdf2Sha512();

      const result = kdf.generateKey(
        vector.password,
        Uint8Array.from(Buffer.from(vector.salt, 'utf-8')),
        vector.keySize,
        vector.iterations,
      );

      const hexResult = Array.from(result)
        .map((byte) => byte.toString(16).padStart(2, '0'))
        .join('');

      expect(hexResult).toBe(
        Array.from(expectedResult)
          .map((byte) => byte.toString(16).padStart(2, '0'))
          .join('')
      );
    });
  }
});
