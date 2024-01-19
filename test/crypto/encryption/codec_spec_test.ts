import { AesParams } from "../../../src/crypto/encryption/cipher/aes";
import { SCryptParams } from "../../../src/crypto/encryption/kdf/scrypt";
import { VaultStore } from "../../../src/crypto/encryption/vault_store";

describe('Codec Spec', () => {
  test('AES Params > Encode and Decode', () => {
    const expected = Helpers.expectedAesParams();

    // Decode test
    const testParams = AesParams.fromJson(expected.json);
    expect(testParams).toEqual(expected.value);

    // Encode test
    const testJson = testParams.toJson();
    expect(testJson).toEqual(expected.json);

    // Decode then Encode test
    const encodedFromDecoded = testParams.toJson();
    expect(encodedFromDecoded).toEqual(expected.json);

    // Encode then Decode test
    const decodedFromEncoded = AesParams.fromJson(testJson);
    expect(decodedFromEncoded).toEqual(expected.value);
  });

  // Add similar test cases for other scenarios...

  test('VaultStore > Decode fails with invalid JSON', () => {
    const expected = Helpers.expectedSCryptParams();

    // verify if underlying piece fails, the whole decode fails
    const invalidKdfParams = { ...expected.fields, salt: undefined, kdf: 'invalid-kdf' };

    const fields = { kdf: invalidKdfParams, ...expected.fields, salt: undefined };
    const invalidJson = fields;

    // Assuming VaultStore.fromJson returns a result object
    const result = VaultStore.fromJson(invalidJson);
    expect(result.isLeft).toBe(true);
  });
});

class Helpers {
  static expectedAesParams() {
    const iv = new Uint8Array('iv'.split('').map((char) => char.charCodeAt(0)));
    const value = new AesParams(iv);

    const fields = { iv: iv };
    const json = fields;

    return { value, fields, json };
  }

  static expectedSCryptParams() {
    const salt = new Uint8Array('salt'.split('').map((char) => char.charCodeAt(0)));
    const value = new SCryptParams(salt);
    const fields = {
      salt: salt,
      n: value.n,
      r: value.r,
      p: value.p,
      dkLen: value.dkLen,
    };
    const json = fields;
    return { value, fields, json };
  }

  // Add similar helper functions for other scenarios...
}
