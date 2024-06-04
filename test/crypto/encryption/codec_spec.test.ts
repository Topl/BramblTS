import { VaultStore } from "@/crypto/crypto.js";
import { AesParams, Aes } from "@/crypto/encryption/cipher/aes.js";
import { Kdf } from "@/crypto/encryption/kdf/kdf.js";
import { SCrypt, SCryptParams } from "@/crypto/encryption/kdf/scrypt.js";
import { Json } from "@/utils/json.js";
import { describe, test, expect } from "vitest";
import { Cipher } from "@/crypto/encryption/cipher/cipher.js";
import { isLeft, toRightE } from "@/common/functional/brambl_fp.js";


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

  test('SCrypt Params > Decode fails with invalid JSON', () => {
    const invalidJson = JSON.stringify({
      salt: 'salt',
      r: 10,
      p: 10,
      dkLen: 10,
      // 'n' is missing
    });
    expect(() => SCryptParams.fromJson(JSON.parse(invalidJson))).toThrow();
  });

  test('Cipher > AES > Encode and Decode', () => {
    const expected = Helpers.expectedCipher();

    const testCipher = Cipher.fromJson(JSON.parse(expected.json));
    expect(testCipher).toEqual(expected.value);

    const testJson = JSON.stringify(expected.value.toJson());
    expect(testJson).toEqual(expected.json);

    const encodedFromDecoded = JSON.stringify(testCipher.toJson());
    expect(encodedFromDecoded).toEqual(expected.json);

    const decodedFromEncoded = Cipher.fromJson(JSON.parse(testJson));
    expect(decodedFromEncoded).toEqual(expected.value);
  });

  test('Cipher > AES > Decode fails with invalid label', () => {
    const expected = Helpers.expectedAesParams();
    const fields = { ...expected.fields, cipher: 'invalid-label' };
    const invalidJson = JSON.stringify(fields);

    expect(() => Cipher.fromJson(JSON.parse(invalidJson))).toThrow();
  });

  test('Cipher > AES > Decode fails with invalid JSON', () => {
    const expected = Helpers.expectedAesParams();
    const fields = { cipher: expected.value.cipher }; // IV is missing
    const invalidJson = JSON.stringify(fields);

    expect(() => Cipher.fromJson(JSON.parse(invalidJson))).toThrow();
  });

  test('KDF > SCrypt > Encode and Decode', () => {
    const expected = Helpers.expectedKdf();

    const testKdf = Kdf.fromJson(JSON.parse(expected.json));
    expect(testKdf).toEqual(expected.value);

    const testJson = JSON.stringify(expected.value);
    expect(testJson).toEqual(expected.json);

    const encodedFromDecoded = JSON.stringify(testKdf.toJson());
    expect(encodedFromDecoded).toEqual(expected.json);

    const decodedFromEncoded = Kdf.fromJson(JSON.parse(testJson));
    expect(decodedFromEncoded).toEqual(expected.value);
  });

  test('KDF > SCrypt > Decode fails with invalid label', () => {
    const expected = Helpers.expectedSCryptParams();
    const invalidJson = JSON.stringify(expected.fields); // label is missing

    expect(() => Kdf.fromJson(JSON.parse(invalidJson))).toThrow(TypeError);
  });

  test('KDF > SCrypt > Decode fails with invalid JSON', () => {
    const expected = Helpers.expectedSCryptParams();

    // Create a new object without the 'salt' property
    const { salt, ...fieldsWithoutSalt } = expected.fields;
    const invalidJson = JSON.stringify({ ...fieldsWithoutSalt, kdf: expected.value.kdf });

    expect(() => Kdf.fromJson(JSON.parse(invalidJson))).toThrow(TypeError);
  });

  test('VaultStore > Encode and Decode', () => {
    const expected = Helpers.expectedVaultStore();

    const testVaultStore = toRightE(VaultStore.fromJson(JSON.parse(expected.json)));
    expect(testVaultStore).toEqual(expected.value);

    const testJson = JSON.stringify(expected.value.toJson());
    expect(testJson).toEqual(expected.json);

    const encodedFromDecoded = JSON.stringify(testVaultStore.toJson());
    expect(encodedFromDecoded).toEqual(expected.json);

    const decodedFromEncoded = toRightE(VaultStore.fromJson(JSON.parse(testJson)));
    expect(decodedFromEncoded).toEqual(expected.value);
  });

  test('VaultStore > Decode fails with invalid JSON', () => {
    const expected = Helpers.expectedSCryptParams();

    // verify if underlying piece fails, the whole decode fails
    const invalidKdfParams = { ...expected.fields, salt: undefined, kdf: 'invalid-kdf' };

    const fields = { kdf: invalidKdfParams, ...expected.fields, salt: undefined };
    const invalidJson = fields;

    // Assuming VaultStore.fromJson returns a result object
    const result = VaultStore.fromJson(invalidJson);
    expect(isLeft(result)).toBe(true);
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

  static expectedCipher() {
    const e = Helpers.expectedAesParams();
    const iv = e.value.iv;
    const value = new Aes(iv);

    const fields = { cipher: 'aes', iv: iv.toString() };
    const json = JSON.stringify(fields);

    return {
      value: value,
      fields: fields,
      json: json,
    };
  }

  static expectedKdf() {
    const s = Helpers.expectedSCryptParams();
    const value = new SCrypt(s.value);

    const fields = { kdf: s.value.kdf, ...s.fields };
    const json = JSON.stringify(fields);

    return {
      value: value,
      fields: fields,
      json: json,
    };
  }

  static expectedVaultStore() {
    const c = Helpers.expectedCipher();
    const k = Helpers.expectedKdf();
    const cipherText = new TextEncoder().encode('cipherText');
    const mac = new TextEncoder().encode('mac');

    const value = new VaultStore(k.value, c.value, cipherText, mac);
    const fields = {
      kdf: k.json,
      cipher: c.json,
      cipherText: Json.encodeUint8List(cipherText),
      mac: Json.encodeUint8List(mac),
    };

    const json = JSON.stringify(fields);

    return {
      value: value,
      fields: fields,
      json: json,
    };
  }
}
