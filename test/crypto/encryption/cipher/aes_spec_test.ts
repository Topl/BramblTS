import { padArray, equals, hexToUint8List } from '../../../../src/utils/extensions';
import { Aes, AesParams } from '../../../../src/crypto/encryption/cipher/aes';

// Converts a string to a hexadecimal string representation
function stringToHex(str) {
  return str.split('').map((c) => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
}

describe('Aes Spec', () => {
  test('Encrypting the same secret with different keys produces different ciphertexts', () => {
    const aes = new Aes();
    // Using padArray and hexToUint8List from the extension file
    const encryptKey1 = padArray(hexToUint8List(stringToHex('encryptKey1')), 16);
    const encryptKey2 = padArray(hexToUint8List(stringToHex('encryptKey2')), 16);
    const message: Uint8Array = new TextEncoder().encode('message');
    const cipherText1 = aes.encrypt(message, encryptKey1);
    const cipherText2 = aes.encrypt(message, encryptKey2);

    expect(cipherText1).not.toEqual(cipherText2);
  });

  test('Encrypting the same secret with different key lengths produces different ciphertexts', () => {
    const aes = new Aes();
    const encryptKey1 = padArray(hexToUint8List(stringToHex('encryptKey1')), 16);
    const encryptKey2 = padArray(hexToUint8List(stringToHex('encryptKey2')), 32);
    const message: Uint8Array = new TextEncoder().encode('message');
    const cipherText1 = aes.encrypt(message, encryptKey1);
    const cipherText2 = aes.encrypt(message, encryptKey2);

    expect(cipherText1).not.toEqual(cipherText2);
  });

  test('Encrypting the same secret with different ivs produces different ciphertexts', () => {
    const params1 = Aes.generateIv();
    let params2 = Aes.generateIv();

    // Using equals from the extension file
    while (equals(params2, params1)) {
      params2 = Aes.generateIv();
    }

    const aes1 = new Aes(params1);
    const aes2 = new Aes(params2);

    const key = padArray(hexToUint8List(stringToHex('key')), 16);
    const message: Uint8Array = new TextEncoder().encode('message');

    const cipherText1 = aes1.encrypt(message, key);
    const cipherText2 = aes2.encrypt(message, key);

    expect(cipherText1).not.toEqual(cipherText2);
  });

  test('Encrypt and decrypt is successful with the same key and iv', () => {
    for (const keySize of [16, 24, 32]) {
      const key = padArray(hexToUint8List(stringToHex('key')), keySize);
      const params = AesParams.generate();
      const aes = new Aes(params);
      const message: Uint8Array = new TextEncoder().encode('message');

      const cipherText = aes.encrypt(message, key);
      const decodedText = aes.decrypt(cipherText, key);

      expect(decodedText).toEqual(message);
    }
  });

  test('Encrypt and decrypt is unsuccessful with a different key', () => {
    const aes = new Aes();
    const encryptKey = padArray(hexToUint8List(stringToHex('encryptKey')), 16);
    const decryptKey = padArray(hexToUint8List(stringToHex('decryptKey')), 16);
    const message: Uint8Array = new TextEncoder().encode('message');

    const cipherText = aes.encrypt(message, encryptKey);
    const decodedText = aes.decrypt(cipherText, decryptKey);

    expect(decodedText).not.toEqual(message);
  });

  test('Encrypt and decrypt is unsuccessful with a different iv', () => {
    const encryptParams = AesParams.generate();
    let decryptParams = AesParams.generate();

    while (equals(decryptParams, encryptParams)) {
      decryptParams = AesParams.generate();
    }

    const aesEncrypt = new Aes(encryptParams);
    const aesDecrypt = new Aes(decryptParams);

    const key = padArray(hexToUint8List(stringToHex('key')), 16);
    const message: Uint8Array = new TextEncoder().encode('message');

    const cipherText = aesEncrypt.encrypt(message, key);
    const decodedText = aesDecrypt.decrypt(cipherText, key);

    expect(decodedText).not.toEqual(message);
  });
});
