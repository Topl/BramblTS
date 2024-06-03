
import { Aes } from '@/crypto/encryption/cipher/aes.js';
import { equals, padArray } from '@/utils/extensions.js';
import { describe, test, expect } from 'vitest';
import { hexToUint8List } from '../../signing/test_vectors/ckd_ed25519_vectors.js';

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
    const message: Uint8Array = 'message'.bToUint8Array();
    const cipherText1 = aes.encrypt(message, encryptKey1);
    const cipherText2 = aes.encrypt(message, encryptKey2);
    expect(cipherText1).not.toEqual(cipherText2);
  });

  test('Encrypting the same secret with different key lengths produces different ciphertexts', () => {
    const aes = new Aes();
    const encryptKey1 = padArray(hexToUint8List(stringToHex('encryptKey1')), 16);
    const encryptKey2 = padArray(hexToUint8List(stringToHex('encryptKey2')), 32);
    const message: Uint8Array = 'message'.bToUint8Array();
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
    const message: Uint8Array = 'message'.bToUint8Array();

    const cipherText1 = aes1.encrypt(message, key);
    const cipherText2 = aes2.encrypt(message, key);

    expect(cipherText1).not.toEqual(cipherText2);
  });

  test('Encrypt and decrypt is successful with the same key and iv', () => {
    for (const keySize of [16, 24, 32]) {
      const key = padArray(hexToUint8List(stringToHex('key')), keySize);
      const iv = Aes.generateIv();
      const aes = new Aes(iv);
      const message: Uint8Array = 'message'.bToUint8Array();

      const cipherText = aes.encrypt(message, key);
      const decodedText = aes.decrypt(cipherText, key);

      expect(decodedText).toEqual(message);
    }
  });

  test('Encrypt and decrypt is unsuccessful with a different key', () => {
    const aes = new Aes();
    const encryptKey = padArray(hexToUint8List(stringToHex('encryptKey')), 16);
    const decryptKey = padArray(hexToUint8List(stringToHex('decryptKey')), 16);
    const message: Uint8Array = 'message'.bToUint8Array();

    const cipherText = aes.encrypt(message, encryptKey);
    const decodedText = aes.decrypt(cipherText, decryptKey);

    expect(decodedText).not.toEqual(message);
  });

  test('Encrypt and decrypt is unsuccessful with a different iv', () => {
    const iv1 = Aes.generateIv();
    let iv2 = Aes.generateIv();

    while (equals(iv2, iv1)) {
      iv2 = Aes.generateIv();
    }

    const aesEncrypt = new Aes(iv1);
    const aesDecrypt = new Aes(iv2);

    const key = padArray(hexToUint8List(stringToHex('key')), 16);
    const message: Uint8Array = 'message'.bToUint8Array();

    const cipherText = aesEncrypt.encrypt(message, key);
    const decodedText = aesDecrypt.decrypt(cipherText, key);

    expect(decodedText).not.toEqual(message);
  });
});
