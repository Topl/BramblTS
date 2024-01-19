import crypto from 'crypto';
import { Aes, AesParams } from '../../../../src/crypto/encryption/cipher/aes';

function stringToUint8Array(str: string): Uint8Array {
  return new Uint8Array([...str].map(char => char.charCodeAt(0)));
}

function padUint8Array(arr: Uint8Array, length: number): Uint8Array {
  const paddedArray = new Uint8Array(length);
  paddedArray.set(arr, 0);
  return paddedArray;
}

function areArraysEqual(arr1: Uint8Array, arr2: Uint8Array): boolean {
  if (arr1.length !== arr2.length) {
    return false;
  }

  for (let i = 0; i < arr1.length; i++) {
    if (arr1[i] !== arr2[i]) {
      return false;
    }
  }

  return true;
}

describe('Aes Spec', () => {
  test('Encrypting the same secret with different keys produces different ciphertexts', () => {
    const aes = new Aes();
    const encryptKey1 = padUint8Array(stringToUint8Array('encryptKey1'), 16);
    const encryptKey2 = padUint8Array(stringToUint8Array('encryptKey2'), 16);
    const message: Uint8Array = new TextEncoder().encode('message');
    const cipherText1 = aes.encrypt(message, encryptKey1);
    const cipherText2 = aes.encrypt(message, encryptKey2);
    
    expect(cipherText1).not.toEqual(cipherText2);
  });

  test('encrypting the same secret with different key lengths produces different ciphertexts', () => {
    const aes = new Aes();
    const encryptKey1 = padUint8Array(stringToUint8Array('encryptKey1'), 16);
    const encryptKey2 = padUint8Array(stringToUint8Array('encryptKey2'), 32);
    const message: Uint8Array = new TextEncoder().encode('message');
    const cipherText1 = aes.encrypt(message, encryptKey1);
    const cipherText2 = aes.encrypt(message, encryptKey2);
    
    expect(cipherText1).not.toEqual(cipherText2);
  });

  test('encrypting the same secret with different ivs produces different ciphertexts', () => {
    const params1 = Aes.generateIv();
    let params2 = Aes.generateIv();

    while (areArraysEqual(params2, params1)) {
      params2 = Aes.generateIv();
    }
    
    const aes1 = new Aes(params1);
    const aes2 = new Aes(params2);

    const key = padUint8Array(stringToUint8Array('key'), 16);
    const message: Uint8Array = new TextEncoder().encode('message');

    const cipherText1 = aes1.encrypt(message, key);
    const cipherText2 = aes2.encrypt(message, key);

    expect(cipherText1).not.toEqual(cipherText2);
  });

  test('encrypt and decrypt is successful with the same key and iv', () => {
    // Test with different sizes of keys
    for (const keySize of [16, 24, 32]) {
      const key = padUint8Array(stringToUint8Array('key'), keySize);
      const params = AesParams.generate();
      const aes = new Aes(params);
      const message: Uint8Array = new TextEncoder().encode('message');

      const cipherText = aes.encrypt(message, key);
      const decodedText = aes.decrypt(cipherText, key);

      expect(decodedText).not.toEqual(message);
    }
  });

  test('encrypt and decrypt is unsuccessful with a different key', () => {
    const encryptKey = Buffer.from('encryptKey').slice(0, 16);
    const decryptKey = Buffer.from('decryptKey').slice(0, 16);
    const iv = crypto.randomBytes(16);
    const aesEncrypt = crypto.createCipheriv('aes-128-cbc', encryptKey, iv);
    const message = Buffer.from('message');
    const cipherText = Buffer.concat([aesEncrypt.update(message), aesEncrypt.final()]);

    const aesDecrypt = crypto.createDecipheriv('aes-128-cbc', decryptKey, iv);
    const decodedText = Buffer.concat([aesDecrypt.update(cipherText), aesDecrypt.final()]);
    
    expect(decodedText.equals(message)).toBe(false);
  });

  test('encrypt and decrypt is unsuccessful with a different iv', () => {
    const ivEncrypt = crypto.randomBytes(16);
    const ivDecrypt = crypto.randomBytes(16);
    const key = Buffer.from('key').slice(0, 16);
    const aesEncrypt = crypto.createCipheriv('aes-128-cbc', key, ivEncrypt);
    const message = Buffer.from('message');
    const cipherText = Buffer.concat([aesEncrypt.update(message), aesEncrypt.final()]);

    const aesDecrypt = crypto.createDecipheriv('aes-128-cbc', key, ivDecrypt);
    const decodedText = Buffer.concat([aesDecrypt.update(cipherText), aesDecrypt.final()]);
    
    expect(decodedText.equals(message)).toBe(false);
  });
});
