import { Aes, AesParams } from './aes.js';

/**
 * Ciphers are used to encrypt and decrypt data.
 * @see [https://en.wikipedia.org/wiki/Cipher]
 */
export abstract class Cipher {
  /**
   * JSON decoder for a Cipher.
   * @param json - JSON object to decode.
   * @returns An instance of a subclass of Cipher.
   */
  static fromJson (json: { [key: string]: any }): any {
    const cipherType = json['cipher'];
    switch (cipherType) {
      case 'aes':
        const aesParams = AesParams.fromJson(json);
        return new Aes(aesParams.iv);
      default:
        throw new UnknownCipherException();
    }
  }

  abstract get params(): Params;

  /**
   * Encrypt data.
   * @param plainText - Data to encrypt.
   * @param key - Encryption key.
   * @returns Encrypted data.
   */
  abstract encrypt(plainText: Uint8Array, key: Uint8Array): Uint8Array;

  /**
   * Decrypt data.
   * @param cipherText - Data to decrypt.
   * @param key - Decryption key.
   * @returns Decrypted data.
   */
  abstract decrypt(cipherText: Uint8Array, key: Uint8Array): Uint8Array;

  /**
   * JSON encoder for a Cipher.
   * @returns JSON representation of the cipher.
   */
  abstract toJson(): { [key: string]: any };
}

/**
 * Cipher parameters.
 */
export abstract class Params {
  abstract get cipher(): string;
}

/**
 * Exception for unknown cipher types.
 */
export class UnknownCipherException extends Error {
  constructor () {
    super('Unknown cipher type.');
  }
}
