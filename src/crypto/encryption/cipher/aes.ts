import { randomBytes, createCipheriv, createDecipheriv } from 'crypto';

/**
 * AES encryption.
 * Aes is a symmetric block cipher that can encrypt and decrypt data using the same key.
 * @see [https://en.wikipedia.org/wiki/Advanced_Encryption_Standard]
 */
export class Aes {
  private static readonly blockSize: number = 16;
  private iv: Buffer;

  /**
   * Constructs an AES encryption object with an optional initialization vector (IV) and parameters.
   * @param {Buffer} [iv] - Initialization vector. If not provided, a random IV will be generated.
   */
  constructor(iv?: Buffer) {
    this.iv = iv || Aes.generateIv();
  }

  /**
   * Generates a random initialization vector.
   * @returns {Buffer} The generated initialization vector.
   */
  static generateIv(): Buffer {
    return randomBytes(Aes.blockSize);
  }

  /**
   * Creates an AES instance from a JSON object.
   * @param json - The JSON object with an 'iv' property.
   * @returns An instance of the Aes class.
   */
  static fromJson(json: { iv: string }): Aes {
    return new Aes(Buffer.from(json.iv, 'hex'));
  }

  /**
   * Encrypt data.
   * AES block size is a multiple of 16, so the data must have a length multiple of 16.
   * Simply padding the bytes would make it impossible to determine the initial data bytes upon decryption.
   * The amount padded to the plaintext is prepended to the plaintext. Since we know the amount padded is
   * <16, only one byte is needed to store the amount padded.
   * @param plainText - Data to encrypt.
   * @param key - The symmetric key for encryption and decryption must be 128/192/256 bits or 16/24/32 bytes.
   * @returns The encrypted data.
   */
  encrypt(plainText: Buffer, key: Buffer): Buffer {
    const cipher = createCipheriv('aes-256-cbc', key, this.iv);
    const amountPadded = (Aes.blockSize - ((plainText.length + 1) % Aes.blockSize)) % Aes.blockSize;
    const paddedBytes = Buffer.concat([Buffer.from([amountPadded]), plainText, Buffer.alloc(amountPadded)]);
    return Buffer.concat([cipher.update(paddedBytes), cipher.final()]);
  }

  /**
   * Decrypt data.
   * The preImage consists of [paddedAmount] ++ [data] ++ [padding]
   * @param cipherText - Data to decrypt.
   * @param key - The symmetric key for encryption and decryption. Must be 128/192/256 bits or 16/24/32 bytes.
   * @returns Decrypted data.
   */
  decrypt(cipherText: Buffer, key: Buffer): Buffer {
    const decipher = createDecipheriv('aes-256-cbc', key, this.iv);
    const preImage = Buffer.concat([decipher.update(cipherText), decipher.final()]);
    const paddedAmount = preImage[0];
    return preImage.slice(1, preImage.length - paddedAmount);
  }

  /**
   * Converts the AES instance to a JSON object.
   * @returns A JSON representation of the AES instance.
   */
  toJson(): { iv: string } {
    return { iv: this.iv.toString('hex') };
  }
}

/**
 * Class representing AES parameters.
 * @param {Buffer} iv - Initialization vector.
 */
export class AesParams {
  private iv: Buffer;

  constructor(iv: Buffer) {
    this.iv = iv;
  }

  /**
   * Generates a new AesParams instance with a random initialization vector.
   * @returns A new AesParams instance.
   */
  static generate(): AesParams {
    return new AesParams(Aes.generateIv());
  }

  /**
   * Creates an AesParams instance from a JSON object.
   * @param json - The JSON object with an 'iv' property.
   * @returns An instance of the AesParams class.
   */
  static fromJson(json: { iv: string }): AesParams {
    return new AesParams(Buffer.from(json.iv, 'hex'));
  }

  /**
   * Converts the AesParams instance to a JSON object.
   * @returns A JSON representation of the AesParams instance.
   */
  toJson(): { iv: string } {
    return { iv: this.iv.toString('hex') };
  }
}
