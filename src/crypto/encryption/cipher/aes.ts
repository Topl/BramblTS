import { createCipheriv, randomBytes } from 'crypto';
import type { Cipher } from './cipher.js';

export class Aes implements Cipher {
  static readonly blockSize: number = 16;
  readonly params: AesParams;

  constructor(iv?: Uint8Array, params?: AesParams) {
    this.params = params ?? new AesParams(iv ?? Aes.generateIv());
  }

  static fromJson(json: any): Aes {
    const params = AesParams.fromJson(json);
    return new Aes(params.iv, params);
  }

  static generateIv(): Uint8Array {
    return randomBytes(Aes.blockSize);
  }

  /**
   * Encrypt data.
   *
   * @note AES block size is a multiple of 16, so the data must have a length multiple of 16.
   *       Simply padding the bytes would make it impossible to determine the initial data bytes upon encryption.
   *       The amount padded to the plaintext is prepended to the plaintext. Since we know the amount padded is
   *       <16, only one byte is needed to store the amount padded.
   * @param plainText data to encrypt
   * @param key       the symmetric key for encryption and decryption
   *                  Must be 128/192/256 bits or 16/24/32 bytes.
   * @return encrypted data
   */
  encrypt(plainText: Uint8Array, key: Uint8Array): Uint8Array {
    // + 1 to account for the byte storing the amount padded. This value is guaranteed to be <16
    const amountPadded = (Aes.blockSize - ((plainText.length + 1) % Aes.blockSize)) % Aes.blockSize;
    const paddedBytes = new Uint8Array([amountPadded, ...plainText, ...new Uint8Array(amountPadded)]);
    return this.processAes(paddedBytes, key, this.params.iv, true);
  }

  /**
   * Decrypt data.
   *
   * @note The preImage consists of [paddedAmount] ++ [data] ++ [padding]
   * @param cipherText data to decrypt
   * @param key        the symmetric key for encryption and decryption
   *                   Must be 128/192/256 bits or 16/24/32 bytes.
   * @returns decrypted data
   */
  decrypt(cipherText: Uint8Array, key: Uint8Array): Uint8Array {
    const preImage = this.processAes(cipherText, key, this.params.iv, false);
    const paddedAmount = preImage[0];
    const paddedBytes = preImage.slice(1);
    const out = paddedBytes.slice(0, paddedBytes.length - paddedAmount);
    return out;
  }

  private processAes(input: Uint8Array, key: Uint8Array, iv: Uint8Array, encrypt: boolean = false): Uint8Array {
    const algo = this.getAlgorithm(key);
    const aesCtr = createCipheriv(algo, key, iv);

    const out = aesCtr.update(input);
    const out2 = aesCtr.final();
    const final = Buffer.concat([out, out2]);
    return final;
  }

  toJson(): any {
    return {
      cipher: this.params.cipher,
      ...this.params.toJson(),
    };
  }

  /// Get the algorithm based on the IV length.
  private getAlgorithm(iv: Uint8Array): string {
    switch (iv.length) {
      case 16:
        return 'aes-128-ctr';
      case 24:
        return 'aes-192-ctr';
      case 32:
        return 'aes-256-ctr';
      default:
        throw new Error('Invalid IV length');
    }
  }
}

export class AesParams {
  readonly iv: Uint8Array;

  constructor(iv: Uint8Array) {
    this.iv = iv;
  }

  static generate(): AesParams {
    return new AesParams(Aes.generateIv());
  }

  static fromJson(json: any): AesParams {
    const iv = new Uint8Array(Buffer.from(json.iv, 'hex'));
    return new AesParams(iv);
  }

  get cipher(): string {
    return 'aes';
  }

  toJson(): any {
    return { iv: Buffer.from(this.iv).toString('hex') };
  }
}
