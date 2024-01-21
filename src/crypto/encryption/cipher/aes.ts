/* eslint-disable @typescript-eslint/no-explicit-any */
import { randomBytes, createCipheriv, createDecipheriv } from 'crypto';
// import { Cipher, Params } from './cipher';
// import { ModeOfOperation } from 'aes-js';

export class Aes {
  static readonly blockSize: number = 16;
  readonly iv: Uint8Array;
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

  encrypt(plainText: Uint8Array, key: Uint8Array): Uint8Array {
    const cipher = createCipheriv('aes-256-cbc', key, this.params.iv);
    const amountPadded = (Aes.blockSize - ((plainText.length + 1) % Aes.blockSize)) % Aes.blockSize;
    const paddedBytes = Buffer.from([
      ...Array.from({ length: 1 }, () => amountPadded),
      ...plainText,
      ...new Uint8Array(amountPadded),
    ]);
    return Buffer.concat([cipher.update(paddedBytes), cipher.final()]);
  }

  decrypt(cipherText: Uint8Array, key: Uint8Array): Uint8Array {
    const decipher = createDecipheriv('aes-256-cbc', key, this.params.iv);
    const decrypted = Buffer.concat([decipher.update(cipherText), decipher.final()]);
    const paddedAmount = decrypted[0];
    return decrypted.slice(1, decrypted.length - paddedAmount);
  }

  // private processAes(input: Uint8Array, key: Uint8Array, iv: Uint8Array, encrypt: boolean = false): Uint8Array {
  //   let cipher;
  //   if (encrypt) {
  //     cipher = createCipheriv('aes-256-cbc', key, iv);
  //   } else {
  //     cipher = createDecipheriv('aes-256-cbc', key, iv);
  //   }

  //   return new Uint8Array(cipher.update(input, undefined, 'binary') + cipher.final('binary'));
  // }

  toJson(): any {
    return {
      cipher: this.params.cipher,
      ...this.params.toJson(),
    };
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
