import { randomBytes, createCipheriv, createDecipheriv } from 'crypto';

export class Aes {
  private static readonly blockSize: number = 16;
  private iv: Buffer;

  constructor(iv?: Buffer) {
    this.iv = iv || Aes.generateIv();
  }

  static generateIv(): Buffer {
    return randomBytes(Aes.blockSize);
  }

  static fromJson(json: { iv: string }): Aes {
    return new Aes(Buffer.from(json.iv, 'hex'));
  }

  encrypt(plainText: Buffer, key: Buffer): Buffer {
    const cipher = createCipheriv('aes-256-cbc', key, this.iv);
    const amountPadded = (Aes.blockSize - ((plainText.length + 1) % Aes.blockSize)) % Aes.blockSize;
    const paddedBytes = Buffer.concat([Buffer.from([amountPadded]), plainText, Buffer.alloc(amountPadded)]);
    return Buffer.concat([cipher.update(paddedBytes), cipher.final()]);
  }

  decrypt(cipherText: Buffer, key: Buffer): Buffer {
    const decipher = createDecipheriv('aes-256-cbc', key, this.iv);
    const preImage = Buffer.concat([decipher.update(cipherText), decipher.final()]);
    const paddedAmount = preImage[0];
    return preImage.slice(1, preImage.length - paddedAmount);
  }

  toJson(): { iv: string } {
    return { iv: this.iv.toString('hex') };
  }
}

export class AesParams {
  private iv: Buffer;

  constructor(iv: Buffer) {
    this.iv = iv;
  }

  static generate(): AesParams {
    return new AesParams(Aes.generateIv());
  }

  static fromJson(json: { iv: string }): AesParams {
    return new AesParams(Buffer.from(json.iv, 'hex'));
  }

  toJson(): { iv: string } {
    return { iv: this.iv.toString('hex') };
  }
}
