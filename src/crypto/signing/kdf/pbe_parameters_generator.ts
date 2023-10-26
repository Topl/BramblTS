/* eslint-disable @typescript-eslint/no-unused-vars */
import { CipherParameters } from './cipherParameters';

export class PBEParametersGenerator {
  protected password: Uint8Array;
  protected salt: Uint8Array;
  protected iterationCount: number;

  init(password: Uint8Array, salt: Uint8Array, iterationCount: number): void {
    this.password = password;
    this.salt = salt;
    this.iterationCount = iterationCount;
  }

  generateDerivedParameters(keySize: number): CipherParameters {
    throw new Error('Method not implemented.');
  }

  generateDerivedParametersWithIV(keySize: number, ivSize: number): CipherParameters {
    throw new Error('Method not implemented.');
  }

  generateDerivedMacParameters(keySize: number): CipherParameters;

  static pkcs5PasswordToBytes(password: string | null): Uint8Array {
    if (password && password.length > 0) {
      const pw = password.split('').map((char) => char.charCodeAt(0) & 0xff);
      // const bytes = new Uint8Array(pw.length);

      // for (let i = 0; i < bytes.length; i++) {
      //   bytes[i] = pw[i] & 0xff;
      // }

      // return bytes;
      return new Uint8Array(pw);
    } else {
      return new Uint8Array(0);
    }
  }

  static pkcs5PasswordToUTF8Bytes(password: string): Uint8Array {
    if (password.length > 0) {
      const encoder = new TextEncoder();
      return encoder.encode(password);
    } else {
      return new Uint8Array(0);
    }
  }

  static pkcs12PasswordToBytes(password: string | null): Uint8Array {
    if (password && password.length > 0) {
      const pw = password.split('').map((char) => char.charCodeAt(0));
      const bytes = new Uint8Array((pw.length + 1) * 2);

      for (let i = 0; i < pw.length; i++) {
        bytes[i * 2] = (pw[i] >> 8) & 0xff;
        bytes[i * 2 + 1] = pw[i] & 0xff;
      }

      return bytes;
    } else {
      return new Uint8Array(0);
    }
  }
}
