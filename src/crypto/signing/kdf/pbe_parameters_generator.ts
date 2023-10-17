import { CipherParameters } from './cipherParameters';

abstract class PBEParametersGenerator {
  protected password: Uint8Array;
  protected salt: Uint8Array;
  protected iterationCount: number;

  public init(password: Uint8Array, salt: Uint8Array, iterationCount: number): void {
    this.password = password;
    this.salt = salt;
    this.iterationCount = iterationCount;
  }

  public abstract generateDerivedParameters(keySize: number): CipherParameters;

  public abstract generateDerivedParametersWithIV(keySize: number, ivSize: number): CipherParameters;

  public abstract generateDerivedMacParameters(keySize: number): CipherParameters;

  public static pkcs5PasswordToBytes(password: string | null): Uint8Array {
    if (password !== null && password !== '') {
      const pw = password.split('').map((char) => char.charCodeAt(0));
      const bytes = new Uint8Array(pw.length);

      for (let i = 0; i < bytes.length; i++) {
        bytes[i] = pw[i] & 0xff;
      }

      return bytes;
    } else {
      return new Uint8Array(0);
    }
  }

  public static pkcs5PasswordToUTF8Bytes(password: string): Uint8Array {
    if (password !== '') {
      const encoder = new TextEncoder();
      return encoder.encode(password);
    } else {
      return new Uint8Array(0);
    }
  }

  public static pkcs12PasswordToBytes(password: string | null): Uint8Array {
    if (password !== null && password !== '') {
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
