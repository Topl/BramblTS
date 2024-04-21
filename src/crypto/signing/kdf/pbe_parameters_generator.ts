/* eslint-disable @typescript-eslint/no-unused-vars */
import { CipherParameters } from './cipherParameters.js';

/**
 * Super class for all Password Based Encryption (PBE) parameter generator classes.
 * Port from Bouncy Castle Java.
 */
export abstract class PBEParametersGenerator {
  protected password!: Uint8Array;
  protected salt!: Uint8Array;
  protected iterationCount!: number;

  /**
   * Initialise the PBE generator.
   * 
   * @param password - The password converted into bytes.
   * @param salt - The salt to be mixed with the password.
   * @param iterationCount - The number of iterations the "mixing" function is to be applied for.
   */
  init(password: Uint8Array, salt: Uint8Array, iterationCount: number): void {
    this.password = password;
    this.salt = salt;
    this.iterationCount = iterationCount;
  }

  /**
   * Generate derived parameters for a key of length keySize.
   * 
   * @param keySize - The length, in bits, of the key required.
   */
  abstract generateDerivedParameters(keySize: number): CipherParameters;

  /**
   * Generate derived parameters for a key of length keySize, and
   * an initialisation vector (IV) of length ivSize.
   * 
   * @param keySize - The length, in bits, of the key required.
   * @param ivSize - The length, in bits, of the iv required.
   */
  abstract generateDerivedParametersWithIV(keySize: number, ivSize: number): CipherParameters;

  /**
   * Generate derived parameters for a key of length keySize, specifically
   * for use with a MAC.
   * 
   * @param keySize - The length, in bits, of the key required.
   */
  abstract generateDerivedMacParameters(keySize: number): CipherParameters;

  /**
   * Converts a password to a byte array according to the scheme in
   * PKCS5 (ascii, no padding).
   * 
   * @param password - A character array representing the password.
   */
  static pkcs5PasswordToBytes(password: string | null): Uint8Array {
    if (password && password.length > 0) {
      const pw = password.split('').map((char) => char.charCodeAt(0) & 0xff);
      const bytes = new Uint8Array(pw.length);

      for (let i = 0; i < bytes.length; i++) {
        bytes[i] = pw[i] & 0xff;
      }

      return bytes;
    } else {
      return new Uint8Array(0);
    }
  }

  /**
   * Converts a password to a byte array according to the scheme in
   * PKCS5 (UTF-8, no padding).
   * 
   * @param password - A character array representing the password.
   */
  static pkcs5PasswordToUTF8Bytes(password: string): Uint8Array {
    if (password.length > 0) {
      const encoder = new TextEncoder();
      return encoder.encode(password);
    } else {
      return new Uint8Array(0);
    }
  }

  /**
   * Converts a password to a byte array according to the scheme in
   * PKCS12 (unicode, big endian, 2 zero pad bytes at the end).
   * 
   * @param password - A character array representing the password.
   */
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
