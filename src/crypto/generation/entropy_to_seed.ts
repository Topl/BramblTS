import { pbkdf2Sync } from 'crypto';
import { Entropy } from './mnemonic/entropy.js';

/**
 * Abstract class defining a method to convert entropy to a seed.
 */
export abstract class EntropyToSeed {
  constructor() {}

  /**
   * Converts entropy to a seed using a key derivation function.
   *
   * @param entropy The entropy value.
   * @param password Optional password for the key derivation function.
   * @param seedLength The desired length of the seed.
   * @returns A Uint8Array representing the generated seed.
   */
  toSeed(entropy: Entropy, password: string | null, seedLength: number): Uint8Array {
    const kdf = new Pbkdf2Sha512();
    return kdf.generateKey(password ?? '', entropy.value, seedLength, 4096);
  }
}

/**
 * PBKDF-SHA512 defines a function for creating a key from a password and salt.
 * It repeats the HMAC-SHA512 hashing function a given number of iterations and then slices a number of bytes off the result.
 */
export class Pbkdf2Sha512 extends EntropyToSeed {
  constructor() {
    super();
  }

  /**
   * Generates a key from the given password and salt.
   *
   * @param password The password used to create the key.
   * @param salt The salt applied to the key.
   * @param keySizeBytes The size of the key in bytes.
   * @param iterations The number of iterations to run the HMAC-SHA512 hashing function.
   * @returns A Uint8Array of the generated key.
   */
  generateKey(password: string, salt: Uint8Array, keySizeBytes: number, iterations: number): Uint8Array {
    const deriveKey = pbkdf2Sync(password, salt, iterations, keySizeBytes, 'sha512');
    return Uint8Array.from(deriveKey);
  }
}
