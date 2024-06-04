/* eslint-disable @typescript-eslint/no-explicit-any */
import { Json } from '@/utils/json.js';
import { randomBytes, scryptSync } from 'crypto';
import { Params, type Kdf } from './kdf.js';

/**
 * SCrypt is a key derivation function.
 * @see [https://en.wikipedia.org/wiki/Scrypt]
 */
class SCrypt implements Kdf {
  readonly params: SCryptParams;

  constructor(params: SCryptParams) {
    this.params = params;
  }

  /**
   * Create a SCrypt with generated salt.
   */
  static withGeneratedSalt(): SCrypt {
    return new SCrypt(SCryptParams.withGeneratedSalt());
  }

  /**
   * Create an SCrypt instance from a JSON object.
   * @param json JSON object with SCrypt parameters.
   */
  static fromJson(json: { [key: string]: any }): SCrypt {
    const params = SCryptParams.fromJson(json);
    return new SCrypt(params);
  }

  /**
   * Derive a key from a secret.
   * @param secret Secret to derive key from.
   * @returns Derived key.
   */
  deriveKey(secret: Uint8Array): Buffer {
    const options = new _scryptOptions(this.params.n, this.params.r, this.params.p);
    return scryptSync(secret, this.params.salt, this.params.dkLen, options.toInterface());
  }

  /**
   * Generate a random initialization vector.
   * @returns Randomly generated salt.
   */
  static generateSalt(): Buffer {
    return randomBytes(32);
  }

  /**
   * Converts SCrypt instance to a JSON object.
   * @returns JSON representation of the SCrypt instance.
   */
  toJson(): { [key: string]: any } {
    return { kdf: this.params.kdf, ...this.params.toJson() };
  }
}

/**
 * SCrypt parameters.
 */
class SCryptParams implements Params {
  readonly salt: Uint8Array;
  readonly n: number;
  readonly r: number;
  readonly p: number;
  readonly dkLen: number;

  /**
   * SCrypt parameters constructor.
   * @param salt Salt.
   * @param n CPU/Memory cost parameter. Must be larger than 1, a power of 2 and less than 2^(128 * r / 8). Defaults to 2^18.
   * @param r Block size. Must be >= 1. Defaults to 8.
   * @param p Parallelization parameter. Must be a positive integer less than or equal to Integer.MAX_VALUE / (128 * r * 8). Defaults to 1.
   * @param dkLen Length of derived key. Defaults to 32.
   */
  constructor(salt: Uint8Array, n: number = 262144, r: number = 8, p: number = 1, dkLen: number = 32) {
    this.salt = salt;
    this.n = n;
    this.r = r;
    this.p = p;
    this.dkLen = dkLen;
  }

  /**
   * Create SCryptParams with generated salt.
   */
  static withGeneratedSalt(): SCryptParams {
    return new SCryptParams(SCrypt.generateSalt());
  }

  /**
   * Create SCryptParams from a JSON object.
   * @param json JSON object with SCrypt parameters.
   */
  static fromJson(json: { [key: string]: any }): SCryptParams {
    const saltUint8Array = Json.decodeUint8List(json['salt']);
    const salt = Buffer.from(saltUint8Array);
    const n = json['n'];
    const r = json['r'];
    const p = json['p'];
    const dkLen = json['dkLen'];
    return new SCryptParams(salt, n, r, p, dkLen);
  }

  /**
   * Get the key derivation function name.
   * @returns Name of the key derivation function.
   */
  get kdf(): string {
    return 'scrypt';
  }

  /**
   * Converts SCryptParams to a JSON object.
   * @returns JSON representation of the SCrypt parameters.
   */
  toJson(): { [key: string]: any } {
    return {
      salt: Json.encodeUint8List(this.salt),
      n: this.n,
      r: this.r,
      p: this.p,
      dkLen: this.dkLen,
    };
  }
}

/// helper interface for working with scrypt
class _scryptOptions {
  N: number;
  r: number;
  p: number;
  maxmem: number;

  constructor(N: number, r: number, p: number) {
    this.N = N;
    this.r = r;
    this.p = p;
    this.maxmem = 128 * p * r + 128 * (2 + N) * r;
    /// Long story, the node developers decided to not calculate this value automatically dependent pm the N and R values
    ///  The node crypto library states:`maxmem` {number} Memory upper bound. It is an error when (approximately)
    /// `128*N*r > maxmem` **Default:** `32 * 1024 * 1024`.
    /// We've adapted this so there's some extra room otherwise the scrypt function will throw an error
    /// relevant thread: [https://github.com/nodejs/node/issues/21524]
  }

  /**
   * Converts _scryptOptions to a JSON object.
   * @returns JSON representation of the _scryptOptions instance.
   */
  toInterface() {
    return {
      N: this.N,
      r: this.r,
      p: this.p,
      maxmem: this.maxmem,
    };
  }
}

export { SCrypt, SCryptParams };
