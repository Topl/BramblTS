import * as crypto from 'crypto';
import { Digest, Digest32, Digest64 } from './digest/digest.js';
import { Hash, type Message } from './baseHash.js';

/**
 * An abstract class for SHA hash functions.
 */
abstract class SHA extends Hash {
  /**
   * Gets this algorithm's standard name.
   * @returns The name of the algorithm.
   */
  abstract algorithmName(): string;
  /**
   * Gets this digest's output size in bytes.
   * @returns The size of the digest.
   */
  abstract digestSize(): number;
  /**
   * Adds one byte of data to the digested input.
   * @param inp The input byte array.
   */
  abstract updateByte(inp: Uint8Array): void;
  /**
   * Adds data to the digested input.
   * @param inp The input byte array.
   * @param inpOff The offset within the array.
   * @param len The length of the data to add.
   */
  abstract update(inp: Uint8Array, inpOff: number, len: number): void;
  /**
   * Completes the hash computation and stores the result in the output array.
   * @param out The output array to store the digest.
   * @param outOff The offset within the output array.
   * @returns The size of the digest.
   */
  abstract doFinal(out: Uint8Array, inp: number): number;
  abstract override hash(bytes: Uint8Array): Uint8Array;
  abstract override hashComplex(options: { prefix?: number; messages: Message[] }): Digest;
}

/**
 * Computes the SHA-256 (32-byte) hash of a list of bytes.
 */
export class SHA256 extends SHA {
  digest = crypto.createHash('sha256');
  hashDigest!: Uint8Array;

  algorithmName (): string {
    return 'SHA-256';
  }

  digestSize (): number {
    return 32;
  }

  updateByte (inp: Uint8Array): void {
    this.digest.update(inp);
  }

  update (inp: Uint8Array, inpOff: number, len: number): void {
    this.updateByte(inp.slice(inpOff, inpOff + len));
  }

  doFinal (out: Uint8Array, inp: number): number {
    const hashBuffer = this.digest.digest();

    hashBuffer.copy(out, inp);
    // Reset the hash object for future use
    this.digest = crypto.createHash('sha256');
    return out.length;
  }

  hash (bytes: Uint8Array): Uint8Array {
    const out = new Uint8Array(this.digestSize());
    this.update(bytes, 0, bytes.length);
    this.doFinal(out, 0);
    return out;
  }

  hashComplex (options: { prefix?: number; messages: Message[] }): Digest {
    let input: Uint8Array[] = [];
    if (options.prefix !== undefined) {
      input.push(new Uint8Array([options.prefix]));
    }
    input = input.concat(options.messages);

    const flattened: number[] = [];
    input.forEach(arr => {
      flattened.push(...arr);
    });

    const result = this.hash(new Uint8Array(flattened));

    const digestResult = Digest32.from(result);

    if (digestResult.kind === 'Right') {
      return digestResult.value;
    } else {
      throw digestResult.value;
    }
  }
}

/**
 * Computes the SHA-512 (64-byte) hash of a list of bytes.
 */
export class SHA512 extends SHA {
  digest = crypto.createHash('sha512');
  hashDigest!: Uint8Array;

  algorithmName (): string {
    return 'SHA-512';
  }

  digestSize (): number {
    return 64;
  }

  updateByte (inp: Uint8Array): void {
    this.digest.update(inp);
  }

  update (inp: Uint8Array, inpOff: number, len: number): void {
    this.updateByte(inp.slice(inpOff, inpOff + len));
  }

  doFinal (out: Uint8Array, inp: number): number {
    const hashBuffer = this.digest.digest();

    hashBuffer.copy(out, inp);
    // Reset the hash object for future use
    this.digest = crypto.createHash('sha512');
    return out.length;
  }

  hash (bytes: Uint8Array): Uint8Array {
    const out = new Uint8Array(this.digestSize());
    this.update(bytes, 0, bytes.length);
    this.doFinal(out, 0);
    return out;
  }

  hashComplex (options: { prefix?: number; messages: Message[] }): Digest {
    let input: Uint8Array[] = [];
    if (options.prefix !== undefined) {
      input.push(new Uint8Array([options.prefix]));
    }
    input = input.concat(options.messages);

    const flattened: number[] = [];
    input.forEach(arr => {
      flattened.push(...arr);
    });

    const result = this.hash(new Uint8Array(flattened));

    const digestResult = Digest64.from(result);

    if (digestResult.kind === 'Right') {
      return digestResult.value;
    } else {
      throw digestResult.value;
    }
  }
}
