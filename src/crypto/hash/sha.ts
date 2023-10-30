import * as crypto from 'crypto';
import { Digest, Digest32, Digest64 } from './digest/digest';
import { Hash, Message } from './baseHash';

abstract class SHA extends Hash {
  abstract hash(bytes: Uint8Array): Uint8Array;
  abstract hashComplex(options: { prefix?: number; messages: Message[] }): Digest;
  // Flag to track finalization
  protected finalized: boolean = false;

  abstract updateByte(inp: Uint8Array): void;
  abstract update(inp: Uint8Array, inpOff: number, len: number): void;
  abstract doFinal(): Uint8Array;
}

export class SHA256 extends SHA {
  digest = crypto.createHash('sha256');
  hashDigest!: Uint8Array;

  doFinal(): Uint8Array {
    if (this.finalized) {
      throw new Error('Instance has already been finalized.');
    }
    this.finalized = true;
    return this.digest.digest();
  }

  isFinalized(): boolean {
    return this.finalized;
  }

  updateByte(inp: Uint8Array): void {
    if (this.finalized) {
      throw new Error('Instance has been finalized and cannot be updated.');
    }
    this.digest.update(inp);
  }

  update(inp: Uint8Array, inpOff: number, len: number): void {
    if (this.finalized) {
      throw new Error('Instance has been finalized and cannot be updated.');
    }
    this.updateByte(inp.slice(inpOff, inpOff + len));
  }

  hash(bytes: Uint8Array): Uint8Array {
    if (this.finalized) {
      throw new Error('Instance has been finalized and cannot be used for hashing.');
    }
    this.update(bytes, 0, bytes.length);
    return this.doFinal();
  }

  hashComplex(options: { prefix?: number; messages: Message[] }): Digest {
    let input: Uint8Array[] = [];
    if (options.prefix !== undefined) {
      input.push(new Uint8Array([options.prefix]));
    }
    input = input.concat(options.messages);

    const flattened: number[] = [];
    input.forEach((arr) => {
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

export class SHA512 extends SHA {
  digest = crypto.createHash('sha512');
  hashDigest!: Uint8Array;

  doFinal(): Uint8Array {
    if (this.finalized) {
      throw new Error('Instance has already been finalized.');
    }
    this.finalized = true;
    return this.digest.digest();
  }

  isFinalized(): boolean {
    return this.finalized;
  }

  updateByte(inp: Uint8Array): void {
    if (this.finalized) {
      throw new Error('Instance has been finalized and cannot be updated.');
    }
    this.digest.update(inp);
  }

  update(inp: Uint8Array, inpOff: number, len: number): void {
    if (this.finalized) {
      throw new Error('Instance has been finalized and cannot be updated.');
    }
    this.updateByte(inp.slice(inpOff, inpOff + len));
  }

  hash(bytes: Uint8Array): Uint8Array {
    if (this.finalized) {
      throw new Error('Instance has been finalized and cannot be used for hashing.');
    }
    this.update(bytes, 0, bytes.length);
    return this.doFinal();
  }

  hashComplex(options: { prefix?: number; messages: Message[] }): Digest {
    let input: Uint8Array[] = [];
    if (options.prefix !== undefined) {
      input.push(new Uint8Array([options.prefix]));
    }
    input = input.concat(options.messages);

    const flattened: number[] = [];
    input.forEach((arr) => {
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
