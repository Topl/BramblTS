import * as crypto from 'crypto';
import { Digest, Digest32, Digest64 } from './digest/digest';
import { Hash, Message } from './baseHash';

abstract class SHA extends Hash {
  abstract algorithmName(): string;
  abstract digestSize(): number;
  abstract hash(bytes: Uint8Array): Uint8Array;
  abstract hashComplex(options: { prefix?: number; messages: Message[] }): Digest;
  abstract updateByte(inp: Uint8Array): void;
  abstract update(inp: Uint8Array, inpOff: number, len: number): void;
  abstract doFinal(out: Uint8Array, inp: number): number;
}

export class SHA256 extends SHA {
  digest = crypto.createHash('sha256');
  hashDigest!: Uint8Array;

  algorithmName(): string {
    return 'SHA-256';
  }

  digestSize(): number {
    return 32;
  }

  doFinal(out: Uint8Array, inp: number): number {
    const hashBuffer = this.digest.digest();

    hashBuffer.copy(out, inp);
    // Reset the hash object for future use
    this.digest = crypto.createHash('sha256');
    return out.length;
  }

  updateByte(inp: Uint8Array): void {
    this.digest.update(inp);
  }

  update(inp: Uint8Array, inpOff: number, len: number): void {
    this.updateByte(inp.slice(inpOff, inpOff + len));
  }

  hash(bytes: Uint8Array): Uint8Array {
    let out = new Uint8Array(this.digestSize());
    this.update(bytes, 0, bytes.length);
    this.doFinal(out, 0);
    return out;
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

  algorithmName(): string {
    return 'SHA-512';
  }

  digestSize(): number {
    return 64;
  }

  doFinal(out: Uint8Array, inp: number): number {
    const hashBuffer = this.digest.digest();

    hashBuffer.copy(out, inp);
    // Reset the hash object for future use
    this.digest = crypto.createHash('sha256');
    return out.length;
  }

  updateByte(inp: Uint8Array): void {
    this.digest.update(inp);
  }

  update(inp: Uint8Array, inpOff: number, len: number): void {
    this.updateByte(inp.slice(inpOff, inpOff + len));
  }

  hash(bytes: Uint8Array): Uint8Array {
    let out = new Uint8Array(this.digestSize());
    this.update(bytes, 0, bytes.length);
    this.doFinal(out, 0);
    return out;
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
