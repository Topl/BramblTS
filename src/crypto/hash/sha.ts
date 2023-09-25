import * as crypto from 'crypto';
import { Digest, Digest32, Digest64 } from './digest/digest';
import { Hash, Message } from './baseHash';

abstract class SHA extends Hash {
  abstract hash(bytes: Uint8Array): Uint8Array;
  abstract hashComplex(options: { prefix?: number; messages: Message[] }): Digest;
}

export class SHA256 extends SHA {
  hash(bytes: Uint8Array): Uint8Array {
    const hash = crypto.createHash('sha256');
    return hash.update(bytes).digest();
  }

  hashComplex(options: { prefix?: number; messages: Message[] }): Digest {
    const hash = crypto.createHash('sha256');
    let input: Uint8Array[] = [];
    if (options.prefix !== undefined) {
      input.push(new Uint8Array([options.prefix]));
    }
    input = input.concat(options.messages);

    const flattened: number[] = [];
    input.forEach((arr) => {
      flattened.push(...arr);
    });

    const result = hash.update(new Uint8Array(flattened)).digest();

    const digestResult = Digest32.from(result);

    if (digestResult.kind === 'Right') {
      return digestResult.value;
    } else {
      throw digestResult.value;
    }
  }
}

export class SHA512 extends SHA {
  hash(bytes: Uint8Array): Uint8Array {
    const hash = crypto.createHash('sha512');
    return hash.update(bytes).digest();
  }

  hashComplex(options: { prefix?: number; messages: Message[] }): Digest {
    const hash = crypto.createHash('sha512');
    let input: Uint8Array[] = [];
    if (options.prefix !== undefined) {
      input.push(new Uint8Array([options.prefix]));
    }
    input = input.concat(options.messages);

    const flattened: number[] = [];
    input.forEach((arr) => {
      flattened.push(...arr);
    });

    const result = hash.update(new Uint8Array(flattened)).digest();

    const digestResult = Digest64.from(result);

    if (digestResult.kind === 'Right') {
      return digestResult.value;
    } else {
      throw digestResult.value;
    }
  }
}
