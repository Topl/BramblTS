import { Digest, Digest32, Digest64 } from './digest/digest';
import { Hash, Message } from './hash';
import * as blake from 'blakejs';

abstract class Blake2b extends Hash {
  abstract hash(bytes: Uint8Array): Uint8Array;
  abstract hashComplex(options: { prefix?: number; messages: Message[] }): Digest;
}

export class Blake2b256 extends Blake2b {
  hash(bytes: Uint8Array): Uint8Array {
    return blake.blake2b(bytes, undefined, 32);
  }

  hashComplex({ prefix, messages }: { prefix?: number; messages: Message[] }): Digest {
    let input: Uint8Array[] = [];
    if (prefix) {
      input.push(new Uint8Array([prefix]));
    }
    input = input.concat(messages);

    let flattened: number[] = [];
    input.forEach((arr) => {
      flattened.push(...arr);
    });

    const result = blake.blake2b(new Uint8Array(flattened), undefined, 32);

    const digestResult = Digest32.from(result);

    if (digestResult.kind === 'Right') {
      return digestResult.value;
    } else {
      throw digestResult.value;
    }
  }
}

export class Blake2b512 extends Blake2b {
  hash(bytes: Uint8Array): Uint8Array {
    return blake.blake2b(bytes, undefined, 64);
  }

  hashComplex({ prefix, messages }: { prefix?: number; messages: Message[] }): Digest {
    let input: Uint8Array[] = [];
    if (prefix) {
      input.push(new Uint8Array([prefix]));
    }
    input = input.concat(messages);

    let flattened: number[] = [];
    input.forEach((arr) => {
      flattened.push(...arr);
    });

    const result = blake.blake2b(new Uint8Array(flattened), undefined, 64);

    const digestResult = Digest64.from(result);

    if (digestResult.kind === 'Right') {
      return digestResult.value;
    } else {
      throw digestResult.value;
    }
  }
}
