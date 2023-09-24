import { Digest } from './digest/digest';
import { Blake2b256, Blake2b512 } from './blake2B';
import { SHA256, SHA512 } from './sha';

export type Message = Uint8Array;

export { blake2b256, blake2b512, sha256, sha512 };

export abstract class Hash {
  abstract hash(bytes: Uint8Array): Uint8Array;

  abstract hashComplex(options: { prefix?: number; messages: Message[] }): Digest;

  hashWithPrefix(prefix: number, messages: Message[]): Digest {
    return this.hashComplex({ prefix, messages });
  }

  hashMessage(message: Uint8Array): Digest {
    return this.hashComplex({ messages: [message] });
  }
}

const blake2b256 = new Blake2b256();
const blake2b512 = new Blake2b512();
const sha256 = new SHA256();
const sha512 = new SHA512();