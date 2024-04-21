import { Digest } from './digest/digest.js';

export type Message = Uint8Array;

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
