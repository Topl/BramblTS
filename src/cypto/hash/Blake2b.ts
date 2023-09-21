import { Digest32 } from './digest/digest.js';
// import { Digest, Message, InvalidDigestFailure } from './path/to/your/dependencies';
// import { Blake2bDigest } from 'path/to/pointycastle/digests/blake2b';

abstract class Hash {
  abstract hash(bytes: Uint8Array): Uint8Array;

  abstract hashComplex(options: { prefix?: number, messages: Message[] }): Digest;
}

abstract class Blake2b extends Hash {
  abstract hash(bytes: Uint8Array): Uint8Array;
  abstract hashComplex(options: { prefix?: number, messages: Message[] }): Digest;
}

class Blake2b256 extends Blake2b {
  private readonly _digest: Blake2bDigest;

  constructor() {
    super();
    this._digest = new Blake2bDigest(Digest32.size);
  }

  hash(bytes: Uint8Array): Uint8Array {
    const out = new Uint8Array(this._digest.digestSize);
    this._digest.update(bytes, 0, bytes.length);
    this._digest.doFinal(out, 0);
    return out;
  }

  hashComplex({ prefix, messages }: { prefix?: number, messages: Message[] }): Digest {
    if (prefix !== undefined) {
      for (const byte of [prefix]) {
        this._digest.updateByte(byte);
      }
    }

    for (const m of messages) {
      this._digest.update(m, 0, m.length);
    }

    const res = new Message(this._digest.digestSize);
    this._digest.doFinal(res, 0);

    const x = Digest32.from(res);
    if (x.isLeft) {
      throw new Error(x.left!.message);
    }

    return x.right!;
  }
}

class Blake2b512 extends Blake2b {
  private readonly _digest: Blake2bDigest;

  constructor() {
    super();
    this._digest = new Blake2bDigest(Digest64.size);
  }

  hash(bytes: Uint8Array): Uint8Array {
    const out = new Uint8Array(this._digest.digestSize);
    this._digest.update(bytes, 0, bytes.length);
    this._digest.doFinal(out, 0);
    return out;
  }

  hashComplex({ prefix, messages }: { prefix?: number, messages: Message[] }): Digest {
    if (prefix !== undefined) {
      this._digest.update([prefix], 0, 1);
    }

    for (const m of messages) {
      this._digest.update(m, 0, m.length);
    }

    const res = new Message(this._digest.digestSize);
    this._digest.doFinal(res, 0);

    const x = Digest64.from(res);
    if (x.isLeft) {
      throw new Error(x.left!.message);
    }

    return x.right!;
  }
}

export { Blake2b256, Blake2b512 };
