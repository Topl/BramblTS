// import { Digest, Message, InvalidDigestFailure } from './path/to/your/dependencies';
// import * as pc from 'path/to/pointycastle/api';
// import { SHA256Digest, SHA512Digest } from 'path/to/pointycastle/digests';

abstract class Hash {
  protected abstract _digest: pc.Digest;

  abstract hash(bytes: Uint8Array): Uint8Array;

  get algorithmName(): string {
    return this._digest.algorithmName;
  }

  get digestSize(): number {
    return this._digest.digestSize;
  }

  reset(): void {
    this._digest.reset();
  }

  updateByte(inp: number): void {
    this._digest.updateByte(inp);
  }

  update(inp: Uint8Array, inpOff: number, len: number): void {
    this._digest.update(inp, inpOff, len);
  }

  doFinal(out: Uint8Array, outOff: number): number {
    return this._digest.doFinal(out, outOff);
  }

  abstract hashComplex(options: { prefix?: number, messages: Message[] }): Digest;
}

abstract class SHA extends Hash {}

class SHA256 extends SHA {
  private readonly _digest: pc.Digest = new SHA256Digest();

  hash(bytes: Uint8Array): Uint8Array {
    const out = new Uint8Array(this.digestSize);
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

    const res = new Message(this.digestSize);
    this._digest.doFinal(res, 0);

    const x = Digest32.from(res);
    if (x.isLeft) {
      throw new Error(x.left!.message);
    }

    return x.right!;
  }
}

class SHA512 extends SHA {
  private readonly _digest: pc.Digest = new SHA512Digest();

  hash(bytes: Uint8Array): Uint8Array {
    const out = new Uint8Array(this.digestSize);
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

    const res = new Message(this.digestSize);
    this._digest.doFinal(res, 0);

    const x = Digest64.from(res);
    if (x.isLeft) {
      throw new Error(x.left!.message);
    }

    return x.right!;
  }
}
