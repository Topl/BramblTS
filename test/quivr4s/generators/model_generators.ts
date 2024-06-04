import { Digest32 } from '@/crypto/hash/digest/digest.js';

export class ModelGenerators {
  genSizedStrictByteString(n: number, random?: () => number): number[] {
    const byteGen = random ? random() : Math.floor(Math.random() * 32);
    const bytes = Array.from({ length: n }, () => byteGen);
    return bytes;
  }

  arbitraryDigest(): Digest32 {
    const byteString = this.genSizedStrictByteString(32);
    return Digest32.from(new Uint8Array(byteString));
  }
}
