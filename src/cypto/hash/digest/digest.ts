import { Either, EitherException } from "@/common/either.js";

class Digest {
  constructor(public readonly bytes: Uint8Array) { }

  static empty(): Digest {
    return new Digest(new Uint8Array(0));
  }

  equals(other: Digest): boolean {
    return this.bytes.length === other.bytes.length && 
           this.bytes.every((value, index) => value === other.bytes[index]);
  }

  getHashCode(): number {
    return this.bytes.reduce((acc, byte) => acc + byte, 0);
  }
}

class InvalidDigestFailure extends EitherException {
  constructor(message: string) {
    super(message);
  }
}
