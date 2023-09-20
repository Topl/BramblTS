import { Either, EitherException } from '@/common/either.js';

class Digest {
  constructor(public readonly bytes: Uint8Array) {}

  static empty(): Digest {
    return new Digest(new Uint8Array(0));
  }

  equals(other: Digest): boolean {
    return this.bytes.length === other.bytes.length && this.bytes.every((value, index) => value === other.bytes[index]);
  }

  getHashCode(): number {
    return this.bytes.reduce((acc, byte) => acc + byte, 0);
  }
}

class Digest32 {
  private static readonly size: number = 32;

  private constructor() {}

  static from(bytes: Uint8Array): Either<InvalidDigestFailure, Digest> {
    if (bytes.length !== this.size) {
      return { kind: 'Left', value: new InvalidDigestFailure(`Invalid digest size: ${bytes.length}`) };
    }
    return { kind: 'Right', value: new Digest(bytes) };
  }
}

class Digest64 {
  private static readonly size: number = 64;

  private constructor() {}

  static from(bytes: Uint8Array): Either<InvalidDigestFailure, Digest> {
    if (bytes.length !== this.size) {
      return { kind: 'Left', value: new InvalidDigestFailure(`Invalid digest size: ${bytes.length}`) };
    }
    return { kind: 'Right', value: new Digest(bytes) };
  }
}

class InvalidDigestFailure extends EitherException {
  constructor(message: string) {
    super(message);
  }
}
