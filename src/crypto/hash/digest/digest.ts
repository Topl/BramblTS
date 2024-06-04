/* eslint-disable @typescript-eslint/no-explicit-any */

export class Digest {
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

export class Digest32 {
  static readonly size: number = 32;

  private constructor() {}

  static from(bytes: Uint8Array): any {
    if (bytes.length !== this.size) {
      return { kind: 'Left', value: new InvalidDigestFailure(`Invalid digest size: ${bytes.length}`) };
    }
    return { kind: 'Right', value: new Digest(bytes) };
  }
}

export class Digest64 {
  static readonly size: number = 64;

  private constructor() {}

  static from(bytes: Uint8Array): any {
    if (bytes.length !== this.size) {
      return { kind: 'Left', value: new InvalidDigestFailure(`Invalid digest size: ${bytes.length}`) };
    }
    return { kind: 'Right', value: new Digest(bytes) };
  }
}

export class InvalidDigestFailure extends Error {
  constructor(
    message?: string,
    public readonly originalError?: Error,
  ) {
    super(message);
    Object.setPrototypeOf(this, new.target.prototype);
  }
}
