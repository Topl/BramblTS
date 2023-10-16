import { Either } from "@/common/either";

interface ExtendedEd25519Spec {
  signatureLength: number;
  keyLength: number;
  publicKeyLength: number;
  seedLength: number;
  clampBits(sizedSeed: Uint8Array): SecretKey;
  edBaseN: bigint;
  validate(value: SecretKey): Either<InvalidDerivedKey, SecretKey>;
  leftNumber(secretKey: SecretKey): bigint;
  rightNumber(secretKey: SecretKey): bigint;
  hmac512WithKey(key: Uint8Array, data: Uint8Array): Uint8Array;
}

class SecretKey extends SigningKey implements ExtendedEd25519Spec {
  leftKey: Uint8Array;
  rightKey: Uint8Array;
  chainCode: Uint8Array;

  constructor(leftKey: Uint8Array, rightKey: Uint8Array, chainCode: Uint8Array) {
    super();
    this.leftKey = leftKey;
    this.rightKey = rightKey;
    this.chainCode = chainCode;

    if (leftKey.length !== this.keyLength) {
      throw new Error(`Invalid left key length. Expected: ${this.keyLength}, Received: ${leftKey.length}`);
    }

    if (rightKey.length !== this.keyLength) {
      throw new Error(`Invalid right key length. Expected: ${this.keyLength}, Received: ${rightKey.length}`);
    }

    if (chainCode.length !== this.keyLength) {
      throw new Error(`Invalid chain code length. Expected: ${this.keyLength}, Received: ${chainCode.length}`);
    }
  }

  static proto(sk: pb.SigningKey_ExtendedEd25519Sk): SecretKey {
    return new SecretKey(sk.leftKey as Uint8Array, sk.rightKey as Uint8Array, sk.chainCode as Uint8Array);
  }

  equals(other: SecretKey): boolean {
    return (
      arrayEquals(this.leftKey, other.leftKey) &&
      arrayEquals(this.rightKey, other.rightKey) &&
      arrayEquals(this.chainCode, other.chainCode)
    );
  }
}

class PublicKey extends VerificationKey implements ExtendedEd25519Spec {
  vk: spec.PublicKey;
  chainCode: Uint8Array;

  constructor(vk: spec.PublicKey, chainCode: Uint8Array) {
    super();
    this.vk = vk;
    this.chainCode = chainCode;

    if (chainCode.length !== this.keyLength) {
      throw new Error(`Invalid chain code length. Expected: ${this.keyLength}, Received: ${chainCode.length}`);
    }
  }

  static proto(vk: pb.VerificationKey_ExtendedEd25519Vk): PublicKey {
    return new PublicKey(new spec.PublicKey((vk.vk as pb.BytesValue).value as Uint8Array), vk.chainCode as Uint8Array);
  }

  equals(other: PublicKey): boolean {
    return this.vk.equals(other.vk) && arrayEquals(this.chainCode, other.chainCode);
  }
}

class InvalidDerivedKey extends Error {}

// Helper function for array comparison
function arrayEquals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// Define BigInt in TypeScript
declare interface BigInt {
  toString(radix?: number): string;
}

declare var BigInt: {
  (value: number): bigint;
  (value: string): bigint;
  new (value: number): bigint;
  new (value: string): bigint;
  readonly prototype: bigint;
};
