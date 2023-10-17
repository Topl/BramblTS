/* eslint-disable @typescript-eslint/no-unused-vars */
import { Either } from '@/common/either';

export interface ExtendedEd25519Spec {
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
  signatureLength: number;
  keyLength: number;
  publicKeyLength: number;
  seedLength: number;
  clampBits(sizedSeed: Uint8Array): SecretKey {
    throw new Error('Method not implemented.');
  }
  edBaseN: bigint;
  validate(value: SecretKey): Either<InvalidDerivedKey, SecretKey> {
    throw new Error('Method not implemented.');
  }
  leftNumber(secretKey: SecretKey): bigint {
    throw new Error('Method not implemented.');
  }
  rightNumber(secretKey: SecretKey): bigint {
    throw new Error('Method not implemented.');
  }
  hmac512WithKey(key: Uint8Array, data: Uint8Array): Uint8Array {
    throw new Error('Method not implemented.');
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
  vk: PublicKey;
  chainCode: Uint8Array;

  constructor(vk: PublicKey, chainCode: Uint8Array) {
    super();
    this.vk = vk;
    this.chainCode = chainCode;

    if (chainCode.length !== this.keyLength) {
      throw new Error(`Invalid chain code length. Expected: ${this.keyLength}, Received: ${chainCode.length}`);
    }
  }
  signatureLength: number;
  keyLength: number;
  publicKeyLength: number;
  seedLength: number;
  clampBits(sizedSeed: Uint8Array): SecretKey {
    throw new Error('Method not implemented.');
  }
  edBaseN: bigint;
  validate(value: SecretKey): Either<InvalidDerivedKey, SecretKey> {
    throw new Error('Method not implemented.');
  }
  leftNumber(secretKey: SecretKey): bigint {
    throw new Error('Method not implemented.');
  }
  rightNumber(secretKey: SecretKey): bigint {
    throw new Error('Method not implemented.');
  }
  hmac512WithKey(key: Uint8Array, data: Uint8Array): Uint8Array {
    throw new Error('Method not implemented.');
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
