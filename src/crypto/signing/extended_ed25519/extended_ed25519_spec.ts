/* eslint-disable @typescript-eslint/no-unused-vars */
import { createHmac } from 'crypto';
import * as spec from '../ed25519/ed25519_spec';

interface Either<L, R> {
  isLeft: boolean;
  leftValue?: L;
  rightValue?: R;
}

class InvalidDerivedKey implements Error {
  name: string;
  message: string;
  stack?: string;
}

export class ExtendedEd25519Spec {
  static readonly signatureLength: number = 64;
  static readonly keyLength: number = 32;
  static readonly publicKeyLength: number = 32;
  static readonly seedLength: number = 96;

  static clampBits(sizedSeed: Uint8Array): SecretKey {
    const seed = new Uint8Array(sizedSeed);

    // turn seed into a valid ExtendedPrivateKeyEd25519 per the SLIP-0023 Icarus spec
    seed[0] = seed[0] & 0xf8;
    seed[31] = (seed[31] & 0x1f) | 0x40;

    return new SecretKey(seed.slice(0, 32), seed.slice(32, 64), seed.slice(64, 96));
  }

  static readonly edBaseN: bigint = BigInt(
    '7237005577332262213973186563042994240857116359379907606001950938285454250989',
  );

  static validate(value: SecretKey): Either<InvalidDerivedKey, SecretKey> {
    return {
      isLeft: ExtendedEd25519Spec.leftNumber(value) % ExtendedEd25519Spec.edBaseN !== BigInt(0),
      rightValue: value,
    };
  }

  static leftNumber(secretKey: SecretKey): bigint {
    return BigInt(`0x${Buffer.from(secretKey.leftKey).toString('hex')}`);
  }

  static rightNumber(secretKey: SecretKey): bigint {
    return BigInt(`0x${Buffer.from(secretKey.rightKey).toString('hex')}`);
  }

  static hmac512WithKey(key: Uint8Array, data: Uint8Array): Uint8Array {
    const hmac = createHmac('sha512', Buffer.from(key));
    hmac.update(Buffer.from(data));
    return new Uint8Array(hmac.digest());
  }
}

export class SecretKey {
  leftKey: Uint8Array;
  rightKey: Uint8Array;
  chainCode: Uint8Array;

  constructor(leftKey: Uint8Array, rightKey: Uint8Array, chainCode: Uint8Array) {
    this.leftKey = leftKey;
    this.rightKey = rightKey;
    this.chainCode = chainCode;

    if (this.leftKey.length !== ExtendedEd25519Spec.keyLength) {
      throw new Error(
        `Invalid left key length. Expected: ${ExtendedEd25519Spec.keyLength}, Received: ${this.leftKey.length}`,
      );
    }

    if (this.rightKey.length !== ExtendedEd25519Spec.keyLength) {
      throw new Error(
        `Invalid right key length. Expected: ${ExtendedEd25519Spec.keyLength}, Received: ${this.rightKey.length}`,
      );
    }

    if (this.chainCode.length !== ExtendedEd25519Spec.keyLength) {
      throw new Error(
        `Invalid chain code length. Expected: ${ExtendedEd25519Spec.keyLength}, Received: ${this.chainCode.length}`,
      );
    }
  }

  static proto(sk: pb.SigningKey_ExtendedEd25519Sk): SecretKey {
    return new SecretKey(sk.leftKey, sk.rightKey, sk.chainCode);
  }

  equals(other: SecretKey): boolean {
    return (
      Buffer.from(this.leftKey).equals(Buffer.from(other.leftKey)) &&
      Buffer.from(this.rightKey).equals(Buffer.from(other.rightKey)) &&
      Buffer.from(this.chainCode).equals(Buffer.from(other.chainCode))
    );
  }

  hashCode(): number {
    return (
      Buffer.from(this.leftKey).reduce((hash, byte) => (hash << 5) - hash + byte, 0) ^
      Buffer.from(this.rightKey).reduce((hash, byte) => (hash << 5) - hash + byte, 0) ^
      Buffer.from(this.chainCode).reduce((hash, byte) => (hash << 5) - hash + byte, 0)
    );
  }
}

export class PublicKey {
  vk: spec.PublicKey;
  chainCode: Uint8Array;

  constructor(vk: spec.PublicKey, chainCode: Uint8Array) {
    this.vk = vk;
    this.chainCode = chainCode;

    if (this.chainCode.length !== ExtendedEd25519Spec.keyLength) {
      throw new Error(
        `Invalid chain code length. Expected: ${ExtendedEd25519Spec.keyLength}, Received: ${this.chainCode.length}`,
      );
    }
  }

  static proto(vk: pb.VerificationKey_ExtendedEd25519Vk): PublicKey {
    return new PublicKey(new spec.PublicKey(vk.vk.value), vk.chainCode);
  }

  equals(other: PublicKey): boolean {
    return this.vk.equals(other.vk) && Buffer.from(this.chainCode).equals(Buffer.from(other.chainCode));
  }

  hashCode(): number {
    return this.vk.hashCode() ^ Buffer.from(this.chainCode).reduce((hash, byte) => (hash << 5) - hash + byte, 0);
  }
}
