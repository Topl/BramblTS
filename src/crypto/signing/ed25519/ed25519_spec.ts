// /* eslint-disable @typescript-eslint/no-unused-vars */
// /* eslint-disable @typescript-eslint/no-explicit-any */
import * as spec from '../../../../proto/quivr/models/shared';

export class Ed25519Spec {
  static signatureLength: number = 64;
  static keyLength: number = 32;
  static publicKeyLength: number = 32;
  static seedLength: number = 32;
}

export class SecretKey extends spec.quivr.models.SigningKey implements Ed25519Spec {
  bytes: Uint8Array;

  constructor(bytes: Uint8Array) {
    super();
    if (bytes.length !== Ed25519Spec.keyLength) {
      throw new Error(`Invalid left key length. Expected: ${Ed25519Spec.keyLength}, Received: ${bytes.length}`);
    }
    this.bytes = bytes;
  }

  equals(other: SecretKey): boolean {
    return (
      this === other || (other instanceof SecretKey && this.bytes.every((byte, index) => byte === other.bytes[index]))
    );
  }

  hashCode(): number {
    return this.bytes.reduce((acc, byte) => (acc * 31 + byte) | 0, 0);
  }
}

export class PublicKey extends spec.quivr.models.VerificationKey implements Ed25519Spec {
  bytes: Uint8Array;

  constructor(bytes: Uint8Array) {
    super();
    if (bytes.length !== Ed25519Spec.publicKeyLength) {
      throw new Error(`Invalid right key length. Expected: ${Ed25519Spec.publicKeyLength}, Received: ${bytes.length}`);
    }
    this.bytes = bytes;
  }

  equals(other: PublicKey): boolean {
    return (
      this === other || (other instanceof PublicKey && this.bytes.every((byte, index) => byte === other.bytes[index]))
    );
  }

  hashCode(): number {
    return this.bytes.reduce((acc, byte) => (acc * 31 + byte) | 0, 0);
  }
}
