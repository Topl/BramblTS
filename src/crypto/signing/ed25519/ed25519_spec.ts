// /* eslint-disable @typescript-eslint/no-unused-vars */
// /* eslint-disable @typescript-eslint/no-explicit-any */
import * as spec from '../../../../proto/quivr/models/shared';
// interface Ed25519Spec {
//   signatureLength: number;
//   keyLength: number;
//   publicKeyLength: number;
//   seedLength: number;
// }

// const ed25519Spec: Ed25519Spec = {
//   signatureLength: 64,
//   keyLength: 32,
//   publicKeyLength: 32,
//   seedLength: 32,
// };

// class SecretKey extends SigningKey {
//   chainCode(chainCode: Uint8Array, zHmacData: Uint8Array) {
//     throw new Error('Method not implemented.');
//   }
//   readonly bytes: Uint8Array;
//   leftKey: any;
//   rightKey: any;

//   constructor(bytes: Uint8Array) {
//     super();
//     this.bytes = bytes;

//     if (this.bytes.length !== ed25519Spec.keyLength) {
//       throw new Error(`Invalid secret key length. Expected: ${ed25519Spec.keyLength}, Received: ${this.bytes.length}`);
//     }
//   }

//   equals(other: SecretKey): boolean {
//     return (
//       this === other || (other instanceof SecretKey && this.bytes.every((val, index) => val === other.bytes[index]))
//     );
//   }

//   hashCode(): number {
//     let hash = 0;
//     for (const byte of this.bytes) {
//       hash = (hash << 5) - hash + byte;
//     }
//     return hash;
//   }
// }

// class PublicKey extends VerificationKey {
//   chainCode(chainCode: Uint8Array, arg1: Uint8Array) {
//     throw new Error('Method not implemented.');
//   }
//   readonly bytes: Uint8Array;
//   vk: any;

//   constructor(bytes: Uint8Array) {
//     this.bytes = bytes;

//     if (this.bytes.length !== ed25519Spec.publicKeyLength) {
//       throw new Error(
//         `Invalid public key length. Expected: ${ed25519Spec.publicKeyLength}, Received: ${this.bytes.length}`,
//       );
//     }
//   }

//   equals(other: PublicKey): boolean {
//     return (
//       this === other || (other instanceof PublicKey && this.bytes.every((val, index) => val === other.bytes[index]))
//     );
//   }

//   hashCode(): number {
//     let hash = 0;
//     for (const byte of this.bytes) {
//       hash = (hash << 5) - hash + byte;
//     }
//     return hash;
//   }
// }

// export { PublicKey, SecretKey, ed25519Spec };

export interface Ed25519Spec {
  signatureLength: number;
  keyLength: number;
  publicKeyLength: number;
  seedLength: number;
}

export const ed25519Spec: Ed25519Spec = {
  signatureLength: 64,
  keyLength: 32,
  publicKeyLength: 32,
  seedLength: 32,
};

export class SecretKey extends spec.quivr.models.SigningKey implements Ed25519Spec {
  bytes: Uint8Array;
  signatureLength = 64;
  keyLength = 32;
  publicKeyLength = 32;
  seedLength = 32;

  constructor(bytes: Uint8Array) {
    super();
    this.bytes = bytes;

    if (bytes.length !== this.keyLength) {
      throw new Error(`Invalid left key length. Expected: ${this.keyLength}, Received: ${bytes.length}`);
    }
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
  signatureLength = 64;
  keyLength = 32;
  publicKeyLength = 32;
  seedLength = 32;

  constructor(bytes: Uint8Array) {
    super();
    this.bytes = bytes;

    if (bytes.length !== this.publicKeyLength) {
      throw new Error(`Invalid right key length. Expected: ${this.publicKeyLength}, Received: ${bytes.length}`);
    }
  }
  // signatureLength: number;
  // keyLength: number;
  // publicKeyLength: number;
  // seedLength: number;

  // static signatureLength = 64;
  // static keyLength = 32;
  // static publicKeyLength = 32;
  // static seedLength = 32;

  equals(other: PublicKey): boolean {
    return (
      this === other || (other instanceof PublicKey && this.bytes.every((byte, index) => byte === other.bytes[index]))
    );
  }

  hashCode(): number {
    return this.bytes.reduce((acc, byte) => (acc * 31 + byte) | 0, 0);
  }
}
