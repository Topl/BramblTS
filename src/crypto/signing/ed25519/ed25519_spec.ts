interface Ed25519Spec {
  signatureLength: number;
  keyLength: number;
  publicKeyLength: number;
  seedLength: number;
}

const ed25519Spec: Ed25519Spec = {
  signatureLength: 64,
  keyLength: 32,
  publicKeyLength: 32,
  seedLength: 32,
};

class SecretKey {
  readonly bytes: Uint8Array;

  constructor(bytes: Uint8Array) {
    this.bytes = bytes;

    if (this.bytes.length !== ed25519Spec.keyLength) {
      throw new Error(`Invalid secret key length. Expected: ${ed25519Spec.keyLength}, Received: ${this.bytes.length}`);
    }
  }

  // equals(other: SecretKey): boolean {
  //   return (
  //     this === other || (other instanceof SecretKey && this.bytes.every((val, index) => val === other.bytes[index]))
  //   );
  // }

  // hashCode(): number {
  //   let hash = 0;
  //   for (const byte of this.bytes) {
  //     hash = (hash << 5) - hash + byte;
  //   }
  //   return hash;
  // }
}

class PublicKey {
  readonly bytes: Uint8Array;

  constructor(bytes: Uint8Array) {
    this.bytes = bytes;

    if (this.bytes.length !== ed25519Spec.publicKeyLength) {
      throw new Error(
        `Invalid public key length. Expected: ${ed25519Spec.publicKeyLength}, Received: ${this.bytes.length}`,
      );
    }
  }

  // equals(other: PublicKey): boolean {
  //   return (
  //     this === other || (other instanceof PublicKey && this.bytes.every((val, index) => val === other.bytes[index]))
  //   );
  // }

  // hashCode(): number {
  //   let hash = 0;
  //   for (const byte of this.bytes) {
  //     hash = (hash << 5) - hash + byte;
  //   }
  //   return hash;
  // }
}

export { PublicKey, SecretKey, ed25519Spec };
