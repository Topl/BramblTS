abstract class SigningKey {}

abstract class VerificationKey {}

class KeyPair<SK extends SigningKey, VK extends VerificationKey> {
  signingKey: SK;
  verificationKey: VK;

  constructor(signingKey: SK, verificationKey: VK) {
    this.signingKey = signingKey;
    this.verificationKey = verificationKey;
  }

  equals(other: KeyPair<SK, VK>): boolean {
    return (
      this.signingKey === other.signingKey &&
      this.verificationKey === other.verificationKey
    );
  }

  hashCode(): number {
    return this.signingKey.hashCode() ^ this.verificationKey.hashCode();
  }
}
