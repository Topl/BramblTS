export abstract class SigningKey {}

export abstract class VerificationKey {}

export class KeyPair<SK extends SigningKey, VK extends VerificationKey> {
  readonly signingKey: SK;
  readonly verificationKey: VK;

  constructor(signingKey: SK, verificationKey: VK) {
    this.signingKey = signingKey;
    this.verificationKey = verificationKey;
  }

  equals(other: KeyPair<SK, VK>): boolean {
    return this === other ||
      (other instanceof KeyPair &&
       this.signingKey === other.signingKey &&
       this.verificationKey === other.verificationKey);
  }
}
