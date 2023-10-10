interface Entropy {
  // Define the properties and methods of the Entropy interface
}

interface EntropyToSeed {
  // Define the properties and methods of the EntropyToSeed interface
}

interface SigningKey {
  // Define the properties and methods of the SigningKey interface
}

interface VerificationKey {
  // Define the properties and methods of the VerificationKey interface
}

interface KeyPair<SK, VK> {
  // Define the properties and methods of the KeyPair interface
}

export abstract class EllipticCurveSignatureScheme<SK extends SigningKey, VK extends VerificationKey> {
  private readonly seedLength: number;

  constructor(seedLength: number) {
    this.seedLength = seedLength;
  }

  deriveKeyPairFromEntropy(entropy: Entropy, passphrase: string | null, options: { entropyToSeed?: EntropyToSeed } = {}): KeyPair<SK, VK> {
    const { entropyToSeed = { toSeed: () => new Uint8Array() } } = options;
    const seed = entropyToSeed.toSeed(entropy, passphrase, this.seedLength);
    return this.deriveKeyPairFromSeed(seed);
  }

  abstract deriveKeyPairFromSeed(seed: Uint8Array): KeyPair<SK, VK>;

  abstract deriveSecretKeyFromSeed(seed: Uint8Array): SK;

  abstract sign(privateKey: SK, message: Uint8Array): Uint8Array;

  abstract verify(signature: Uint8Array, message: Uint8Array, verifyKey: VK): boolean;

  abstract getVerificationKey(privateKey: SK): VK;
}
