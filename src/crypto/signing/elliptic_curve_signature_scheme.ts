/* eslint-disable @typescript-eslint/no-unused-vars */
// import { Entropy } from './entropy'; // Assuming Entropy class definition
// import { KeyPair } from './key-pair'; // Assuming KeyPair class definition
// import { Pbkdf2Sha512 } from './entropy-to-seed'; // Assuming Pbkdf2Sha512 class definition

import { Entropy } from "../generation/mnemonic/entropy";

export abstract class EllipticCurveSignatureScheme<SK extends SigningKey, VK extends VerificationKey> {
  readonly seedLength: number;

  constructor(seedLength: number) {
    this.seedLength = seedLength;
  }

  deriveKeyPairFromEntropy(
    entropy: Entropy,
    passphrase: string | null,
    options: { entropyToSeed: EntropyToSeed } = { entropyToSeed: new Pbkdf2Sha512() }
  ): KeyPair<SK, VK> {
    const seed = options.entropyToSeed.toSeed(entropy, passphrase, this.seedLength);
    return this.deriveKeyPairFromSeed(seed);
  }

  abstract deriveKeyPairFromSeed(seed: Uint8Array): KeyPair<SK, VK>;

  abstract deriveSecretKeyFromSeed(seed: Uint8Array): SK;

  abstract sign(privateKey: SK, message: Uint8Array): Uint8Array;

  abstract verify(signature: Uint8Array, message: Uint8Array, verifyKey: VK): boolean;

  abstract getVerificationKey(privateKey: SK): VK;
}
