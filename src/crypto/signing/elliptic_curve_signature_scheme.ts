/* eslint-disable @typescript-eslint/no-unused-vars */
import * as spec from '../../../proto/quivr/models/shared';
import { EntropyToSeed, Pbkdf2Sha512 } from '../generation/entropy_to_seed';
import { Entropy } from '../generation/mnemonic/entropy';
import { KeyPair } from './signing';

export abstract class EllipticCurveSignatureScheme<SK extends spec.quivr.models.SigningKey, VK extends spec.quivr.models.VerificationKey> {
  readonly seedLength: number;

  constructor(seedLength: number) {
    this.seedLength = seedLength;
  }

  deriveKeyPairFromEntropy(
    entropy: Entropy,
    passphrase: string | null,
    options: { entropyToSeed: EntropyToSeed } = { entropyToSeed: new Pbkdf2Sha512() },
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
