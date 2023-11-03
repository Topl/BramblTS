/* eslint-disable @typescript-eslint/no-unused-vars */
import { EntropyToSeed, Pbkdf2Sha512 } from '../generation/entropy_to_seed';
import { Entropy } from '../generation/mnemonic/entropy';
import {KeyPair, SigningKey, VerificationKey} from './signing';

export abstract class EllipticCurveSignatureScheme<SK extends SigningKey, VK extends VerificationKey> {
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

  deriveKeyPairFromSeed(seed: Uint8Array): KeyPair<SK, VK> {
    const secretKey = this.deriveSecretKeyFromSeed(seed);
    const verificationKey = this.getVerificationKey(secretKey);
    return new KeyPair(secretKey, verificationKey);
  }
  
  abstract deriveSecretKeyFromSeed(seed: Uint8Array): SK;

  abstract sign(privateKey: SK, message: Uint8Array): Uint8Array;

  abstract verify(signature: Uint8Array, message: Uint8Array, verifyKey: VK): boolean;

  abstract getVerificationKey(privateKey: SK): VK;
}
