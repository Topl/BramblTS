/* eslint-disable @typescript-eslint/no-unused-vars */
import { Pbkdf2Sha512 } from '../generation/entropy_to_seed';
import { Entropy } from '../generation/mnemonic/entropy';
import { KeyPair, SigningKey, VerificationKey } from './signing';

/**
 * Abstract class representing an elliptic curve signature scheme.
 * It supports generating key pairs from entropy or seed, signing messages, and verifying signatures.
 *
 * @template SK - Type extending SigningKey, representing the secret key.
 * @template VK - Type extending VerificationKey, representing the verification key.
 */
export abstract class EllipticCurveSignatureScheme<SK extends SigningKey, VK extends VerificationKey> {
  readonly seedLength: number;

  /**
   * Constructor for elliptic curve signature scheme.
   * @param seedLength - Length of the seed used for generating keys.
   */
  constructor(seedLength: number) {
    this.seedLength = seedLength;
  }

  /**
   * Generate a key pair from given entropy and passphrase.
   *
   * @param entropy - Entropy used for generating the seed.
   * @param passphrase - Passphrase used in conjunction with the entropy.
   * @param entropyToSeed - Optional parameter for the entropy to seed conversion method.
   * @returns KeyPair<SK, VK> - The generated key pair.
   */
  deriveKeyPairFromEntropy(
    entropy: Entropy,
    passphrase: string | null,
    entropyToSeed = new Pbkdf2Sha512(),
  ): KeyPair<SK, VK> {
    const seed = entropyToSeed.toSeed(entropy, passphrase, this.seedLength);
    return this.deriveKeyPairFromSeed(seed);
  }

  /**
   * Derive a key pair from a seed.
   *
   * @param seed - The seed used for generating the key pair.
   * @returns KeyPair<SK, VK> - The derived key pair.
   */
  deriveKeyPairFromSeed(seed: Uint8Array): KeyPair<SK, VK> {
    const secretKey = this.deriveSecretKeyFromSeed(seed);
    const verificationKey = this.getVerificationKey(secretKey);
    return new KeyPair(secretKey, verificationKey);
  }

  // Derive a secret key from a seed.
  abstract deriveSecretKeyFromSeed(seed: Uint8Array): SK;

  // Sign a given message with a given signing key.
  abstract sign(privateKey: SK, message: Uint8Array): Uint8Array;

  // Verify a signature against a message using the public verification key.
  abstract verify(signature: Uint8Array, message: Uint8Array, verifyKey: VK): boolean;

  // Get the public key from the secret key
  abstract getVerificationKey(privateKey: SK): VK;
}
