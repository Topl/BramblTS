import { Ed25519 as EdDSAEd25519 } from '../eddsa/ed25519';
import { EllipticCurveSignatureScheme } from '../elliptic_curve_signature_scheme';
import * as spec from './ed25519_spec';

/**
 * Ed25519 native implementation ported from BramblSC Scala.
 * This class extends EllipticCurveSignatureScheme and provides Ed25519 specific implementations.
 */
export class Ed25519 extends EllipticCurveSignatureScheme<spec.SecretKey, spec.PublicKey> {
  public impl: EdDSAEd25519;

  constructor() {
    super(spec.Ed25519Spec.seedLength);
    this.impl = new EdDSAEd25519();
  }

  /**
   * Signs a given message with a given signing key.
   * Preconditions: the private key must be a valid Ed25519 secret key - thus having a length of 32 bytes
   * Postconditions: the signature must be a valid Ed25519 signature - thus having a length of 64 bytes
   * @param privateKey The secret key used for signing.
   * @param message The message to sign.
   * @returns The signature.
   */
  sign(privateKey: spec.SecretKey, message: Uint8Array): Uint8Array {
    const sig = new Uint8Array(spec.Ed25519Spec.signatureLength);
    this.impl.sign({
      sk: privateKey.bytes,
      skOffset: 0,
      message,
      messageOffset: 0,
      messageLength: message.length,
      signature: sig,
      signatureOffset: 0,
    });
    return sig;
  }

  /**
   * Verifies a signature against a message using the public verification key.
   * Preconditions: the public key must be a valid Ed25519 public key
   * Preconditions: the signature must be a valid Ed25519 signature
   * @param signature The signature to verify.
   * @param message The message to verify against.
   * @param publicKey The public key used for verification.
   * @returns True if the signature is verified; otherwise false.
   */
  verify(signature: Uint8Array, message: Uint8Array, publicKey: spec.PublicKey): boolean {
    const sigByteArray = signature;
    const vkByteArray = publicKey.bytes;
    const msgByteArray = message;
    return (
      sigByteArray.length == spec.Ed25519Spec.signatureLength &&
      vkByteArray.length == spec.Ed25519Spec.publicKeyLength &&
      this.impl.verify({
        signature: sigByteArray,
        signatureOffset: 0,
        pk: vkByteArray,
        pkOffset: 0,
        message: msgByteArray,
        messageOffset: 0,
        messageLength: msgByteArray.length,
      })
    );
  }

  /**
   * Gets the public key from the secret key.
   * Preconditions: the secret key must be a valid Ed25519 secret key - thus having a length of 32 bytes
   * @param secretKey The secret key.
   * @returns The public verification key.
   */
  getVerificationKey(secretKey: spec.SecretKey): spec.PublicKey {
    const pkBytes = new Uint8Array(spec.Ed25519Spec.publicKeyLength);
    this.impl.generatePublicKey(secretKey.bytes, 0, pkBytes, 0);
    return new spec.PublicKey(pkBytes);
  }

  /**
   * Derives an Ed25519 secret key from a seed.
   * Preconditions: the seed must have a length of at least 32 bytes
   * @param seed The seed used for key derivation.
   * @returns The secret signing key.
   */
  deriveSecretKeyFromSeed(seed: Uint8Array): spec.SecretKey {
    if (seed.length < spec.Ed25519Spec.seedLength) {
      throw new Error(`Invalid seed length. Expected: ${spec.Ed25519Spec.seedLength}, Received: ${seed.length}`);
    }
    return new spec.SecretKey(seed.slice(0, 32));
  }
}

export default Ed25519;
