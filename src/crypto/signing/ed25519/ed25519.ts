import { Ed25519 as EdDSAEd25519 } from '../eddsa/ed25519';

import { EllipticCurveSignatureScheme } from '../elliptic_curve_signature_scheme';
import { PublicKey, SecretKey, ed25519Spec } from './ed25519_spec';

export class Ed25519 extends EllipticCurveSignatureScheme<SecretKey, PublicKey> {
  private impl: EdDSAEd25519;

  constructor() {
    super(ed25519Spec.seedLength);
    this.impl = new EdDSAEd25519();
  }

  sign(privateKey: SecretKey, message: Uint8Array): Uint8Array {
    const sig = new Uint8Array(ed25519Spec.signatureLength);
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

  verify(signature: Uint8Array, message: Uint8Array, publicKey: PublicKey): boolean {
    const sigByteArray = signature;
    const vkByteArray = publicKey.bytes;
    const msgByteArray = message;

    return (
      sigByteArray.length === ed25519Spec.signatureLength &&
      vkByteArray.length === ed25519Spec.publicKeyLength &&
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

  getVerificationKey(secretKey: SecretKey): PublicKey {
    const pkBytes = new Uint8Array(ed25519Spec.publicKeyLength);
    this.impl.generatePublicKey(secretKey.bytes, 0, pkBytes, 0);
    return new PublicKey(pkBytes);
  }

  deriveSecretKeyFromSeed(seed: Uint8Array): SecretKey {
    if (seed.length < ed25519Spec.seedLength) {
      throw new Error(`Invalid seed length. Expected: ${ed25519Spec.seedLength}, Received: ${seed.length}`);
    }
    return new SecretKey(seed.slice(0, 32));
  }
}

export default Ed25519;
