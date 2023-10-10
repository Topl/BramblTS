// import * as ed from '@noble/ed25519';

// class Ed25519 {
//   sign(privateKey: Uint8Array, message: Uint8Array) {
//     return ed.sign(message, privateKey);
//   }

//   verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array) {
//     return ed.verify(signature, message, publicKey);
//   }

//   getVerificationKey(privateKey: Uint8Array) {
//     return ed.getPublicKey(privateKey);
//   }
// }

// export const ed25519 = new Ed25519();


import { Ed25519 as EdDSAEd25519 } from 'ed25519';

import { SecretKey, PublicKey, ed25519Spec } from './ed25519_spec';
import { EllipticCurveSignatureScheme } from '../elliptic_curve_signature_scheme';

class Ed25519 extends EllipticCurveSignatureScheme<SecretKey, PublicKey> {
  private impl: EdDSAEd25519;

  constructor() {
    super(ed25519Spec.seedLength);
    this.impl = new EdDSAEd25519();
  }

  sign(privateKey: SecretKey, message: Uint8Array): Uint8Array {
    const sig = new Uint8Array(ed25519Spec.signatureLength);
    this.impl.sign(
      privateKey.bytes,
      0,
      message,
      0,
      message.length,
      sig,
      0,
    );
    return sig;
  }

  verify(signature: Uint8Array, message: Uint8Array, publicKey: PublicKey): boolean {
    const sigByteArray = signature;
    const vkByteArray = publicKey.bytes;
    const msgByteArray = message;

    return sigByteArray.length === ed25519Spec.signatureLength &&
      vkByteArray.length === ed25519Spec.publicKeyLength &&
      this.impl.verify(
        sigByteArray,
        0,
        vkByteArray,
        0,
        msgByteArray,
        0,
        msgByteArray.length,
      );
  }

  getVerificationKey(secretKey: SecretKey): PublicKey {
    const pkBytes = new Uint8Array(ed25519Spec.publicKeyLength);
    this.impl.generatePublicKey(
      secretKey.bytes,
      0,
      pkBytes,
      0,
    );
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
