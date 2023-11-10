/* eslint-disable @typescript-eslint/no-explicit-any */
import { Ed25519 as EdDSAEd25519 } from '../eddsa/ed25519';

import { EllipticCurveSignatureScheme } from '../elliptic_curve_signature_scheme';
import * as spec from './ed25519_spec';

export class Ed25519 extends EllipticCurveSignatureScheme<spec.SecretKey, spec.PublicKey> {
  public impl: EdDSAEd25519;

  constructor() {
    super(spec.Ed25519Spec.seedLength);
    this.impl = new EdDSAEd25519();
  }

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

  verify(signature: Uint8Array, message: Uint8Array, publicKey: spec.PublicKey): boolean {
    const sigByteArray = signature;
    const vkByteArray = publicKey.bytes;
    const msgByteArray = message;

    return (
      sigByteArray.length === spec.Ed25519Spec.signatureLength &&
      vkByteArray.length === spec.Ed25519Spec.publicKeyLength &&
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

  getVerificationKey(secretKey: spec.SecretKey): spec.PublicKey {
    const pkBytes = new Uint8Array(spec.Ed25519Spec.publicKeyLength);
    // console.log('secret key', secretKey.bytes);
    // console.log('pkBytes', pkBytes);
    this.impl.generatePublicKey(secretKey.bytes, 0, pkBytes, 0);
    console.log('pkBytes after generatePublicKey ->', pkBytes);
    return new spec.PublicKey(pkBytes);
  }

  deriveSecretKeyFromSeed(seed: Uint8Array): spec.SecretKey {
    if (seed.length < spec.Ed25519Spec.seedLength) {
      throw new Error(`Invalid seed length. Expected: ${spec.Ed25519Spec.seedLength}, Received: ${seed.length}`);
    }
    return new spec.SecretKey(seed.slice(0, 32));
  }
}

export default Ed25519;
