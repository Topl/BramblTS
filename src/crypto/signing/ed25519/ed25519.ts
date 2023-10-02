import * as ed from '@noble/ed25519';

class Ed25519 {
  sign(privateKey: Uint8Array, message: Uint8Array) {
    return ed.sign(message, privateKey);
  }

  verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array) {
    return ed.verify(signature, message, publicKey);
  }

  getVerificationKey(privateKey: Uint8Array) {
    return ed.getPublicKey(privateKey);
  }
}

export const ed25519 = new Ed25519();
