export abstract class SigningKey {}

import type { PlainMessage, BinaryReadOptions, JsonValue, JsonReadOptions, BinaryWriteOptions, JsonWriteOptions, JsonWriteStringOptions, MessageType } from '@bufbuild/protobuf';
import { extend } from 'fp-ts/lib/pipeable.js';
import { type SigningKey as tSK, Ed25519Sk, Ed25519Vk, ExtendedEd25519Sk, ExtendedEd25519Vk, type VerificationKey as tVK, KeyPair as tKP } from 'topl_common';

export abstract class VerificationKey {}

export class KeyPair<SK extends SigningKey, VK extends VerificationKey> {
  readonly signingKey: SK;
  readonly verificationKey: VK;

  constructor (signingKey: SK, verificationKey: VK) {
    this.signingKey = signingKey;
    this.verificationKey = verificationKey;
  }

  equals (other: KeyPair<SK, VK>): boolean {
    return (
      this === other ||
      (other instanceof KeyPair &&
        this.signingKey === other.signingKey &&
        this.verificationKey === other.verificationKey)
    );
  }
}

/// TODO: finish experimental keypair implementation, should provide a simpler way to create keypairs
export class UnifiedKeyPair extends tKP {
  readonly _signingKey: tSK;

  readonly _verificationKey: tVK;

  readonly algorithm: string;
 
  constructor (signingKey: tSK, verificationKey: tVK) {
    if (signingKey.sk.case !== verificationKey.vk.case) {
      throw new Error('Algorithm mismatch');
    }
    super({
      sk: signingKey,
      vk: verificationKey
    });

    this.algorithm = signingKey.sk.case;
    this._signingKey = signingKey;
    this._verificationKey = verificationKey;
  }
}

export class Ed25519KeyPair extends UnifiedKeyPair {}
export class ExtendedEd25519KeyPair extends UnifiedKeyPair {}