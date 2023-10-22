import { Option } from 'fp-ts/lib/Option';
import { Bip32Index } from '../../../../src/crypto/generation/bip32_index';
import { PublicKey, SecretKey } from '../../../../src/crypto/signing/extended_ed25519/extended_ed25519';

export class CkdEd25519TestVector {
  description: string;
  rootSecretKey: SecretKey;
  rootVerificationKey: Option<PublicKey>;
  path: Bip32Index[];
  childSecretKey: SecretKey;
  childVerificationKey: PublicKey;

  constructor(
    description: string,
    rootSecretKey: SecretKey,
    rootVerificationKey: Option<PublicKey>,
    path: Bip32Index[],
    childSecretKey: SecretKey,
    childVerificationKey: PublicKey,
  ) {
    this.description = description;
    this.rootSecretKey = rootSecretKey;
    this.rootVerificationKey = rootVerificationKey;
    this.path = path;
    this.childSecretKey = childSecretKey;
    this.childVerificationKey = childVerificationKey;
  }

  
}
