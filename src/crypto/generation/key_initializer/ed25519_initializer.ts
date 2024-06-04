import Ed25519 from '@/crypto/signing/ed25519/ed25519.js';
import { SigningKey } from '@/crypto/signing/signing.js';
import { v4 as uuidv4 } from 'uuid';
import { Entropy } from '../mnemonic/entropy.js';
import { English, Language } from '../mnemonic/language.js';
import * as ed25519_spec from './../../signing/ed25519/ed25519_spec.js';
import { InitializationFailure } from './initialization_failure.js';
import { isLeft, left, right, type Either } from '@/common/functional/brambl_fp.js';
import type { KeyInitializer } from './key_initializer.js';

export class Ed25519Initializer implements KeyInitializer<SigningKey> {
  private readonly ed25519: Ed25519;

  constructor(ed25519: Ed25519) {
    this.ed25519 = ed25519;
  }

  random(): SigningKey {
    const uuid = uuidv4();
    return this.fromEntropy(Entropy.fromUuid(uuid));
  }

  fromEntropy(entropy: Entropy, password?: string | undefined): SigningKey {
    return this.ed25519.deriveKeyPairFromEntropy(entropy, password).signingKey;
  }

  fromBytes(bytes: Uint8Array): SigningKey {
    return new ed25519_spec.SecretKey(bytes);
  }

  async fromMnemonicString(
    mnemonicString: string,
    { language = new English(), password }: { language?: Language; password?: string } = {},
  ): Promise<Either<InitializationFailure, SigningKey>> {
    const entropyResult = await Entropy.fromMnemonicString(mnemonicString, { language });

    if (isLeft(entropyResult)) {
      return left(InitializationFailure.failedToCreateEntropy(entropyResult.left.toString()));
    }

    const entropy = entropyResult.right;
    const keyResult = this.fromEntropy(entropy, password);
    return right(keyResult);
  }
}
