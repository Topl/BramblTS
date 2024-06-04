import { isLeft, left, right, type Either } from '@/common/functional/brambl_fp.js';
import { ExtendedEd25519 } from '@/crypto/signing/extended_ed25519/extended_ed25519.js';
import { SigningKey } from '@/crypto/signing/signing.js';
import { v4 as uuidv4 } from 'uuid';
import * as spec from '../../signing/extended_ed25519/extended_ed25519_spec.js';
import { Entropy } from '../mnemonic/entropy.js';
import { English, Language } from '../mnemonic/language.js';
import { InitializationFailure } from './initialization_failure.js';
import type { KeyInitializer } from './key_initializer.js';

export class ExtendedEd25519Initializer implements KeyInitializer<SigningKey> {
  private extendedEd25519: ExtendedEd25519;

  constructor(extendedEd25519: ExtendedEd25519) {
    this.extendedEd25519 = extendedEd25519;
  }

  random(): SigningKey {
    const uuid = uuidv4();
    return this.fromEntropy(Entropy.fromUuid(uuid));
  }

  fromBytes(bytes: Uint8Array): SigningKey {
    return new spec.SecretKey(bytes.slice(0, 32), bytes.slice(32, 64), bytes.slice(64, 96));
  }

  fromEntropy(entropy: Entropy, password?: string | null): SigningKey {
    return this.extendedEd25519.deriveKeyPairFromEntropy(entropy, password).signingKey;
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
