/* eslint-disable @typescript-eslint/no-unused-vars */
import { Either } from '@/common/functional/either';
import { randomUUID } from 'crypto';
import * as spec from '../../signing/extended_ed25519/extended_ed25519_spec';
import { Entropy } from '../mnemonic/entropy';
import { English, Language } from '../mnemonic/language';
import { InitializationFailure, InitializationFailureType } from './initialization_failure';
import { KeyInitializer } from './key_initializer';

class ExtendedEd25519Initializer implements KeyInitializer {
  private extendedEd25519: ExtendedEd25519;

  constructor(extendedEd25519: ExtendedEd25519) {
    this.extendedEd25519 = extendedEd25519;
  }

  random(): SigningKey {
    return this.fromEntropy(Entropy.fromUuid(randomUUID()));
  }

  fromBytes(bytes: Uint8Array): SigningKey {
    return new spec.SecretKey(bytes.slice(0, 32), bytes.slice(32, 64), bytes.slice(64, 96));
  }

  fromEntropy(entropy: Entropy, password?: string | null): SigningKey {
    return this.extendedEd25519.deriveKeyPairFromEntropy(entropy, password).signingKey;
  }

  async fromMnemonicString(
    mnemonicString: string,
    options: { language?: Language; password?: string | null } = {},
  ): Promise<Either<InitializationFailure, SigningKey>> {
    const { language = new English(), password } = options;

    try {
      const entropyResult = await Entropy.fromMnemonicString(mnemonicString, { language });

      if (entropyResult.isLeft) {
        return Either.left(
          new InitializationFailure(InitializationFailureType.FailedToCreateEntropy, {
            context: entropyResult.getLeft().toString(),
          }),
        );
      }

      const entropy = entropyResult.getRight()!;
      const keyResult = this.fromEntropy(entropy, password);
      return Either.right(keyResult);
    } catch (error) {
      // Handle any exceptions here
      return Either.left(
        new InitializationFailure(InitializationFailureType.FailedToCreateEntropy, { context: error.message }),
      );
    }
  }
}
