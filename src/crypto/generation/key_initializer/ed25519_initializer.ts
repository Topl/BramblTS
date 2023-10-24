/* eslint-disable @typescript-eslint/no-unused-vars */
import { Either } from '../../../common/functional/either';
import Ed25519 from '@/crypto/signing/ed25519/ed25519';
import { Entropy } from '../mnemonic/entropy';
import { English, Language } from '../mnemonic/language';
import { InitializationFailure, InitializationFailureType } from './initialization_failure';
import { KeyInitializer } from './key_initializer';
import { randomUUID } from 'crypto';

class Ed25519Initializer implements KeyInitializer {
  private readonly ed25519: Ed25519;

  constructor(ed25519: Ed25519) {
    this.ed25519 = ed25519;
  }

  random(): SigningKey {
    const entropy = Entropy.fromUuid(randomUUID());
    return this.fromEntropy(entropy);
  }

  fromEntropy(entropy: Entropy, password?: string | undefined): SigningKey {
    return this.ed25519.deriveKeyPairFromEntropy(entropy, password).signingKey;
  }

  fromBytes(bytes: Uint8Array): SigningKey {
    return new this.ed25519.SecretKey(bytes); // Assuming SecretKey constructor takes a Uint8Array
  }

  async fromMnemonicString(
    mnemonicString: string,
    options: {
      language?: Language;
      password?: string | null;
    } = {},
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
